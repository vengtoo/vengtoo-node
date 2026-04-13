export interface Subject {
  id: string;
  type?: string;
  attributes?: Record<string, unknown>;
  roles?: string[];
}

export interface Resource {
  id: string;
  type?: string;
  attributes?: Record<string, unknown>;
}

export interface AuthorizeRequest {
  subject: Subject;
  resource: Resource;
  action: string;
  context?: Record<string, unknown>;
}

export interface AuthorizeResponse {
  allowed: boolean;
  reason: string;
  policy_id?: string;
  access_path?: string;
}

export interface AuthzXOptions {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
}

export class AuthzXError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
    this.name = "AuthzXError";
  }

  get isAuthError(): boolean {
    return this.statusCode === 401;
  }
  get isForbidden(): boolean {
    return this.statusCode === 403;
  }
  get isNotFound(): boolean {
    return this.statusCode === 404;
  }
  get isServerError(): boolean {
    return this.statusCode >= 500;
  }
}

export class AuthzX {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;
  private maxRetries: number;

  constructor(options: AuthzXOptions = {}) {
    this.apiKey = options.apiKey || "";
    this.baseUrl = options.baseUrl || "https://api.authzx.com/v1";
    this.timeout = options.timeout || 10000;
    this.maxRetries = options.maxRetries ?? 2;
  }

  private get url(): string {
    return this.baseUrl.endsWith("/v1")
      ? `${this.baseUrl}/authorize`
      : `${this.baseUrl}/v1/authorize`;
  }

  async authorize(req: AuthorizeRequest): Promise<AuthorizeResponse> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, attempt * 100));
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      try {
        const response = await fetch(this.url, {
          method: "POST",
          headers,
          body: JSON.stringify(req),
          signal: controller.signal,
        });

        if (response.ok) {
          return (await response.json()) as AuthorizeResponse;
        }

        const body = await response.text();
        const err = new AuthzXError(response.status, body);

        // Only retry on 5xx or 429
        if (response.status >= 500 || response.status === 429) {
          lastError = err;
          continue;
        }

        throw err;
      } catch (err) {
        if (err instanceof AuthzXError) throw err;
        lastError = err as Error;
      } finally {
        clearTimeout(timeoutId);
      }
    }

    throw lastError;
  }

  async check(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Record<string, unknown>
  ): Promise<boolean> {
    const resp = await this.authorize({ subject, action, resource, context });
    return resp.allowed;
  }

  /**
   * Express middleware factory.
   * Usage: app.get('/docs/:id', authzx.middleware('document', 'read'), handler)
   */
  middleware(
    resourceType: string,
    action: string,
    getSubjectId: (req: any) => string = (req) =>
      req.headers["x-user-id"] || req.user?.id
  ) {
    return async (req: any, res: any, next: any) => {
      const subjectId = getSubjectId(req);
      if (!subjectId) {
        return res.status(401).json({ error: "missing subject ID" });
      }

      try {
        const allowed = await this.check(
          { id: subjectId, type: "user" },
          action,
          { type: resourceType, id: req.params?.id || req.path }
        );

        if (!allowed) {
          return res.status(403).json({ error: "forbidden" });
        }

        next();
      } catch {
        return res
          .status(500)
          .json({ error: "authorization check failed" });
      }
    };
  }
}

export default AuthzX;

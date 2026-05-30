export interface Subject {
  id: string;
  type?: string;
  attributes?: Record<string, unknown>;
  properties?: Record<string, unknown>;
  roles?: string[];
}

export interface Resource {
  id: string;
  type?: string;
  attributes?: Record<string, unknown>;
  properties?: Record<string, unknown>;
}

export interface Action {
  name: string;
  properties?: Record<string, unknown>;
}

export interface AuthorizeRequest {
  subject: Subject;
  resource: Resource;
  action: Action;
  context?: Record<string, unknown>;
}

export interface AuthorizeContext {
  reason?: string;
  reason_code?: string;
  policy_id?: string;
  access_path?: string;
}

export interface AuthorizeResponse {
  decision: boolean;
  context?: AuthorizeContext;
}

export interface BatchEvalItem {
  subject?: Subject;
  action?: Action;
  resource?: Resource;
  context?: Record<string, unknown>;
}

export interface BatchOptions {
  evaluations_semantic?: string;
}

export interface BatchEvaluationRequest {
  evaluations: BatchEvalItem[];
  subject?: Subject;
  action?: Action;
  resource?: Resource;
  context?: Record<string, unknown>;
  options?: BatchOptions;
}

export interface BatchEvaluationResponse {
  evaluations: AuthorizeResponse[];
}

export interface AuthzXOptions {
  apiKey?: string;
  /** OAuth2 Client Credentials: client identifier. */
  clientId?: string;
  /** OAuth2 Client Credentials: client secret (azx_cs_...). */
  clientSecret?: string;
  /** Override the OAuth2 token endpoint (defaults to AuthzX Cloud). */
  tokenUrl?: string;
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

/**
 * Thrown when the OAuth2 Client Credentials token exchange fails. Distinct
 * from AuthzXError so customers debugging setup know the failure was the
 * OAuth exchange, not their authorize() call.
 */
export class AuthzXOAuthError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    public readonly description: string
  ) {
    const msg =
      code === "invalid_client"
        ? "OAuth authentication failed: check client_id/client_secret"
        : description
          ? `OAuth token exchange failed (${code}): ${description}`
          : `OAuth token exchange failed (${code})`;
    super(msg);
    this.name = "AuthzXOAuthError";
  }
}

const DEFAULT_TOKEN_URL =
  "https://api.authzx.com/v1/oauth/token";
const REFRESH_SKEW_MS = 60_000;

interface CachedToken {
  accessToken: string;
  expiresAt: number; // epoch ms
}

export class AuthzX {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;
  private maxRetries: number;

  private oauth?: {
    clientId: string;
    clientSecret: string;
    tokenUrl: string;
  };
  private cachedToken?: CachedToken;
  /** In-flight token fetch promise — acts as a mutex across concurrent callers. */
  private tokenFetch?: Promise<string>;

  constructor(options: AuthzXOptions = {}) {
    this.apiKey = options.apiKey || "";
    this.baseUrl = options.baseUrl || "https://api.authzx.com/v1";
    this.timeout = options.timeout || 10000;
    this.maxRetries = options.maxRetries ?? 2;

    const hasOAuth = !!(options.clientId || options.clientSecret);
    if (hasOAuth) {
      if (!options.clientId || !options.clientSecret) {
        throw new Error(
          "AuthzX: both clientId and clientSecret are required for OAuth"
        );
      }
      this.oauth = {
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        tokenUrl: options.tokenUrl || DEFAULT_TOKEN_URL,
      };
    }

    if (this.apiKey && this.oauth) {
      throw new Error(
        "AuthzX: configure either apiKey or OAuth client credentials, not both"
      );
    }
  }

  private get url(): string {
    return `${this.baseUrl}/access/v1/evaluation`;
  }

  private get batchUrl(): string {
    return `${this.baseUrl}/access/v1/evaluations`;
  }

  /** Fetches (or returns cached) OAuth access token. Thread-safe via promise guard. */
  private async getAccessToken(): Promise<string> {
    if (!this.oauth) {
      throw new Error("AuthzX: OAuth not configured");
    }
    const now = Date.now();
    if (this.cachedToken && now < this.cachedToken.expiresAt - REFRESH_SKEW_MS) {
      return this.cachedToken.accessToken;
    }
    if (this.tokenFetch) {
      return this.tokenFetch;
    }
    this.tokenFetch = this.fetchToken().finally(() => {
      this.tokenFetch = undefined;
    });
    return this.tokenFetch;
  }

  private async fetchToken(): Promise<string> {
    const oauth = this.oauth!;
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
    }).toString();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    let response: Response;
    try {
      response = await fetch(oauth.tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const text = await response.text();
    if (response.ok) {
      let payload: {
        access_token?: string;
        token_type?: string;
        expires_in?: number;
        scope?: string;
      };
      try {
        payload = JSON.parse(text);
      } catch {
        throw new AuthzXOAuthError(
          response.status,
          "invalid_response",
          "token endpoint returned non-JSON body"
        );
      }
      if (!payload.access_token) {
        throw new AuthzXOAuthError(
          response.status,
          "invalid_response",
          "token endpoint returned empty access_token"
        );
      }
      const ttlMs = (payload.expires_in ?? 3600) * 1000;
      this.cachedToken = {
        accessToken: payload.access_token,
        expiresAt: Date.now() + ttlMs,
      };
      return payload.access_token;
    }

    // Error response — try to decode RFC 6749 error body.
    let errCode = "token_endpoint_error";
    let errDescription = text;
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object") {
        if (parsed.error) errCode = String(parsed.error);
        if (parsed.error_description)
          errDescription = String(parsed.error_description);
      }
    } catch {
      // leave defaults
    }
    if (response.status === 401 && errCode === "token_endpoint_error") {
      errCode = "invalid_client";
    }
    throw new AuthzXOAuthError(response.status, errCode, errDescription);
  }

  private invalidateToken(): void {
    this.cachedToken = undefined;
  }

  private async authHeader(): Promise<string | undefined> {
    if (this.oauth) {
      const token = await this.getAccessToken();
      return `Bearer ${token}`;
    }
    if (this.apiKey) {
      return `Bearer ${this.apiKey}`;
    }
    return undefined;
  }

  async authorize(req: AuthorizeRequest): Promise<AuthorizeResponse> {
    // OAuth flow gets exactly one 401-triggered refresh+retry across the
    // whole authorize() call, independent of maxRetries.
    let oauthRetried = false;

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, attempt * 100));
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      const auth = await this.authHeader();
      if (auth) headers["Authorization"] = auth;

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

        if (response.status === 401 && this.oauth && !oauthRetried) {
          this.invalidateToken();
          oauthRetried = true;
          attempt--; // refresh+retry doesn't count against maxRetries
          continue;
        }

        const err = new AuthzXError(response.status, body);

        // Only retry on 5xx or 429
        if (response.status >= 500 || response.status === 429) {
          lastError = err;
          continue;
        }

        throw err;
      } catch (err) {
        if (err instanceof AuthzXError) throw err;
        if (err instanceof AuthzXOAuthError) throw err;
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
    const resp = await this.authorize({ subject, action: { name: action }, resource, context });
    return resp.decision;
  }

  async authorizeBatch(req: BatchEvaluationRequest): Promise<BatchEvaluationResponse> {
    if (!req.evaluations || req.evaluations.length === 0) {
      throw new Error("authzx: batch request requires at least one evaluation");
    }
    if (req.evaluations.length > 50) {
      throw new Error("authzx: batch request exceeds maximum of 50 evaluations");
    }

    let oauthRetried = false;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, attempt * 100));
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      const auth = await this.authHeader();
      if (auth) headers["Authorization"] = auth;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      try {
        const response = await fetch(this.batchUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(req),
          signal: controller.signal,
        });

        if (response.ok) {
          return (await response.json()) as BatchEvaluationResponse;
        }

        const body = await response.text();

        if (response.status === 401 && this.oauth && !oauthRetried) {
          this.invalidateToken();
          oauthRetried = true;
          attempt--;
          continue;
        }

        const err = new AuthzXError(response.status, body);
        if (response.status >= 500 || response.status === 429) {
          lastError = err;
          continue;
        }
        throw err;
      } catch (err) {
        if (err instanceof AuthzXError) throw err;
        if (err instanceof AuthzXOAuthError) throw err;
        lastError = err as Error;
      } finally {
        clearTimeout(timeoutId);
      }
    }

    throw lastError;
  }

  async checkBatch(req: BatchEvaluationRequest): Promise<boolean[]> {
    const resp = await this.authorizeBatch(req);
    return resp.evaluations.map((e) => e.decision);
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

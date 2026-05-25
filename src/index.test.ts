import { AuthzX, AuthzXError, AuthzXOAuthError } from "./index";
import { createServer, IncomingMessage, ServerResponse } from "http";

function mockServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void
): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => server.close(),
      });
    });
  });
}

function collectBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk: string) => (data += chunk));
    req.on("end", () => resolve(JSON.parse(data)));
  });
}

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`  PASS  ${name}`);
  } catch (e: any) {
    console.log(`  FAIL  ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

function assert(condition: boolean, msg: string) {
  if (!condition) throw new Error(msg);
}

async function main() {
  console.log("AuthzX Node SDK Tests\n");

  await test("check returns true when allowed", async () => {
    const srv = await mockServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "role_match" } }));
    });
    try {
      const client = new AuthzX({ apiKey: "test-key", baseUrl: srv.url });
      const allowed = await client.check({ id: "user-1" }, "read", { id: "doc-1" });
      assert(allowed === true, "expected true");
    } finally {
      srv.close();
    }
  });

  await test("check returns false when denied", async () => {
    const srv = await mockServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: false, context: { reason: "no policy" } }));
    });
    try {
      const client = new AuthzX({ apiKey: "test-key", baseUrl: srv.url });
      const allowed = await client.check({ id: "user-1" }, "delete", { id: "doc-1" });
      assert(allowed === false, "expected false");
    } finally {
      srv.close();
    }
  });

  await test("authorize returns full response", async () => {
    const srv = await mockServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "direct", policy_id: "pol-1", access_path: "direct" } }));
    });
    try {
      const client = new AuthzX({ apiKey: "test-key", baseUrl: srv.url });
      const resp = await client.authorize({
        subject: { id: "user-1" },
        resource: { id: "doc-1" },
        action: { name: "read" },
      });
      assert(resp.decision === true, "expected decision=true");
      assert(resp.context?.policy_id === "pol-1", "expected pol-1");
      assert(resp.context?.access_path === "direct", "expected direct");
    } finally {
      srv.close();
    }
  });

  await test("sends correct headers and body", async () => {
    const srv = await mockServer(async (req, res) => {
      const body = await collectBody(req);
      assert(req.headers["authorization"] === "Bearer my-key", "bad auth header");
      assert(body.subject.id === "user-1", "bad subject");
      assert(body.action.name === "read", "bad action name");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "ok" } }));
    });
    try {
      const client = new AuthzX({ apiKey: "my-key", baseUrl: srv.url });
      await client.check({ id: "user-1" }, "read", { id: "doc-1" });
    } finally {
      srv.close();
    }
  });

  await test("throws AuthzXError on 401", async () => {
    const srv = await mockServer((req, res) => {
      res.writeHead(401);
      res.end("invalid key");
    });
    try {
      const client = new AuthzX({ apiKey: "bad", baseUrl: srv.url });
      try {
        await client.check({ id: "user-1" }, "read", { id: "doc-1" });
        assert(false, "should have thrown");
      } catch (e: any) {
        assert(e instanceof AuthzXError, "expected AuthzXError");
        assert(e.statusCode === 401, "expected 401");
        assert(e.isAuthError, "expected isAuthError");
      }
    } finally {
      srv.close();
    }
  });

  await test("retries on 500 then succeeds", async () => {
    let attempts = 0;
    const srv = await mockServer((req, res) => {
      attempts++;
      if (attempts < 3) {
        res.writeHead(500);
        res.end("error");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "ok" } }));
    });
    try {
      const client = new AuthzX({ apiKey: "test", baseUrl: srv.url, maxRetries: 2 });
      const allowed = await client.check({ id: "user-1" }, "read", { id: "doc-1" });
      assert(allowed === true, "expected true after retry");
      assert(attempts === 3, `expected 3 attempts, got ${attempts}`);
    } finally {
      srv.close();
    }
  });

  // --- OAuth2 Client Credentials ---

  function collectForm(req: IncomingMessage): Promise<URLSearchParams> {
    return new Promise((resolve) => {
      let data = "";
      req.on("data", (chunk: string) => (data += chunk));
      req.on("end", () => resolve(new URLSearchParams(data)));
    });
  }

  await test("oauth: token exchange happy path", async () => {
    let tokenCalls = 0;
    let apiCalls = 0;
    let gotAuthHeader = "";
    const srv = await mockServer(async (req, res) => {
      if (req.url === "/oauth/token") {
        tokenCalls++;
        const form = await collectForm(req);
        assert(
          req.headers["content-type"] === "application/x-www-form-urlencoded",
          "bad token content-type"
        );
        assert(form.get("grant_type") === "client_credentials", "bad grant_type");
        assert(form.get("client_id") === "cid", "bad client_id");
        assert(form.get("client_secret") === "azx_cs_secret", "bad client_secret");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "jwt.token.here",
            token_type: "Bearer",
            expires_in: 3600,
          })
        );
        return;
      }
      apiCalls++;
      gotAuthHeader = req.headers["authorization"] as string;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "ok" } }));
    });
    try {
      const client = new AuthzX({
        clientId: "cid",
        clientSecret: "azx_cs_secret",
        baseUrl: srv.url,
        tokenUrl: `${srv.url}/oauth/token`,
      });
      const allowed = await client.check({ id: "u-1" }, "read", { id: "d-1" });
      assert(allowed === true, "expected allowed");
      assert(tokenCalls === 1, `expected 1 token call, got ${tokenCalls}`);
      assert(apiCalls === 1, `expected 1 API call, got ${apiCalls}`);
      assert(
        gotAuthHeader === "Bearer jwt.token.here",
        `bad auth header: ${gotAuthHeader}`
      );
    } finally {
      srv.close();
    }
  });

  await test("oauth: invalid_client surfaces clear error", async () => {
    const srv = await mockServer((req, res) => {
      if (req.url === "/oauth/token") {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_client" }));
        return;
      }
      res.writeHead(500);
      res.end("API should not be called");
    });
    try {
      const client = new AuthzX({
        clientId: "cid",
        clientSecret: "azx_cs_wrong",
        baseUrl: srv.url,
        tokenUrl: `${srv.url}/oauth/token`,
      });
      try {
        await client.check({ id: "u-1" }, "read", { id: "d-1" });
        assert(false, "should have thrown");
      } catch (e: any) {
        assert(
          e instanceof AuthzXOAuthError,
          `expected AuthzXOAuthError, got ${e?.constructor?.name}`
        );
        assert(
          e.message.includes("check client_id/client_secret"),
          `bad message: ${e.message}`
        );
      }
    } finally {
      srv.close();
    }
  });

  await test("oauth: cached token reused across calls", async () => {
    let tokenCalls = 0;
    let apiCalls = 0;
    const srv = await mockServer((req, res) => {
      if (req.url === "/oauth/token") {
        tokenCalls++;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "tok-abc",
            token_type: "Bearer",
            expires_in: 3600,
          })
        );
        return;
      }
      apiCalls++;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "ok" } }));
    });
    try {
      const client = new AuthzX({
        clientId: "cid",
        clientSecret: "azx_cs_secret",
        baseUrl: srv.url,
        tokenUrl: `${srv.url}/oauth/token`,
      });
      await client.check({ id: "u-1" }, "read", { id: "d-1" });
      await client.check({ id: "u-1" }, "read", { id: "d-1" });
      await client.check({ id: "u-1" }, "read", { id: "d-1" });
      assert(tokenCalls === 1, `expected 1 token call, got ${tokenCalls}`);
      assert(apiCalls === 3, `expected 3 API calls, got ${apiCalls}`);
    } finally {
      srv.close();
    }
  });

  await test("oauth: 401 on API triggers refresh+retry", async () => {
    let tokenCalls = 0;
    let apiCalls = 0;
    const srv = await mockServer((req, res) => {
      if (req.url === "/oauth/token") {
        tokenCalls++;
        const tok = tokenCalls === 1 ? "tok-stale" : "tok-fresh";
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: tok,
            token_type: "Bearer",
            expires_in: 3600,
          })
        );
        return;
      }
      apiCalls++;
      const auth = req.headers["authorization"];
      if (auth === "Bearer tok-stale") {
        res.writeHead(401);
        res.end("stale token");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: true, context: { reason: "ok" } }));
    });
    try {
      const client = new AuthzX({
        clientId: "cid",
        clientSecret: "azx_cs_secret",
        baseUrl: srv.url,
        tokenUrl: `${srv.url}/oauth/token`,
      });
      const allowed = await client.check({ id: "u-1" }, "read", { id: "d-1" });
      assert(allowed === true, "expected allowed after refresh+retry");
      assert(tokenCalls === 2, `expected 2 token calls, got ${tokenCalls}`);
      assert(apiCalls === 2, `expected 2 API calls, got ${apiCalls}`);
    } finally {
      srv.close();
    }
  });

  await test("oauth: 401 retry only once (no loop)", async () => {
    let apiCalls = 0;
    const srv = await mockServer((req, res) => {
      if (req.url === "/oauth/token") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "tok",
            token_type: "Bearer",
            expires_in: 3600,
          })
        );
        return;
      }
      apiCalls++;
      res.writeHead(401);
      res.end("nope");
    });
    try {
      const client = new AuthzX({
        clientId: "cid",
        clientSecret: "azx_cs_secret",
        baseUrl: srv.url,
        tokenUrl: `${srv.url}/oauth/token`,
      });
      try {
        await client.check({ id: "u-1" }, "read", { id: "d-1" });
        assert(false, "should have thrown");
      } catch (e: any) {
        assert(e instanceof AuthzXError, `expected AuthzXError, got ${e?.constructor?.name}`);
        assert(e.statusCode === 401, `expected 401, got ${e.statusCode}`);
      }
      assert(apiCalls === 2, `expected 2 API calls, got ${apiCalls}`);
    } finally {
      srv.close();
    }
  });

  await test("oauth: apiKey + OAuth is construction error", async () => {
    try {
      new AuthzX({
        apiKey: "azx_key",
        clientId: "cid",
        clientSecret: "azx_cs_secret",
      });
      assert(false, "should have thrown");
    } catch (e: any) {
      assert(
        e.message.includes("either apiKey or OAuth"),
        `bad message: ${e.message}`
      );
    }
  });

  await test("no retry on 400", async () => {
    let attempts = 0;
    const srv = await mockServer((req, res) => {
      attempts++;
      res.writeHead(400);
      res.end("bad request");
    });
    try {
      const client = new AuthzX({ apiKey: "test", baseUrl: srv.url });
      try {
        await client.check({ id: "user-1" }, "read", { id: "doc-1" });
        assert(false, "should have thrown");
      } catch (e: any) {
        assert(e instanceof AuthzXError, "expected AuthzXError");
        assert(attempts === 1, `expected 1 attempt, got ${attempts}`);
      }
    } finally {
      srv.close();
    }
  });

  console.log();
}

main();

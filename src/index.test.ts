import { AuthzX, AuthzXError } from "./index";
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
      res.end(JSON.stringify({ allowed: true, reason: "role_match" }));
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
      res.end(JSON.stringify({ allowed: false, reason: "no policy" }));
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
      res.end(JSON.stringify({ allowed: true, reason: "direct", policy_id: "pol-1", access_path: "direct" }));
    });
    try {
      const client = new AuthzX({ apiKey: "test-key", baseUrl: srv.url });
      const resp = await client.authorize({
        subject: { id: "user-1" },
        resource: { id: "doc-1" },
        action: "read",
      });
      assert(resp.allowed === true, "expected allowed");
      assert(resp.policy_id === "pol-1", "expected pol-1");
      assert(resp.access_path === "direct", "expected direct");
    } finally {
      srv.close();
    }
  });

  await test("sends correct headers and body", async () => {
    const srv = await mockServer(async (req, res) => {
      const body = await collectBody(req);
      assert(req.headers["authorization"] === "Bearer my-key", "bad auth header");
      assert(body.subject.id === "user-1", "bad subject");
      assert(body.action === "read", "bad action");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ allowed: true, reason: "ok" }));
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
      res.end(JSON.stringify({ allowed: true, reason: "ok" }));
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

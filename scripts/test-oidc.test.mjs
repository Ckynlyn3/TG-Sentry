import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { loginTestAdmin, startTestOIDC } from "./test-oidc.mjs";

// Helper contract test, not a substitute for the real provider/server integration.
test("headless helper scopes transaction/session cookies and verifies a human admin", async (t) => {
  let callbackCookie;
  let providerCookie;
  const provider = createServer((req, res) => {
    providerCookie = req.headers.cookie;
    res.writeHead(302, { Location: `${base}/api/v1/auth/callback?code=fixture-code&state=fixture-state` });
    res.end();
  });
  provider.listen(0, "127.0.0.1");
  await once(provider, "listening");
  t.after(() => new Promise((resolve) => provider.close(resolve)));
  const service = createServer((req, res) => {
    switch (req.url) {
      case "/api/v1/auth/login":
        res.writeHead(302, {
          Location: `http://127.0.0.1:${provider.address().port}/authorize`,
          "Set-Cookie": "aegis_oidc_tx=transaction; Path=/api/v1/auth/callback; HttpOnly; SameSite=Lax",
        });
        break;
      case "/api/v1/auth/callback?code=fixture-code&state=fixture-state":
        callbackCookie = req.headers.cookie;
        res.writeHead(302, { Location: "/", "Set-Cookie": [
          "aegis_oidc_tx=; Max-Age=0; Path=/api/v1/auth/callback",
          "aegis_session=session; Path=/; HttpOnly; SameSite=Strict",
        ] });
        break;
      case "/api/v1/me":
        if (req.headers.cookie !== "aegis_session=session") {
          res.writeHead(401);
          break;
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ kind: "human", role: "admin", subject: "subject" }));
        return;
      default:
        res.writeHead(404); // A fallback to legacy POST /login must fail.
    }
    res.end();
  });
  service.listen(0, "127.0.0.1");
  await once(service, "listening");
  t.after(() => new Promise((resolve) => service.close(resolve)));
  const base = `http://127.0.0.1:${service.address().port}`;
  assert.equal(await loginTestAdmin(base), "aegis_session=session");
  assert.equal(callbackCookie, "aegis_oidc_tx=transaction");
  assert.equal(providerCookie, undefined);
});

test("missing test provider binary fails instead of falling back to token login", async () => {
  await assert.rejects(startTestOIDC({
    binary: new URL("./missing-test-binaries/aegishook", import.meta.url).pathname,
    dataDir: new URL("./missing-test-data", import.meta.url).pathname,
    base: "http://127.0.0.1:18792",
  }), { code: "ENOENT" });
});

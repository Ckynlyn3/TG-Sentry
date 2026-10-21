// Test fixture only: real OIDC redirects and local admin bind, no token-login fallback.
import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { once } from "node:events";

export async function stopTestProcess(proc) {
  if (proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = once(proc, "exit");
  proc.kill("SIGTERM");
  await exited;
}

export async function startTestOIDC({ binary, dataDir, base, name = "Display Name" }) {
  const fixture = join(dirname(binary), process.platform === "win32" ? "test-oidc.exe" : "test-oidc");
  const subject = "subject"; // Same synthetic principal as internal/testoidc.
  const proc = spawn(fixture, ["--subject", subject, "--name", name], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    const issuer = await new Promise((resolve, reject) => {
      const lines = createInterface({ input: proc.stdout });
      // Existing adapter readiness budget: 100 attempts × 30 ms.
      const timer = setTimeout(() => finish(new Error("test OIDC did not become ready")), 100 * 30);
      const finish = (error, url) => {
        clearTimeout(timer);
        lines.close();
        proc.off("error", failed);
        proc.off("exit", exited);
        if (error) reject(error);
        else resolve(url);
      };
      const failed = (error) => finish(error);
      const exited = (code, signal) => finish(new Error(`test OIDC exited: ${code ?? signal}`));
      proc.once("error", failed);
      proc.once("exit", exited);
      lines.on("line", (line) => {
        if (line.startsWith("test OIDC ready ")) finish(null, line.slice("test OIDC ready ".length));
      });
    });
    await promisify(execFile)(binary, ["admin", "bind", "--data-dir", dataDir, "--issuer", issuer, "--subject", subject, "--name", name]);
    return {
      // readOIDCSettings in internal/server/oidc.go is the production config path.
      env: {
        TG_SENTRY_OIDC_ISSUER: issuer,
        TG_SENTRY_OIDC_CLIENT_ID: "client",
        TG_SENTRY_OIDC_CLIENT_SECRET: "synthetic-fixture-secret",
        TG_SENTRY_OIDC_REDIRECT_URL: `${base}/api/v1/auth/callback`,
        TG_SENTRY_OIDC_ROLE_CLAIM: "roles",
        TG_SENTRY_OIDC_ROLE_MAP: "admin=admins,auditor=auditors,readonly=readers",
        TG_SENTRY_OIDC_TRUSTED_AUDIENCES: "",
      },
      stop: () => stopTestProcess(proc),
    };
  } catch (error) {
    // A failed spawn has no PID and will not emit exit.
    if (proc.pid) await stopTestProcess(proc);
    throw error;
  }
}

function cookie(response, name) {
  const value = response.headers.getSetCookie().find((entry) => entry.startsWith(`${name}=`));
  assert.ok(value, `missing ${name} cookie`);
  return value.split(";")[0];
}

function redirect(response) {
  assert.equal(response.status, 302, `OIDC redirect failed at ${response.url}`);
  const location = response.headers.get("location");
  assert.ok(location, "missing OIDC Location");
  return new URL(location, response.url);
}

export async function loginTestAdmin(base) {
  // A scoped two-cookie jar: the transaction goes only to our callback; the
  // resulting session goes only to management APIs, never to the provider.
  const login = await fetch(`${base}/api/v1/auth/login`, { redirect: "manual" });
  const authorizeURL = redirect(login);
  const transaction = cookie(login, "aegis_oidc_tx");
  const authorize = await fetch(authorizeURL, { redirect: "manual" });
  const callbackURL = redirect(authorize);
  assert.equal(callbackURL.origin, new URL(base).origin);
  assert.equal(callbackURL.pathname, "/api/v1/auth/callback");
  const callback = await fetch(callbackURL, { redirect: "manual", headers: { Cookie: transaction } });
  redirect(callback);
  const session = cookie(callback, "aegis_session");
  const me = await fetch(`${base}/api/v1/me`, { headers: { Cookie: session } });
  assert.equal(me.status, 200);
  const identity = await me.json();
  assert.equal(identity.kind, "human");
  assert.equal(identity.role, "admin");
  assert.equal(identity.subject, "subject");
  return session;
}

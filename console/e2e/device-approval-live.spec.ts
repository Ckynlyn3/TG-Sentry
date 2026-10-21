import { execFile, spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { expect, request, test as baseTest, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import zhCN from "../src/i18n/zh-CN";
import { startTestOIDC, stopTestProcess } from "../../scripts/test-oidc.mjs";

const bin = resolve(process.env.AEGIS_BIN ?? join(import.meta.dirname, "../../bin/aegishook"));
// Reuse server.spec.ts's serialized loopback fixture address; no production server is contacted.
const base = "http://127.0.0.1:18797";
const run = promisify(execFile);
interface LiveServer { dataDir: string; stop: () => Promise<void>; start: () => Promise<void> }
interface Fixtures { approverRole: "admin" | "auditor" | "readonly"; liveServer: LiveServer }
interface GrantTicket { device_code: string; user_code: string; verification_uri: string }

// Real OIDC and real S3 endpoints, never page.route or a reused administrator cookie. Each test owns
// and removes its server, provider and temporary data. Claims and bindings below are synthetic only.
const test = baseTest.extend<Fixtures>({
  approverRole: ["admin", { option: true }],
  liveServer: async ({ approverRole }, provideServer) => {
    expect(existsSync(bin), "build the integrated control plane and embedded console first").toBe(true);
    expect(Object.hasOwn(process.env, "TG_SENTRY_DATABASE_URL"), "live fixture requires its own SQLite, not a configured PostgreSQL DSN").toBe(false);
    const dir = await mkdtemp(join(tmpdir(), "tgs-device-live-"));
    const dataDir = join(dir, "data");
    let server: ChildProcess | undefined;
    let oidc: Awaited<ReturnType<typeof startTestOIDC>> | undefined;
    const stop = async () => { if (server) await stopTestProcess(server); server = undefined; };
    try {
      oidc = await startTestOIDC({ binary: bin, dataDir, base, name: `fixture-${approverRole}` });
      const env = { ...process.env, ...oidc.env, XDG_CONFIG_HOME: join(dir, "config"), ...(approverRole !== "admin" ? { TG_SENTRY_OIDC_ROLE_CLAIM: "name", TG_SENTRY_OIDC_ROLE_MAP: "admin=fixture-admin,auditor=fixture-auditor,readonly=fixture-readonly" } : {}) };
      if (approverRole !== "admin") {
        // test-oidc's signed name claim is mapped through the existing configurable role machinery.
        // Remove only this generated recovery binding so it cannot override the mapped readonly/auditor role.
        const issuer = oidc.env.TG_SENTRY_OIDC_ISSUER;
        if (typeof issuer !== "string" || !issuer) throw new Error("missing synthetic fixture issuer");
        await run(bin, ["admin", "unbind", "--data-dir", dataDir, "--issuer", issuer, "--subject", "subject"]);
      }
      const start = async () => {
        server = spawn(bin, ["serve", "--data-dir", dataDir, "--addr", "127.0.0.1:18797"], { env, stdio: "ignore" });
        let spawnError: Error | undefined;
        server.once("error", (error) => { spawnError = error; });
        // Same readiness budget as server.spec.ts: 200 attempts × 50 ms.
        await expect.poll(async () => {
          if (spawnError) throw spawnError;
          if (server?.exitCode !== null) throw new Error("fixture server exited before readiness");
          try { return (await fetch(base)).ok; } catch { return false; }
        }, { timeout: 200 * 50 }).toBe(true);
      };
      await start();
      await provideServer({ dataDir, stop, start });
    } finally {
      await stop();
      await oidc?.stop();
      await rm(dir, { recursive: true, force: true });
    }
  },
});

async function signIn(page: Page, path = "/device") {
  await page.goto(`${base}${path}`);
  await expect(page.getByRole("heading", { name: zhCN.login.title })).toBeVisible();
  await page.getByRole("button", { name: zhCN.login.sso, exact: true }).click();
}
async function review(page: Page, ticket: GrantTicket) {
  await signIn(page, `/device?user_code=${encodeURIComponent(ticket.user_code)}`);
  await expect(page.getByRole("textbox", { name: zhCN.device.code })).toHaveValue(ticket.user_code);
  await page.getByRole("button", { name: zhCN.device.lookup }).click();
  await expect(page.getByText("Headless build device", { exact: true })).toBeVisible();
  await expect(page.getByText(ticket.user_code, { exact: true })).toBeVisible();
}
async function createGrant(poller: Awaited<ReturnType<typeof request.newContext>>): Promise<GrantTicket> {
  const authorization = await poller.post("/api/v1/client/device-authorization", { form: { client_id: "aegishook", name: "Headless build device", platform: "linux" } });
  expect(authorization.status()).toBe(200);
  const ticket: GrantTicket = await authorization.json();
  expect(ticket.verification_uri).toBe(`${base}/device`);
  expect(ticket.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
  return ticket;
}
const tokenForm = (ticket: GrantTicket) => ({ client_id: "aegishook", grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: ticket.device_code });

test.describe("live device verification @live-s3", () => {
  test("browser authenticates, approves once, and a separate headless poller redeems once", async ({ page, liveServer }) => {
    void liveServer;
    const poller = await request.newContext({ baseURL: base }); // no browser cookie jar
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(String(error)));
    try {
      const ticket = await createGrant(poller);
      await review(page, ticket);
      const identity = await page.request.get(`${base}/api/v1/me`);
      expect((await identity.json()).kind).toBe("human");
      await page.getByRole("checkbox").check();
      let submissions = 0;
      page.on("request", (req) => { if (new URL(req.url()).pathname === "/api/v1/device-grants/decision") submissions++; });
      await page.getByRole("button", { name: zhCN.device.approve, exact: true }).dblclick();
      await expect(page.getByRole("heading", { name: zhCN.device.approvedTitle })).toBeFocused();
      expect(submissions).toBe(1);
      await page.reload();
      await page.getByRole("button", { name: zhCN.device.lookup }).click();
      await expect(page.getByRole("heading", { name: zhCN.device.approvedTitle })).toBeFocused();
      await expect(page.getByRole("checkbox")).toHaveCount(0);
      const redeemed = await poller.post("/api/v1/client/device-token", { form: tokenForm(ticket) });
      expect(redeemed.status()).toBe(200);
      const token: { access_token: string; token_type: string; nodeId: string } = await redeemed.json();
      // Do not attach or print device_code/access_token as evidence.
      expect(Boolean(token.access_token && token.nodeId)).toBe(true);
      expect(token.token_type).toBe("Bearer");
      const duplicate = await poller.post("/api/v1/client/device-token", { form: tokenForm(ticket) });
      expect(duplicate.status()).toBe(400);
      expect((await duplicate.json()).error).toBe("invalid_grant");
      expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze()).violations).toEqual([]);
      expect(errors).toEqual([]);
    } finally { await poller.dispose(); }
  });

  test("denial is recovered accurately from lookup and the headless device receives access_denied", async ({ page, liveServer }) => {
    void liveServer;
    const poller = await request.newContext({ baseURL: base });
    try {
      const ticket = await createGrant(poller);
      await review(page, ticket);
      await page.getByRole("checkbox").check();
      await page.getByRole("button", { name: zhCN.device.deny, exact: true }).click();
      await expect(page.getByRole("heading", { name: zhCN.device.deniedTitle })).toBeFocused();
      await page.reload();
      await page.getByRole("button", { name: zhCN.device.lookup }).click();
      await expect(page.getByRole("heading", { name: zhCN.device.deniedTitle })).toBeFocused();
      await expect(page.getByRole("checkbox")).toHaveCount(0);
      const response = await poller.post("/api/v1/client/device-token", { form: tokenForm(ticket) });
      expect(response.status()).toBe(400);
      expect((await response.json()).error).toBe("access_denied");
    } finally { await poller.dispose(); }
  });

  test("unknown code and seeded expiry cannot be approved or redeemed", async ({ page, liveServer }) => {
    const poller = await request.newContext({ baseURL: base });
    try {
      await signIn(page, "/device?user_code=BCDF-GHJK");
      await page.getByRole("button", { name: zhCN.device.lookup }).click();
      await expect(page.getByRole("heading", { name: zhCN.device.expiredTitle })).toBeFocused();
      const ticket = await createGrant(poller);
      const lookup = await page.request.post(`${base}/api/v1/device-grants/lookup`, { data: { userCode: ticket.user_code } });
      expect(lookup.status()).toBe(200);
      const grant: { grantId: string } = await lookup.json();
      await liveServer.stop();
      // Seeded expiry, not a wall-clock 900-second wait. Modify only this stopped, test-owned SQLite
      // grant (core/store_database.go records schema; core/device_grants.go expiresAt), using Node 24 stdlib.
      await run(process.execPath, ["--input-type=module", "-e", `
        import assert from 'node:assert/strict'; import { DatabaseSync } from 'node:sqlite';
        const db = new DatabaseSync(process.argv[1]);
        try { const result = db.prepare("UPDATE records SET payload=json_set(payload,'$.expiresAt',?) WHERE tenant_id='default' AND kind='device_grants' AND id=?").run(new Date(0).toISOString(), process.argv[2]); assert.equal(result.changes, 1); } finally { db.close(); }
      `, join(liveServer.dataDir, "aegishook.db"), grant.grantId]);
      await liveServer.start();
      await signIn(page, `/device?user_code=${encodeURIComponent(ticket.user_code)}`);
      await page.getByRole("button", { name: zhCN.device.lookup }).click();
      await expect(page.getByRole("heading", { name: zhCN.device.expiredTitle })).toBeFocused();
      await expect(page.getByRole("checkbox")).toHaveCount(0);
      const expired = await poller.post("/api/v1/client/device-token", { form: tokenForm(ticket) });
      expect(expired.status()).toBe(400);
      expect((await expired.json()).error).toBe("expired_token");
    } finally { await poller.dispose(); }
  });

  for (const approverRole of ["readonly", "auditor"] satisfies Array<"readonly" | "auditor">) {
    test.describe(`live ${approverRole} denial`, () => {
      test.use({ approverRole });
      test("SSO non-admin cannot inspect or decide a device grant", async ({ page, liveServer }) => {
        void liveServer;
        await signIn(page);
        await expect(page.getByRole("heading", { name: zhCN.device.forbiddenTitle })).toBeFocused();
        await expect(page.getByRole("textbox")).toHaveCount(0);
        expect((await (await page.request.get(`${base}/api/v1/me`)).json()).role).toBe(approverRole);
        expect((await page.request.post(`${base}/api/v1/device-grants/lookup`, { data: { userCode: "BCDF-GHJK" } })).status()).toBe(403);
        expect((await page.request.post(`${base}/api/v1/device-grants/decision`, { data: { grantId: "not-a-grant", decision: "approve" } })).status()).toBe(403);
      });
    });
  }
});

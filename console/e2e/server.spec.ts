import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import zhCN from "../src/i18n/zh-CN";
import { startTestOIDC, loginTestAdmin, stopTestProcess } from "../../scripts/test-oidc.mjs";

// Live smoke against a real control plane serving the embedded console (scripts/prepare-assets.mjs →
// internal/assets/ui → `go build`). Spawns a throwaway `aegishook serve` like adapter/opencode.test.mjs,
// seeds real risk events through the hook API, then checks list, identity, detail and paging in the UI.
// AEGIS_BIN overrides the binary; in CI a missing binary fails instead of skipping.
const bin = resolve(process.env.AEGIS_BIN ?? join(import.meta.dirname, "../../bin/aegishook"));
const base = "http://127.0.0.1:18797";
const SEEDED = 26; // one more than the console page size (src/lib/api.ts PAGE_SIZE = 25)

test.skip(!existsSync(bin) && !process.env.CI, `build ${bin} (npm run build at the repo root) to run the live smoke`);
test.describe.configure({ mode: "serial" });

let server: ChildProcess | undefined;
let oidc: Awaited<ReturnType<typeof startTestOIDC>> | undefined;
let dir = "";

test.beforeAll(async () => {
  expect(existsSync(bin), `control-plane binary at ${bin}`).toBe(true);
  dir = await mkdtemp(join(tmpdir(), "tgs-console-live-"));
  oidc = await startTestOIDC({ binary: bin, dataDir: join(dir, "data"), base, name: "本地管理员" });
  server = spawn(bin, ["serve", "--data-dir", join(dir, "data"), "--addr", "127.0.0.1:18797"], {
    env: { ...process.env, ...oidc.env, XDG_CONFIG_HOME: join(dir, "config") },
    stdio: "ignore",
  });
  for (let i = 0; i < 200; i++) {
    try {
      if ((await fetch(base)).ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("control plane did not become ready");
});

test.afterAll(async () => {
  if (server) await stopTestProcess(server);
  await oidc?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

const token = (name: string) => readFile(join(dir, "data", `${name}.token`), "utf8").then((t) => t.trim());

async function seed() {
  const cookie = await loginTestAdmin(base);
  const me = (await (await fetch(`${base}/api/v1/me`, { headers: { cookie } })).json()) as { version: string };
  const hook = { "Content-Type": "application/json", Authorization: `Bearer ${await token("hook")}` };
  const post = async (path: string, body: unknown) => {
    const res = await fetch(`${base}${path}`, { method: "POST", headers: hook, body: JSON.stringify(body) });
    expect(res.status, `${path}: ${await res.clone().text()}`).toBe(200);
  };
  // Same producer journey as internal/server/risk_events_test.go: an unenrolled local Claude session.
  await post("/api/v1/instances", { id: "e2e", agent: "claude", sessionId: "session", cwd: dir, hookVersion: me.version });
  for (let i = 0; i < SEEDED; i++)
    await post("/api/v1/reviews", { instanceId: "e2e", callId: `call-${i}`, toolName: "Bash", argumentsObj: { command: "redis-cli FLUSHALL" } });
  return cookie;
}

test("control plane serves the console: login, seeded risk events, identity, detail, paging", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && !m.text().startsWith("Failed to load resource") && errors.push(m.text()));

  const root = await page.request.get(`${base}/`);
  expect(root.status()).toBe(200); // the OpenCode adapter test's readiness probe
  expect(root.headers()["content-security-policy"]).toContain("default-src 'self'");
  const cookie = await seed();
  const newest = (await (await fetch(`${base}/api/v1/risk-events?page_size=1`, { headers: { cookie } })).json()) as { items: { id: string }[] };
  const newestId = newest.items[0]?.id ?? "";
  expect(newestId).not.toBe("");

  await page.goto(`${base}/events`);
  await expect(page.getByRole("heading", { name: "登录控制台" })).toBeVisible();
  const list = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/risk-events");
  await page.getByRole("button", { name: zhCN.login.sso, exact: true }).click();
  expect((await list).status()).toBe(200);

  const table = page.getByRole("table", { name: "风险事件，按发现时间倒序" });
  const rows = table.locator("tbody tr");
  await expect(rows).toHaveCount(25);
  const first = rows.first();
  await expect(first.getByRole("link", { name: "R_DB_REDIS" })).toBeVisible(); // analytic uid, not "unnamed"
  await expect(first).toContainText("规则");
  await expect(first).toContainText("未登记"); // unenrolled local agent (#10)
  await expect(page.getByRole("banner").getByRole("button", { name: zhCN.shell.account.replace("{{name}}", "本地管理员"), exact: true })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  await first.getByRole("link", { name: "R_DB_REDIS" }).click();
  const drawer = page.getByRole("dialog", { name: "R_DB_REDIS" });
  await expect(drawer).toContainText(newestId);
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  const older = page.waitForResponse((r) => new URL(r.url()).searchParams.has("page_token"));
  await page.getByRole("link", { name: "更早的事件" }).click();
  expect((await older).status()).toBe(200);
  await expect(rows).toHaveCount(SEEDED - 25);
  await expect(page.getByText("没有更早的事件")).toBeVisible();

  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "风险事件" })).toBeVisible(); // session cookie + SPA fallback
  expect(errors).toEqual([]);
});

declare global {
  interface Window {
    __themeCSP: { theme: number | null; paint: number | null; violations: string[] };
  }
}

// #92 R1 regression: Vite's lazy-import dependency maps preload the emitted stylesheet (e.g.
// OverviewPage → assets/index-*.css). The build must keep serving it: behind the SPA fallback a
// missing asset answers HTML + nosniff, the browser rejects it, and the lazy stats surface fails.
// The seeded risk events from the first test give the stats surface real data (serial mode).
test("overview stats charts render with every lazy-referenced stylesheet served", async ({ page }) => {
  const errors: string[] = [];
  const failed: string[] = [];
  const cssBad: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && !m.text().startsWith("Failed to load resource") && errors.push(m.text()));
  page.on("requestfailed", (r) => failed.push(`${r.url()} ${r.failure()?.errorText}`));
  page.on("response", (r) => {
    const path = new URL(r.url()).pathname;
    if (path.endsWith(".css") && (r.status() !== 200 || !r.headers()["content-type"]?.includes("text/css")))
      cssBad.push(`${r.status()} ${r.headers()["content-type"]} ${r.url()}`);
    // The pre-auth /api/v1/me 401 is the router guard's intended probe, not a failure.
    if (r.status() >= 400 && !(r.status() === 401 && path === "/api/v1/me")) failed.push(`${r.status()} ${r.url()}`);
  });

  await page.goto(`${base}/overview`);
  await expect(page.getByRole("heading", { name: "登录控制台" })).toBeVisible();
  await page.getByRole("button", { name: zhCN.login.sso, exact: true }).click();
  try {
    await expect(page.locator(".recharts-surface").first()).toBeVisible({ timeout: 15_000 });
  } finally {
    console.log("css violations:", JSON.stringify(cssBad), "failed responses:", JSON.stringify(failed), "page errors:", JSON.stringify(errors));
  }
  await expect(page.locator(".chart-trend")).toBeVisible();
  expect(cssBad).toEqual([]);
  expect(failed).toEqual([]);
  expect(errors).toEqual([]);
});


test("control-plane CSP allows the saved theme before first paint without an external theme request", async ({ page }) => {
  const errors: string[] = [];
  const themeRequests: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && !m.text().startsWith("Failed to load resource") && errors.push(m.text()));
  page.on("request", (r) => new URL(r.url()).pathname === "/theme-init.js" && themeRequests.push(r.url()));
  await page.emulateMedia({ colorScheme: "light" });
  await page.addInitScript(() => {
    localStorage.setItem("tgs-theme", "dark");
    window.__themeCSP = { theme: null, paint: null, violations: [] };
    document.addEventListener("securitypolicyviolation", (e) => window.__themeCSP.violations.push(e.violatedDirective));
    new MutationObserver(() => {
      if (window.__themeCSP.theme === null && document.documentElement?.dataset.theme) window.__themeCSP.theme = performance.now();
    }).observe(document, { attributes: true, childList: true, subtree: true });
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) if (entry.name === "first-paint") window.__themeCSP.paint = entry.startTime;
    }).observe({ type: "paint", buffered: true });
  });
  const response = await page.goto(`${base}/login`);
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect.poll(() => page.evaluate(() => typeof window.__themeCSP.paint === "number")).toBe(true);
  const state = await page.evaluate(() => ({ ...window.__themeCSP, final: document.documentElement.dataset.theme }));
  expect(state.final).toBe("dark");
  expect(typeof state.theme).toBe("number");
  expect(typeof state.paint).toBe("number");
  expect(state.theme!).toBeLessThanOrEqual(state.paint!);
  expect(state.violations).toEqual([]);
  expect(errors).toEqual([]);
  expect(themeRequests).toEqual([]);
  const script = await page.locator("script#theme-init").textContent();
  expect(script).not.toBeNull();
  const hash = createHash("sha256").update(script!).digest("base64");
  expect(response?.headers()["content-security-policy"]).toContain(`script-src 'self' 'sha256-${hash}'`);
});

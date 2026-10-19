import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { allEvents, callsPage, clientNodes, firstPage, instances, me, policiesPage, riskStats24h, sessionSummaries, templatesPage } from "../src/test/fixtures";

type ListMode = "ok" | "empty" | "error" | "forbidden";
const WIDTHS = [320, 1440] as const;
const THEMES = ["light", "dark"] as const;
const SHOTS = process.env.CONSOLE_SHOTS; // optional evidence directory

// Test-only API: the same EVENT-SCHEMA-shaped fixtures as the unit tests.
async function mockApi(page: Page, { authed = true, list = "ok" as ListMode, stats = false, sessions = "ok" as ListMode } = {}) {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (url.pathname === "/api/v1/me")
      return authed ? json(200, stats ? { ...me, capabilities: ["risk-stats"] } : me) : json(401, { error: "请使用本机管理令牌登录" });
    const fixed: Record<string, unknown> = {
      "/api/v1/client-nodes": clientNodes,
      "/api/v1/instances": instances,
      "/api/v1/calls": callsPage,
      "/api/v1/policies": policiesPage,
      "/api/v1/templates": templatesPage,
    };
    if (url.pathname in fixed) return json(200, fixed[url.pathname]);
    if (url.pathname === "/api/v1/session-summaries") {
      if (sessions === "empty") return json(200, { items: [], total: 0, page: 1, pageSize: 20 });
      if (sessions === "error") return json(500, { error: "数据库不可用" });
      if (sessions === "forbidden") return json(403, { error: "forbidden" });
      return json(200, sessionSummaries);
    }
    // Proposed stats endpoint: answered only in the capability variant; otherwise the app must not ask.
    if (url.pathname === "/api/v1/risk-events/stats") return stats ? json(200, riskStats24h) : json(404, { error: "not found" });
    if (url.pathname === "/api/v1/risk-events") {
      if (list === "empty") return json(200, { items: [], next_page_token: "" });
      if (list === "error") return json(500, { error: "数据库不可用" });
      if (list === "forbidden") return json(403, { error: "forbidden" });
      return json(200, firstPage);
    }
    const id = url.pathname.match(/^\/api\/v1\/risk-events\/(.+)$/)?.[1];
    const e = allEvents.find((x) => x.id === decodeURIComponent(id ?? ""));
    return e ? json(200, e) : json(404, { error: "事件不存在" });
  });
}

function watchConsole(page: Page) {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  // Mocked 4xx/5xx responses are logged by the browser as resource errors; those are expected.
  page.on("console", (m) => m.type() === "error" && !m.text().startsWith("Failed to load resource") && errors.push(m.text()));
  return errors;
}

async function setup(page: Page, width: number, theme: (typeof THEMES)[number]) {
  await page.setViewportSize({ width, height: 900 });
  await page.emulateMedia({ colorScheme: theme });
  await page.addInitScript((t) => localStorage.setItem("tgs-theme", t), theme);
}

async function check(page: Page, name: string) {
  // Measure settled pixels: fonts loaded and entrance animations finished (SOP lens 3).
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all(document.getAnimations().map((a) => a.finished));
  });
  const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(axe.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), name).toEqual([]);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow, `${name}: horizontal page overflow`).toBeLessThanOrEqual(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
}

for (const width of WIDTHS)
  for (const theme of THEMES)
    test.describe(`${width}px ${theme}`, () => {
      test.setTimeout(60_000);
      test("login, list, drawer, empty, error and forbidden pass axe with no overflow", async ({ page }) => {
        const errors = watchConsole(page);
        await setup(page, width, theme);

        await mockApi(page, { authed: false });
        await page.goto("/events");
        await expect(page.getByRole("heading", { name: "登录控制台" })).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
        await check(page, `login-${width}-${theme}`);

        await page.unrouteAll();
        await mockApi(page);
        await page.goto("/events");
        await expect(page.getByRole("table")).toBeVisible();
        const header = page.getByRole("banner");
        await expect(header.getByText("单租户部署")).toBeVisible();
        await expect(header.getByText("本地管理员")).toBeVisible();
        await check(page, `events-${width}-${theme}`);

        await page.getByRole("link", { name: "远程代码下载与执行" }).first().click();
        await expect(page.getByRole("dialog")).toBeVisible();
        await check(page, `drawer-${width}-${theme}`);

        await page.goto("/overview");
        await expect(page.getByRole("heading", { name: "风险事件统计暂未提供" })).toBeVisible();
        await expect(page.getByText("其中 2 条在等人工审批")).toBeVisible();
        await check(page, `overview-${width}-${theme}`);

        await page.unrouteAll();
        await mockApi(page, { stats: true });
        await page.goto("/overview");
        await expect(page.locator(".chart-trend .recharts-area").first()).toBeVisible();
        await check(page, `overview-stats-${width}-${theme}`);

        for (const list of ["empty", "error", "forbidden"] as const) {
          await page.unrouteAll();
          await mockApi(page, { list });
          await page.goto("/events");
          // A 500 surfaces after TanStack Query's default 3 retries with exponential backoff (~7 s).
          await expect(list === "empty" ? page.getByRole("heading", { name: "还没有风险事件" }) : page.getByRole("alert")).toBeVisible({ timeout: 15_000 });
          await check(page, `${list}-${width}-${theme}`);
        }
        expect(errors).toEqual([]);
      });
    });

for (const width of WIDTHS)
  test(`keyboard journey at ${width}px: skip link → row link → drawer → Esc returns focus`, async ({ page, browserName }) => {
    await page.setViewportSize({ width, height: 900 });
    await mockApi(page);
    await page.goto("/events");
    await expect(page.getByRole("table")).toBeVisible();
    // WebKit (Safari default) skips links on Tab unless "Press Tab to highlight each item" is on;
    // Option+Tab is the documented equivalent (microsoft/playwright#2114).
    const tab = browserName === "webkit" ? "Alt+Tab" : "Tab";
    await page.keyboard.press(tab);
    await expect(page.getByRole("link", { name: "跳到主要内容" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main")).toBeFocused();
    const link = page.locator('[data-event-link="evt_block_01"]');
    for (let i = 0; i < 30 && !(await link.evaluate((el) => el === document.activeElement)); i++) {
      await page.keyboard.press(tab);
      const outline = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        return el && el !== document.body ? parseFloat(getComputedStyle(el).outlineWidth) : 2;
      });
      expect(outline, "visible focus ring (≥ 2px)").toBeGreaterThanOrEqual(2);
    }
    await expect(link).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: "关闭事件详情" })).toBeFocused();
    for (let i = 0; i < 6; i++) await page.keyboard.press(tab);
    expect(await page.evaluate(() => Boolean(document.activeElement?.closest('[role="dialog"]'))), "focus stays in the dialog").toBe(true);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
    await expect(link).toBeFocused();
  });

test("mobile nav at 320px is modal: focus contained, Esc returns focus, active link closes it", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await mockApi(page);
  await page.goto("/events");
  await expect(page.getByRole("table")).toBeVisible();
  // Role queries skip the toggle while the modal nav hides the background (aria-hidden), so use CSS.
  const toggle = page.locator("button.nav-toggle");
  await expect(page.getByRole("button", { name: "打开导航" })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "主导航" });
  await expect(nav).toBeHidden();
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  // APG modal dialog: focus moves to the first focusable element, now the Overview link.
  await expect(nav.getByRole("link", { name: "总览" })).toBeFocused();
  // Background is hidden from AT (aria-hidden keeps live-region ancestors, theKashey/aria-hidden#10).
  expect(await page.evaluate(() => ["main#main", "header.app-header"].every((q) => document.querySelector(q)?.closest('[aria-hidden="true"]')))).toBe(true);
  // SC 2.4.11 / APG modal: Tab and Shift+Tab never reach controls behind the opaque panel.
  const inNav = () => page.evaluate(() => Boolean(document.activeElement?.closest("#app-nav")));
  for (const key of ["Tab", "Tab", "Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab"]) {
    await page.keyboard.press(key);
    expect(await inNav(), `focus after ${key} stays in the open nav`).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(nav).toBeHidden();
  await expect(toggle).toBeFocused();
  // Activating the current page's link still closes the overlay.
  await toggle.click();
  await nav.getByRole("link", { name: "风险事件" }).click();
  await expect(nav).toBeHidden();
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("table")).toBeVisible();
});

test("reduced motion collapses the drawer animation", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await mockApi(page);
  await page.goto("/events?event=evt_block_01");
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  const ms = await drawer.evaluate((el) => parseFloat(getComputedStyle(el).animationDuration) * 1000);
  expect(ms).toBeLessThanOrEqual(0.01);
});

test("Plex is the loaded UI face and CJK falls back to system fonts", async ({ page }) => {
  await mockApi(page);
  await page.goto("/events");
  await expect(page.getByRole("table")).toBeVisible();
  expect(await page.evaluate(async () => (await document.fonts.ready, document.fonts.check('14px "IBM Plex Sans"')))).toBe(true);
});

test("overview without the stats capability never requests the stats endpoint", async ({ page }) => {
  const asked: string[] = [];
  page.on("request", (r) => r.url().includes("/api/v1/risk-events/stats") && asked.push(r.url()));
  await mockApi(page);
  await page.goto("/overview");
  await expect(page.getByRole("heading", { name: "风险事件统计暂未提供" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "最新风险事件" })).toBeVisible();
  expect(asked).toEqual([]);
});

test("overview range select is keyboard operable and lands in the URL", async ({ page }) => {
  await mockApi(page, { stats: true });
  await page.goto("/overview");
  const select = page.getByLabel("时间范围");
  await expect(select).toBeVisible();
  await select.focus();
  await select.selectOption("7d");
  await expect(page).toHaveURL(/range=7d/);
});

// Session audit (#16 S4): list, custom-range filter bar, empty/error/forbidden at both widths and themes.
for (const width of WIDTHS)
  for (const theme of THEMES)
    test(`sessions ${width}px ${theme}: list, filters and states pass axe with no overflow`, async ({ page }) => {
      test.setTimeout(60_000);
      const errors = watchConsole(page);
      await setup(page, width, theme);
      await mockApi(page);
      await page.goto("/sessions");
      await expect(page.getByRole("table", { name: "会话，按开始时间倒序" })).toBeVisible();
      await expect(page.getByLabel("用户")).toBeDisabled();
      await expect(page.getByText("0 次调用")).toBeVisible();
      await check(page, `sessions-${width}-${theme}`);

      await page.getByLabel("时间范围").selectOption("custom");
      await expect(page.getByLabel("开始")).toBeVisible();
      await check(page, `sessions-custom-${width}-${theme}`);

      for (const sessions of ["empty", "error", "forbidden"] as const) {
        await page.unrouteAll();
        await mockApi(page, { sessions });
        await page.goto("/sessions");
        await expect(sessions === "empty" ? page.getByRole("heading", { name: "还没有会话记录" }) : page.getByRole("alert")).toBeVisible({ timeout: 15_000 });
        await check(page, `sessions-${sessions}-${width}-${theme}`);
      }
      expect(errors).toEqual([]);
    });

for (const width of WIDTHS)
  test(`sessions keyboard journey at ${width}px: skip link → filters → session key → reset`, async ({ page, browserName }) => {
    await page.setViewportSize({ width, height: 900 });
    await mockApi(page);
    await page.goto("/sessions");
    await expect(page.getByRole("table")).toBeVisible();
    const tab = browserName === "webkit" ? "Alt+Tab" : "Tab";
    await page.keyboard.press(tab);
    await expect(page.getByRole("link", { name: "跳到主要内容" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main")).toBeFocused();
    const key = page.getByLabel("会话 ID");
    for (let i = 0; i < 30 && !(await key.evaluate((el) => el === document.activeElement)); i++) {
      await page.keyboard.press(tab);
      const outline = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        return el && el !== document.body ? parseFloat(getComputedStyle(el).outlineWidth) : 2;
      });
      expect(outline, "visible focus ring (≥ 2px)").toBeGreaterThanOrEqual(2);
    }
    await expect(key).toBeFocused();
    await page.keyboard.type("ses-heartbeat-only");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/sessionKey=ses-heartbeat-only/);
    const reset = page.getByRole("link", { name: "重置筛选" });
    await reset.focus();
    await page.keyboard.press("Enter");
    await expect(page).not.toHaveURL(/sessionKey=/);
  });

import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import zhCN from "../src/i18n/zh-CN";
import { me } from "../src/test/fixtures";

// Mocked browser accessibility verification; the separate live S3 suite exercises real transport.
const grant = { grantId: "grant-1", userCode: "BCDF-GHJK", name: "研发笔记本", platform: "linux", source: "127.0.0.1", status: "pending", associatedUser: null };

async function check(page: Page) {
  await page.evaluate(async () => { await document.fonts.ready; await Promise.all(document.getAnimations().map((a) => a.finished)); });
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
}

// Viewports from the global web/testing.md responsive matrix; themes and height reuse console.spec.ts.
const themes: ("light" | "dark")[] = ["light", "dark"];
for (const width of [320, 375, 768, 1024, 1440, 1920]) for (const theme of themes) {
  test(`device approval mocked axe and keyboard ${width}px ${theme}`, async ({ page, browserName }) => {
    test.setTimeout(60_000); // existing console.spec.ts browser-state matrix deadline
    // Safari's default Tab skips non-text controls; reuse console.spec.ts:131–133 (playwright#2114).
    const tab = browserName === "webkit" ? "Alt+Tab" : "Tab";
    await page.setViewportSize({ width, height: 900 });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.addInitScript((value) => localStorage.setItem("tgs-theme", value), theme);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(String(error)));
    page.on("console", (message) => { if (message.type() === "error" && !message.text().startsWith("Failed to load resource")) errors.push(message.text()); });
    let role = "admin";
    let kind = "human";
    let status = "pending";
    let failure = 0;
    const decisions: unknown[] = [];
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const json = (code: number, body: unknown, headers: Record<string, string> = {}) => route.fulfill({ status: code, contentType: "application/json", headers, body: JSON.stringify(body) });
      if (path === "/api/v1/me") return json(200, { ...me, role, kind });
      // #72 U4: the lookup's strong ETag is the reviewed validator for the decision.
      if (path === "/api/v1/device-grants/lookup") return failure ? json(failure, { error: "refused" }) : json(200, { ...grant, status }, { ETag: '"grant-tag"' });
      if (path === "/api/v1/device-grants/decision") {
        const body: unknown = route.request().postDataJSON();
        expect(route.request().headers()["if-match"]).toBe('"grant-tag"');
        decisions.push(body);
        const denied = typeof body === "object" && body !== null && "decision" in body && body.decision === "deny";
        return json(200, { grantId: grant.grantId, status: denied ? "denied" : "approved" });
      }
      throw new Error(`unhandled mock path ${path}`);
    });
    await page.goto("/device?user_code=bcdf-ghjk");
    await expect(page.getByRole("textbox", { name: zhCN.device.code })).toBeFocused();
    await check(page);
    expect(decisions).toEqual([]);
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { name: zhCN.device.reviewTitle })).toBeFocused();
    await check(page);
    await page.keyboard.press(tab);
    const checkbox = page.getByRole("checkbox");
    await expect(checkbox).toBeFocused();
    await page.keyboard.press("Space");
    await page.keyboard.press(tab);
    await expect(page.getByRole("button", { name: zhCN.device.approve, exact: true })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { name: zhCN.device.approvedTitle })).toBeFocused();
    await check(page);
    expect(decisions).toEqual([{ grantId: grant.grantId, decision: "approve" }]);

    await page.goto("/device?user_code=BCDF-GHJK");
    await page.getByRole("button", { name: zhCN.device.lookup }).click();
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: zhCN.device.deny, exact: true }).click();
    await expect(page.getByRole("heading", { name: zhCN.device.deniedTitle })).toBeFocused();
    await check(page);
    for (const terminal of ["approved", "denied", "expired", "consumed"]) {
      status = terminal;
      await page.goto("/device?user_code=BCDF-GHJK");
      await page.getByRole("button", { name: zhCN.device.lookup }).click();
      const title = terminal === "expired" ? zhCN.device.expiredTitle : terminal === "approved" ? zhCN.device.approvedTitle : terminal === "denied" ? zhCN.device.deniedTitle : zhCN.device.alreadyTitle;
      await expect(page.getByRole("heading", { name: title })).toBeFocused();
      await check(page);
    }
    for (const code of [404, 403, 500]) {
      failure = code;
      await page.goto("/device?user_code=BCDF-GHJK");
      await page.getByRole("button", { name: zhCN.device.lookup }).click();
      await expect(page.getByRole("heading", { name: code === 404 ? zhCN.device.expiredTitle : code === 403 ? zhCN.device.forbiddenTitle : zhCN.device.errorTitle })).toBeFocused();
      await check(page);
    }
    for (const deniedRole of ["readonly", "auditor", "cli"]) {
      role = deniedRole === "cli" ? "admin" : deniedRole;
      kind = deniedRole === "cli" ? "cli" : "human";
      await page.goto("/device");
      await expect(page.getByRole("heading", { name: zhCN.device.forbiddenTitle })).toBeFocused();
      await expect(page.getByRole("textbox")).toHaveCount(0);
      await check(page);
    }
    expect(errors).toEqual([]);
  });
}

// #72 employee entry is outside the console guard; OIDC redirects are mocked, not live auth.
for (const theme of themes) test(`employee association code → begin → OIDC → preview → confirm ${theme}`, async ({ page }) => {
  test.setTimeout(60_000); // Existing device/browser state matrix deadline.
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
  await page.addInitScript((value) => localStorage.setItem("tgs-theme", value), theme);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  const confirmed: unknown[] = [];
  const navigations: string[] = [];
  const user = { issuer: "https://idp.example", subject: "employee-1", name: "张三" };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    // https://playwright.dev/docs/api/class-page#page-route (redirected requests):
    // Playwright routes do not intercept subsequent HTTP redirects. Separate document
    // navigations model the mocked redirects; Go tests cover the real 302/cookie chain.
    const redirect = (location: string) => route.fulfill({ status: 200, contentType: "text/html", body: `<script>location.replace(${JSON.stringify(location)})</script>` });
    if (path === "/api/v1/device-grants/association/begin") {
      expect(route.request().method()).toBe("POST");
      const form = new URLSearchParams(route.request().postData() ?? "");
      expect([...form.entries()]).toEqual([["client_id", "aegishook"], ["userCode", grant.userCode]]);
      navigations.push("begin");
      return redirect("/api/v1/auth/login");
    }
    if (path === "/api/v1/auth/login") {
      navigations.push("login");
      return redirect("/api/v1/auth/callback?code=mock-oidc-code&state=mock-state");
    }
    if (path === "/api/v1/auth/callback") {
      navigations.push("oidc-callback");
      return redirect("/device/associate?continuation=confirm");
    }
    if (path === "/api/v1/device-grants/association/confirm") {
      if (route.request().method() === "GET") return json(200, { grant, user, confirmation: "mock-preview-token" });
      confirmed.push(route.request().postDataJSON());
      return json(200, { ...grant, associatedUser: user });
    }
    throw new Error(`employee journey must not request console management: ${path}`);
  });
  await page.goto("/device/associate");
  await expect(page.getByRole("textbox", { name: zhCN.device.code })).toBeFocused();
  await check(page);
  await page.getByRole("textbox", { name: zhCN.device.code }).fill("bcdfghjk");
  await page.getByRole("button", { name: zhCN.device.associationBegin }).click();
  await expect(page.getByRole("heading", { name: zhCN.device.associationTitle })).toBeFocused();
  expect(navigations).toEqual(["begin", "login", "oidc-callback"]);
  expect(confirmed).toEqual([]);
  await expect(page.getByText("张三 (employee-1)")).toBeVisible();
  await expect(page.getByText(user.issuer)).toBeVisible();
  await check(page);
  await page.getByRole("button", { name: zhCN.device.associationConfirm }).click();
  await expect(page.getByRole("heading", { name: zhCN.device.associatedTitle })).toBeFocused();
  expect(confirmed).toEqual([{ confirm: true, confirmation: "mock-preview-token" }]);
  await check(page);
  expect(errors).toEqual([]);
});

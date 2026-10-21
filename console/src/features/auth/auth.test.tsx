import { afterEach, describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { axeViolations, renderApp, screen } from "../../test/render";
import { ssoLoginHref } from "../../lib/api";
import { safeRedirect } from "../../router";

const unauthenticated = () => server.use(http.get("*/api/v1/me", () => HttpResponse.json({ error: "未登录" }, { status: 401 })));

// SSO initiation is window.location.assign (a top-level navigation jsdom cannot perform); observe it so the
// handoff is testable without leaving the page. The full 302 round-trip is the server's concern
// (internal/server/oidc_test.go), not a vitest one — once the SPA navigates away it is out of scope.
// jsdom's location.assign is a non-configurable read-only data property, so it can't be spied or proxied.
// Swap window.location for a plain stand-in that copies the real URL fields (safeRedirect and the fetch
// harness read origin; jsdom's cookie layer reads the parts) and overrides only assign.
const LOCATION_FIELDS = ["href", "origin", "protocol", "host", "hostname", "port", "pathname", "search", "hash"] as const;
let realLocation: Location | undefined;
const stubAssign = () => {
  const assign = vi.fn();
  realLocation ??= window.location;
  const stand: Record<string, unknown> = { assign, replace: () => {}, reload: () => {} };
  for (const f of LOCATION_FIELDS) stand[f] = realLocation[f];
  Object.defineProperty(window, "location", { configurable: true, value: stand });
  return assign;
};
const hasToken = (s: Storage) => Object.keys(s).some((k) => /token/i.test(k));

afterEach(() => {
  vi.restoreAllMocks();
  if (realLocation) {
    Object.defineProperty(window, "location", { configurable: true, value: realLocation });
    realLocation = undefined;
  }
});

describe("auth guard and SSO sign-in", () => {
  it("sends an unauthenticated visitor to login and keeps the intended target", async () => {
    unauthenticated();
    const { router, container } = await renderApp("/events?severity=high");
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
    expect(router.state.location.search).toEqual({ redirect: "/events?severity=high" });
    expect(await axeViolations(container)).toEqual([]);
  });

  it("starts the SSO flow at /api/v1/auth/login with an encoded same-origin next, and never posts a token", async () => {
    let postedLogin = false;
    server.use(http.post("*/api/v1/login", () => ((postedLogin = true), HttpResponse.json({ ok: true }))));
    unauthenticated();
    const assign = stubAssign();
    await renderApp("/events?severity=critical");
    await userEvent.click(await screen.findByRole("button", { name: /SSO/ }));

    const expected = ssoLoginHref("/events?severity=critical");
    expect(expected).toBe(`/api/v1/auth/login?next=${encodeURIComponent("/events?severity=critical")}`);
    // Direct top-level navigation — no client pre-flight fetch to the login endpoint (that would start a
    // spurious OIDC transaction). The server runs the 302 chain, or returns 503 sso_not_configured which it
    // owns (internal/server/oidc_test.go); once the SPA navigates away it is out of vitest scope.
    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith(expected));
    expect(assign).toHaveBeenCalledTimes(1);
    // AC2: no admin-token path remains — nothing posts /api/v1/login, nothing reads or writes a token.
    expect(postedLogin).toBe(false);
    expect(hasToken(localStorage)).toBe(false);
    expect(hasToken(sessionStorage)).toBe(false);
  });

  it("accepts only same-origin paths as a post-login redirect (plan §3.8 predicate)", () => {
    expect(safeRedirect("/events?x=1")).toBe("/events?x=1");
    expect(safeRedirect("//evil.example/")).toBeUndefined(); // protocol-relative → foreign host
    expect(safeRedirect("/\\evil.example")).toBeUndefined(); // backslash byte
    expect(safeRedirect("/a\tb")).toBeUndefined(); // control byte (TAB)
    expect(safeRedirect("/a\x7fb")).toBeUndefined(); // DEL
    expect(safeRedirect("https://evil.example/")).toBeUndefined(); // cross-origin absolute
    expect(safeRedirect("javascript:alert(1)")).toBeUndefined(); // scheme, not path-absolute
    expect(safeRedirect(42)).toBeUndefined();
  });
});

describe("app shell", () => {
  it("shows the tenant and role from /me, a skip link and the current nav entry", async () => {
    await renderApp("/events");
    const header = await screen.findByRole("banner");
    expect(within(header).getByText("default")).toBeInTheDocument(); // me.tenant
    expect(within(header).getByText("管理员")).toBeInTheDocument(); // me.role = admin → shell.roleAdmin
    expect(screen.getByRole("link", { name: "跳到主要内容" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "主导航" });
    expect(within(nav).getByRole("link", { name: "风险事件" })).toHaveAttribute("aria-current", "page");
  });

  it("redirects / to risk events (overview is M6)", async () => {
    const { router } = await renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "风险事件" });
    expect(router.state.location.pathname).toBe("/events");
  });

  it("toggles the theme and persists the choice", async () => {
    await renderApp("/events");
    const btn = await screen.findByRole("button", { name: "深色主题" });
    const before = document.documentElement.dataset.theme;
    await userEvent.click(btn);
    const after = document.documentElement.dataset.theme;
    expect(after).not.toBe(before);
    expect(localStorage.getItem("tgs-theme")).toBe(after);
    expect(btn).toHaveAttribute("aria-pressed", String(after === "dark"));
  });

  it("switches language to English and updates html lang", async () => {
    await renderApp("/events");
    await userEvent.click(await screen.findByRole("button", { name: "语言：简体中文。切换到 English" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Risk events" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
  });

  it("signs out through POST /api/v1/logout", async () => {
    let loggedOut = false;
    server.use(http.post("*/api/v1/logout", () => ((loggedOut = true), HttpResponse.json({ ok: true }))));
    await renderApp("/events");
    await userEvent.click(await screen.findByRole("button", { name: "账户菜单：管理员" }));
    unauthenticated();
    await userEvent.click(await screen.findByRole("button", { name: "退出登录" }));
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeInTheDocument();
    expect(loggedOut).toBe(true);
  });

  it("shows a not-found page for unknown routes", async () => {
    await renderApp("/nope");
    expect(await screen.findByRole("heading", { name: "页面不存在" })).toBeInTheDocument();
  });
});

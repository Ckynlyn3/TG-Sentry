import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { FIXTURE_TOKEN } from "../../test/fixtures";
import { axeViolations, renderApp, screen } from "../../test/render";
import { safeRedirect } from "../../router";

const unauthenticated = () => server.use(http.get("*/api/v1/me", () => HttpResponse.json({ error: "请使用本机管理令牌登录" }, { status: 401 })));

describe("auth guard and login", () => {
  it("sends an unauthenticated visitor to login and keeps the target", async () => {
    unauthenticated();
    const { router, container } = await renderApp("/events?severity=high");
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
    expect(router.state.location.search).toEqual({ redirect: "/events?severity=high" });
    expect(await axeViolations(container)).toEqual([]);
  });

  it("validates the empty field, then reports an invalid token on 401 and refocuses it", async () => {
    unauthenticated();
    await renderApp("/login");
    const input = await screen.findByLabelText("管理令牌");
    await userEvent.click(screen.getByRole("button", { name: "登录" }));
    expect(await screen.findByText("请输入管理令牌")).toBeInTheDocument();
    await userEvent.type(input, "wrong-token{Enter}");
    expect(await screen.findByText(/管理令牌无效/)).toBeInTheDocument();
    expect(input).toHaveAttribute("aria-invalid", "true");
    await waitFor(() => expect(input).toHaveFocus());
  });

  it("signs in with the admin token and lands on the requested page", async () => {
    let authed = false;
    server.use(
      http.get("*/api/v1/me", () => (authed ? HttpResponse.json({ name: "管理员", version: "0.1.0" }) : HttpResponse.json({ error: "x" }, { status: 401 }))),
      http.post("*/api/v1/login", async ({ request }) => {
        const body: unknown = await request.json();
        authed = typeof body === "object" && body !== null && "token" in body && body.token === FIXTURE_TOKEN;
        return authed ? HttpResponse.json({ ok: true }) : HttpResponse.json({ error: "x" }, { status: 401 });
      }),
    );
    const { router } = await renderApp("/events?severity=critical");
    await userEvent.type(await screen.findByLabelText("管理令牌"), `${FIXTURE_TOKEN}{Enter}`);
    expect(await screen.findByRole("heading", { level: 1, name: "风险事件" })).toBeInTheDocument();
    expect(router.state.location.search).toEqual({ severity: "critical" });
  });

  it("explains a transport failure separately from a wrong token", async () => {
    unauthenticated();
    server.use(http.post("*/api/v1/login", () => HttpResponse.error()));
    await renderApp("/login");
    await userEvent.type(await screen.findByLabelText("管理令牌"), "anything{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent("连不上控制平面");
  });

  it("accepts only same-origin paths as a post-login redirect", () => {
    expect(safeRedirect("/events?x=1")).toBe("/events?x=1");
    expect(safeRedirect("//evil.example/")).toBeUndefined();
    expect(safeRedirect("/\\evil.example")).toBeUndefined();
    expect(safeRedirect("https://evil.example/")).toBeUndefined();
    expect(safeRedirect(42)).toBeUndefined();
  });
});

describe("app shell", () => {
  it("shows tenant and role, a skip link and the risk-events nav entry as current", async () => {
    await renderApp("/events");
    const header = await screen.findByRole("banner");
    expect(within(header).getByText("单租户部署")).toBeInTheDocument();
    expect(within(header).getByText("本地管理员")).toBeInTheDocument();
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

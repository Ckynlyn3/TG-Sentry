import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { requests } from "../../test/handlers";
import { sessionSummaries } from "../../test/fixtures";
import { axeViolations, renderApp, screen } from "../../test/render";

const table = () => screen.findByRole("table", { name: "会话，按开始时间倒序" });
const last = () => requests.filter((u) => u.pathname === "/api/v1/session-summaries").at(-1)?.searchParams;
const params = () => Object.fromEntries(last() ?? []);
const empty = { items: [], total: 0, page: 1, pageSize: 20 };

describe("sessions list (#16 S4)", () => {
  it("lists summaries in server order with every agent and device, revoked badge, unassociated user and honest zeros", async () => {
    const { container } = await renderApp("/sessions");
    const rows = within(await table()).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    const [multi, orphan, liveness] = rows.map((r) => within(r));
    expect(rows[0]).toHaveTextContent(sessionSummaries.items[0]!.sessionId);
    expect(multi!.getByText("Claude Code")).toBeInTheDocument();
    expect(multi!.getByText("Codex")).toBeInTheDocument();
    expect(multi!.getByText("OLD-0099")).toBeInTheDocument();
    expect(multi!.getByText("MBP-RD-0142")).toBeInTheDocument();
    expect(multi!.getAllByText("已撤销")).toHaveLength(1); // node-0099 is revoked in /client-nodes
    expect(multi!.getByText("12")).toBeInTheDocument();
    expect(multi!.getByText("未关联")).toBeInTheDocument();
    expect(orphan!.getByText("没有设备记录")).toBeInTheDocument();
    expect(liveness!.getByText("node-local")).toBeInTheDocument();
    expect(liveness!.getByText("0 次调用")).toBeInTheDocument();
    expect(liveness!.getByText("无调用")).toBeInTheDocument();
    expect(rows[0]!.querySelector("time")).toHaveAttribute("dateTime", "2026-10-19T02:10:05.123456789Z");
    expect(params()).toEqual({ page: "1", size: "20" });
    expect(screen.getByText("第 1–3 条，共 43 条 · 按会话开始时间倒序")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "会话审计" })).toHaveAttribute("aria-current", "page");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("shows the user filter disabled with the reason, and never sends a user parameter", async () => {
    await renderApp("/sessions");
    await table();
    const user = screen.getByLabelText("用户");
    expect(user).toBeDisabled();
    expect(user).toHaveAccessibleDescription("还没有经过验证的用户关联，暂时不能按用户筛选。");
    expect(last()?.has("user")).toBe(false);
  });

  it("turns a preset into RFC 3339 from/to in the URL and the request, and resets the page", async () => {
    const { router } = await renderApp("/sessions?page=2");
    await table();
    await userEvent.selectOptions(screen.getByLabelText("时间范围"), "1h");
    await waitFor(() => expect(last()?.has("from")).toBe(true));
    const { from, to, page } = params();
    expect(Date.parse(to!) - Date.parse(from!)).toBe(3_600_000);
    expect(page).toBe("1");
    expect(router.state.location.search).toMatchObject({ preset: "1h", from, to });
    expect(screen.getByText(/ 至 /)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("时间范围"), "");
    await waitFor(() => expect(last()?.has("from")).toBe(false));
  });

  it("computes the instants once for a shared link that names only a relative preset", async () => {
    const { router } = await renderApp("/sessions?preset=24h");
    await table();
    const { from, to } = router.state.location.search;
    expect(Date.parse(to!) - Date.parse(from!)).toBe(86_400_000);
    expect(params()).toMatchObject({ from, to });
  });

  it("applies a custom local range and refuses a reversed one before asking the server", async () => {
    const { router } = await renderApp("/sessions");
    await table();
    await userEvent.selectOptions(screen.getByLabelText("时间范围"), "custom");
    const from = screen.getByLabelText("开始");
    const to = screen.getByLabelText("结束");
    fireEvent.change(from, { target: { value: "2026-10-19T12:00" } });
    fireEvent.change(to, { target: { value: "2026-10-19T10:00" } });
    const before = requests.length;
    await userEvent.click(within(screen.getByRole("form", { name: "自定义" })).getByRole("button", { name: "应用" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("结束时间不能早于开始时间");
    expect(from).toHaveAttribute("aria-invalid", "true");
    expect(requests.length).toBe(before);
    fireEvent.change(to, { target: { value: "2026-10-19T13:00" } });
    await userEvent.click(within(screen.getByRole("form", { name: "自定义" })).getByRole("button", { name: "应用" }));
    const want = { from: new Date(2026, 9, 19, 12).toISOString(), to: new Date(2026, 9, 19, 13).toISOString() };
    await waitFor(() => expect(params()).toMatchObject(want));
    expect(router.state.location.search).toMatchObject({ preset: "custom", ...want });
  });

  it("filters by agent family, by device from /client-nodes (revoked labelled) and by exact session key", async () => {
    const { router } = await renderApp("/sessions?page=2");
    await table();
    await userEvent.selectOptions(screen.getByLabelText("智能体"), "codex");
    await waitFor(() => expect(last()?.get("agent")).toBe("codex"));
    expect(router.state.location.search).toEqual({ agent: "codex" }); // page dropped
    const device = screen.getByLabelText("设备");
    expect(within(device).getByRole("option", { name: "OLD-0099 · node-0099（已撤销）" })).toBeInTheDocument();
    await userEvent.selectOptions(device, "node-0142");
    await waitFor(() => expect(last()?.get("nodeId")).toBe("node-0142"));
    await userEvent.type(screen.getByLabelText("会话 ID"), ` ${sessionSummaries.items[0]!.sessionId} {Enter}`);
    await waitFor(() => expect(last()?.get("sessionKey")).toBe(sessionSummaries.items[0]!.sessionId));
    expect(params()).toMatchObject({ agent: "codex", nodeId: "node-0142" });
    await userEvent.click(screen.getByRole("link", { name: "重置筛选" }));
    await waitFor(() => expect(params()).toEqual({ page: "1", size: "20" }));
  });

  it("keeps URL values the option lists lack selectable and drops values outside the contract", async () => {
    const { router } = await renderApp("/sessions?agent=acme-bot&nodeId=node-gone&page=abc&size=500&from=yesterday&preset=week");
    await table();
    expect(screen.getByLabelText("智能体")).toHaveValue("acme-bot");
    expect(screen.getByLabelText("设备")).toHaveValue("node-gone");
    expect(params()).toEqual({ agent: "acme-bot", nodeId: "node-gone", page: "1", size: "20" });
    expect(router.state.location.search).toEqual({ agent: "acme-bot", nodeId: "node-gone" });
  });

  // Review F1: Zod alone accepted +99:99 and Intl threw, replacing the page and its reset control.
  it.each([
    ["from", "/sessions?preset=custom&from=2026-10-19T00%3A00%3A00%2B99%3A99&to=2026-10-19T12%3A00%3A00Z&agent=claude"],
    ["to", "/sessions?preset=24h&from=2026-10-19T00%3A00%3A00Z&to=2026-10-19T12%3A00%3A00%2B23%3A60&agent=claude"],
  ])("drops an invalid %s offset in the URL back to the default time selection", async (_, path) => {
    const { router } = await renderApp(path);
    await table();
    expect(router.state.location.search).toEqual({ agent: "claude" });
    expect(params()).toEqual({ agent: "claude", page: "1", size: "20" });
    expect(screen.getByText("时间不限")).toBeInTheDocument();
  });

  it("treats an invalid instant in the response as a contract error and keeps the filters usable", async () => {
    const broken = { ...sessionSummaries, items: [{ ...sessionSummaries.items[0], sessionTime: "2026-10-19T02:10:05+99:99" }] };
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json(broken)));
    await renderApp("/sessions?agent=claude");
    expect(await screen.findByRole("alert")).toHaveTextContent("服务返回的数据不符合事件约定");
    expect(screen.getByLabelText("时间范围")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "重置筛选" })).toBeInTheDocument();
  });

  it("renders agent ids that shadow Object.prototype names as reported (review F2)", async () => {
    const odd = { ...sessionSummaries, items: [{ ...sessionSummaries.items[1], agents: ["__proto__", "constructor", "toString"] }] };
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json(odd)));
    await renderApp("/sessions?agent=constructor");
    const row = within(await table()).getAllByRole("row")[1]!;
    for (const id of ["__proto__", "constructor", "toString"]) expect(within(row).getByText(id)).toBeInTheDocument();
    expect(screen.getByLabelText("智能体")).toHaveValue("constructor");
  });

  it("pages with page/size and offers a way back from a page past the end", async () => {
    await renderApp("/sessions");
    await table();
    await userEvent.click(screen.getByRole("link", { name: "下一页" }));
    await waitFor(() => expect(last()?.get("page")).toBe("2"));
    expect(await screen.findByRole("link", { name: "上一页" })).toBeInTheDocument();
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json({ ...empty, total: 43, page: 9 })));
    await userEvent.click(screen.getByRole("link", { name: "上一页" }));
    expect(await screen.findByRole("heading", { name: "这一页没有会话" })).toBeInTheDocument();
  });

  it("states the last page without a next link and honours a size from the URL", async () => {
    await renderApp("/sessions?page=3&size=20");
    expect(await screen.findByText("第 41–43 条，共 43 条 · 按会话开始时间倒序")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "下一页" })).toBeNull();
  });

  it("shows a measured empty state, and a filtered empty state with reset", async () => {
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json(empty)));
    const first = await renderApp("/sessions");
    expect(await screen.findByRole("heading", { name: "还没有会话记录" })).toBeInTheDocument();
    first.unmount();
    await renderApp("/sessions?agent=claude");
    expect(await screen.findByRole("heading", { name: "没有符合筛选条件的会话" })).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "重置筛选" }).length).toBeGreaterThan(0);
  });

  it("shows an inline error with the server's reason and retries", async () => {
    let fail = true;
    server.use(
      http.get("*/api/v1/session-summaries", () =>
        fail ? HttpResponse.json({ error: "invalid session summary query" }, { status: 400 }) : HttpResponse.json(sessionSummaries),
      ),
    );
    const { container } = await renderApp("/sessions");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("会话没有加载出来");
    expect(alert).toHaveTextContent("服务返回错误 400。 invalid session summary query");
    expect(await axeViolations(container)).toEqual([]);
    fail = false;
    await userEvent.click(within(alert).getByRole("button", { name: "重试" }));
    expect(await table()).toBeInTheDocument();
  });

  it("shows a forbidden state on 403 without retry", async () => {
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json({ error: "forbidden" }, { status: 403 })));
    const { container } = await renderApp("/sessions");
    expect(await screen.findByRole("alert")).toHaveTextContent("你没有查看会话审计的权限");
    expect(screen.queryByRole("button", { name: "重试" })).toBeNull();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("refuses a response that breaks the summary contract instead of rendering a user", async () => {
    const broken = { ...sessionSummaries, items: [{ ...sessionSummaries.items[0], user: "张三" }] };
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json(broken)));
    await renderApp("/sessions");
    expect(await screen.findByRole("alert")).toHaveTextContent("服务返回的数据不符合事件约定");
    expect(screen.queryByText("张三")).toBeNull();
  });

  it("returns to login when the session has expired", async () => {
    server.use(http.get("*/api/v1/session-summaries", () => HttpResponse.json({ error: "请使用本机管理令牌登录" }, { status: 401 })));
    await renderApp("/sessions");
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeInTheDocument();
  });

  it("says why the device picker is short when /client-nodes fails or is forbidden", async () => {
    server.use(http.get("*/api/v1/client-nodes", () => HttpResponse.json({ error: "数据库不可用" }, { status: 500 })));
    const first = await renderApp("/sessions");
    await table();
    expect(await screen.findByText("设备列表没有加载出来，稍后刷新页面再试。")).toBeInTheDocument();
    expect(screen.getByLabelText("设备")).toHaveAccessibleDescription("设备列表没有加载出来，稍后刷新页面再试。");
    first.unmount();
    server.use(http.get("*/api/v1/client-nodes", () => HttpResponse.json({ error: "forbidden" }, { status: 403 })));
    await renderApp("/sessions");
    expect(await screen.findByText("你没有查看设备列表的权限。")).toBeInTheDocument();
  });

  it("loads the evidence drawer from the open deep link and closes with its button", async () => {
    const { router } = await renderApp("/sessions?open=ses-heartbeat-only");
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    expect(router.state.location.search).toEqual({ open: "ses-heartbeat-only" });
    expect(within(d).queryByRole("tab")).toBeNull();
    await userEvent.click(within(d).getByRole("button", { name: "关闭会话证据" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(router.state.location.search).toEqual({});
  });

  it("renders the English locale", async () => {
    const { default: i18n } = await import("../../i18n");
    await renderApp("/sessions");
    await table();
    await i18n.changeLanguage("en");
    expect(await screen.findByRole("table", { name: "Sessions, newest start first" })).toBeInTheDocument();
    expect(screen.getByText("0 calls")).toBeInTheDocument();
    expect(screen.getAllByText("Unassociated").length).toBe(3);
  });
});

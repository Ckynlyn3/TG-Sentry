import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { requests } from "../../test/handlers";
import { blockEvent, riskEvent, serverEvent, serverPage } from "../../test/fixtures";
import { axeViolations, renderApp, screen } from "../../test/render";

describe("real control-plane response shape (#10)", () => {
  it("names the event by its analytic uid, labels it a rule, and states the unknown outcome", async () => {
    server.use(
      http.get("*/api/v1/risk-events", () => HttpResponse.json(serverPage)),
      http.get("*/api/v1/risk-events/:id", () => HttpResponse.json(serverEvent)),
    );
    await renderApp("/events");
    const row = within(await table()).getByRole("link", { name: "R_DB_REDIS" }).closest("tr");
    expect(row).not.toBeNull();
    const cells = within(row as HTMLElement);
    expect(row).toHaveTextContent("规则 · 未分类");
    expect(cells.getByText("处置未知")).toBeInTheDocument();
    expect(cells.getByText("未登记")).toBeInTheDocument();
    await userEvent.click(cells.getByRole("link", { name: "R_DB_REDIS" }));
    const dialog = await screen.findByRole("dialog", { name: "R_DB_REDIS" });
    expect(dialog).toHaveTextContent(serverEvent.id);
    expect(dialog).toHaveTextContent("检测到风险，处置结果未知");
  });
});

const table = async () => screen.findByRole("table", { name: "风险事件，按发现时间倒序" });
const lastRequest = () => requests.at(-1)?.searchParams;

describe("risk events list", () => {
  it("lists events from GET /api/v1/risk-events in server order, with verdict, severity and identity", async () => {
    const { container } = await renderApp("/events");
    const rows = within(await table()).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(4);
    expect(rows[0]).toHaveTextContent("拦截");
    expect(rows[0]).toHaveTextContent("严重");
    expect(rows[0]).toHaveTextContent("远程代码下载与执行");
    expect(rows[0]).toHaveTextContent("高危操作拦截");
    expect(rows[0]).toHaveTextContent("Claude Code");
    expect(rows[0]).toHaveTextContent("张三");
    expect(rows[1]).toHaveTextContent("提醒");
    expect(rows[1]).toHaveTextContent("敏感信息防护");
    // unenrolled agent shows a reason, not a blank cell (#10)
    expect(rows[2]).toHaveTextContent("未登记");
    expect(rows[2]).toHaveTextContent("未关联用户");
    // unknown outcome and severity are named, never shown as a block or as zero
    expect(rows[3]).toHaveTextContent("处置未知");
    expect(rows[3]).toHaveTextContent("未知");
    expect(rows[3]).toHaveTextContent("未命名检测项");
    expect(lastRequest()?.get("page_size")).toBe("25");
    expect(lastRequest()?.has("page_token")).toBe(false);
    expect(await axeViolations(container)).toEqual([]);
  });

  it("applies a severity filter through the URL and drops the cursor", async () => {
    const { router } = await renderApp("/events?cursor=cursor-page-2");
    await table();
    await userEvent.selectOptions(screen.getByLabelText("严重度"), "critical");
    await waitFor(() => expect(lastRequest()?.get("severity")).toBe("critical"));
    expect(lastRequest()?.has("page_token")).toBe(false);
    expect(router.state.location.search).toEqual({ severity: "critical" });
  });

  it("sends category and agent filters with the #10 values", async () => {
    await renderApp("/events");
    await table();
    await userEvent.selectOptions(screen.getByLabelText("防护类型"), "category::prompt-attack");
    await waitFor(() => expect(lastRequest()?.get("category")).toBe("category::prompt-attack"));
    await userEvent.type(screen.getByLabelText("智能体"), "node-0142/claude-code{Enter}");
    await waitFor(() => expect(lastRequest()?.get("agent")).toBe("node-0142/claude-code"));
    expect(lastRequest()?.get("category")).toBe("category::prompt-attack");
  });

  it("ignores filter values outside the contract", async () => {
    await renderApp("/events?severity=extreme&category=bogus");
    await table();
    expect(lastRequest()?.has("severity")).toBe(false);
    expect(lastRequest()?.has("category")).toBe(false);
  });

  it("pages with the opaque cursor and states the end of the list", async () => {
    await renderApp("/events");
    await table();
    await userEvent.click(screen.getByRole("link", { name: "更早的事件" }));
    await waitFor(() => expect(lastRequest()?.get("page_token")).toBe("cursor-page-2"));
    expect(await screen.findByText("没有更早的事件")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "回到最新" })).toBeInTheDocument();
  });

  it("shows a measured empty state, and a filtered empty state with a way out", async () => {
    server.use(http.get("*/api/v1/risk-events", () => HttpResponse.json({ items: [], next_page_token: "" })));
    const first = await renderApp("/events");
    expect(await screen.findByRole("heading", { name: "还没有风险事件" })).toBeInTheDocument();
    first.unmount();
    await renderApp("/events?severity=low");
    expect(await screen.findByRole("heading", { name: "没有符合筛选条件的事件" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "清除筛选" })).toBeInTheDocument();
  });

  it("shows an inline error with retry, keeping the page", async () => {
    let fail = true;
    server.use(
      http.get("*/api/v1/risk-events", () =>
        fail ? HttpResponse.json({ error: "数据库不可用" }, { status: 500 }) : HttpResponse.json({ items: [blockEvent], next_page_token: "" }),
      ),
    );
    const { container } = await renderApp("/events");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("风险事件没有加载出来");
    expect(alert).toHaveTextContent("服务返回错误 500。 数据库不可用");
    expect(screen.getByRole("heading", { level: 1, name: "风险事件" })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
    fail = false;
    await userEvent.click(within(alert).getByRole("button", { name: "重试" }));
    expect(await table()).toBeInTheDocument();
  });

  it("shows a forbidden state on 403", async () => {
    server.use(http.get("*/api/v1/risk-events", () => HttpResponse.json({ error: "forbidden" }, { status: 403 })));
    const { container } = await renderApp("/events");
    expect(await screen.findByRole("alert")).toHaveTextContent("你没有查看风险事件的权限");
    expect(screen.queryByRole("button", { name: "重试" })).not.toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("refuses a response that breaks the event contract instead of rendering guesses", async () => {
    const broken = { ...riskEvent({ id: "x", time: 0 }), type: "something.else" };
    server.use(http.get("*/api/v1/risk-events", () => HttpResponse.json({ items: [broken], next_page_token: "" })));
    await renderApp("/events");
    expect(await screen.findByRole("alert")).toHaveTextContent("服务返回的数据不符合事件约定");
  });

  it("returns to login when the session has expired", async () => {
    server.use(http.get("*/api/v1/risk-events", () => HttpResponse.json({ error: "请使用本机管理令牌登录" }, { status: 401 })));
    await renderApp("/events");
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeInTheDocument();
  });

  it("has a pause control for auto-refresh with a visible state (SC 2.2.2)", async () => {
    await renderApp("/events");
    await table();
    expect(screen.getByText("每 60 秒自动刷新")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "暂停自动刷新" }));
    expect(screen.getByText("自动刷新已暂停")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "继续自动刷新" })).toBeInTheDocument();
  });
});

describe("event detail drawer", () => {
  it("opens from the row link, focuses close, Esc returns focus to the link", async () => {
    const { router } = await renderApp("/events");
    await table();
    const link = screen.getAllByRole("link", { name: "远程代码下载与执行" })[0]!;
    await userEvent.click(link);
    const dialog = await screen.findByRole("dialog", { name: "远程代码下载与执行" });
    expect(router.state.location.search).toEqual({ event: "evt_block_01" });
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "关闭事件详情" })).toHaveFocus());
    expect(dialog).toHaveTextContent("判定过程");
    expect(dialog).toHaveTextContent("shell-ast");
    expect(dialog).toHaveTextContent("未随事件上报"); // policy is not in the risk-event contract yet
    expect(dialog).toHaveTextContent("已拦截，操作没有执行");
    expect(dialog).toHaveTextContent("命令会下载远程脚本并直接交给 shell 执行");
    expect(dialog).toHaveTextContent("ses_7f3a9c21");
    expect(dialog).toHaveTextContent("toolu_demo_01");
    expect(await axeViolations(document.body)).toEqual([]);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(router.state.location.search).toEqual({});
    await waitFor(() => expect(screen.getAllByRole("link", { name: "远程代码下载与执行" })[0]).toHaveFocus());
  });

  it("loads a shared deep link for an event not on the page via GET /risk-events/{id}", async () => {
    await renderApp("/events?event=evt_old_05");
    const dialog = await screen.findByRole("dialog", { name: "远程代码下载与执行" });
    expect(dialog).toHaveTextContent("evt_old_05");
  });

  it("says when an event is not found", async () => {
    await renderApp("/events?event=evt_missing");
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("找不到这条事件");
  });

  it("names an unknown outcome instead of claiming a block", async () => {
    await renderApp("/events?event=evt_unknown_04");
    const dialog = await screen.findByRole("dialog", { name: "未命名检测项" });
    expect(dialog).toHaveTextContent("检测到风险，处置结果未知");
    expect(dialog).toHaveTextContent("事件没有附带原因说明。");
  });
});

describe("design v2 polish", () => {
  it("states missing reported fields once for the loaded page", async () => {
    await renderApp("/events");
    await table();
    const note = screen.getByRole("note", { name: "本页数据完整度" });
    expect(note).toHaveTextContent("本页 4 条");
    expect(note).toHaveTextContent("处置未知 1");
    expect(note).toHaveTextContent("严重度未知 1");
    expect(note).toHaveTextContent("未登记智能体 1");
    expect(note).not.toHaveTextContent("没有身份信息");
  });

  it("hides the coverage strip when every field is reported", async () => {
    server.use(http.get("*/api/v1/risk-events", () => HttpResponse.json({ items: [blockEvent], next_page_token: "" })));
    await renderApp("/events");
    await table();
    expect(screen.queryByRole("note", { name: "本页数据完整度" })).toBeNull();
  });

  it("offers clear-filters in the toolbar when a filtered page has rows", async () => {
    await renderApp("/events?severity=critical");
    await table();
    expect(screen.getByRole("link", { name: "清除筛选" })).toHaveAttribute("href", "/events");
  });
});

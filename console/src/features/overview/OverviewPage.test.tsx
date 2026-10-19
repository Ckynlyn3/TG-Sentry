import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { instances, me, riskStats24h } from "../../test/fixtures";
import { axeViolations, renderApp, screen } from "../../test/render";

const kpi = (label: string) => screen.getByText(label, { selector: ".kpi-label" }).closest("li") as HTMLElement;
const statsRequests: URL[] = [];
const withStats = () =>
  server.use(
    http.get("*/api/v1/me", () => HttpResponse.json({ ...me, capabilities: ["risk-stats"] })),
    http.get("*/api/v1/risk-events/stats", ({ request }) => {
      const url = new URL(request.url);
      statsRequests.push(url);
      return HttpResponse.json({ ...riskStats24h, window: url.searchParams.get("window") ?? "24h" });
    }),
  );

describe("overview from existing endpoints", () => {
  it("shows each KPI with denominator, scope and fetch time; ACL is a labelled gap, not zero", async () => {
    const { container } = await renderApp("/overview");
    await screen.findByRole("heading", { name: "总览", level: 1 });
    await waitFor(() => expect(kpi("已登记设备")).toHaveTextContent("2/ 3 台"));
    expect(kpi("已登记设备")).toHaveTextContent("不含已撤销的 1 台");
    await waitFor(() => expect(kpi("在线智能体会话")).toHaveTextContent("1/ 已注册 3 个"));
    expect(kpi("工具调用记录")).toHaveTextContent("32");
    expect(kpi("工具调用记录")).toHaveTextContent("其中 2 条在等人工审批");
    expect(kpi("防护策略")).toHaveTextContent("防护模板 2 个 · 配置修订 r7");
    for (const l of ["已登记设备", "在线智能体会话", "工具调用记录", "防护策略"]) expect(kpi(l)).toHaveTextContent("获取于");
    expect(kpi("访问控制规则")).toHaveTextContent("暂不可用");
    expect(kpi("访问控制规则")).not.toHaveTextContent(/\b0\b/);
    expect(screen.getByText(/数据获取于/)).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("without the stats capability it states the gap and never requests the stats endpoint", async () => {
    statsRequests.length = 0;
    server.use(
      http.get("*/api/v1/risk-events/stats", ({ request }) => {
        statsRequests.push(new URL(request.url));
        return HttpResponse.json(riskStats24h);
      }),
    );
    await renderApp("/overview");
    expect(await screen.findByRole("heading", { name: "风险事件统计暂未提供" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "风险事件趋势" })).toBeNull();
    expect(screen.getByRole("link", { name: "查看风险事件" })).toHaveAttribute("href", "/events");
    // latest events come from the real list endpoint
    expect(await screen.findByRole("heading", { name: "最新风险事件" })).toBeInTheDocument();
    expect(statsRequests).toHaveLength(0);
  });

  it("groups sessions by agent type and shows a never-reported heartbeat as unknown", async () => {
    await renderApp("/overview");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("claude");
    expect(rows[0]).toHaveTextContent(/^claude12/);
    expect(rows[1]).toHaveTextContent("codex");
    expect(rows[1]).toHaveTextContent("—");
  });

  it("says the heartbeat was not reported when sessions exist but none has one (review F4)", async () => {
    server.use(http.get("*/api/v1/instances", () => HttpResponse.json([instances[2]])));
    await renderApp("/overview");
    await waitFor(() => expect(kpi("在线智能体会话")).toHaveTextContent("0/ 已注册 1 个"));
    expect(kpi("在线智能体会话")).toHaveTextContent("还没有上报心跳");
    expect(kpi("在线智能体会话")).not.toHaveTextContent("还没有智能体会话");
  });

  it("keeps a failed tile inside its tile, with retry, while the others render", async () => {
    server.use(http.get("*/api/v1/client-nodes", () => HttpResponse.json({ error: "数据库不可用" }, { status: 500 })));
    await renderApp("/overview");
    await waitFor(() => expect(kpi("已登记设备")).toHaveTextContent("没有加载出来"));
    expect(within(kpi("已登记设备")).getByRole("button", { name: "重试" })).toBeInTheDocument();
    await waitFor(() => expect(kpi("工具调用记录")).toHaveTextContent("32"));
  });

  it("a forbidden tile says so and offers no retry", async () => {
    server.use(http.get("*/api/v1/calls", () => HttpResponse.json({ error: "forbidden" }, { status: 403 })));
    await renderApp("/overview");
    await waitFor(() => expect(kpi("工具调用记录")).toHaveTextContent("无权查看"));
    expect(within(kpi("工具调用记录")).queryByRole("button")).toBeNull();
  });
});

describe("overview statistics (proposed contract, capability-gated)", () => {
  it("renders trend totals, unknown counts, category breakdown, top agents and a data table", async () => {
    withStats();
    const { container } = await renderApp("/overview");
    expect(await screen.findByRole("heading", { name: "风险事件趋势" }, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText(/近 24 小时共 30 条风险事件：拦截 6，提醒 14，其他 10/)).toBeInTheDocument();
    expect(screen.getByText(/其中 9 条严重度未知，4 条没有关联到已登记的智能体/)).toBeInTheDocument();
    const cats = screen.getByRole("heading", { name: "按防护类型" }).closest("section") as HTMLElement;
    expect(cats).toHaveTextContent("高危操作拦截拦截 4 · 提醒 6 · 其他 3");
    expect(cats).toHaveTextContent("行为检测这段时间没有事件");
    // Uncategorized has no verdict split in the contract: a total only, never a fabricated "拦截 0" (review F2).
    expect(cats).toHaveTextContent("未分类合计 6");
    expect(cats).not.toHaveTextContent("未分类拦截");
    const top = screen.getByRole("heading", { name: "风险较多的智能体" }).closest("section") as HTMLElement;
    expect(within(top).getByRole("link", { name: "Claude Code" })).toHaveAttribute("href", "/events?agent=node-0142%2Fclaude-code");
    await userEvent.click(screen.getByText("查看数据"));
    expect(screen.getByRole("region", { name: "查看数据" })).toBeVisible();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("changes the range through the URL and refetches with that window", async () => {
    statsRequests.length = 0;
    withStats();
    const { router } = await renderApp("/overview");
    const select = await screen.findByLabelText("时间范围", undefined, { timeout: 5000 });
    await userEvent.selectOptions(select, "7d");
    await waitFor(() => expect(statsRequests.at(-1)?.searchParams.get("window")).toBe("7d"));
    expect(router.state.location.search).toEqual({ range: "7d" });
  });

  it("drops an invalid range from the URL to the 24h default", async () => {
    statsRequests.length = 0;
    withStats();
    await renderApp("/overview?range=1y");
    await waitFor(() => expect(statsRequests.at(-1)?.searchParams.get("window")).toBe("24h"), { timeout: 5000 });
  });

  it("a stats failure stays in the trend panel with retry", async () => {
    server.use(
      http.get("*/api/v1/me", () => HttpResponse.json({ ...me, capabilities: ["risk-stats"] })),
      http.get("*/api/v1/risk-events/stats", () => HttpResponse.json({ error: "x" }, { status: 500 })),
    );
    await renderApp("/overview");
    expect(await screen.findByText("风险事件统计没有加载出来", undefined, { timeout: 5000 })).toBeInTheDocument();
    await waitFor(() => expect(kpi("工具调用记录")).toHaveTextContent("32"));
  });
});

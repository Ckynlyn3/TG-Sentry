import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { axeViolations, renderApp, screen } from "../../test/render";
import { inventoryAgent, inventoryCodex, inventoryLastPage, inventoryPage, inventoryRestricted } from "../../test/fixtures";

const claude = inventoryAgent;
const ID_A = inventoryAgent.id;
const ID_B = inventoryCodex.id;
const page = inventoryPage;
const lastPage = inventoryLastPage;
const restricted = inventoryRestricted;

const requests: URLSearchParams[] = [];
const lastRequest = () => requests.at(-1);
beforeEach(() => {
  requests.length = 0;
  server.use(
    http.get("*/api/v1/discovered-agents", ({ request }) => {
      const p = new URL(request.url).searchParams;
      requests.push(p);
      return HttpResponse.json(p.get("page_token") === "inv-cursor-2" ? lastPage : page);
    }),
  );
});
const respond = (body: object, status = 200) => server.use(http.get("*/api/v1/discovered-agents", () => HttpResponse.json(body, { status })));
const table = async () => screen.findByRole("table", { name: "发现的智能体，按设备分组，按最近扫描时间倒序" });
const agentRow = (t: HTMLElement, family: string) => within(t).getByRole("link", { name: family }).closest("tr") as HTMLElement;
const categoryRow = (t: HTMLElement, label: string) => within(t).getByText(label).closest("tr") as HTMLElement;

describe("inventory ledger", () => {
  it("groups agents by device and labels every agent, category and freshness state", async () => {
    const { container } = await renderApp("/inventory");
    const t = await table();
    // Device groups: client-node name where known, the node id otherwise.
    const groups = [...t.querySelectorAll('th[scope="rowgroup"]')].map((g) => g.textContent?.replace(/\s+/g, " ").trim());
    expect(groups).toEqual(["设备 MBP-RD-0142 node-0142", "设备 WIN-OPS-0143 node-0143"]);

    const a = agentRow(t, "claude-code");
    expect(a).toHaveTextContent("zhangsan");
    expect(a).toHaveTextContent("501");
    expect(a).toHaveTextContent("/Users/zhangsan");
    expect(a).toHaveTextContent("已发现");
    expect(a).toHaveTextContent("存在");
    expect(a).toHaveTextContent(".claude/settings.json");
    expect(a).toHaveTextContent("版本未知");
    expect(a).toHaveTextContent("数据最新");
    expect(agentRow(t, "codex")).toHaveTextContent("未发现");
    expect(agentRow(t, "codex")).toHaveTextContent("已移除");
    expect(agentRow(t, "codex")).toHaveTextContent("未记录路径");
    expect(agentRow(t, "codex")).toHaveTextContent("数据已过期");
    expect(agentRow(t, "opencode")).toHaveTextContent("无法确认");
    expect(agentRow(t, "opencode")).toHaveTextContent("状态未知");
    expect(agentRow(t, "opencode")).toHaveTextContent("暂无扫描数据");

    expect(categoryRow(t, "技能")).toHaveTextContent("已扫描");
    expect(categoryRow(t, "技能")).toHaveTextContent("主目录");
    expect(categoryRow(t, "MCP 服务器")).toHaveTextContent("扫描出错");
    expect(categoryRow(t, "MCP 服务器")).toHaveTextContent("配置解析失败");
    expect(categoryRow(t, "插件")).toHaveTextContent("状态未知");
    expect(categoryRow(t, "内置工具")).toHaveTextContent("不支持扫描");
    const memory = categoryRow(t, "记忆文件");
    expect(memory).toHaveTextContent("项目");
    expect(memory).toHaveTextContent("项目级目录暂不扫描");
    // Never-scanned timestamps are a state, not year 1.
    expect(within(memory).getAllByText("未扫描").length).toBeGreaterThan(0);
    expect(t.querySelector('time[datetime^="0001"]')).toBeNull();
    expect(t).not.toHaveTextContent("0001");

    expect(lastRequest()?.get("page_size")).toBe("20");
    expect(lastRequest()?.has("page_token")).toBe(false);
    expect(await axeViolations(container)).toEqual([]);
  });

  it("renders fields the role cannot see as a labelled restricted cell", async () => {
    respond({ items: [restricted], next_page_token: "" });
    const { container } = await renderApp("/inventory");
    const row = agentRow(await table(), "claude-code");
    expect(within(row).getAllByText("无权查看")).toHaveLength(3);
    expect(row).toHaveTextContent("501");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("applies category and state filters through the URL and drops the cursor", async () => {
    const { router } = await renderApp("/inventory?cursor=inv-cursor-2");
    await table();
    await userEvent.selectOptions(screen.getByLabelText("类别"), "mcp");
    await waitFor(() => expect(lastRequest()?.get("category")).toBe("mcp"));
    expect(lastRequest()?.has("page_token")).toBe(false);
    await userEvent.selectOptions(screen.getByLabelText("扫描状态"), "error");
    await waitFor(() => expect(lastRequest()?.get("state")).toBe("error"));
    expect(router.state.location.search).toEqual({ category: "mcp", state: "error" });
  });

  it("sends exact node, account and agent filters", async () => {
    await renderApp("/inventory");
    await table();
    await userEvent.type(screen.getByLabelText("设备 ID"), "node-0142");
    await userEvent.type(screen.getByLabelText("账户 ID"), "501");
    await userEvent.type(screen.getByLabelText("智能体 ID"), `${ID_A}{Enter}`);
    await waitFor(() => expect(lastRequest()?.get("agent")).toBe(ID_A));
    expect(lastRequest()?.get("node")).toBe("node-0142");
    expect(lastRequest()?.get("account")).toBe("501");
  });

  it("filters to one agent from its row link", async () => {
    const { router } = await renderApp("/inventory");
    await userEvent.click(within(await table()).getByRole("link", { name: "codex" }));
    await waitFor(() => expect(lastRequest()?.get("agent")).toBe(ID_B));
    expect(router.state.location.search).toEqual({ agent: ID_B });
  });

  it("ignores filter values outside the contract", async () => {
    await renderApp("/inventory?category=bogus&state=stale");
    await table();
    expect(lastRequest()?.has("category")).toBe(false);
    expect(lastRequest()?.has("state")).toBe(false);
  });

  it("pages with the opaque cursor and states the end of the list", async () => {
    await renderApp("/inventory");
    await table();
    await userEvent.click(screen.getByRole("link", { name: "下一页" }));
    await waitFor(() => expect(lastRequest()?.get("page_token")).toBe("inv-cursor-2"));
    expect(await screen.findByText("没有更多智能体了")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "回到第一页" })).toBeInTheDocument();
  });

  it("shows a measured empty state, and a filtered empty state with a way out", async () => {
    respond({ items: [], next_page_token: "" });
    const first = await renderApp("/inventory");
    expect(await screen.findByRole("heading", { name: "还没有发现智能体" })).toBeInTheDocument();
    first.unmount();
    await renderApp("/inventory?category=skills");
    expect(await screen.findByRole("heading", { name: "没有符合筛选条件的智能体" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "清除筛选" })).toHaveAttribute("href", "/inventory");
  });

  it("shows an inline error with retry, keeping the page", async () => {
    let fail = true;
    server.use(
      http.get("*/api/v1/discovered-agents", () =>
        fail ? HttpResponse.json({ error: "discovery inventory unavailable" }, { status: 500 }) : HttpResponse.json(page),
      ),
    );
    const { container } = await renderApp("/inventory");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("资产清单没有加载出来");
    expect(alert).toHaveTextContent("服务返回错误 500。 discovery inventory unavailable");
    expect(screen.getByRole("heading", { level: 1, name: "资产扫描" })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
    fail = false;
    await userEvent.click(within(alert).getByRole("button", { name: "重试" }));
    expect(await table()).toBeInTheDocument();
  });

  it("shows a forbidden state on 403", async () => {
    respond({ error: "forbidden" }, 403);
    const { container } = await renderApp("/inventory");
    expect(await screen.findByRole("alert")).toHaveTextContent("你没有查看资产扫描结果的权限");
    expect(screen.queryByRole("button", { name: "重试" })).not.toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("refuses a response that breaks the contract instead of rendering guesses", async () => {
    respond({ items: [{ ...claude, freshness: "maybe" }], next_page_token: "" });
    await renderApp("/inventory");
    expect(await screen.findByRole("alert")).toHaveTextContent("服务返回的数据不符合");
  });

  it("refuses a wrong-typed evidence mtime as a contract break", async () => {
    respond({ items: [{ ...claude, evidence: { ...claude.evidence, mtime: 1792381109031 } }], next_page_token: "" });
    await renderApp("/inventory");
    expect(await screen.findByRole("alert")).toHaveTextContent("服务返回的数据不符合");
  });

  it("keeps numeric account and node ids from a direct URL as exact text", async () => {
    const { router } = await renderApp("/inventory?account=501&node=142");
    await table();
    expect(lastRequest()?.get("account")).toBe("501");
    expect(lastRequest()?.get("node")).toBe("142");
    expect(router.state.location.search).toEqual({ account: "501", node: "142" });
  });

  it("associates each category row with its agent row header and the matching column headers (H43)", async () => {
    await renderApp("/inventory");
    const t = await table();
    const agent = within(t).getByRole("rowheader", { name: /^claude-code/ });
    expect(agent.tagName).toBe("TH");
    const row = categoryRow(t, "MCP 服务器");
    const header = (cell: Element) => (cell.getAttribute("headers") ?? "").split(" ").map((id) => document.getElementById(id)?.textContent);
    const state = within(row).getByText("扫描出错").closest("td") as HTMLElement;
    expect(state).not.toHaveAttribute("colspan");
    expect(header(state)).toEqual(expect.arrayContaining([agent.textContent, "扫描状态"]));
    expect(header(within(row).getByText("MCP 服务器").closest("td") as HTMLElement)).toEqual(expect.arrayContaining([agent.textContent, "智能体 / 类别"]));
    expect(header(within(row).getByText("数据已过期").closest("td") as HTMLElement)).toEqual(expect.arrayContaining([agent.textContent, "数据新鲜度"]));
  });

  it("returns to login when the session has expired", async () => {
    respond({ error: "unauthorized" }, 401);
    await renderApp("/inventory");
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeInTheDocument();
  });

  it("is reachable from the rail under 资产", async () => {
    await renderApp("/events");
    const nav = await screen.findByRole("navigation", { name: "主导航" });
    expect(nav).toHaveTextContent("资产");
    await userEvent.click(within(nav).getByRole("link", { name: "资产扫描" }));
    await table();
    expect(within(nav).getByRole("link", { name: "资产扫描" })).toHaveAttribute("aria-current", "page");
  });
});

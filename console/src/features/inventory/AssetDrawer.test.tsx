import { beforeEach, describe, expect, it } from "vitest";
import { delay, http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { axeViolations, renderApp, screen } from "../../test/render";
import { inventoryAgent, inventoryAsset, inventoryAssetPage, inventoryMcpAsset, inventoryPage } from "../../test/fixtures";

const AGENT = inventoryAgent.id;
const SKILL = inventoryAsset.assetId;
const MCP = inventoryMcpAsset.assetId;
const assetRequests: URLSearchParams[] = [];

beforeEach(() => {
  assetRequests.length = 0;
  server.use(
    http.get("*/api/v1/discovered-agents", () => HttpResponse.json(inventoryPage)),
    http.get("*/api/v1/agent-assets", ({ request }) => {
      assetRequests.push(new URL(request.url).searchParams);
      return HttpResponse.json(inventoryAssetPage);
    }),
    http.get("*/api/v1/agent-assets/:id", ({ params }) => {
      const a = inventoryAssetPage.items.find((x) => x.assetId === params.id);
      return a ? HttpResponse.json(a) : HttpResponse.json({ error: "discovery asset not found" }, { status: 404 });
    }),
  );
});
const detail = (body: object, status = 200) => server.use(http.get("*/api/v1/agent-assets/:id", () => HttpResponse.json(body, { status })));
const dialog = (name?: string) => screen.findByRole("dialog", name ? { name } : undefined);
const value = (d: HTMLElement, term: string) => within(d).getByText(term, { selector: "dt" }).nextElementSibling as HTMLElement;

describe("asset detail drawer", () => {
  it("opens from the asset link of a narrowed ledger, focuses close, Esc returns focus to the link", async () => {
    const { router } = await renderApp(`/inventory?agent=${AGENT}`);
    const link = await screen.findByRole("link", { name: "review-pr" });
    expect(assetRequests.at(-1)?.get("agent")).toBe(AGENT);
    expect(assetRequests.at(-1)?.get("page_size")).toBe("100");
    await userEvent.click(link);
    const d = await dialog("review-pr");
    expect(router.state.location.pathname).toBe(`/inventory/${SKILL}`);
    expect(router.state.location.search).toEqual({ agent: AGENT });
    await waitFor(() => expect(within(d).getByRole("button", { name: "关闭资产详情" })).toHaveFocus());
    expect(value(d, "类别")).toHaveTextContent("技能");
    expect(value(d, "哈希类型")).toHaveTextContent("文件内容 SHA-256");
    expect(value(d, "哈希值")).toHaveTextContent(inventoryAsset.hash);
    expect(value(d, "大小")).toHaveTextContent("2,048 字节");
    expect(value(d, "修改时间").querySelector("time")).toHaveAttribute("dateTime", inventoryAsset.mtime);
    expect(value(d, "来源路径")).toHaveTextContent(".claude/skills/review-pr/SKILL.md");
    expect(value(d, "扫描状态")).toHaveTextContent("已扫描");
    expect(value(d, "数据新鲜度")).toHaveTextContent("数据最新");
    expect(d).not.toHaveTextContent("MCP 配置投影");
    expect(await axeViolations(document.body)).toEqual([]);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(router.state.location.pathname).toBe("/inventory");
    expect(router.state.location.search).toEqual({ agent: AGENT });
    await waitFor(() => expect(screen.getByRole("link", { name: "review-pr" })).toHaveFocus());
  });

  it("loads a shared /inventory/{id} deep link and shows MCP projection keys, never values", async () => {
    detail({ ...inventoryMcpAsset, descriptor: { ...inventoryMcpAsset.descriptor, env: { GITHUB_TOKEN: "SENTINEL_value" }, command: "SENTINEL_cmd" }, extra: "SENTINEL_x" });
    await renderApp(`/inventory/${MCP}`);
    const d = await dialog("github");
    expect(value(d, "传输方式")).toHaveTextContent("stdio");
    expect(value(d, "环境变量名")).toHaveTextContent("GITHUB_TOKEN");
    expect(value(d, "请求头名")).toHaveTextContent("Authorization");
    expect(value(d, "哈希类型")).toHaveTextContent("配置投影 SHA-256");
    expect(d).toHaveTextContent("不记录任何取值");
    expect(document.body).not.toHaveTextContent("SENTINEL");
    // Error and stale are labelled states beside each other; absent size/mtime are "not reported", never 0.
    expect(value(d, "扫描状态")).toHaveTextContent("扫描出错");
    expect(value(d, "扫描状态")).toHaveTextContent("配置解析失败");
    expect(value(d, "数据新鲜度")).toHaveTextContent("数据已过期");
    expect(value(d, "大小")).toHaveTextContent("未上报");
    expect(value(d, "大小")).not.toHaveTextContent("0");
    expect(value(d, "修改时间")).toHaveTextContent("未上报");
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("renders a role-withheld path as restricted, distinct from no recorded path", async () => {
    // Readonly projection drops sourceRelPath (projectAgentAsset); undefined is dropped by JSON serialization.
    detail({ ...inventoryAsset, sourceRelPath: undefined });
    const first = await renderApp(`/inventory/${SKILL}`);
    const path = value(await dialog("review-pr"), "来源路径");
    expect(path).toHaveTextContent("无权查看");
    expect(path).not.toHaveTextContent("未记录路径");
    first.unmount();
    detail({ ...inventoryAsset, sourceRelPath: "" });
    await renderApp(`/inventory/${SKILL}`);
    const empty = value(await dialog("review-pr"), "来源路径");
    expect(empty).toHaveTextContent("未记录路径");
    expect(empty).not.toHaveTextContent("无权查看");
  });

  it.each([
    ["not_supported", "不支持扫描", "not_scanned", "暂无扫描数据"],
    ["not_scanned", "未扫描", "not_scanned", "暂无扫描数据"],
    ["unknown", "状态未知", "stale", "数据已过期"],
  ])("labels scan state %s and never shows a zero time", async (scanState, label, freshness, freshLabel) => {
    detail({ ...inventoryAsset, scanState, freshness, scanCompletedAt: "0001-01-01T00:00:00Z" });
    await renderApp(`/inventory/${SKILL}`);
    const d = await dialog("review-pr");
    expect(value(d, "扫描状态")).toHaveTextContent(label);
    expect(value(d, "数据新鲜度")).toHaveTextContent(freshLabel);
    expect(value(d, "最近扫描")).toHaveTextContent("未扫描");
    expect(d).not.toHaveTextContent("0001");
  });

  it("shows a loading status while the detail is in flight", async () => {
    server.use(
      http.get("*/api/v1/agent-assets/:id", async () => {
        await delay("infinite");
        return HttpResponse.json(inventoryAsset);
      }),
    );
    await renderApp(`/inventory/${SKILL}`);
    const d = await dialog();
    expect(within(d).getByRole("status")).toHaveTextContent("正在加载资产详情");
  });

  it("says when an asset is not found", async () => {
    await renderApp("/inventory/missing-asset");
    expect(await within(await dialog()).findByRole("alert")).toHaveTextContent("找不到这项资产");
  });

  it("shows a forbidden state on 403", async () => {
    detail({ error: "forbidden" }, 403);
    await renderApp(`/inventory/${SKILL}`);
    const alert = await within(await dialog()).findByRole("alert");
    expect(alert).toHaveTextContent("你没有查看这项资产的权限");
    expect(within(alert).queryByRole("button", { name: "重试" })).not.toBeInTheDocument();
  });

  it("refuses a detail that breaks the contract instead of rendering guesses", async () => {
    detail({ ...inventoryAsset, hashKind: "md5" });
    await renderApp(`/inventory/${SKILL}`);
    const alert = await within(await dialog()).findByRole("alert");
    expect(alert).toHaveTextContent("资产详情没有加载出来");
    expect(alert).toHaveTextContent("服务返回的数据不符合");
  });

  // Same QueryClient across close/reopen: TanStack keeps the last successful data after a failed refetch, so an
  // authoritative refusal or contract break must replace it, in the header and body, paths included.
  it.each([
    ["404", () => HttpResponse.json({ error: "discovery asset not found" }, { status: 404 }), "找不到这项资产"],
    ["403", () => HttpResponse.json({ error: "forbidden" }, { status: 403 }), "你没有查看这项资产的权限"],
    ["contract break", () => HttpResponse.json({ ...inventoryAsset, hashKind: "md5" }), "服务返回的数据不符合"],
  ])("a failing reopen (%s) replaces the earlier details", async (_label, failure, message) => {
    await renderApp(`/inventory?agent=${AGENT}`);
    await userEvent.click(await screen.findByRole("link", { name: "review-pr" }));
    expect(value(await dialog("review-pr"), "来源路径")).toHaveTextContent(inventoryAsset.sourceRelPath);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    server.use(http.get("*/api/v1/agent-assets/:id", failure));
    await userEvent.click(screen.getByRole("link", { name: "review-pr" }));
    const d = await dialog();
    expect(await within(d).findByRole("alert")).toHaveTextContent(message);
    expect(within(d).getByRole("heading", { level: 2 })).toHaveTextContent("资产详情");
    expect(d).not.toHaveTextContent(inventoryAsset.sourceRelPath);
    expect(d).not.toHaveTextContent(inventoryAsset.hash);
    expect(d).not.toHaveTextContent(inventoryAsset.assetId);
  });

  it("closes from the close button back to the ledger with filters kept", async () => {
    const { router } = await renderApp(`/inventory/${SKILL}?category=skills`);
    const d = await dialog("review-pr");
    await userEvent.click(within(d).getByRole("button", { name: "关闭资产详情" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(router.state.location.pathname).toBe("/inventory");
    expect(router.state.location.search).toEqual({ category: "skills" });
  });
});

describe("asset rows in a narrowed ledger", () => {
  it("lists assets only when narrowed to one agent, under their category", async () => {
    const first = await renderApp("/inventory");
    await screen.findByRole("table");
    expect(assetRequests).toHaveLength(0);
    expect(screen.queryByRole("link", { name: "review-pr" })).toBeNull();
    first.unmount();
    await renderApp(`/inventory?agent=${AGENT}`);
    const mcp = await screen.findByRole("link", { name: "github" });
    expect(mcp).toHaveAttribute("href", `/inventory/${MCP}?agent=${AGENT}`);
  });

  it("says when the asset list did not load, keeping the ledger", async () => {
    server.use(http.get("*/api/v1/agent-assets", () => HttpResponse.json({ error: "discovery inventory unavailable" }, { status: 500 })));
    await renderApp(`/inventory?agent=${AGENT}`);
    expect(await screen.findByRole("alert")).toHaveTextContent("这个智能体的资产明细没有加载出来");
    expect(screen.getByRole("table")).toBeInTheDocument();
  });

  it("states when only the first page of assets is listed", async () => {
    server.use(http.get("*/api/v1/agent-assets", () => HttpResponse.json({ ...inventoryAssetPage, next_page_token: "more" })));
    await renderApp(`/inventory?agent=${AGENT}`);
    expect(await screen.findByText("只列出前 100 项资产")).toBeInTheDocument();
  });
});

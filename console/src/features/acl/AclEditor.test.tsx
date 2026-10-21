import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { axeViolations, renderApp, screen } from "../../test/render";

// #44 S5b editor: subject kinds are exactly all|agents|tags (docs/design/protection.openapi.json ACLSubject);
// targets are admin-entered exact hook tool names (plan LD6) — no trimming, case folding or wildcard.
const rule = {
  id: "acl-1",
  name: "允许读取",
  description: "",
  enabled: true,
  subject: { kind: "all" },
  effect: "allow",
  target: { kind: "tools", tools: ["Read"] },
  updatedAt: "2026-10-19T02:10:05Z",
};
const review = {
  id: "rev-9",
  baseRevision: 12,
  resourceId: "acl-new",
  resource: "acl",
  delete: false,
  // Server create diff (acl_review_impact_test.go TestACLReviewDiffAndAffectedAgents): top-level pointers, null before.
  diff: [
    { field: "/description", before: null, after: "" },
    { field: "/effect", before: null, after: "deny" },
    { field: "/enabled", before: null, after: true },
    { field: "/name", before: null, after: "禁用 Bash" },
    { field: "/subject", before: null, after: { kind: "tags", agentIds: [], tags: ["engineering"] } },
    { field: "/target", before: null, after: { kind: "tools", tools: ["Bash", "mcp__FS__write_file"] } },
  ],
  downgrades: [],
  warning: "",
  affectedPolicyIds: [],
  affectedAgentIds: [],
  bindings: [],
  tenant: "default",
};
const reviewBodies: { path: string; body: unknown }[] = [];
const useRules = (items: object[]) =>
  server.use(http.get("*/api/v1/acl", () => HttpResponse.json({ revision: 12, items, total: items.length, page: 1, pageSize: 100, virtualDefault: false }, { headers: { ETag: '"12"' } })));

beforeEach(() => {
  reviewBodies.length = 0;
  useRules([rule]);
  server.use(
    http.post("*/api/v1/acl/*", async ({ request }) => {
      reviewBodies.push({ path: new URL(request.url).pathname, body: await request.json() });
      return HttpResponse.json(review, { headers: { ETag: '"12"' } });
    }),
  );
});

async function openNew() {
  const user = userEvent.setup();
  await renderApp("/acl");
  await user.click(await screen.findByRole("button", { name: "新建规则" }));
  const dialog = await screen.findByRole("dialog", { name: "新建访问控制规则" });
  return { user, dialog };
}

describe("ACL editor (#44 S5b)", () => {
  it("offers exactly all / agents / tags subjects — no user subject — and focuses the name field", async () => {
    const { dialog } = await openNew();
    const subjects = within(within(dialog).getByRole("group", { name: "适用对象" })).getAllByRole("radio");
    expect(subjects.map((r) => r.closest("label")?.textContent)).toEqual(["全部智能体", "指定智能体", "按标签"]);
    expect(within(dialog).queryByText(/用户/)).toBeNull();
    expect(within(dialog).getByRole("textbox", { name: "名称" })).toHaveFocus();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("creates a deny rule with exact tool names, previews it in plain language, then publishes", async () => {
    const published: unknown[] = [];
    server.use(
      http.post("*/api/v1/acl", async ({ request }) => {
        published.push({ ifMatch: request.headers.get("If-Match"), body: await request.json() });
        return HttpResponse.json({ revision: 13, item: { ...rule, id: "acl-new" }, virtualDefault: false }, { headers: { ETag: '"13"' } });
      }),
    );
    const { user, dialog } = await openNew();
    await user.type(within(dialog).getByRole("textbox", { name: "名称" }), "禁用 Bash");
    await user.click(within(dialog).getByRole("radio", { name: "拒绝" }));
    await user.click(within(dialog).getByRole("radio", { name: "指定工具" }));
    // One row per tool name; a blank row drops, everything else is kept byte-exact (case and inner spacing).
    await user.type(within(dialog).getByRole("textbox", { name: "工具名 1" }), "Bash");
    await user.click(within(dialog).getByRole("button", { name: "添加工具名" }));
    await user.click(within(dialog).getByRole("button", { name: "添加工具名" }));
    await user.type(within(dialog).getByRole("textbox", { name: "工具名 3" }), "mcp__FS__write_file");
    expect(within(dialog).getByText("拒绝全部智能体调用工具 Bash、mcp__FS__write_file。")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    const reviewDialog = await screen.findByRole("dialog", { name: "检查变更：禁用 Bash" });
    // Whole /subject and /target objects render as their meaning, never "[object Object]".
    expect(within(reviewDialog).getByRole("row", { name: /适用对象/ })).toHaveTextContent("适用对象无标签：engineering");
    expect(within(reviewDialog).getByRole("row", { name: /^工具/ })).toHaveTextContent("工具无指定工具：Bash、mcp__FS__write_file");
    expect(within(reviewDialog).getByRole("row", { name: /效果/ })).toHaveTextContent("效果无拒绝");
    expect(reviewDialog).not.toHaveTextContent("[object Object]");
    expect(reviewBodies).toEqual([
      {
        path: "/api/v1/acl/review",
        body: { name: "禁用 Bash", description: "", enabled: true, subject: { kind: "all" }, effect: "deny", target: { kind: "tools", tools: ["Bash", "mcp__FS__write_file"] } },
      },
    ]);
    await user.click(screen.getByRole("button", { name: "发布" }));
    await waitFor(() => expect(published).toEqual([{ ifMatch: '"12"', body: { reviewId: "rev-9", confirmDowngrade: false } }]));
  });

  it("says an allow rule still goes through the other protection checks", async () => {
    const { dialog } = await openNew();
    expect(within(dialog).getByText("全部智能体可以调用全部工具，调用仍要经过其他防护检查。")).toBeInTheDocument();
  });

  it("validates before any request: name, tools and tags are required", async () => {
    const { user, dialog } = await openNew();
    await user.click(within(dialog).getByRole("radio", { name: "指定工具" }));
    await user.click(within(dialog).getByRole("radio", { name: "按标签" }));
    expect(within(dialog).getByText("填好适用对象和工具后，这里会说明这条规则的实际效果。")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    expect(within(dialog).getByRole("textbox", { name: "名称" })).toHaveAccessibleDescription("请填写名称");
    expect(within(dialog).getByRole("group", { name: "工具名" })).toHaveAccessibleDescription(/至少填写一个工具名/);
    expect(within(dialog).getByRole("group", { name: "标签" })).toHaveAccessibleDescription(/至少填写一个标签/);
    expect(reviewBodies).toEqual([]);
  });

  it("picks agents from enrolled, non-revoked devices and splits tags on commas", async () => {
    const { user, dialog } = await openNew();
    await user.type(within(dialog).getByRole("textbox", { name: "名称" }), "研发机");
    await user.click(within(dialog).getByRole("radio", { name: "指定智能体" }));
    const picker = within(dialog).getByRole("group", { name: "选择智能体" });
    expect(within(picker).getAllByRole("checkbox").map((c) => c.closest("label")?.textContent)).toEqual(["MBP-RD-0142node-0142", "WIN-OPS-0143node-0143"]);
    await user.click(within(picker).getByRole("checkbox", { name: /MBP-RD-0142/ }));
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    await waitFor(() => expect(reviewBodies).toHaveLength(1));
    expect(reviewBodies[0]?.body).toMatchObject({ subject: { kind: "agents", agentIds: ["node-0142"] } });
  });

  it("keeps a comma-containing tag as one value (one row per tag, no splitting)", async () => {
    const { user, dialog } = await openNew();
    await user.type(within(dialog).getByRole("textbox", { name: "名称" }), "标签规则");
    await user.click(within(dialog).getByRole("radio", { name: "按标签" }));
    await user.type(within(dialog).getByRole("textbox", { name: "标签 1" }), "ops,prod");
    await user.click(within(dialog).getByRole("button", { name: "添加标签" }));
    await user.type(within(dialog).getByRole("textbox", { name: "标签 2" }), "构建机");
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    await waitFor(() => expect(reviewBodies).toHaveLength(1));
    expect(reviewBodies[0]?.body).toMatchObject({ subject: { kind: "tags", tags: ["ops,prod", "构建机"] } });
  });

  it("an unrelated edit sends stored tags and tool names unchanged, even with delimiters (review F2)", async () => {
    const odd = { ...rule, id: "acl-7", name: "奇怪的值", subject: { kind: "tags", tags: ["ops,prod", "a， b"] }, target: { kind: "tools", tools: ["Read", "multi\nline", " padded "] } };
    useRules([odd]);
    const user = userEvent.setup();
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "编辑规则“奇怪的值”" }));
    const dialog = await screen.findByRole("dialog", { name: "编辑规则“奇怪的值”" });
    expect(within(dialog).getByRole("textbox", { name: "标签 1" })).toHaveValue("ops,prod");
    await user.type(within(dialog).getByRole("textbox", { name: "说明（可选）" }), "x");
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    await waitFor(() => expect(reviewBodies).toHaveLength(1));
    expect(reviewBodies[0]?.body).toMatchObject({ subject: odd.subject, target: odd.target });
  });

  it("shows an already-selected revoked agent with a remove control and never offers it for new selection (review F3)", async () => {
    const withRevoked = { ...rule, id: "acl-8", name: "含已撤销设备", subject: { kind: "agents", agentIds: ["node-0142", "node-0099"] } };
    useRules([withRevoked]);
    const user = userEvent.setup();
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "编辑规则“含已撤销设备”" }));
    const dialog = await screen.findByRole("dialog", { name: "编辑规则“含已撤销设备”" });
    const picker = within(dialog).getByRole("group", { name: "选择智能体" });
    expect(within(picker).getAllByRole("checkbox").map((c) => c.closest("label")?.textContent)).toEqual(["MBP-RD-0142node-0142", "WIN-OPS-0143node-0143"]);
    expect(within(picker).getByText("OLD-0099")).toBeInTheDocument();
    expect(within(picker).getByText("已撤销或不存在")).toBeInTheDocument();
    await user.click(within(picker).getByRole("button", { name: "移除智能体 OLD-0099" }));
    expect(within(picker).queryByText("OLD-0099")).toBeNull();
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    await waitFor(() => expect(reviewBodies).toHaveLength(1));
    expect(reviewBodies[0]?.body).toMatchObject({ subject: { kind: "agents", agentIds: ["node-0142"] } });
  });

  it("renders nested pointer diffs (/target/tools, /subject/agentIds) with device names", async () => {
    server.use(
      http.post("*/api/v1/acl/*", () =>
        HttpResponse.json(
          {
            ...review,
            resourceId: "acl-1",
            diff: [
              { field: "/subject/agentIds", before: [], after: ["node-0142"] },
              { field: "/subject/kind", before: "all", after: "agents" },
              { field: "/target/tools", before: ["Read"], after: ["Read", "Write"] },
            ],
          },
          { headers: { ETag: '"12"' } },
        ),
      ),
    );
    const user = userEvent.setup();
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "编辑规则“允许读取”" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "检查变更" }));
    const dialog = await screen.findByRole("dialog", { name: "检查变更：允许读取" });
    expect(within(dialog).getByRole("row", { name: /工具名/ })).toHaveTextContent("工具名ReadRead、Write");
    expect(within(dialog).getByRole("row", { name: /^指定智能体/ })).toHaveTextContent("指定智能体无MBP-RD-0142");
    expect(within(dialog).getByRole("row", { name: /^适用对象/ })).toHaveTextContent("适用对象全部智能体指定智能体");
  });

  it("edits an existing rule through its resource review endpoint, prefilled", async () => {
    const user = userEvent.setup();
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "编辑规则“允许读取”" }));
    const dialog = await screen.findByRole("dialog", { name: "编辑规则“允许读取”" });
    expect(within(dialog).getByRole("textbox", { name: "工具名 1" })).toHaveValue("Read");
    await user.type(within(dialog).getByRole("textbox", { name: "说明（可选）" }), "只读");
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    await waitFor(() => expect(reviewBodies).toHaveLength(1));
    expect(reviewBodies[0]).toEqual({
      path: "/api/v1/acl/acl-1/review",
      body: { name: "允许读取", description: "只读", enabled: true, subject: { kind: "all" }, effect: "allow", target: { kind: "tools", tools: ["Read"] } },
    });
  });

  it("Escape closes the editor and returns focus to the button that opened it", async () => {
    const { user } = await openNew();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(screen.getByRole("button", { name: "新建规则" })).toHaveFocus());
  });

  // WebKit/Safari does not focus a button on mouse click (#90), so the opener must come from the click, not activeElement.
  it("returns focus to the opener even when the click did not focus it (WebKit)", async () => {
    const user = userEvent.setup();
    await renderApp("/acl");
    const opener = await screen.findByRole("button", { name: "停用规则“允许读取”" });
    fireEvent.click(opener);
    expect(await screen.findByRole("dialog")).toBeVisible();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("goes back from review to the draft without losing it", async () => {
    const { user, dialog } = await openNew();
    await user.type(within(dialog).getByRole("textbox", { name: "名称" }), "禁用 Bash");
    await user.click(within(dialog).getByRole("button", { name: "检查变更" }));
    await user.click(await screen.findByRole("button", { name: "返回修改" }));
    expect(await screen.findByRole("textbox", { name: "名称" })).toHaveValue("禁用 Bash");
  });
});

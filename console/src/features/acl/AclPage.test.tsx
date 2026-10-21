import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { me } from "../../test/fixtures";
import { axeViolations, renderApp, screen } from "../../test/render";

// #44 S5b: wire shapes from internal/server/acl.go (list/review/publish) and the virtual default from
// internal/core/protection.go EffectiveACLRules (zero updatedAt, never published).
const allowRead = {
  id: "acl-1",
  name: "允许读取",
  description: "全员可读文件",
  enabled: true,
  subject: { kind: "all" },
  effect: "allow",
  target: { kind: "tools", tools: ["Read"] },
  updatedAt: "2026-10-19T02:10:05Z",
};
const denyBash = {
  id: "acl-2",
  name: "构建机禁用 Bash",
  description: "",
  enabled: false,
  subject: { kind: "tags", tags: ["构建机"] },
  effect: "deny",
  target: { kind: "tools", tools: ["Bash"] },
  updatedAt: "2026-10-19T03:00:00Z",
};
const agentsAllow = {
  id: "acl-3",
  name: "研发机全部放行",
  description: "",
  enabled: true,
  subject: { kind: "agents", agentIds: ["node-0142"] },
  effect: "allow",
  target: { kind: "all" },
  updatedAt: "2026-10-19T04:00:00Z",
};
const list = { revision: 12, items: [allowRead, denyBash, agentsAllow], total: 3, page: 1, pageSize: 100, virtualDefault: false };
const review = (patch: object = {}) => ({
  id: "rev-1",
  baseRevision: 12,
  resourceId: "acl-1",
  resource: "acl",
  delete: false,
  // Server diff: RFC 6901 pointers from internal/core/protection_review.go protectionDiff (acl_review_impact_test.go).
  diff: [{ field: "/enabled", before: true, after: false }],
  downgrades: [],
  warning: "",
  affectedPolicyIds: [],
  affectedAgentIds: [],
  bindings: [],
  tenant: "default",
  ...patch,
});
const useList = (body: object = list) => server.use(http.get("*/api/v1/acl", () => HttpResponse.json(body, { headers: { ETag: `"${(body as { revision: number }).revision}"` } })));
const asRole = (role: string) => server.use(http.get("*/api/v1/me", () => HttpResponse.json({ ...me, role })));
const rowOf = (name: string) => screen.getByRole("cell", { name: new RegExp(name) }).closest("tr") as HTMLElement;

beforeEach(() => useList());

describe("ACL list (#44 S5b)", () => {
  it("lists rules with applies-to, tools, effect, status and updated time; axe clean", async () => {
    const { container } = await renderApp("/acl");
    expect(await screen.findByRole("heading", { name: "访问控制", level: 1 })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "访问控制规则" });
    const headers = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["名称", "说明", "适用对象", "工具", "效果", "更新时间", "状态", "操作"]);
    expect(rowOf("允许读取")).toHaveTextContent("全部智能体");
    expect(rowOf("允许读取")).toHaveTextContent("Read");
    expect(rowOf("允许读取")).toHaveTextContent("允许");
    expect(rowOf("允许读取")).toHaveTextContent("acl-1");
    expect(rowOf("构建机禁用 Bash")).toHaveTextContent("标签：构建机");
    expect(rowOf("构建机禁用 Bash")).toHaveTextContent("拒绝");
    expect(rowOf("构建机禁用 Bash")).toHaveTextContent("已停用");
    // agent IDs resolve to enrolled device names (GET /api/v1/client-nodes)
    expect(rowOf("研发机全部放行")).toHaveTextContent("MBP-RD-0142");
    expect(rowOf("研发机全部放行")).toHaveTextContent("全部工具");
    expect(screen.getByText(/配置修订 r12/)).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("explains the virtual allow-all default before the first publication", async () => {
    useList({ revision: 0, items: [{ ...allowRead, id: "acl-default-all-pass", name: "Allow all tools", target: { kind: "all" }, updatedAt: "0001-01-01T00:00:00Z" }], total: 1, page: 1, pageSize: 100, virtualDefault: true });
    await renderApp("/acl");
    expect(await screen.findByText("访问控制还没有发布过")).toBeInTheDocument();
    expect(rowOf("Allow all tools")).toHaveTextContent("尚未发布");
  });

  it("says an initialized-empty ACL denies every tool call (deny-unless-permit)", async () => {
    useList({ revision: 5, items: [], total: 0, page: 1, pageSize: 100, virtualDefault: false });
    await renderApp("/acl");
    expect(await screen.findByRole("heading", { name: "没有访问控制规则" })).toBeInTheDocument();
    expect(screen.getByText(/所有工具调用都会被拒绝/)).toBeInTheDocument();
  });

  it("filters by name, applies-to and effect, kept in the URL", async () => {
    const user = userEvent.setup();
    const { router } = await renderApp("/acl?effect=deny");
    await screen.findByRole("table", { name: "访问控制规则" });
    expect(screen.getByRole("combobox", { name: "效果" })).toHaveValue("deny");
    expect(screen.queryByRole("cell", { name: /允许读取/ })).toBeNull();
    expect(rowOf("构建机禁用 Bash")).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "效果" }), "");
    await user.selectOptions(screen.getByRole("combobox", { name: "适用对象" }), "agents");
    await waitFor(() => expect(router.state.location.search).toEqual({ subject: "agents" }));
    expect(screen.getAllByRole("row")).toHaveLength(2);
    await user.type(screen.getByRole("searchbox", { name: "名称或 ID" }), "不存在");
    expect(await screen.findByRole("heading", { name: "没有符合筛选条件的规则" })).toBeInTheDocument();
  });

  it.each(["readonly", "auditor"])("%s sees the rules but no mutate controls (server RBAC: publish is admin-only)", async (role) => {
    asRole(role);
    await renderApp("/acl");
    await screen.findByRole("table", { name: "访问控制规则" });
    expect(screen.queryByRole("button", { name: "新建规则" })).toBeNull();
    expect(screen.queryByRole("button", { name: /编辑规则/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /停用规则|启用规则/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /删除规则/ })).toBeNull();
    expect(screen.queryByRole("columnheader", { name: "操作" })).toBeNull();
  });

  it("shows a forbidden panel on 403", async () => {
    server.use(http.get("*/api/v1/acl", () => HttpResponse.json({ error: "forbidden" }, { status: 403 })));
    await renderApp("/acl");
    expect(await screen.findByText("无权查看访问控制规则")).toBeInTheDocument();
  });

  it("has a navigation entry", async () => {
    await renderApp("/acl");
    expect(await screen.findByRole("link", { name: "访问控制" })).toHaveAttribute("href", "/acl");
  });
});

describe("ACL review → publish from a row (#44 S5b)", () => {
  it("disable: reviews with the list ETag, shows the diff, publishes with the review ETag, refreshes", async () => {
    const user = userEvent.setup();
    const seen: string[] = [];
    let published = false;
    server.use(
      http.get("*/api/v1/acl", () =>
        HttpResponse.json(published ? { ...list, revision: 13, items: [{ ...allowRead, enabled: false }, denyBash, agentsAllow] } : list, {
          headers: { ETag: published ? '"13"' : '"12"' },
        }),
      ),
      http.post("*/api/v1/acl/:id/review", async ({ request, params }) => {
        seen.push(`review ${params.id} ${request.headers.get("If-Match")} ${JSON.stringify(await request.json())}`);
        return HttpResponse.json(review(), { headers: { ETag: '"12"' } });
      }),
      http.put("*/api/v1/acl/:id", async ({ request, params }) => {
        seen.push(`put ${params.id} ${request.headers.get("If-Match")} ${JSON.stringify(await request.json())}`);
        published = true;
        return HttpResponse.json({ revision: 13, item: { ...allowRead, enabled: false }, virtualDefault: false }, { headers: { ETag: '"13"' } });
      }),
    );
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "停用规则“允许读取”" }));
    const dialog = await screen.findByRole("dialog", { name: "检查变更：允许读取" });
    expect(within(dialog).getByText("基于配置修订 r12")).toBeInTheDocument();
    expect(within(dialog).getByRole("row", { name: /状态/ })).toHaveTextContent(/已启用.*已停用/);
    await user.click(within(dialog).getByRole("button", { name: "发布" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(seen).toEqual([
      'review acl-1 "12" {"name":"允许读取","description":"全员可读文件","enabled":false,"subject":{"kind":"all"},"effect":"allow","target":{"kind":"tools","tools":["Read"]}}',
      'put acl-1 "12" {"reviewId":"rev-1","confirmDowngrade":false}',
    ]);
    await waitFor(() => expect(screen.getByText("配置修订 r13")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("已发布，配置修订 r13");
  });

  it("delete: reviews {delete:true}, warns about losing the last allow, publishes DELETE", async () => {
    const user = userEvent.setup();
    const seen: string[] = [];
    let releaseRefetch = () => {};
    const refetchGate = new Promise<void>((resolve) => (releaseRefetch = resolve));
    server.use(
      http.post("*/api/v1/acl/:id/review", async ({ request }) => {
        seen.push(JSON.stringify(await request.json()));
        return HttpResponse.json(review({
          delete: true,
          // Deletion: every top-level field before → null; subject/target arrive as whole objects with all arrays present.
          diff: [
            { field: "/description", before: "全员可读文件", after: null },
            { field: "/effect", before: "allow", after: null },
            { field: "/enabled", before: true, after: null },
            { field: "/name", before: "允许读取", after: null },
            { field: "/subject", before: { kind: "all", agentIds: [], tags: [] }, after: null },
            { field: "/target", before: { kind: "tools", tools: ["Read"] }, after: null },
          ],
        }), { headers: { ETag: '"12"' } });
      }),
      http.delete("*/api/v1/acl/:id", async ({ request, params }) => {
        seen.push(`delete ${params.id} ${request.headers.get("If-Match")} ${JSON.stringify(await request.json())}`);
        // #91: the post-publish refetch drops the row, and lands only after the drawer has closed and restored focus.
        server.use(
          http.get("*/api/v1/acl", async () => {
            await refetchGate;
            return HttpResponse.json({ ...list, revision: 13, items: [denyBash, agentsAllow], total: 2 }, { headers: { ETag: '"13"' } });
          }),
        );
        return HttpResponse.json({ ok: true, revision: 13 }, { headers: { ETag: '"13"' } });
      }),
    );
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "删除规则“允许读取”" }));
    const dialog = await screen.findByRole("dialog", { name: "删除规则：允许读取" });
    expect(within(dialog).getByText(/最后一条允许规则/)).toBeInTheDocument();
    expect(within(dialog).getByRole("row", { name: /适用对象/ })).toHaveTextContent("适用对象全部智能体无");
    expect(within(dialog).getByRole("row", { name: /^工具/ })).toHaveTextContent("工具指定工具：Read无");
    expect(dialog).not.toHaveTextContent("[object Object]");
    await user.click(within(dialog).getByRole("button", { name: "删除" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(seen).toEqual(['{"delete":true}', 'delete acl-1 "12" {"reviewId":"rev-1","confirmDowngrade":false}']);
    // APG modal dialog: the invoking element is going away, so focus a stable logical element, not the doomed button.
    releaseRefetch();
    await waitFor(() => expect(screen.queryByRole("cell", { name: /允许读取/ })).toBeNull());
    expect(document.activeElement).toBe(document.getElementById("main"));
  });

  it("permission-expanding change: publish stays disabled until the downgrade is acknowledged", async () => {
    const user = userEvent.setup();
    const bodies: unknown[] = [];
    server.use(
      http.post("*/api/v1/acl/:id/review", () =>
        HttpResponse.json(review({ resourceId: "acl-2", diff: [{ field: "/enabled", before: false, after: true }], downgrades: ["ACL permission expanded: acl-2"] }), {
          headers: { ETag: '"12"' },
        }),
      ),
      http.put("*/api/v1/acl/:id", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ revision: 13, item: denyBash, virtualDefault: false }, { headers: { ETag: '"13"' } });
      }),
    );
    const { container } = await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "启用规则“构建机禁用 Bash”" }));
    const dialog = await screen.findByRole("dialog", { name: "检查变更：构建机禁用 Bash" });
    expect(within(dialog).getByText("这次修改会放宽访问权限")).toBeInTheDocument();
    expect(within(dialog).getByText("ACL permission expanded: acl-2")).toBeInTheDocument();
    const publish = within(dialog).getByRole("button", { name: "发布" });
    expect(publish).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox", { name: "我已了解这次修改会放宽权限" }));
    expect(publish).toBeEnabled();
    expect(await axeViolations(container.ownerDocument.body)).toEqual([]);
    await user.click(publish);
    await waitFor(() => expect(bodies).toEqual([{ reviewId: "rev-1", confirmDowngrade: true }]));
  });

  it("412 on publish keeps the dialog open and offers to review again", async () => {
    const user = userEvent.setup();
    let reviews = 0;
    server.use(
      http.post("*/api/v1/acl/:id/review", () => {
        reviews++;
        return HttpResponse.json(review(), { headers: { ETag: '"12"' } });
      }),
      http.put("*/api/v1/acl/:id", () => HttpResponse.json({ error: "protection revision changed; keep the draft and review again" }, { status: 412 })),
    );
    await renderApp("/acl");
    await user.click(await screen.findByRole("button", { name: "停用规则“允许读取”" }));
    const dialog = await screen.findByRole("dialog", { name: "检查变更：允许读取" });
    await user.click(within(dialog).getByRole("button", { name: "发布" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("检查之后配置又被改过了");
    await user.click(within(dialog).getByRole("button", { name: "重新检查" }));
    await waitFor(() => expect(reviews).toBe(2));
  });
});

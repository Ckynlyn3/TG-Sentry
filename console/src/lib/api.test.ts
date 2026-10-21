import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/setup";
import { ApiError, listAcl, publishAcl, reviewAcl } from "./api";
import { aclInputOf, aclListSchema, aclRuleSchema, protectionReviewSchema } from "./schema";

// #44 S5a contract: wire shapes from internal/server/acl.go and docs/design/protection.openapi.json
// (ACLRule, ACLInput, Review, Confirm). The virtual default carries Go's zero time (protection.go
// EffectiveACLRules) and omitempty drops empty agentIds/tags/tools (internal/core/types.go ACLSubject/ACLTarget).
const virtualDefault = {
  id: "acl-default-all-pass",
  name: "Allow all tools",
  description: "",
  enabled: true,
  subject: { kind: "all" },
  effect: "allow",
  target: { kind: "all" },
  updatedAt: "0001-01-01T00:00:00Z",
};
const denyBash = {
  id: "acl-2",
  name: "构建机禁用 Bash",
  description: "构建机只跑脚本",
  enabled: true,
  subject: { kind: "tags", tags: ["构建机"] },
  effect: "deny",
  target: { kind: "tools", tools: ["Bash", "mcp__fs__write_file"] },
  updatedAt: "2026-10-19T02:10:05.123456789Z",
};
const list = { revision: 12, items: [denyBash], total: 1, page: 1, pageSize: 100, virtualDefault: false };
const review = {
  id: "rev-1",
  baseRevision: 12,
  resourceId: "acl-2",
  resource: "acl",
  delete: false,
  diff: [{ field: "enabled", before: true, after: false }],
  downgrades: [],
  warning: "",
  affectedPolicyIds: [],
  affectedAgentIds: [],
  bindings: [],
  tenant: "default",
};

describe("ACL schema (#44 S5a)", () => {
  it("parses the list, the virtual default with its zero time, and round-trips a rule to ACLInput", () => {
    const page = aclListSchema.parse({ ...list, items: [virtualDefault, denyBash], total: 2, virtualDefault: true });
    expect(page.virtualDefault).toBe(true);
    expect(page.items[0]?.updatedAt).toBe("0001-01-01T00:00:00Z");
    // ACLInput carries no server-owned fields (id, updatedAt) and keeps tool names byte-exact.
    expect(aclInputOf(aclRuleSchema.parse(denyBash))).toEqual({
      name: "构建机禁用 Bash",
      description: "构建机只跑脚本",
      enabled: true,
      subject: { kind: "tags", tags: ["构建机"] },
      effect: "deny",
      target: { kind: "tools", tools: ["Bash", "mcp__fs__write_file"] },
    });
    expect(aclInputOf(aclRuleSchema.parse(virtualDefault))).toEqual({
      name: "Allow all tools",
      description: "",
      enabled: true,
      subject: { kind: "all" },
      effect: "allow",
      target: { kind: "all" },
    });
  });

  it.each([
    ["a user subject (no trusted user source, plan §1)", { subject: { kind: "user" } }],
    ["a users subject", { subject: { kind: "users" } }],
    ["an unknown effect", { effect: "audit" }],
    ["an unknown target kind", { target: { kind: "mcp" } }],
    ["a missing updatedAt", { updatedAt: undefined }],
  ])("refuses %s", (_, patch) => {
    expect(aclRuleSchema.safeParse({ ...denyBash, ...patch }).success).toBe(false);
  });

  it("parses the Review shape including null diff values", () => {
    const r = protectionReviewSchema.parse({ ...review, diff: [{ field: "description", before: null, after: "x" }] });
    expect(r.diff[0]).toEqual({ field: "description", before: null, after: "x" });
  });
});

describe("ACL requests keep headers and ETag (#44 S5a)", () => {
  it("listAcl returns the parsed page with the response ETag", async () => {
    server.use(http.get("*/api/v1/acl", () => HttpResponse.json(list, { headers: { ETag: '"12"' } })));
    const r = await listAcl();
    expect(r.etag).toBe('"12"');
    expect(r.data.total).toBe(1);
  });

  it("review sends If-Match with the caller's ETag and keeps Accept/Content-Type; create vs resource path", async () => {
    const seen: { url: string; ifMatch: string | null; accept: string | null; type: string | null; body: unknown }[] = [];
    server.use(
      http.post("*/api/v1/acl/*", async ({ request }) => {
        seen.push({
          url: new URL(request.url).pathname,
          ifMatch: request.headers.get("If-Match"),
          accept: request.headers.get("Accept"),
          type: request.headers.get("Content-Type"),
          body: await request.json(),
        });
        return HttpResponse.json(review, { headers: { ETag: '"12"' } });
      }),
    );
    const input = aclInputOf(aclRuleSchema.parse(denyBash));
    const created = await reviewAcl(input, '"12"');
    expect(created.etag).toBe('"12"');
    expect(created.data.id).toBe("rev-1");
    await reviewAcl({ delete: true }, '"12"', "acl-2");
    expect(seen).toEqual([
      { url: "/api/v1/acl/review", ifMatch: '"12"', accept: "application/json", type: "application/json", body: input },
      { url: "/api/v1/acl/acl-2/review", ifMatch: '"12"', accept: "application/json", type: "application/json", body: { delete: true } },
    ]);
  });

  it("publish picks POST / PUT / DELETE and sends Confirm with If-Match", async () => {
    const seen: string[] = [];
    const record = async ({ request }: { request: Request }) => {
      seen.push(`${request.method} ${new URL(request.url).pathname} ${request.headers.get("If-Match")} ${JSON.stringify(await request.json())}`);
      return request.method === "DELETE"
        ? HttpResponse.json({ ok: true, revision: 13 }, { headers: { ETag: '"13"' } })
        : HttpResponse.json({ revision: 13, item: denyBash, virtualDefault: false }, { headers: { ETag: '"13"' } });
    };
    server.use(http.post("*/api/v1/acl", record), http.put("*/api/v1/acl/:id", record), http.delete("*/api/v1/acl/:id", record));
    expect((await publishAcl({}, { reviewId: "rev-1", confirmDowngrade: false }, '"12"')).data.revision).toBe(13);
    await publishAcl({ id: "acl-2" }, { reviewId: "rev-2", confirmDowngrade: true }, '"12"');
    const del = await publishAcl({ id: "acl-2", delete: true }, { reviewId: "rev-3", confirmDowngrade: false }, '"12"');
    expect(del.etag).toBe('"13"');
    expect(seen).toEqual([
      'POST /api/v1/acl "12" {"reviewId":"rev-1","confirmDowngrade":false}',
      'PUT /api/v1/acl/acl-2 "12" {"reviewId":"rev-2","confirmDowngrade":true}',
      'DELETE /api/v1/acl/acl-2 "12" {"reviewId":"rev-3","confirmDowngrade":false}',
    ]);
  });

  it("a stale If-Match surfaces as a 412 ApiError with the server message", async () => {
    server.use(http.put("*/api/v1/acl/:id", () => HttpResponse.json({ error: "protection revision changed; keep the draft and review again" }, { status: 412 })));
    const err = await publishAcl({ id: "acl-2" }, { reviewId: "rev-1", confirmDowngrade: false }, '"11"').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(412);
  });
});

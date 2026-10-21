import { describe, expect, it } from "vitest";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { server } from "../test/setup";
import { callItems, callsForSession, clientNodes, riskStats24h, sessionSummaries } from "../test/fixtures";
import { ApiError, listSessionCalls, listSessionSummaries } from "./api";
import { callItemSchema, callsPageSchema, clientNodesSchema, isInstant, meSchema, riskStatsSchema, sessionSummaryPageSchema, STATS_WINDOWS } from "./schema";

// #16 S3b contract freeze: fixtures carry the Go wire shapes (internal/core/session_summaries.go,
// content_state.go, client_nodes.go). A schema that drifts from them fails here before any page renders.

describe("session-summaries contract", () => {
  it("parses the server page shape: nanosecond instants, nameless devices, null lastCallAt, explicit null user", () => {
    const page = sessionSummaryPageSchema.parse(sessionSummaries);
    expect(page.items).toHaveLength(3);
    expect(page.items[0]?.sessionTime).toBe("2026-10-19T02:10:05.123456789Z");
    expect(page.items[2]?.devices).toEqual([{ nodeId: "node-local" }]);
    expect(page.items[2]?.lastCallAt).toBeNull();
    expect(page.items[1]?.devices).toEqual([]);
  });

  it.each([
    ["a user value before verified association exists (#72)", { user: "张三" }],
    ["an absent user (must be explicit null)", { user: undefined }],
    ["another userState", { userState: "verified" }],
    ["a missing device array", { devices: undefined }],
    ["a negative call count", { callCount: -1 }],
    ["a session time without a zone", { sessionTime: "2026-10-19 02:10:05" }],
    ["a session time with an out-of-range offset (review F1)", { sessionTime: "2026-10-19T02:10:05+99:99" }],
    ["a last call with offset minutes past 59", { lastCallAt: "2026-10-19T02:31:40+08:60" }],
  ])("refuses %s", (_, patch) => {
    const item = { ...sessionSummaries.items[0], ...patch };
    expect(sessionSummaryPageSchema.safeParse({ ...sessionSummaries, items: [item] }).success).toBe(false);
  });
});

describe("RFC 3339 instants (§5.6 time-numoffset)", () => {
  it.each(["2026-10-19T02:10:05Z", "2026-10-19T02:10:05.123456789Z", "2026-10-19T10:10:05+08:00", "2026-10-18T21:10:05-23:59"])("accepts %s", (v) => {
    expect(isInstant(v)).toBe(true);
  });
  it.each(["2026-10-19T00:00:00+99:99", "2026-10-19T00:00:00+24:00", "2026-10-19T00:00:00+23:60", "2026-13-01T00:00:00Z", "2026-10-19T00:00:00"])(
    "refuses %s",
    (v) => {
      expect(isInstant(v)).toBe(false);
    },
  );
});

describe("/calls content states (plan A1, A4)", () => {
  it("parses one item per state, including the restricted ReviewMetaView", () => {
    const page = callsPageSchema.parse(callsForSession);
    expect(page.items.map((c) => [c.inputState, c.outputState])).toEqual([
      ["captured", "captured"],
      ["captured", "captured"],
      ["captured", "policy_omitted"],
      ["policy_omitted", "policy_omitted"],
      ["captured", "not_yet_available"],
      ["never_captured", "never_captured"],
      ["permission_restricted", "permission_restricted"],
    ]);
    expect(page.items[1]?.argumentsObj).toEqual({});
    expect(page.items[3]?.argumentsObj).toBeNull();
  });

  it("refuses a restricted call that still carries content instead of hiding it", () => {
    for (const leak of [{ argumentsObj: { command: "cat .env" } }, { userMessage: "x" }, { context: "y" }, { result: "z" }]) {
      expect(callItemSchema.safeParse({ ...callItems.restricted, ...leak }).success, JSON.stringify(leak)).toBe(false);
    }
  });

  // Review F3: fields Zod would strip must be caught before stripping (internal/server/calls_capability_test.go).
  it.each([
    ["legacy modelContext", { modelContext: "prompt text" }],
    ["detailed modelInput", { modelInput: { messages: [] } }],
    ["a script body", { scriptFiles: [{ path: "run.sh", sha256: "ab", bytes: 3, complete: true, content: "rm" }] }],
    ["a null argumentsObj key", { argumentsObj: null }],
  ])("refuses a restricted call carrying %s", (_, leak) => {
    const r = callItemSchema.safeParse({ ...callItems.restricted, ...leak });
    expect(r.success).toBe(false);
  });

  it("keeps script metadata on a restricted call", () => {
    const meta = { path: "run.sh", sha256: "ab", bytes: 3, complete: true };
    expect(callItemSchema.parse({ ...callItems.restricted, scriptFiles: [meta] }).scriptFiles).toEqual([meta]);
  });

  it("does not police content on an allowed call (the server already strips script bodies there)", () => {
    expect(callItemSchema.safeParse({ ...callItems.captured, modelContext: "legacy" }).success).toBe(true);
  });

  it.each([
    ["input not_yet_available (only output waits)", { inputState: "not_yet_available" }],
    ["the design's reserved not_recorded, which the server does not define", { outputState: "not_recorded" }],
    ["an unknown decision", { decision: "maybe" }],
    ["an unknown execution", { execution: "running" }],
  ])("refuses %s", (_, patch) => {
    expect(callItemSchema.safeParse({ ...callItems.captured, ...patch }).success).toBe(false);
  });
});

// S5 (#46): the risk-stats contract is shipped, not proposed. Enum, bucket shape and ranking are the
// landed Go types (docs/RISK-STATS.md; internal/core/risk_stats.go). A schema that drifts fails here.
describe("risk-stats contract (docs/RISK-STATS.md; internal/core/risk_stats.go)", () => {
  it("uses the shipped window enum 24h|7d|all and rejects the dropped 30d (risk_stats.go:135 hasExact)", () => {
    expect([...STATS_WINDOWS]).toEqual(["24h", "7d", "all"]);
    expect(riskStatsSchema.shape.window.safeParse("all").success).toBe(true);
    expect(riskStatsSchema.shape.window.safeParse("30d").success).toBe(false);
  });

  it("requires the shipped bucket end and partial fields (risk_stats.go RiskStatsBucket)", () => {
    const s = riskStatsSchema.parse(riskStats24h);
    expect(s.buckets[0]).toMatchObject({ start: expect.any(Number), end: expect.any(Number), partial: expect.any(Boolean) });
    // A bucket missing end/partial is not the shipped shape and must be refused.
    expect(riskStatsSchema.safeParse({ ...riskStats24h, buckets: [{ start: 0, block: 0, alert: 0, other: 0 }] }).success).toBe(false);
  });

  it("requires the landed /me identity fields role, tenant, subject and kind (#12; internal/server/server.go /me)", () => {
    const full = { name: "a", version: "1", role: "auditor", tenant: "default", subject: "u1", kind: "human", capabilities: ["risk-stats"] };
    expect(meSchema.parse(full)).toMatchObject({ role: "auditor", tenant: "default", subject: "u1", kind: "human" });
    // Required now the OIDC backend has landed: a minimal/older /me no longer parses (fails closed to the error page).
    expect(meSchema.safeParse({ name: "a", version: "1" }).success).toBe(false);
    // role and kind are the closed Go sets (core.Role*, session.Kind); an unmapped value is refused.
    expect(meSchema.safeParse({ ...full, role: "superadmin" }).success).toBe(false);
    expect(meSchema.safeParse({ ...full, kind: "robot" }).success).toBe(false);
  });
});

describe("client-nodes contract", () => {
  it("keeps revoked nodes and their names", () => {
    expect(clientNodesSchema.parse(clientNodes).map((n) => [n.id, n.name, n.revoked])).toContainEqual(["node-0099", "OLD-0099", true]);
  });
});

describe("typed wrappers", () => {
  const capture = (path: string, body: JsonBodyType) => {
    const seen: URL[] = [];
    server.use(http.get(`*${path}`, ({ request }) => (seen.push(new URL(request.url)), HttpResponse.json(body))));
    return seen;
  };

  it("sends summary filters with the /calls paging defaults and drops empty ones", async () => {
    const seen = capture("/api/v1/session-summaries", sessionSummaries);
    await listSessionSummaries({ agent: "claude", nodeId: "", from: "2026-10-19T01:00:00.000Z" });
    expect(Object.fromEntries(seen[0]!.searchParams)).toEqual({ agent: "claude", from: "2026-10-19T01:00:00.000Z", page: "1", size: "20" });
  });

  it("drills into a session by its exact stored key, never sessionId", async () => {
    const seen = capture("/api/v1/calls", callsForSession);
    const key = sessionSummaries.items[0]!.sessionId;
    const page = await listSessionCalls(key, 2);
    expect(page.total).toBe(7);
    expect(seen[0]!.searchParams.get("sessionKey")).toBe(key);
    expect(seen[0]!.searchParams.has("sessionId")).toBe(false);
    expect(seen[0]!.searchParams.get("page")).toBe("2");
  });

  it("refuses an empty session key without a request (it would list every call)", async () => {
    const seen = capture("/api/v1/calls", callsForSession);
    await expect(listSessionCalls("")).rejects.toBeInstanceOf(ApiError);
    expect(seen).toHaveLength(0);
  });
});

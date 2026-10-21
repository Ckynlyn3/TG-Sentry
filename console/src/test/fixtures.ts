import { riskEventSchema, type RiskEvent } from "../lib/schema";

// Test-only fixtures shaped per docs/EVENT-SCHEMA.md §2–3 and the #10 contract: CloudEvents 1.0
// envelope, OCSF 1.9.0 Detection Finding data. Names/hosts are fictional (RFC 2606 style ids).
// Never imported by application code.
type Overrides = { id: string; time: number; data?: Partial<RiskEvent["data"]> };

export function riskEvent({ id, time, data }: Overrides): RiskEvent {
  const base: RiskEvent["data"] = {
    class_uid: 2004,
    severity_id: 5,
    time,
    action_id: 2,
    disposition_id: 2,
    message: "命令会下载远程脚本并直接交给 shell 执行",
    metadata: {
      uid: id,
      tenant_uid: "tenant-demo",
      correlation_uid: "ses_7f3a9c21",
      labels: ["curl-pipe-shell"],
      product: { name: "TG-Sentry", version: "0.1.0", feature: { name: "shell-ast" } },
    },
    actor: { app_uid: "node-0142/claude-code", app_name: "Claude Code", user: { uid: "user-zhangsan", name: "张三" } },
    device: { uid: "node-0142", name: "MBP-RD-0142" },
    finding_info: {
      uid: `finding-${id}`,
      title: "远程代码下载与执行",
      types: ["category::high-risk-ops"],
      analytic: { uid: "rule-remote-exec", name: "远程代码下载与执行", type_id: 1 },
    },
    unmapped: { tg_sentry: { tool_call_id: "toolu_demo_01" } },
  };
  return {
    specversion: "1.0",
    id,
    source: "/endpoints/node-0142",
    type: "tg.sentry.risk.v1",
    time: new Date(time).toISOString(),
    data: { ...base, ...data },
  };
}

const T0 = Date.UTC(2026, 9, 19, 2, 31, 40);

export const blockEvent = riskEvent({ id: "evt_block_01", time: T0 });
export const alertEvent = riskEvent({
  id: "evt_alert_02",
  time: T0 - 60_000,
  data: {
    severity_id: 4,
    action_id: 3,
    disposition_id: 19,
    message: "读取的文件里有疑似密钥",
    finding_info: { uid: "finding-2", title: "密钥与凭据", types: ["category::sensitive-info"] },
  },
});
// Local unenrolled agent: no actor.app_uid, identity_state "unenrolled" (#10).
export const unenrolledEvent = riskEvent({
  id: "evt_unenrolled_03",
  time: T0 - 120_000,
  data: {
    severity_id: 3,
    action_id: 3,
    disposition_id: 19,
    actor: {},
    device: undefined,
    finding_info: { uid: "finding-3", title: "目标劫持", types: ["category::prompt-attack"] },
    unmapped: { tg_sentry: { identity_state: "unenrolled" } },
  },
});
// Detected, outcome unknown (action_id 0 / disposition_id 0) and severity unknown.
export const unknownEvent = riskEvent({
  id: "evt_unknown_04",
  time: T0 - 180_000,
  data: { severity_id: 0, action_id: 0, disposition_id: 0, message: undefined, finding_info: { uid: "finding-4" } },
});

export const firstPage = { items: [blockEvent, alertEvent, unenrolledEvent, unknownEvent], next_page_token: "cursor-page-2" };
export const lastPage = { items: [riskEvent({ id: "evt_old_05", time: T0 - 86_400_000 })], next_page_token: "" };
export const allEvents = [...firstPage.items, ...lastPage.items];
// /me identity (internal/server/server.go /me): a human admin SSO session with tenant + subject (#12).
// role/kind drive the stats eligibility gate (docs/RISK-STATS.md: human + auditor|admin); tests override
// them to exercise readonly/CLI.
export const me = { name: "管理员", version: "0.1.0", role: "admin", kind: "human", tenant: "default", subject: "sso|admin-001" };

// Verbatim GET /api/v1/risk-events response from the #10 control plane (seeded `redis-cli FLUSHALL`
// review, unenrolled local agent). Real analytics carry {uid, type_id} without a name, and the
// Security Control pair can be 0/0 (outcome unknown).
export const serverPage = {"items":[{"specversion":"1.0","id":"0ce4df8c519c9a0e5372c33a00558f44","source":"/control-plane","type":"tg.sentry.risk.v1","time":"2026-10-19T03:38:29.031952385Z","datacontenttype":"application/json","data":{"category_uid":2,"class_uid":2004,"activity_id":1,"type_uid":200401,"severity_id":0,"time":1792381109031,"metadata":{"uid":"0ce4df8c519c9a0e5372c33a00558f44","version":"1.9.0","product":{"name":"TG-Sentry"},"profiles":["security_control","host"],"tenant_uid":"default","correlation_uid":"session"},"actor":{},"finding_info":{"uid":"afdb8382da1e6d9da5445ca4de9c823607359117eb298885315205ae123b2f3a","analytic":{"uid":"R_DB_REDIS","type_id":1}},"action_id":0,"disposition_id":0,"unmapped":{"tg_sentry":{"identity_state":"unenrolled","tool_call_id":"first"}}}}],"next_page_token":""};
export const serverEvent = riskEventSchema.parse(serverPage.items[0]);

// ---- Overview inputs (shapes from internal/core and internal/server; values fictional).
export const clientNodes = [
  { id: "node-0142", name: "MBP-RD-0142", platform: "darwin", createdAt: "2026-10-01T02:00:00Z", revoked: false },
  { id: "node-0143", name: "WIN-OPS-0143", platform: "windows", createdAt: "2026-10-02T02:00:00Z", revoked: false },
  { id: "node-0099", name: "OLD-0099", platform: "linux", createdAt: "2026-09-01T02:00:00Z", revoked: true },
];
export const instances = [
  { id: "i1", agent: "claude", sessionId: "s1", cwd: "/w", piVersion: "", hookVersion: "", installations: [], startedAt: "2026-10-19T02:00:00Z", heartbeat: "2026-10-19T02:30:00Z", state: "running", online: true },
  { id: "i2", agent: "claude", sessionId: "s2", cwd: "/w", piVersion: "", hookVersion: "", installations: [], startedAt: "2026-10-19T01:00:00Z", heartbeat: "2026-10-19T01:10:00Z", state: "disconnected", online: false },
  { id: "i3", agent: "codex", sessionId: "s3", cwd: "/w", piVersion: "", hookVersion: "", installations: [], startedAt: "0001-01-01T00:00:00Z", heartbeat: "0001-01-01T00:00:00Z", state: "idle", online: false },
];
export const callsPage = { items: [], total: 32, page: 1, pageSize: 1, pendingTotal: 2 };
export const policiesPage = { revision: 7, items: [], total: 3, page: 1, pageSize: 1 };
export const templatesPage = { revision: 7, items: [], total: 2, page: 1, pageSize: 1 };

// Shipped GET /api/v1/risk-events/stats shape (core.RiskStats, internal/core/risk_stats.go; docs/RISK-STATS.md).
// Buckets carry the server-computed start/end/partial; `to` lands mid the final hourly bucket, so that bucket
// is genuinely partial with a clipped end (end === to), exercising the shaded "partial data" path end-to-end.
// Contract emits no agent name. Values are fictional.
const H = 3_600_000;
export const statsNow = Date.UTC(2026, 9, 19, 3, 0, 0);
const statsTo = statsNow - H / 2; // 02:30 — inside the final [02:00,03:00) bucket, so it is partial
export const riskStats24h = {
  window: "24h",
  from: statsNow - 24 * H,
  to: statsTo,
  bucket_ms: H,
  generated_at: statsTo,
  totals: { total: 30, block: 6, alert: 14, other: 10, severity_unknown: 9, unattributed: 4 },
  buckets: Array.from({ length: 24 }, (_, i) => {
    const start = statsNow - (24 - i) * H;
    const partial = i === 23;
    return { start, end: partial ? statsTo : start + H, partial, block: i % 4 === 0 ? 1 : 0, alert: i % 2, other: i < 10 ? 1 : 0 };
  }),
  by_category: [
    { category: "category::high-risk-ops", block: 4, alert: 6, other: 3 },
    { category: "category::sensitive-info", block: 2, alert: 8, other: 1 },
  ],
  uncategorized: 6,
  top_agents: [{ agent: "node-0142/claude-code", block: 4, alert: 9, other: 2, last_seen: statsTo - 5 * 60_000 }],
};

// ---- Asset scan (#38/#41 S11). Wire shape of GET /api/v1/discovered-agents (internal/core/discovery_list.go
// DiscoveredAgentView / DiscoveryPage). Never-scanned categories carry Go's zero time. Values fictional.
const INV_ZERO = "0001-01-01T00:00:00Z";
const INV_T = "2026-10-19T02:31:40.123456789Z";
const invCategory = (category: string, scope: string, scanState: string, freshness: string, last = INV_T, reason?: string) => ({
  category, scope, scanState, ...(reason ? { reason } : {}), lastScanCompletedAt: last, freshness,
});
export const inventoryAgent = {
  id: "a".repeat(64), nodeId: "node-0142", accountId: "501", observedLocalAccount: "zhangsan", homePath: "/Users/zhangsan",
  family: "claude-code", found: "found", evidence: { kind: "config", relPath: ".claude/settings.json", mtime: INV_T }, version: "unknown", state: "present",
  categories: [
    invCategory("skills", "home", "scanned", "fresh"),
    invCategory("mcp", "home", "error", "stale", INV_T, "parse_failed"),
    invCategory("plugins", "home", "unknown", "stale"),
    invCategory("builtin_tools", "home", "not_supported", "not_scanned", INV_ZERO),
    invCategory("memory", "project", "not_scanned", "not_scanned", INV_ZERO, "project_scope_deferred"),
  ],
  scanCompletedAt: INV_T, freshness: "fresh",
};
export const inventoryCodex = { ...inventoryAgent, id: "b".repeat(64), family: "codex", found: "not_found", state: "absent", evidence: { kind: "absent", relPath: "" }, categories: [], freshness: "stale" };
export const inventoryOpencode = { ...inventoryAgent, id: "c".repeat(64), nodeId: "node-0143", accountId: "S-1-5-21-1001", family: "opencode", found: "unknown", state: "unknown", categories: [], freshness: "not_scanned" };
export const inventoryPage = { items: [inventoryAgent, inventoryCodex, inventoryOpencode], next_page_token: "inv-cursor-2" };
export const inventoryLastPage = { items: [{ ...inventoryAgent, id: "d".repeat(64), nodeId: "node-0099", family: "pi" }], next_page_token: "" };
// Readonly projection (internal/server/discovery_list.go projectDiscoveredAgent): account name, home path and
// evidence path omitted; undefined fields are dropped by JSON serialization.
export const inventoryRestricted = { ...inventoryAgent, id: "e".repeat(64), observedLocalAccount: undefined, homePath: undefined, evidence: { kind: "config" } };
// Wire shape of GET /api/v1/agent-assets[/{id}] (internal/core/discovery_list.go AgentAssetView). Size, mtime,
// descriptor and (for readonly) sourceRelPath are omitempty. Values fictional.
export const inventoryAsset = {
  assetId: "1".repeat(64), name: "review-pr", category: "skills", sourceRelPath: ".claude/skills/review-pr/SKILL.md", size: 2048, mtime: INV_T,
  hash: "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1a3c5b7d9f1e", hashKind: "file_sha256",
  discoveredAgentId: inventoryAgent.id, nodeId: "node-0142", accountId: "501", family: "claude-code", scope: "home",
  scanCompletedAt: INV_T, scanState: "scanned", freshness: "fresh",
};
export const inventoryMcpAsset = {
  ...inventoryAsset, assetId: "2".repeat(64), name: "github", category: "mcp", sourceRelPath: ".claude.json", size: undefined, mtime: undefined,
  hash: "4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d", hashKind: "descriptor_sha256",
  descriptor: { name: "github", transport: "stdio", envKeys: ["GITHUB_TOKEN"], headerKeys: ["Authorization"] },
  scanState: "error", reason: "parse_failed", freshness: "stale",
};
export const inventoryAssetPage = { items: [inventoryAsset, inventoryMcpAsset], next_page_token: "" };

// ---- Session audit (#16). Shapes are the Go wire types: internal/core/session_summaries.go SessionSummary
// (time.Time → RFC 3339 with nanoseconds, `user` explicit null, device `name` omitempty) and /calls items
// from internal/core/content_state.go ProjectReviewContent. Values fictional.
const SESSION_KEY_A = "sha256:5c1e0a7d9b44e2f1a3c6d8e0b2f4a6c8e0d2f4b6a8c0e2d4f6a8b0c2d4e6f8a0";
export const sessionSummaries = {
  items: [
    // One session seen by two agent families on two devices, one of them revoked.
    { sessionId: SESSION_KEY_A, agents: ["claude", "codex"], devices: [{ nodeId: "node-0099", name: "OLD-0099" }, { nodeId: "node-0142", name: "MBP-RD-0142" }], user: null, userState: "unassociated", sessionTime: "2026-10-19T02:10:05.123456789Z", lastCallAt: "2026-10-19T02:31:40Z", callCount: 12 },
    // Orphan reviews (no instance): no device, the review's own agent.
    { sessionId: "cursor-ses-41", agents: ["cursor"], devices: [], user: null, userState: "unassociated", sessionTime: "2026-10-19T01:05:00Z", lastCallAt: "2026-10-19T01:06:30Z", callCount: 2 },
    // Liveness-only session (instance, no review rows); device not in /client-nodes, so no name.
    { sessionId: "ses-heartbeat-only", agents: ["pi"], devices: [{ nodeId: "node-local" }], user: null, userState: "unassociated", sessionTime: "2026-10-18T23:00:00Z", lastCallAt: null, callCount: 0 },
  ],
  total: 43,
  page: 1,
  pageSize: 20,
};
export const sessionSummariesPage3 = { ...sessionSummaries, page: 3 };

const call = (o: Record<string, unknown>) => ({
  agent: "claude", id: "rev-1", instanceId: "i1", callId: "toolu_01", toolName: "Bash", sessionId: SESSION_KEY_A, cwd: "/w",
  digest: "d", mode: "model", reviewPath: "rule", version: 3, prompt: "", rules: [], scopes: [], decision: "approve", ruleId: "",
  comment: "", execution: "succeeded", createdAt: "2026-10-19T02:31:40.5Z", decidedAt: "2026-10-19T02:31:41Z", needsHuman: false,
  deadline: "2026-10-19T02:36:40Z", ...o,
});
// One item per content state of the A1/A4 precedence.
export const callItems = {
  captured: call({ inputState: "captured", outputState: "captured", argumentsObj: { command: "ls -la" }, userMessage: "列出文件", result: "total 0" }),
  emptyArgs: call({ id: "rev-2", inputState: "captured", outputState: "captured", argumentsObj: {}, execution: "failed" }),
  outputOmitted: call({ id: "rev-3", inputState: "captured", outputState: "policy_omitted", argumentsObj: { path: "a.txt" }, result: "[REDACTED]", sensitiveInfo: { findings: [] } }),
  inputOmitted: call({ id: "rev-4", inputState: "policy_omitted", outputState: "policy_omitted", argumentsObj: null, result: "[REDACTED]", sensitiveInfo: { findings: [{ type: "secret" }] } }),
  pending: call({ id: "rev-5", inputState: "captured", outputState: "not_yet_available", argumentsObj: { command: "rm -rf build" }, decision: "pending", execution: "not_executed", decidedAt: null }),
  neverCaptured: call({ id: "rev-6", inputState: "never_captured", outputState: "never_captured", argumentsObj: null, decision: "reject", execution: "not_executed" }),
  // ReviewMetaView: argumentsObj, userMessage, context and result are absent from the wire type.
  restricted: call({ id: "rev-7", inputState: "permission_restricted", outputState: "permission_restricted", decision: "approve", execution: "succeeded" }),
};
export const callsForSession = { items: Object.values(callItems), total: 7, page: 1, pageSize: 20, pendingTotal: 1 };

import { z } from "zod";

// Boundary schemas. Wire names are the contract's own names: CloudEvents 1.0 envelope + OCSF 1.9.0
// Detection Finding 2004 (docs/EVENT-SCHEMA.md §2–3; #10 emits OCSF 1.9.0). Only fields the console
// renders are parsed; optional OCSF fields stay optional, so "absent" is shown as unknown, never as zero.

// #10 `severity` filter values (EVENT-SCHEMA §3 RiskLevel names plus unknown).
export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type SeverityFilter = (typeof SEVERITIES)[number];

// #10 `category` filter values: the five protection categories with their `category::` prefix
// (docs/PROTECTION-CATEGORIES.md headings, CONTRIBUTING.md labels).
export const CATEGORIES = [
  "category::sensitive-info",
  "category::high-risk-ops",
  "category::prompt-attack",
  "category::behavior",
  "category::supply-chain",
] as const;
export type CategoryId = (typeof CATEGORIES)[number];

// `capabilities` is a contract proposal (docs/design/CONSOLE-DESIGN.md §V2.6 P2): the server lists the
// optional surfaces it implements, so the console never calls an endpoint the deployment lacks. Absent
// today, which reads as "none of the optional surfaces".
export const meSchema = z.object({ name: z.string(), version: z.string(), capabilities: z.array(z.string()).optional() });
export type Me = z.infer<typeof meSchema>;

const riskData = z.object({
  class_uid: z.literal(2004),
  severity_id: z.number().int(),
  time: z.number(),
  message: z.string().optional(),
  status_detail: z.string().optional(),
  action_id: z.number().int(),
  disposition_id: z.number().int(),
  metadata: z.object({
    uid: z.string(),
    tenant_uid: z.string(),
    correlation_uid: z.string(),
    logged_time: z.number().optional(),
    labels: z.array(z.string()).optional(),
    product: z.object({
      name: z.string(),
      version: z.string().optional(),
      feature: z.object({ name: z.string().optional() }).optional(),
    }),
  }),
  // Local unenrolled agents carry no app_uid (#10); identity_state says why.
  actor: z.object({
    app_uid: z.string().optional(),
    app_name: z.string().optional(),
    user: z.object({ uid: z.string().optional(), name: z.string().optional() }).optional(),
  }).optional(),
  device: z.object({ uid: z.string().optional(), name: z.string().optional() }).optional(),
  finding_info: z.object({
    uid: z.string(),
    title: z.string().optional(),
    types: z.array(z.string()).optional(),
    analytic: z.object({ uid: z.string().optional(), name: z.string().optional(), type_id: z.number().int() }).optional(),
  }),
  unmapped: z
    .object({
      tg_sentry: z.object({ tool_call_id: z.string().optional(), identity_state: z.string().optional() }).optional(),
    })
    .optional(),
});

export const riskEventSchema = z.object({
  specversion: z.literal("1.0"),
  id: z.string().min(1),
  source: z.string(),
  type: z.literal("tg.sentry.risk.v1"),
  time: z.string(),
  data: riskData,
});
export type RiskEvent = z.infer<typeof riskEventSchema>;

// GET /api/v1/risk-events (#10): newest first, cursor pagination. An empty or absent token ends the list.
export const riskEventPageSchema = z.object({
  items: z.array(riskEventSchema),
  next_page_token: z.string().nullish(),
});
export type RiskEventPage = z.infer<typeof riskEventPageSchema>;

// ---- Overview inputs from existing endpoints (internal/server). Only the fields the overview renders.

// GET /api/v1/client-nodes: enrolled remote devices, revoked ones included (internal/core/client_nodes.go
// ClientNode; `name` has no omitempty). The sessions device picker labels nodes by name.
export const clientNodesSchema = z.array(z.object({ id: z.string(), name: z.string(), revoked: z.boolean() }));
export type ClientNode = z.infer<typeof clientNodesSchema>[number];

// GET /api/v1/instances: registered agent sessions (internal/core/types.go Instance). `online` is computed by
// Engine.Instances() (internal/core/store.go): state != "disconnected" AND last heartbeat under 30 s old.
// heartbeat is RFC 3339 (Go time.Time; the zero time means never reported).
export const instancesSchema = z.array(z.object({ id: z.string(), agent: z.string(), online: z.boolean(), heartbeat: z.string() }));

// GET /api/v1/policies and /api/v1/templates: `{revision, items, total, page, pageSize}` (server/protection.go).
export const protectionListSchema = z.object({ revision: z.number().int(), total: z.number().int() });

// GET /api/v1/calls?page=1&size=1: review page with `total` and `pendingTotal` (internal/core/store.go ReviewPage).
export const callsTotalSchema = z.object({ total: z.number().int(), pendingTotal: z.number().int() });

// ---- Proposed: GET /api/v1/risk-events/stats?window=24h|7d|30d (design §V2.6 P1). Not implemented by
// the control plane yet; the console only requests it when /me lists the "risk-stats" capability.
export const STATS_WINDOWS = ["24h", "7d", "30d"] as const;
export type StatsWindow = (typeof STATS_WINDOWS)[number];
const verdictCounts = { block: z.number().int(), alert: z.number().int(), other: z.number().int() };
export const riskStatsSchema = z.object({
  window: z.enum(STATS_WINDOWS),
  from: z.number(),
  to: z.number(),
  bucket_ms: z.number().int().positive(),
  generated_at: z.number(),
  totals: z.object({ total: z.number().int(), ...verdictCounts, severity_unknown: z.number().int(), unattributed: z.number().int() }),
  buckets: z.array(z.object({ start: z.number(), ...verdictCounts })),
  by_category: z.array(z.object({ category: z.string(), ...verdictCounts })),
  uncategorized: z.number().int(),
  top_agents: z.array(z.object({ agent: z.string(), name: z.string().optional(), ...verdictCounts, last_seen: z.number() })),
});
export type RiskStats = z.infer<typeof riskStatsSchema>;

// ---- Session audit (#16). Contract frozen from the server code (code wins over the plan text).

// Go time.Time marshals as RFC 3339 with up to nine fractional digits. Zod's offset check accepts any two
// digits (+99:99), so the offset is held to RFC 3339 §5.6 (time-numoffset: hour 00–23, minute 00–59) and the
// value must still be a finite Date: nothing downstream (Date.parse, Intl) ever sees an invalid instant.
const RFC3339_OFFSET = /(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;
export const isInstant = (v: string) => RFC3339_OFFSET.test(v) && Number.isFinite(Date.parse(v));
export const instantSchema = z.string().datetime({ offset: true }).refine(isInstant, "not an RFC 3339 instant");
const instant = instantSchema;

// GET /api/v1/session-summaries (internal/core/session_summaries.go SessionSummaryPage; docs/ARCHITECTURE.md
// "session-summaries"). Metadata only. `user` is always null and `userState` always "unassociated" until
// verified user association ships (#72), so anything else is a contract change, not data to render.
export const sessionDeviceSchema = z.object({ nodeId: z.string(), name: z.string().optional() });
export const sessionSummarySchema = z.object({
  sessionId: z.string().min(1),
  agents: z.array(z.string()),
  devices: z.array(sessionDeviceSchema),
  user: z.null(),
  userState: z.literal("unassociated"),
  sessionTime: instant,
  lastCallAt: instant.nullable(),
  callCount: z.number().int().nonnegative(),
});
export type SessionSummary = z.infer<typeof sessionSummarySchema>;
const pageFields = { total: z.number().int().nonnegative(), page: z.number().int().positive(), pageSize: z.number().int().positive() };
export const sessionSummaryPageSchema = z.object({ items: z.array(sessionSummarySchema), ...pageFields });
export type SessionSummaryPage = z.infer<typeof sessionSummaryPageSchema>;

// Per-call content states (internal/core/content_state.go; plan A1 + A4 precedence). Input is never
// "not_yet_available": only output waits on a result. The design's reserved "not_recorded" is not
// defined by the server, so it is not accepted here.
export const INPUT_STATES = ["captured", "policy_omitted", "permission_restricted", "never_captured"] as const;
export const OUTPUT_STATES = ["captured", "policy_omitted", "not_yet_available", "permission_restricted", "never_captured"] as const;
export type InputState = (typeof INPUT_STATES)[number];
export type OutputState = (typeof OUTPUT_STATES)[number];
// Stored review vocabulary (internal/server/server.go reviewPageParams validReviewChoice; store.go
// normalises an empty execution to "not_executed").
export const DECISIONS = ["pending", "approve", "reject"] as const;
export const EXECUTIONS = ["not_executed", "awaiting_execution", "succeeded", "failed", "unknown"] as const;

const scriptFileSchema = z.object({
  path: z.string(),
  sha256: z.string().optional(),
  bytes: z.number().int().optional(),
  complete: z.boolean(),
  truncated: z.boolean().optional(),
  readError: z.string().optional(),
});

// Fields ReviewMetaView must not carry (internal/core/content_state.go; asserted by
// internal/server/calls_capability_test.go): input-side content, legacy and detailed model input, and script
// bodies (script path/hash/size metadata stays), plus the result on the output side.
const RESTRICTED_INPUT_FIELDS = ["argumentsObj", "userMessage", "context", "modelContext", "modelInput"] as const;

// Checked on the raw item, before Zod strips unknown keys: a stripped field would otherwise pass unseen.
function restrictedLeaks(raw: unknown): (string | number)[][] {
  if (typeof raw !== "object" || raw === null) return [];
  const r = raw as Record<string, unknown>;
  const leaks: (string | number)[][] = [];
  if (r.inputState === "permission_restricted") {
    for (const k of RESTRICTED_INPUT_FIELDS) if (Object.hasOwn(r, k)) leaks.push([k]);
    if (Array.isArray(r.scriptFiles))
      r.scriptFiles.forEach((f: unknown, i) => typeof f === "object" && f !== null && Object.hasOwn(f, "content") && leaks.push(["scriptFiles", i, "content"]));
  }
  if (r.outputState === "permission_restricted" && Object.hasOwn(r, "result")) leaks.push(["result"]);
  return leaks;
}

const callItemBase = z.object({
  id: z.string().min(1),
  sessionId: z.string(),
  agent: z.string(),
  instanceId: z.string(),
  callId: z.string(),
  toolName: z.string(),
  decision: z.enum(DECISIONS),
  execution: z.enum(EXECUTIONS),
  createdAt: instant,
  inputState: z.enum(INPUT_STATES),
  outputState: z.enum(OUTPUT_STATES),
  argumentsObj: z.record(z.unknown()).nullable().optional(),
  userMessage: z.string().optional(),
  context: z.string().optional(),
  scriptFiles: z.array(scriptFileSchema).optional(),
  result: z.string().optional(),
});

// One /calls item: ReviewListView (content allowed) or ReviewMetaView (content restricted). Content fields
// are optional because ReviewMetaView omits them from the wire type; a restricted item that still carries
// content breaks the contract and is refused rather than hidden.
export const callItemSchema = z.preprocess((raw, ctx) => {
  for (const path of restrictedLeaks(raw)) ctx.addIssue({ code: z.ZodIssueCode.custom, path, message: "content present on a restricted call" });
  return raw;
}, callItemBase);
export type CallItem = z.infer<typeof callItemSchema>;

// GET /api/v1/calls?sessionKey=…&page=…&size=… (internal/server/server.go "GET /api/v1/calls"):
// core.ReviewPage with items projected by ProjectReviewContent.
export const callsPageSchema = z.object({ items: z.array(callItemSchema), ...pageFields, pendingTotal: z.number().int().nonnegative() });
export type CallsPage = z.infer<typeof callsPageSchema>;

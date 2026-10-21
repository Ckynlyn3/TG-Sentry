import { z, type ZodType } from "zod";
import {
  aclListSchema,
  aclPublishSchema,
  callsPageSchema,
  callsTotalSchema,
  clientNodesSchema,
  instancesSchema,
  meSchema,
  protectionListSchema,
  protectionReviewSchema,
  riskEventPageSchema,
  riskEventSchema,
  riskStatsSchema,
  sessionSummaryPageSchema,
  type AclInput,
  type CategoryId,
  type SeverityFilter,
  type StatsWindow,
} from "./schema";

// Error shape of the control plane: `{"error": "..."}` with the HTTP status (internal/server/server.go fail()).
// kind separates transport failure, HTTP refusal and a response that breaks the contract.
export class ApiError extends Error {
  constructor(
    readonly kind: "network" | "http" | "contract",
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export const isApiStatus = (e: unknown, status: number) => e instanceof ApiError && e.status === status;

const errorBody = z.object({ error: z.string() });

// Caller headers (If-Match on protection writes) are kept; Accept and the JSON Content-Type are defaults only.
// The response ETag is returned alongside the body: it is the protection revision the next write must name
// (internal/server/protection.go protectionETag; RFC 9110 §13.1.1).
export async function requestTagged<T>(path: string, schema: ZodType<T>, init?: RequestInit): Promise<{ data: T; etag: string | null }> {
  const headers = new Headers(init?.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (init?.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  let res: Response;
  try {
    res = await fetch(path, { credentials: "same-origin", ...init, headers });
  } catch {
    throw new ApiError("network", 0, "network");
  }
  const body: unknown = await res.json().catch(() => undefined);
  if (!res.ok) {
    const err = errorBody.safeParse(body);
    throw new ApiError("http", res.status, err.success ? err.data.error : "");
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) throw new ApiError("contract", res.status, parsed.error.issues[0]?.path.join(".") ?? "");
  return { data: parsed.data, etag: res.headers.get("ETag") };
}

export const request = async <T>(path: string, schema: ZodType<T>, init?: RequestInit): Promise<T> =>
  (await requestTagged(path, schema, init)).data;

// login/logout answer {"ok":true}; the body carries nothing the console uses.
const okSchema = z.unknown().transform(() => undefined);

export const getMe = () => request("/api/v1/me", meSchema);
export const logout = () => request("/api/v1/logout", okSchema, { method: "POST" });

// SSO sign-in (#12) is a top-level browser 302 chain (BFF, plan §4): the console hands the browser to
// GET /api/v1/auth/login, which redirects to the IdP and back and sets the HttpOnly session cookie — the
// same cookie the removed admin-token path set. Initiation is window.location.assign(ssoLoginHref(next)),
// never fetch: fetch can neither follow the cross-origin IdP redirects nor let the IdP set its cookies.
// `next` is a same-origin path the server re-validates (internal/server/redirect.go safeNext);
// encodeURIComponent keeps the path's reserved characters intact inside the query string.
export const ssoLoginHref = (next?: string): string =>
  `/api/v1/auth/login${next ? `?next=${encodeURIComponent(next)}` : ""}`;

export interface RiskEventQuery {
  severity?: SeverityFilter;
  category?: CategoryId;
  agent?: string;
  cursor?: string;
}

// Page size: the design's 25-row page (docs/design/CONSOLE-DESIGN.md H3 and events mockup "第 1–25 条").
export const PAGE_SIZE = 25;

export function listRiskEvents(q: RiskEventQuery, size = PAGE_SIZE) {
  const p = new URLSearchParams({ page_size: String(size) });
  if (q.cursor) p.set("page_token", q.cursor);
  if (q.severity) p.set("severity", q.severity);
  if (q.category) p.set("category", q.category);
  if (q.agent) p.set("agent", q.agent);
  return request(`/api/v1/risk-events?${p}`, riskEventPageSchema);
}

export const getRiskEvent = (id: string) => request(`/api/v1/risk-events/${encodeURIComponent(id)}`, riskEventSchema);

export const meQuery = { queryKey: ["me"], queryFn: getMe, staleTime: Infinity } as const;

// Overview (design §V2.4). Existing endpoints only, plus the capability-gated risk-stats aggregate.
export const listClientNodes = () => request("/api/v1/client-nodes", clientNodesSchema);
export const listInstances = () => request("/api/v1/instances", instancesSchema);
export const getProtectionTotals = (kind: "policies" | "templates") => request(`/api/v1/${kind}?page=1&pageSize=1`, protectionListSchema);
export const getCallsTotal = () => request("/api/v1/calls?page=1&size=1", callsTotalSchema);
export const getRiskStats = (window: StatsWindow) => request(`/api/v1/risk-events/stats?window=${window}`, riskStatsSchema);

// The risk-stats surface is requested only when /me lists this capability (docs/RISK-STATS.md).
export const CAP_RISK_STATS = "risk-stats";

// ---- Session audit (#16). Page/size follow /calls: page ≥ 1, size 1–100, default 1/20
// (internal/server/session_summaries.go sessionSummaryParams; plan §2 / LD9).
export const SESSIONS_PAGE_SIZE = 20;
export const SESSIONS_MAX_PAGE_SIZE = 100;

export interface SessionSummaryQuery {
  agent?: string;
  nodeId?: string;
  sessionKey?: string;
  from?: string;
  to?: string;
  page?: number;
  size?: number;
}

const params = (q: Record<string, string | number | undefined>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== "") p.set(k, String(v));
  return p;
};

export function listSessionSummaries(q: SessionSummaryQuery) {
  const { page = 1, size = SESSIONS_PAGE_SIZE, ...filters } = q;
  return request(`/api/v1/session-summaries?${params({ ...filters, page, size })}`, sessionSummaryPageSchema);
}

// Drill-down: `sessionKey` matches the stored session key exactly (plan §3.1 / LD1); never `sessionId`,
// which the server re-hashes. An empty key would drop the filter server-side and list every call, so it
// is refused before any request.
export function listSessionCalls(sessionKey: string, page = 1, size = SESSIONS_PAGE_SIZE) {
  if (!sessionKey) return Promise.reject(new ApiError("contract", 0, "sessionKey"));
  return request(`/api/v1/calls?${params({ sessionKey, page, size })}`, callsPageSchema);
}

// ---- Tool access control (#44; internal/server/acl.go). Every write is review → confirm: review against the list's
// ETag, then publish the reviewId against the review's ETag. A stale tag is 412 and nothing is retried (design §7).
// ponytail: one 100-rule page (the server's pageSize maximum) so filters run client-side; page when ACLs outgrow it.
export const ACL_PAGE_SIZE = 100;
export const listAcl = () => requestTagged(`/api/v1/acl?page=1&pageSize=${ACL_PAGE_SIZE}`, aclListSchema);
export const aclQuery = { queryKey: ["acl"], queryFn: listAcl } as const;

const aclPath = (id?: string) => (id ? `/api/v1/acl/${encodeURIComponent(id)}` : "/api/v1/acl");
const ifMatch = (etag: string) => ({ "If-Match": etag });

export const reviewAcl = (input: AclInput, etag: string, id?: string) =>
  requestTagged(`${aclPath(id)}/review`, protectionReviewSchema, { method: "POST", headers: ifMatch(etag), body: JSON.stringify(input) });

export const publishAcl = (target: { id?: string; delete?: boolean }, confirm: { reviewId: string; confirmDowngrade: boolean }, etag: string) =>
  requestTagged(aclPath(target.id), aclPublishSchema, {
    method: !target.id ? "POST" : target.delete ? "DELETE" : "PUT",
    headers: ifMatch(etag),
    body: JSON.stringify(confirm),
  });

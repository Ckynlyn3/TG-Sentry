import { z, type ZodType } from "zod";
import {
  callsPageSchema,
  callsTotalSchema,
  clientNodesSchema,
  instancesSchema,
  meSchema,
  protectionListSchema,
  riskEventPageSchema,
  riskEventSchema,
  riskStatsSchema,
  sessionSummaryPageSchema,
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

async function request<T>(path: string, schema: ZodType<T>, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
    });
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
  return parsed.data;
}

// login/logout answer {"ok":true}; the body carries nothing the console uses.
const okSchema = z.unknown().transform(() => undefined);

export const getMe = () => request("/api/v1/me", meSchema);
export const login = (token: string) => request("/api/v1/login", okSchema, { method: "POST", body: JSON.stringify({ token }) });
export const logout = () => request("/api/v1/logout", okSchema, { method: "POST" });

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

// Overview (design §V2.4). Existing endpoints only, plus the capability-gated stats proposal.
export const listClientNodes = () => request("/api/v1/client-nodes", clientNodesSchema);
export const listInstances = () => request("/api/v1/instances", instancesSchema);
export const getProtectionTotals = (kind: "policies" | "templates") => request(`/api/v1/${kind}?page=1&pageSize=1`, protectionListSchema);
export const getCallsTotal = () => request("/api/v1/calls?page=1&size=1", callsTotalSchema);
export const getRiskStats = (window: StatsWindow) => request(`/api/v1/risk-events/stats?window=${window}`, riskStatsSchema);

// Optional surfaces are requested only when the server says it has them (design §V2.6 P2).
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

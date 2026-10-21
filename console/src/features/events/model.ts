import type { RiskEvent } from "../../lib/schema";

// Verdict from the OCSF Security Control pair (docs/EVENT-SCHEMA.md §3 handling table). Anything not
// listed there is "unknown": an intended deny is never shown as a confirmed block.
export type Verdict = "block" | "alert" | "log" | "detected" | "unknown";

export function verdictOf(e: RiskEvent): Verdict {
  const { action_id: a, disposition_id: d } = e.data;
  if (a === 2 && d === 2) return "block";
  if (a === 3 && d === 19) return "alert";
  if (a === 3 && d === 17) return "log";
  if (a === 3 && d === 15) return "detected";
  return "unknown";
}

// OCSF severity_id enum (Detection Finding): 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
// 5 Critical, 6 Fatal, 99 Other. Pips are the design's 4-step glyph (§8, H3); unknown has none.
export type Severity = "unknown" | "informational" | "low" | "medium" | "high" | "critical" | "fatal" | "other";

const SEVERITY_BY_ID: Record<number, Severity> = { 0: "unknown", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "fatal", 99: "other" };

export const severityOf = (e: RiskEvent): Severity => SEVERITY_BY_ID[e.data.severity_id] ?? "unknown";

export function pipsOf(s: Severity): number {
  switch (s) {
    case "low":
      return 1;
    case "medium":
      return 2;
    case "high":
      return 3;
    case "critical":
    case "fatal":
      return 4;
    case "unknown":
    case "informational":
    case "other":
      return 0;
    default: {
      const exhaustive: never = s;
      return exhaustive;
    }
  }
}

// Agent identity: registry name, else enrolled ID, else the reason it is missing (#10: local
// unenrolled agents carry no app_uid and identity_state "unenrolled").
export type AgentLabel = { kind: "named"; text: string } | { kind: "unenrolled" } | { kind: "unknown" };

export function agentOf(e: RiskEvent): AgentLabel {
  const a = e.data.actor;
  const text = a?.app_name ?? a?.app_uid;
  if (text) return { kind: "named", text };
  return e.data.unmapped?.tg_sentry?.identity_state === "unenrolled" ? { kind: "unenrolled" } : { kind: "unknown" };
}

// What raised the finding. OCSF Analytic: name is optional (the #10 server sends only uid + type_id),
// so fall back to uid, then the finding title. type_id 1 = Rule, 4 = Learning (ML/DL); the other
// enum values (behavioral, statistical, matching …) are shown under the generic "detection" label.
export type AnalyticKind = "rule" | "model" | "other";

export function analyticOf(e: RiskEvent): { name: string | undefined; kind: AnalyticKind } {
  const a = e.data.finding_info.analytic;
  const kind: AnalyticKind = a?.type_id === 1 ? "rule" : a?.type_id === 4 ? "model" : "other";
  return { name: a?.name ?? a?.uid ?? e.data.finding_info.title, kind };
}

// Coverage of the loaded page (design §V2.5): how many events lack each reported field. Counts only the
// rows on screen, and the strip says so; it is not a tenant-wide statistic.
export interface PageCoverage {
  total: number;
  verdictUnknown: number;
  severityUnknown: number;
  // identity_state "unenrolled" (#10) is a stated fact; no identity and no state is only missing attribution.
  agentUnenrolled: number;
  agentUnknown: number;
}

export function pageCoverage(items: readonly RiskEvent[]): PageCoverage {
  return {
    total: items.length,
    verdictUnknown: items.filter((e) => verdictOf(e) === "unknown").length,
    severityUnknown: items.filter((e) => severityOf(e) === "unknown").length,
    agentUnenrolled: items.filter((e) => agentOf(e).kind === "unenrolled").length,
    agentUnknown: items.filter((e) => agentOf(e).kind === "unknown").length,
  };
}

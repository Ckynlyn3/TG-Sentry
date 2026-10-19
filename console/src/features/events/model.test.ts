import { describe, expect, it } from "vitest";
import { riskEvent, serverEvent } from "../../test/fixtures";
import { agentOf, analyticOf, pipsOf, severityOf, verdictOf } from "./model";

const ev = (data: Parameters<typeof riskEvent>[0]["data"]) => riskEvent({ id: "e", time: 0, data });

describe("verdictOf: OCSF action_id/disposition_id (EVENT-SCHEMA §3 table)", () => {
  it.each([
    [2, 2, "block"],
    [3, 19, "alert"],
    [3, 17, "log"],
    [3, 15, "detected"],
    [0, 0, "unknown"],
    [2, 0, "unknown"], // intended deny without confirmed blocking is never shown as a block
    [1, 1, "unknown"],
  ])("action %i / disposition %i → %s", (a, d, v) => {
    expect(verdictOf(ev({ action_id: a, disposition_id: d }))).toBe(v);
  });
});

describe("severityOf / pipsOf: OCSF severity_id", () => {
  it.each([
    [0, "unknown", 0],
    [1, "informational", 0],
    [2, "low", 1],
    [3, "medium", 2],
    [4, "high", 3],
    [5, "critical", 4],
    [6, "fatal", 4],
    [99, "other", 0],
    [42, "unknown", 0],
  ])("severity_id %i → %s (%i pips)", (id, s, pips) => {
    const sev = severityOf(ev({ severity_id: id }));
    expect(sev).toBe(s);
    expect(pipsOf(sev)).toBe(pips);
  });
});

describe("agentOf", () => {
  it("prefers the registry name, then the enrolled id", () => {
    expect(agentOf(ev({ actor: { app_uid: "n/claude", app_name: "Claude Code" } }))).toEqual({ kind: "named", text: "Claude Code" });
    expect(agentOf(ev({ actor: { app_uid: "n/claude" } }))).toEqual({ kind: "named", text: "n/claude" });
  });
  it("shows unenrolled local agents as unenrolled, not blank (#10)", () => {
    expect(agentOf(ev({ actor: {}, unmapped: { tg_sentry: { identity_state: "unenrolled" } } }))).toEqual({ kind: "unenrolled" });
    expect(agentOf(ev({ actor: undefined, unmapped: { tg_sentry: { identity_state: "unenrolled" } } }))).toEqual({ kind: "unenrolled" });
  });
  it("falls back to unknown when identity is missing for no stated reason", () => {
    expect(agentOf(ev({ actor: {}, unmapped: undefined }))).toEqual({ kind: "unknown" });
  });
});

describe("analyticOf: OCSF Analytic name, else uid; type_id 1 Rule, 4 Learning (ML/DL)", () => {
  it("names a real server event by its analytic uid and marks it a rule", () => {
    expect(analyticOf(serverEvent)).toEqual({ name: "R_DB_REDIS", kind: "rule" });
  });
  it("prefers the analytic name and recognises models", () => {
    const fi = (analytic: object) => ev({ finding_info: { uid: "f", analytic: { type_id: 4, ...analytic } } });
    expect(analyticOf(fi({ uid: "m-1", name: "提示词注入模型" }))).toEqual({ name: "提示词注入模型", kind: "model" });
    expect(analyticOf(fi({ type_id: 99 }))).toEqual({ name: undefined, kind: "other" });
  });
});

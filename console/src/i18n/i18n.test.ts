import { describe, expect, it } from "vitest";
import zhCN from "./zh-CN";
import en from "./en";

const keys = (o: object, p = ""): string[] =>
  Object.entries(o).flatMap(([k, v]) => (typeof v === "string" ? [`${p}${k}`] : keys(v as object, `${p}${k}.`)));
const values = (o: object): string[] => Object.values(o).flatMap((v) => (typeof v === "string" ? [v] : values(v as object)));
const vars = (s: string) => [...s.matchAll(/{{(\w+)}}/g)].map((m) => m[1]).sort();

describe("i18n parity (design §13: zh-CN ↔ en key parity)", () => {
  it("has the same keys in both locales", () => {
    expect(keys(en).sort()).toEqual(keys(zhCN).sort());
  });
  it("has no empty strings", () => {
    expect([...values(zhCN), ...values(en)].filter((v) => !v.trim())).toEqual([]);
  });
  it("uses the same interpolation variables per key", () => {
    const get = (o: object, k: string) => k.split(".").reduce<unknown>((a, p) => (a as Record<string, unknown>)[p], o) as string;
    const mismatched = keys(zhCN).filter((k) => vars(get(zhCN, k)).join() !== vars(get(en, k)).join());
    expect(mismatched).toEqual([]);
  });
});

describe("events intro copy stays neutral about enforcement", () => {
  // Real events can carry action_id/disposition_id 0/0 (outcome unknown); only the per-event
  // disposition states what happened, so the page copy must not promise a block or an alert.
  it.each([
    ["zh-CN", zhCN, /拦截|提醒/],
    ["en", en, /block|alert/i],
  ] as const)("%s lede and empty state describe detected risk only", (_, m, enforcement) => {
    for (const text of [m.events.lede, m.events.emptyBody]) expect(text).not.toMatch(enforcement);
    expect(m.events.lede).toContain(m.events.colVerdict);
    expect(m.events.lede).toContain(m.verdict.unknown);
  });
});

describe("coverage copy makes no claim about what enrollment supplies (review F1)", () => {
  it.each([
    ["zh-CN", zhCN, /登记|接入/],
    ["en", en, /enrol/i],
  ] as const)("%s coverage hint is neutral", (_, m, claim) => {
    expect(m.events.covHint).not.toMatch(claim);
    expect(m.events.covAgentUnknown).toBeTruthy();
  });
});

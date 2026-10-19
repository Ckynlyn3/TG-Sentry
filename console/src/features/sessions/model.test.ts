import { describe, expect, it } from "vitest";
import { agentLabel, formatRangeTime, fromLocalInput, isRelative, presetRange, toLocalInput } from "./model";

describe("session filter helpers", () => {
  const now = Date.UTC(2026, 9, 19, 3, 0, 0);

  it.each([
    ["1h", "2026-10-19T02:00:00.000Z"],
    ["24h", "2026-10-18T03:00:00.000Z"],
    ["7d", "2026-10-12T03:00:00.000Z"],
  ] as const)("preset %s yields RFC 3339 instants ending now", (p, from) => {
    expect(presetRange(p, now)).toEqual({ from, to: "2026-10-19T03:00:00.000Z" });
  });

  it("treats only the three windows as relative", () => {
    expect([isRelative("1h"), isRelative("custom"), isRelative(undefined)]).toEqual([true, false, false]);
  });

  it("round-trips datetime-local values through instants in local time", () => {
    const iso = fromLocalInput("2026-10-19T10:30");
    expect(iso).toBe(new Date(2026, 9, 19, 10, 30).toISOString());
    expect(toLocalInput(iso)).toBe("2026-10-19T10:30");
    expect([fromLocalInput(""), fromLocalInput("not-a-date"), toLocalInput(undefined), toLocalInput("bogus")]).toEqual([undefined, undefined, "", ""]);
  });

  it("names known agent families and shows unknown ids as reported", () => {
    expect([agentLabel("claude"), agentLabel("pi"), agentLabel("acme-bot")]).toEqual(["Claude Code", "Pi", "acme-bot"]);
  });

  it.each(["__proto__", "constructor", "toString", "hasOwnProperty"])("labels the inherited-name id %s as itself (review F2)", (id) => {
    expect(agentLabel(id)).toBe(id);
  });

  it("never hands an invalid instant to Intl", () => {
    expect(formatRangeTime("2026-10-19T00:00:00+99:99", "zh-CN")).toBe("2026-10-19T00:00:00+99:99");
    expect(formatRangeTime("2026-10-19T00:00:00Z", "en")).toMatch(/2026/);
  });
});

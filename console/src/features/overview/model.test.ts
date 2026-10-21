import { describe, expect, it } from "vitest";
import { groupSessions, heartbeatMs, oldestFetch, partialBucket, trendPoints } from "./model";
import { pageCoverage } from "../events/model";
import { firstPage, riskEvent } from "../../test/fixtures";

describe("overview model", () => {
  it("treats Go's zero time and garbage as no heartbeat", () => {
    expect(heartbeatMs("0001-01-01T00:00:00Z")).toBeUndefined();
    expect(heartbeatMs("not a time")).toBeUndefined();
    expect(heartbeatMs("2026-10-19T02:30:00Z")).toBe(Date.UTC(2026, 9, 19, 2, 30));
  });

  it("groups sessions per agent with online count and latest heartbeat", () => {
    const g = groupSessions([
      { agent: "codex", online: false, heartbeat: "0001-01-01T00:00:00Z" },
      { agent: "claude", online: true, heartbeat: "2026-10-19T02:30:00Z" },
      { agent: "claude", online: false, heartbeat: "2026-10-19T03:00:00Z" },
    ]);
    expect(g).toEqual([
      { agent: "claude", online: 1, total: 2, lastBeat: Date.UTC(2026, 9, 19, 3) },
      { agent: "codex", online: 0, total: 1, lastBeat: undefined },
    ]);
  });

  it("reports the stalest successful fetch, ignoring queries that never succeeded", () => {
    expect(oldestFetch([{ dataUpdatedAt: 0 }])).toBe(0);
    expect(oldestFetch([{ dataUpdatedAt: 300 }, { dataUpdatedAt: 0 }, { dataUpdatedAt: 200 }])).toBe(200);
  });
});

describe("risk event page coverage", () => {
  it("counts explicitly unenrolled agents apart from agents with no identity at all (review F1)", () => {
    expect(pageCoverage(firstPage.items)).toEqual({ total: 4, verdictUnknown: 1, severityUnknown: 1, agentUnenrolled: 1, agentUnknown: 0 });
    const noIdentity = riskEvent({ id: "e-x", time: 0, data: { actor: {}, unmapped: undefined } });
    expect(pageCoverage([noIdentity])).toMatchObject({ agentUnenrolled: 0, agentUnknown: 1 });
    expect(pageCoverage([])).toEqual({ total: 0, verdictUnknown: 0, severityUnknown: 0, agentUnenrolled: 0, agentUnknown: 0 });
  });
});

describe("partial final bucket: shipped flag + clipped end (contract: buckets[].end/partial, RISK-STATS.md:102-111)", () => {
  it("shades from the partial bucket's start to its clipped end, never past the window `to`", () => {
    // last bucket is clipped: end (150) < start + nominal bucket_ms — shading must stop at `end`, not extend.
    expect(partialBucket({ buckets: [{ start: 0, end: 100, partial: false }, { start: 100, end: 150, partial: true }] })).toEqual({ x1: 100, x2: 150 });
  });
  it("handles a single bucket clipped at both ends (short `all` window)", () => {
    expect(partialBucket({ buckets: [{ start: 30, end: 150, partial: true }] })).toEqual({ x1: 30, x2: 150 });
  });
  it("is absent when the last bucket is not partial, and absent without buckets", () => {
    expect(partialBucket({ buckets: [{ start: 100, end: 200, partial: false }] })).toBeUndefined();
    expect(partialBucket({ buckets: [] })).toBeUndefined();
  });
});

describe("trend points clip the final plotted point to the bucket's shipped end (review H1)", () => {
  it("ends the last bucket at its clipped end, not start + bucket_ms, and keeps its bucket start for the label", () => {
    const pts = trendPoints({ buckets: [{ start: 0, end: 100, block: 1, alert: 0, other: 2 }, { start: 100, end: 150, block: 0, alert: 3, other: 0 }] });
    expect(pts.map((p) => [p.x, p.bucket])).toEqual([[0, 0], [100, 100], [150, 100]]);
    expect(pts.at(-1)).toMatchObject({ block: 0, alert: 3, other: 0 });
  });
  it("draws a single bucket clipped at both ends across [start, end]", () => {
    expect(trendPoints({ buckets: [{ start: 30, end: 150, block: 1, alert: 0, other: 0 }] }).map((p) => p.x)).toEqual([30, 150]);
    expect(trendPoints({ buckets: [] })).toEqual([]);
  });
});

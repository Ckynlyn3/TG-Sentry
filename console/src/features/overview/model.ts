// Pure derivations for the overview (design §V2.4). Inputs are already parsed at the API boundary.

// Go's zero time.Time marshals as 0001-01-01T00:00:00Z: that means "never", not a heartbeat.
export function heartbeatMs(rfc3339: string): number | undefined {
  const ms = Date.parse(rfc3339);
  return Number.isFinite(ms) && ms > 0 ? ms : undefined;
}

export interface SessionGroup {
  agent: string;
  online: number;
  total: number;
  lastBeat: number | undefined;
}

// Registered agent sessions grouped by agent type, most sessions first, then by name.
export function groupSessions(items: ReadonlyArray<{ agent: string; online: boolean; heartbeat: string }>): SessionGroup[] {
  const by = new Map<string, SessionGroup>();
  for (const i of items) {
    const g = by.get(i.agent) ?? { agent: i.agent, online: 0, total: 0, lastBeat: undefined };
    const beat = heartbeatMs(i.heartbeat);
    by.set(i.agent, {
      ...g,
      online: g.online + (i.online ? 1 : 0),
      total: g.total + 1,
      lastBeat: beat && (!g.lastBeat || beat > g.lastBeat) ? beat : g.lastBeat,
    });
  }
  return [...by.values()].sort((a, b) => b.total - a.total || a.agent.localeCompare(b.agent));
}

// Page freshness is its stalest input: the oldest successful fetch among the queries (0 = none yet).
export function oldestFetch(queries: ReadonlyArray<{ dataUpdatedAt: number }>): number {
  const ts = queries.map((q) => q.dataUpdatedAt).filter((t) => t > 0);
  return ts.length ? Math.min(...ts) : 0;
}

// The server flags the bucket that `to` falls strictly inside as partial and clips its `end` to `to`
// (contract: buckets[].partial/end, RISK-STATS.md:102-111; last bucket only). The console reads both and
// shades [start, end] — the clipped end, never start+bucket_ms, so the shading stops at `to`, not past it
// (Datadog partial-data convention).
export function partialBucket(s: { buckets: ReadonlyArray<{ start: number; end: number; partial: boolean }> }) {
  const last = s.buckets.at(-1);
  if (!last || !last.partial) return undefined;
  return { x1: last.start, x2: last.end };
}

export interface TrendPoint {
  x: number; // plotted position on the time axis
  bucket: number; // start of the bucket this point belongs to (tooltip label)
  block: number;
  alert: number;
  other: number;
}

// Step-after points plus an explicit end point, so the final bucket spans its real interval instead of
// collapsing onto its start (review F3). The end point repeats the last counts and keeps its bucket start,
// but is plotted at the shipped clipped `end` (= `to` for a partial bucket), so the trend never draws past
// the window (contract: clipped edges, RISK-STATS.md:102-111; review H1).
export function trendPoints(s: { buckets: ReadonlyArray<{ start: number; end: number; block: number; alert: number; other: number }> }): TrendPoint[] {
  const pts = s.buckets.map((b) => ({ x: b.start, bucket: b.start, block: b.block, alert: b.alert, other: b.other }));
  const last = s.buckets.at(-1);
  return last ? [...pts, { x: last.end, bucket: last.start, block: last.block, alert: last.alert, other: last.other }] : [];
}

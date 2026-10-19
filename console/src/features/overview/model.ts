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

// Each bucket covers [start, start + bucket_ms). The final bucket is partial when it had not ended when
// the server computed the stats; the shaded span is that bucket's own interval (also with one bucket).
export function partialBucket(s: { bucket_ms: number; generated_at: number; buckets: ReadonlyArray<{ start: number }> }) {
  const last = s.buckets.at(-1);
  if (!last || last.start + s.bucket_ms <= s.generated_at) return undefined;
  return { x1: last.start, x2: last.start + s.bucket_ms };
}

export interface TrendPoint {
  x: number; // plotted position on the time axis
  bucket: number; // start of the bucket this point belongs to (tooltip label)
  block: number;
  alert: number;
  other: number;
}

// Step-after points plus an explicit end point, so the final bucket spans its real interval instead of
// collapsing onto its start (review F3). The end point repeats the last counts and keeps its bucket start.
export function trendPoints(s: { bucket_ms: number; buckets: ReadonlyArray<{ start: number; block: number; alert: number; other: number }> }): TrendPoint[] {
  const pts = s.buckets.map((b) => ({ x: b.start, bucket: b.start, block: b.block, alert: b.alert, other: b.other }));
  const last = pts.at(-1);
  return last ? [...pts, { ...last, x: last.bucket + s.bucket_ms }] : [];
}

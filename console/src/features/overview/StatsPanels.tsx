import { useId } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Area, AreaChart, CartesianGrid, ReferenceArea, XAxis, YAxis } from "recharts";
import { useTranslation } from "react-i18next";
import { getRiskStats } from "../../lib/api";
import { partialBucket, trendPoints } from "./model";
import { formatListTime } from "../../lib/format";
import { CATEGORIES, STATS_WINDOWS, type RiskStats, type StatsWindow } from "../../lib/schema";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "../../components/ui/chart";
import { ErrorPanel } from "../../components/States";

// Stack order: block at the baseline (the verdict that matters most), then alert, then other.
const SERIES = ["block", "alert", "other"] as const;
const DAY_MS = 86_400_000;
const WINDOW_KEY = { "24h": "overview.window24h", "7d": "overview.window7d", "30d": "overview.window30d" } as const;

interface Props {
  range: StatsWindow;
  onRange: (w: StatsWindow) => void;
}

// Proposed GET /api/v1/risk-events/stats (design §V2.6 P1); rendered only when /me lists "risk-stats".
export default function StatsPanels({ range, onRange }: Props) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["risk-stats", range], queryFn: () => getRiskStats(range), placeholderData: keepPreviousData });

  return (
    <div className="stats-grid">
      <section className="panel trend-panel" aria-labelledby="ov-trend" aria-busy={q.isFetching}>
        <div className="panel-head">
          <h3 className="panel-title" id="ov-trend">
            {t("overview.trend")}
          </h3>
          <label className="field field-inline">
            <span className="label">{t("overview.window")}</span>
            <select className="input" value={range} onChange={(e) => onRange(STATS_WINDOWS.find((w) => w === e.target.value) ?? "24h")}>
              {STATS_WINDOWS.map((w) => (
                <option key={w} value={w}>
                  {t(WINDOW_KEY[w])}
                </option>
              ))}
            </select>
          </label>
        </div>
        {q.data ? (
          <Trend stats={q.data} />
        ) : q.isError ? (
          <div className="panel-pad">
            <ErrorPanel title={t("overview.statsError")} error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : (
          <p className="panel-pad faint" role="status">
            {t("overview.loading")}
          </p>
        )}
      </section>
      {q.data && <Categories stats={q.data} />}
      {q.data && <TopAgents stats={q.data} />}
    </div>
  );
}

function useFormats(stats: RiskStats) {
  const { i18n } = useTranslation();
  const daily = stats.bucket_ms >= DAY_MS;
  // Daily buckets are UTC days (contract P1), so their labels are formatted in UTC; hourly ones locally.
  const tick = new Intl.DateTimeFormat(i18n.language, daily ? { month: "2-digit", day: "2-digit", timeZone: "UTC" } : { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
  const full = new Intl.DateTimeFormat(i18n.language, daily ? { year: "numeric", month: "2-digit", day: "2-digit", timeZone: "UTC" } : { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
  return { daily, tick: (ms: number) => tick.format(ms), full: (ms: number) => full.format(ms), at: (ms: number) => formatListTime(ms, i18n.language) };
}

function Trend({ stats }: { stats: RiskStats }) {
  const { t } = useTranslation();
  const uid = useId().replace(/:/g, "");
  const f = useFormats(stats);
  const config = {
    block: { label: t("overview.seriesBlock"), color: "var(--viz-block)" },
    alert: { label: t("overview.seriesAlert"), color: "var(--viz-alert)" },
    other: { label: t("overview.seriesOther"), color: "var(--viz-other)" },
  } satisfies ChartConfig;
  const desc = t("overview.trendDesc", { window: t(WINDOW_KEY[stats.window]), ...stats.totals });
  const partial = partialBucket(stats);
  const points = trendPoints(stats);
  // Ticks on bucket boundaries, including the final bucket's end; recharts thins them by minTickGap.
  const ticks = points.map((p) => p.x);

  return (
    <figure className="trend">
      <p className="scope-line trend-scope">
        <span>{t("overview.statsScope", { from: f.full(stats.from), to: f.full(stats.to), time: f.at(stats.generated_at) })}</span>
        <span className="dot" aria-hidden />
        <span>{f.daily ? t("overview.bucketDay") : t("overview.bucketHour")}</span>
      </p>
      <div className="trend-figures">
        {SERIES.map((k) => (
          <p key={k} className={`trend-figure is-${k}`}>
            <small>{config[k].label}</small>
            <span>{stats.totals[k].toLocaleString()}</span>
          </p>
        ))}
      </div>
      <ChartContainer config={config} className="chart-trend" aria-hidden>
        <AreaChart data={points} margin={{ left: 0, right: 16, top: 8 }} accessibilityLayer={false}>
          {/* Flat fills, not shadcn's 0.8→0.1 gradient: Carbon "Never use a gradient in place of a sequential
              palette" (carbondesignsystem.com/building-blocks/data-visualization/color-palettes). */}
          <defs>
            <pattern id={`hatch-${uid}`} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <line x1="0" y1="0" x2="0" y2="6" stroke="var(--viz-other)" strokeWidth="2" />
            </pattern>
          </defs>
          <CartesianGrid vertical={false} />
          <XAxis
            dataKey="x"
            type="number"
            scale="time"
            domain={[ticks[0] ?? 0, ticks.at(-1) ?? 0]}
            ticks={ticks}
            tickLine={false}
            axisLine={false}
            tickMargin={8}
            minTickGap={32}
            tickFormatter={f.tick}
          />
          <YAxis tickLine={false} axisLine={false} width={32} allowDecimals={false} />
          <ChartTooltip
            cursor={false}
            content={<ChartTooltipContent indicator="dot" labelFormatter={(_, p) => (typeof p[0]?.payload?.bucket === "number" ? f.full(p[0].payload.bucket) : "")} />}
          />
          {SERIES.map((k) => (
            // Surface-coloured stroke separates stacked series: block and alert are ~1:1 to each other, and
            // SC 1.4.11 accepts adjacent graphics divided by a contrasting border (W3C Understanding 1.4.11).
            // A bucket's count holds for its whole interval: step (d3 curveStepAfter), not a smoothed curve that
            // shows values between buckets that never existed (found in browser review, design §V2.4).
            <Area key={k} dataKey={k} type="stepAfter" stackId="verdicts" fill={`var(--color-${k})`} fillOpacity={1} stroke="var(--surface-1)" strokeWidth={1.5} isAnimationActive={false} />
          ))}
          {/* Datadog: "the last incomplete time interval … is shaded and labeled as 'partial data'"
              (docs.datadoghq.com/dashboards/widgets/timeseries). */}
          {partial && <ReferenceArea x1={partial.x1} x2={partial.x2} fill={`url(#hatch-${uid})`} ifOverflow="hidden" />}
        </AreaChart>
      </ChartContainer>
      <figcaption className="trend-caption">
        <span>{desc}</span> <span>{t("overview.unknownNote", { severity: stats.totals.severity_unknown, unattributed: stats.totals.unattributed })}</span>{" "}
        <span>{t("overview.otherHint")}</span>
        {partial && <span> {t("overview.partial", { time: f.full(partial.x1) })}</span>}
      </figcaption>
      {/* SC 1.1.1: the chart's numbers as a real table (design §13 "Charts"). */}
      <details className="data-details">
        <summary>{t("overview.viewData")}</summary>
        <div className="table-wrap" tabIndex={0} role="region" aria-label={t("overview.viewData")}>
          <table className="data compact">
            <thead>
              <tr>
                <th scope="col">{t("overview.colBucket")}</th>
                {SERIES.map((k) => (
                  <th key={k} scope="col" className="num">
                    {config[k].label}
                  </th>
                ))}
                <th scope="col" className="num">
                  {t("overview.total")}
                </th>
              </tr>
            </thead>
            <tbody>
              {stats.buckets.map((b) => (
                <tr key={b.start}>
                  <td className="mono">{f.full(b.start)}</td>
                  <td className="num">{b.block}</td>
                  <td className="num">{b.alert}</td>
                  <td className="num">{b.other}</td>
                  <td className="num">{b.block + b.alert + b.other}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}

function Categories({ stats }: { stats: RiskStats }) {
  const { t } = useTranslation();
  // Contract P1: a known category missing from by_category had no events in the window (0 of each).
  // Uncategorized events come as one total without a verdict split, so they are never split here (review F2).
  const rows = CATEGORIES.map((c) => ({ key: c, label: t(`categories.${c}`), ...(stats.by_category.find((x) => x.category === c) ?? { block: 0, alert: 0, other: 0 }) }));
  const max = Math.max(1, stats.uncategorized, ...rows.map((r) => r.block + r.alert + r.other));
  return (
    <section className="panel" aria-labelledby="ov-cat">
      <div className="panel-head">
        <h3 className="panel-title" id="ov-cat">
          {t("overview.byCategory")}
        </h3>
        <span className="faint">{t(WINDOW_KEY[stats.window])}</span>
      </div>
      <ul className="cat-list">
        {rows.map((r) => {
          const total = r.block + r.alert + r.other;
          return (
            <li key={r.key}>
              <span className="cat-name">{r.label}</span>
              <span className="cat-counts">
                {total === 0 ? (
                  <span className="faint">{t("overview.noEvents")}</span>
                ) : (
                  `${t("overview.seriesBlock")} ${r.block} · ${t("overview.seriesAlert")} ${r.alert} · ${t("overview.seriesOther")} ${r.other}`
                )}
              </span>
              <span className="cat-bar" aria-hidden>
                {SERIES.map((k) => (r[k] > 0 ? <span key={k} className={`is-${k}`} style={{ width: `${(r[k] / max) * 100}%` }} /> : null))}
              </span>
            </li>
          );
        })}
        {stats.uncategorized > 0 && (
          <li>
            <span className="cat-name">{t("overview.uncategorized")}</span>
            <span className="cat-counts">{t("overview.categoryTotal", { count: stats.uncategorized })}</span>
            <span className="cat-bar" aria-hidden>
              <span className="is-total" style={{ width: `${(stats.uncategorized / max) * 100}%` }} />
            </span>
          </li>
        )}
      </ul>
    </section>
  );
}

function TopAgents({ stats }: { stats: RiskStats }) {
  const { t } = useTranslation();
  const f = useFormats(stats);
  return (
    <section className="panel top-agents" aria-labelledby="ov-top">
      <div className="panel-head">
        <h3 className="panel-title" id="ov-top">
          {t("overview.topAgents")}
        </h3>
        <span className="faint">{t(WINDOW_KEY[stats.window])}</span>
      </div>
      {stats.top_agents.length === 0 ? (
        <p className="panel-pad faint">{t("overview.topEmpty")}</p>
      ) : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label={t("overview.topAgents")}>
          <table className="data compact">
            <thead>
              <tr>
                <th scope="col">{t("overview.colAgent")}</th>
                {SERIES.map((k) => (
                  <th key={k} scope="col" className="num">
                    {t(k === "block" ? "overview.seriesBlock" : k === "alert" ? "overview.seriesAlert" : "overview.seriesOther")}
                  </th>
                ))}
                <th scope="col">{t("overview.colLast")}</th>
              </tr>
            </thead>
            <tbody>
              {stats.top_agents.map((a) => (
                <tr key={a.agent}>
                  <td>
                    {/* The events filter takes the same app_uid (#10 `agent`). */}
                    <Link className="rowlink" to="/events" search={{ agent: a.agent }}>
                      {a.name ?? <span className="mono">{a.agent}</span>}
                    </Link>
                    {a.name && <small className="faint mono"> {a.agent}</small>}
                  </td>
                  <td className="num">{a.block}</td>
                  <td className="num">{a.alert}</td>
                  <td className="num">{a.other}</td>
                  <td className="mono sub">{f.at(a.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

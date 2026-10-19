import { lazy, Suspense, type ReactNode } from "react";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { BarChart3 } from "lucide-react";
import { useTranslation } from "react-i18next";
import {
  CAP_RISK_STATS,
  getCallsTotal,
  getProtectionTotals,
  isApiStatus,
  listClientNodes,
  listInstances,
  listRiskEvents,
  meQuery,
} from "../../lib/api";
import { formatListTime, isoTime } from "../../lib/format";
import { EmptyState } from "../../components/States";
import { VerdictStamp } from "../events/parts";
import { analyticOf } from "../events/model";
import { groupSessions, heartbeatMs, oldestFetch } from "./model";

// Recharts loads only here, and only when the server implements the stats surface (design §V2.4, budget §14).
const StatsPanels = lazy(() => import("./StatsPanels"));

const route = getRouteApi("/app/overview");
const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;
const LATEST = 5;

// Overview (#46, design §V2.4). Every figure names its scope, denominator and fetch time; a figure no
// existing endpoint can provide is labelled unavailable, never estimated or shown as 0.
export function OverviewPage() {
  const { t, i18n } = useTranslation();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const me = useQuery(meQuery).data;
  const hasStats = me?.capabilities?.includes(CAP_RISK_STATS) ?? false;

  const nodes = useQuery({ queryKey: ["client-nodes"], queryFn: listClientNodes });
  const instances = useQuery({ queryKey: ["instances"], queryFn: listInstances });
  const calls = useQuery({ queryKey: ["calls-total"], queryFn: getCallsTotal });
  const policies = useQuery({ queryKey: ["protection-totals", "policies"], queryFn: () => getProtectionTotals("policies") });
  const templates = useQuery({ queryKey: ["protection-totals", "templates"], queryFn: () => getProtectionTotals("templates") });
  const latest = useQuery({ queryKey: ["risk-events", "latest", LATEST], queryFn: () => listRiskEvents({}, LATEST) });

  const fetched = oldestFetch([nodes, instances, calls, policies, templates, latest]);
  const at = (ms: number) => formatListTime(ms, i18n.language);
  const tz = new Intl.DateTimeFormat(i18n.language, { timeZoneName: "shortOffset" }).formatToParts(new Date()).find((p) => p.type === "timeZoneName")?.value;

  const activeNodes = nodes.data?.filter((n) => !n.revoked).length ?? 0;
  const online = instances.data?.filter((i) => i.online).length ?? 0;
  const lastBeat = Math.max(0, ...(instances.data ?? []).map((i) => heartbeatMs(i.heartbeat) ?? 0));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("overview.title")}</h1>
          <p className="lede">{t("overview.lede")}</p>
        </div>
      </div>
      <p className="scope-line">
        <span>
          {t("overview.tenant")} <strong>{t("shell.singleTenant")}</strong>
        </span>
        {tz && (
          <>
            <span className="dot" aria-hidden />
            <span>{t("overview.timezone", { tz })}</span>
          </>
        )}
        {fetched > 0 && (
          <>
            <span className="dot" aria-hidden />
            <span>{t("overview.fetched", { time: at(fetched) })}</span>
          </>
        )}
      </p>

      <section aria-labelledby="ov-kpi" className="mb-6">
        <h2 id="ov-kpi" className="sr-only">
          {t("overview.kpiHeading")}
        </h2>
        <ul className="kpi-grid">
          <Kpi label={t("overview.devices")} q={nodes}>
            {(d) => ({
              value: activeNodes,
              of: d.length > 0 ? t("overview.devicesOf", { total: d.length }) : undefined,
              scope: d.length > 0 ? t("overview.devicesScope", { revoked: d.length - activeNodes }) : t("overview.devicesNone"),
            })}
          </Kpi>
          <Kpi label={t("overview.sessions")} q={instances}>
            {(d) => ({
              value: online,
              of: d.length > 0 ? t("overview.sessionsOf", { total: d.length }) : undefined,
              // "No sessions" only when there are none; registered sessions without a heartbeat say exactly that (review F4).
              scope: d.length === 0 ? t("overview.sessionsNone") : lastBeat > 0 ? t("overview.sessionsScope", { time: at(lastBeat) }) : t("overview.sessionsNoBeat"),
            })}
          </Kpi>
          <Kpi label={t("overview.calls")} q={calls}>
            {(d) => ({ value: d.total, of: t("overview.callsUnit"), scope: t("overview.callsScope", { pending: d.pendingTotal }) })}
          </Kpi>
          <Kpi label={t("overview.policies")} q={policies}>
            {(d) => ({
              value: d.total,
              of: t("overview.policiesUnit"),
              scope:
                d.total === 0
                  ? t("overview.policiesNone", { revision: d.revision })
                  : t("overview.policiesScope", { templates: templates.data?.total ?? "—", revision: d.revision }),
            })}
          </Kpi>
          {/* No ACL endpoint exists (M5 #44): a labelled gap, not a zero. */}
          <li className="kpi is-unavailable">
            <p className="kpi-label">{t("overview.acl")}</p>
            <p className="kpi-value unknown">{t("overview.unavailable")}</p>
            <p className="kpi-scope">{t("overview.aclScope")}</p>
          </li>
        </ul>
      </section>

      <section aria-labelledby="ov-stats" className="mb-6">
        <h2 id="ov-stats" className="sr-only">
          {t("overview.statsHeading")}
        </h2>
        {hasStats ? (
          <Suspense fallback={<div className="panel panel-pad" role="status">{t("overview.loading")}</div>}>
            <StatsPanels range={search.range} onRange={(range) => void navigate({ search: { range } })} />
          </Suspense>
        ) : (
          <div className="panel panel-pad stats-unavailable">
            <BarChart3 {...ICON} className="unknown" />
            <div className="grow">
              <h3 className="panel-title">{t("overview.statsUnavailableTitle")}</h3>
              <p className="lede-sm">{t("overview.statsUnavailableBody")}</p>
            </div>
            <Link className="btn btn-secondary" to="/events">
              {t("overview.openEvents")}
            </Link>
          </div>
        )}
      </section>

      <div className="ov-grid">
        <Panel
          id="ov-latest"
          title={t("overview.latest")}
          meta={t("overview.latestScope", { count: LATEST })}
          action={
            <Link to="/events" className="panel-link">
              {t("overview.allEvents")}
            </Link>
          }
        >
          <PanelBody q={latest}>
            {(d) =>
              d.items.length === 0 ? (
                <EmptyState title={t("overview.latestEmpty")}>{null}</EmptyState>
              ) : (
                <ol className="ledger-list">
                  {d.items.map((e) => (
                    <li key={e.id}>
                      <VerdictStamp event={e} />
                      <Link className="rowlink" to="/events" search={{ event: e.id }}>
                        {analyticOf(e).name ?? t("events.unknownAnalytic")}
                      </Link>
                      <time className="mono faint" dateTime={isoTime(e.data.time)}>
                        {at(e.data.time)}
                      </time>
                    </li>
                  ))}
                </ol>
              )
            }
          </PanelBody>
        </Panel>
        <Panel id="ov-types" title={t("overview.byType")} meta={instances.dataUpdatedAt ? t("overview.fetchedAt", { time: at(instances.dataUpdatedAt) }) : undefined}>
          <PanelBody q={instances}>
            {(d) =>
              d.length === 0 ? (
                <EmptyState title={t("overview.byTypeEmpty")}>{null}</EmptyState>
              ) : (
                <table className="data compact">
                  <thead>
                    <tr>
                      <th scope="col">{t("overview.colType")}</th>
                      <th scope="col" className="num">
                        {t("overview.colOnline")}
                      </th>
                      <th scope="col" className="num">
                        {t("overview.colRegistered")}
                      </th>
                      <th scope="col">{t("overview.colHeartbeat")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {groupSessions(d).map((g) => (
                      <tr key={g.agent}>
                        <td className="mono">{g.agent}</td>
                        <td className="num">{g.online}</td>
                        <td className="num">{g.total}</td>
                        <td className="mono sub">{g.lastBeat ? at(g.lastBeat) : <span className="unknown">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            }
          </PanelBody>
        </Panel>
      </div>
    </>
  );
}

interface KpiFigure {
  value: number;
  of?: string;
  scope: string;
}

// One KPI tile: value + denominator + scope + its own fetch time. Errors stay inside the tile (design §5).
function Kpi<T>({ label, q, children }: { label: string; q: UseQueryResult<T>; children: (d: T) => KpiFigure }) {
  const { t, i18n } = useTranslation();
  if (q.data === undefined && !q.isError)
    return (
      <li className="kpi" aria-busy="true">
        <p className="kpi-label">{label}</p>
        <span className="skeleton kpi-skeleton" />
      </li>
    );
  if (q.data === undefined)
    return (
      <li className="kpi is-error">
        <p className="kpi-label">{label}</p>
        <p className="kpi-value unknown">—</p>
        <p className="kpi-scope">
          {isApiStatus(q.error, 403) ? t("overview.tileForbidden") : t("overview.tileError")}{" "}
          {!isApiStatus(q.error, 403) && (
            <button className="link-btn" type="button" onClick={() => void q.refetch()}>
              {t("overview.retry")}
            </button>
          )}
        </p>
      </li>
    );
  const f = children(q.data);
  return (
    <li className="kpi">
      <p className="kpi-label">{label}</p>
      <p className="kpi-value">
        <span>{f.value.toLocaleString(i18n.language)}</span>
        {f.of && <small>{f.of}</small>}
      </p>
      <p className="kpi-scope">{f.scope}</p>
      <p className="kpi-fresh">{t("overview.fetchedAt", { time: formatListTime(q.dataUpdatedAt, i18n.language) })}</p>
    </li>
  );
}

function Panel({ id, title, meta, action, children }: { id: string; title: string; meta?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel" aria-labelledby={id}>
      <div className="panel-head">
        <h3 className="panel-title" id={id}>
          {title}
        </h3>
        {meta && <span className="faint">{meta}</span>}
        {action}
      </div>
      {children}
    </section>
  );
}

function PanelBody<T>({ q, children }: { q: UseQueryResult<T>; children: (d: T) => ReactNode }) {
  const { t } = useTranslation();
  if (q.data === undefined && !q.isError)
    return (
      <p className="panel-pad faint" role="status">
        {t("overview.loading")}
      </p>
    );
  if (q.data === undefined)
    return (
      <p className="panel-pad" role="alert">
        <span className="unknown">{isApiStatus(q.error, 403) ? t("overview.tileForbidden") : t("overview.tileError")}</span>{" "}
        {!isApiStatus(q.error, 403) && (
          <button className="link-btn" type="button" onClick={() => void q.refetch()}>
            {t("overview.retry")}
          </button>
        )}
      </p>
    );
  return <>{children(q.data)}</>;
}

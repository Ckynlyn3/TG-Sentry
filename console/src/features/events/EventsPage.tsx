import { useMemo, useState, type FormEvent } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { Pause, Play } from "lucide-react";
import { useTranslation } from "react-i18next";
import { isApiStatus, listRiskEvents, PAGE_SIZE, type RiskEventQuery } from "../../lib/api";
import { formatListTime, isoTime } from "../../lib/format";
import { CATEGORIES, SEVERITIES, type RiskEvent } from "../../lib/schema";
import { EmptyState, ErrorPanel, ForbiddenPanel } from "../../components/States";
import { AgentCell, CategoryText, SeverityChip, VerdictStamp } from "./parts";
import { EventDrawer } from "./EventDrawer";
import { analyticOf, pageCoverage } from "./model";

const route = getRouteApi("/app/events");
const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;
// Poll interval: policy/bundle polling is 60 s (DECISIONS #7); the design reuses it for the list (§5).
const REFRESH_MS = 60_000;
const col = createColumnHelper<RiskEvent>();

export function EventsPage() {
  const { t, i18n } = useTranslation();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const [live, setLive] = useState(true);
  const filters: RiskEventQuery = { severity: search.severity, category: search.category, agent: search.agent, cursor: search.cursor };
  const filtered = Boolean(search.severity || search.category || search.agent);

  const q = useQuery({
    queryKey: ["risk-events", filters],
    queryFn: () => listRiskEvents(filters),
    placeholderData: keepPreviousData,
    // SC 2.2.2: auto-updating content has a pause control and a visible state (design §5, §11).
    refetchInterval: live ? REFRESH_MS : false,
  });

  // A changed filter drops the cursor: page_token is bound to the filters (#10).
  const setFilter = (patch: Partial<RiskEventQuery>) =>
    void navigate({ search: (s) => ({ ...s, ...patch, cursor: undefined, event: undefined }) });

  const columns = useMemo(
    () => [
      col.accessor((e) => e.data.time, {
        id: "time",
        header: () => t("events.colTime"),
        cell: (c) => <time dateTime={isoTime(c.getValue())}>{formatListTime(c.getValue(), i18n.language)}</time>,
      }),
      col.display({ id: "verdict", header: () => t("events.colVerdict"), cell: (c) => <VerdictStamp event={c.row.original} /> }),
      col.display({ id: "severity", header: () => t("events.colSeverity"), cell: (c) => <SeverityChip event={c.row.original} /> }),
      col.display({
        id: "rule",
        header: () => t("events.colRule"),
        cell: ({ row: { original: e } }) => (
          <div className="two-line">
            {/* Native link (design §13): the row's primary cell opens the drawer and is shareable. */}
            <Link className="rowlink" from="/events" to="/events" search={(s) => ({ ...s, event: e.id })} data-event-link={e.id}>
              {analyticOf(e).name ?? t("events.unknownAnalytic")}
            </Link>
            <small>
              {t(`analytic.${analyticOf(e).kind}`)} · <CategoryText event={e} />
            </small>
          </div>
        ),
      }),
      col.display({ id: "agent", header: () => t("events.colAgent"), cell: (c) => <AgentCell event={c.row.original} /> }),
      col.display({
        id: "user",
        header: () => t("events.colUser"),
        cell: ({ row: { original: e } }) => {
          const user = e.data.actor?.user?.name ?? e.data.actor?.user?.uid;
          const device = e.data.device?.name ?? e.data.device?.uid;
          return (
            <div className="two-line">
              <span className={user ? undefined : "unknown"}>{user ?? t("events.unknownUser")}</span>
              <small className={device ? "mono" : undefined}>{device ?? t("events.unknownDevice")}</small>
            </div>
          );
        },
      }),
      col.accessor((e) => e.data.metadata.correlation_uid, {
        id: "session",
        header: () => t("events.colSession"),
        cell: (c) => <span className="mono">{c.getValue()}</span>,
      }),
    ],
    [t, i18n.language],
  );

  const items = q.data?.items ?? [];
  const table = useReactTable({ data: items, columns, getCoreRowModel: getCoreRowModel(), getRowId: (e) => e.id });
  const next = q.data?.next_page_token || undefined;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("events.title")}</h1>
          <p className="lede">{t("events.lede")}</p>
        </div>
      </div>
      <p className="scope-line">
        <span>
          {t("events.tenant")} <strong>{t("shell.singleTenant")}</strong>
        </span>
        <span className="dot" aria-hidden />
        <span>{t("events.order")}</span>
        <span className="dot" aria-hidden />
        <span>{live ? t("events.live") : t("events.paused")}</span>
        {q.dataUpdatedAt > 0 && (
          <>
            <span className="dot" aria-hidden />
            <span>{t("events.updated", { time: formatListTime(q.dataUpdatedAt, i18n.language) })}</span>
          </>
        )}
      </p>
      <section className="panel" aria-labelledby="ev-h">
        <h2 id="ev-h" className="sr-only">
          {t("events.listHeading")}
        </h2>
        <Filters search={search} onFilter={setFilter} live={live} onLive={() => setLive((v) => !v)} filtered={filtered && items.length > 0} />
        {items.length > 0 && <Coverage items={items} />}
        {isApiStatus(q.error, 403) ? (
          <div className="p-5">
            <ForbiddenPanel title={t("events.forbiddenTitle")} body={t("events.forbiddenBody")} />
          </div>
        ) : q.isError && !q.data ? (
          <div className="p-5">
            <ErrorPanel title={t("events.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : (
          <>
            {q.isError && (
              <div className="px-5 pt-4">
                <ErrorPanel title={t("events.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
              </div>
            )}
            {q.isPending ? (
              <Skeleton label={t("events.loading")} />
            ) : items.length === 0 ? (
              <EmptyState title={filtered ? t("events.filteredTitle") : t("events.emptyTitle")}>
                <p>{filtered ? t("events.filteredBody") : t("events.emptyBody")}</p>
                {filtered && (
                  <Link className="btn btn-secondary mt-5" to="/events" search={{}}>
                    {t("events.clear")}
                  </Link>
                )}
              </EmptyState>
            ) : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label={t("events.scroll")} aria-busy={q.isFetching}>
                <table className="data">
                  <caption className="sr-only">{t("events.caption")}</caption>
                  <thead>
                    {table.getHeaderGroups().map((g) => (
                      <tr key={g.id}>
                        {g.headers.map((h) => (
                          <th key={h.id} scope="col">
                            {flexRender(h.column.columnDef.header, h.getContext())}
                          </th>
                        ))}
                      </tr>
                    ))}
                  </thead>
                  <tbody>
                    {table.getRowModel().rows.map((r) => (
                      <tr key={r.id} className={r.id === search.event ? "is-selected" : undefined}>
                        {r.getVisibleCells().map((c) => (
                          <td key={c.id} className={c.column.id === "time" ? "sub mono" : undefined}>
                            {flexRender(c.column.columnDef.cell, c.getContext())}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {!q.isPending && (items.length > 0 || search.cursor) && (
              <div className="table-foot">
                <span>
                  {t("events.pageCount", { count: items.length })} · {t("events.order")}
                </span>
                <span className="pager">
                  {search.cursor && (
                    <Link className="btn btn-secondary" from="/events" to="/events" search={(s) => ({ ...s, cursor: undefined, event: undefined })}>
                      {t("events.newest")}
                    </Link>
                  )}
                  {next ? (
                    <Link className="btn btn-secondary" from="/events" to="/events" search={(s) => ({ ...s, cursor: next, event: undefined })}>
                      {t("events.older")}
                    </Link>
                  ) : (
                    <span>{t("events.end")}</span>
                  )}
                </span>
              </div>
            )}
          </>
        )}
      </section>
      <EventDrawer
        id={search.event}
        cached={items.find((e) => e.id === search.event)}
        onClose={() => void navigate({ search: (s) => ({ ...s, event: undefined }) })}
      />
    </>
  );
}

// Coverage strip (design §V2.5): missing reported fields are stated once for the page instead of being
// read row by row. Shown only when something is missing.
function Coverage({ items }: { items: RiskEvent[] }) {
  const { t } = useTranslation();
  const c = pageCoverage(items);
  const gaps = [
    [c.verdictUnknown, "events.covVerdict"],
    [c.severityUnknown, "events.covSeverity"],
    [c.agentUnenrolled, "events.covUnenrolled"],
    [c.agentUnknown, "events.covAgentUnknown"],
  ] as const;
  if (gaps.every(([n]) => n === 0)) return null;
  return (
    <div className="coverage" role="note" aria-label={t("events.coverageLabel")}>
      <strong>{t("events.coverage", { count: c.total })}</strong>
      {gaps.map(([n, key]) => (n > 0 ? <span key={key} className="cov-item">{t(key, { count: n })}</span> : null))}
      <span className="cov-hint">{t("events.covHint")}</span>
    </div>
  );
}

interface FiltersProps {
  search: { severity?: string; category?: string; agent?: string };
  onFilter: (patch: Partial<RiskEventQuery>) => void;
  live: boolean;
  onLive: () => void;
  filtered: boolean;
}

function Filters({ search, onFilter, live, onLive, filtered }: FiltersProps) {
  const { t } = useTranslation();
  const severity = SEVERITIES.find((s) => s === search.severity);
  const category = CATEGORIES.find((c) => c === search.category);
  const applyAgent = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const v = new FormData(e.currentTarget).get("agent");
    onFilter({ agent: typeof v === "string" && v.trim() ? v.trim() : undefined });
  };
  return (
    <div className="toolbar" role="search" aria-label={t("events.filters")}>
      <label className="field">
        <span className="label">{t("events.severity")}</span>
        <select className="input" value={severity ?? ""} onChange={(e) => onFilter({ severity: SEVERITIES.find((s) => s === e.target.value) })}>
          <option value="">{t("events.any")}</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {t(`severity.${s}`)}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span className="label">{t("events.category")}</span>
        <select className="input" value={category ?? ""} onChange={(e) => onFilter({ category: CATEGORIES.find((c) => c === e.target.value) })}>
          <option value="">{t("events.any")}</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {t(`categories.${c}`)}
            </option>
          ))}
        </select>
      </label>
      {/* key resets the uncontrolled input when the URL changes (back/forward, clear). */}
      <form className="field" onSubmit={applyAgent} key={search.agent ?? ""}>
        <label className="label" htmlFor="agent-filter">
          {t("events.agent")}
        </label>
        <span className="row">
          <input
            id="agent-filter"
            name="agent"
            className="input mono"
            defaultValue={search.agent ?? ""}
            aria-describedby="agent-hint"
            autoComplete="off"
            spellCheck={false}
          />
          <button className="btn btn-secondary" type="submit">
            {t("events.apply")}
          </button>
        </span>
        <span className="hint" id="agent-hint">
          {t("events.agentHint")}
        </span>
      </form>
      <span className="live-toggle">
        {filtered && (
          <Link className="btn btn-ghost" to="/events" search={{}}>
            {t("events.clear")}
          </Link>
        )}
        <button className="btn btn-ghost" type="button" onClick={onLive}>
          {live ? <Pause {...ICON} /> : <Play {...ICON} />}
          <span>{live ? t("events.pause") : t("events.resume")}</span>
        </button>
      </span>
    </div>
  );
}

// Loading: skeleton rows with the final row height (design §5, no layout shift).
function Skeleton({ label }: { label: string }) {
  return (
    <div className="table-wrap" role="status" aria-label={label}>
      <table className="data" aria-hidden>
        <tbody>
          {Array.from({ length: PAGE_SIZE }, (_, i) => (
            <tr key={i}>
              {Array.from({ length: 7 }, (_, j) => (
                <td key={j}>
                  <span className="skeleton" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

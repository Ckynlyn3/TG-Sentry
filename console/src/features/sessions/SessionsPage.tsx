import { useEffect, useMemo } from "react";
import { getRouteApi, Link } from "@tanstack/react-router";
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { isApiStatus, SESSIONS_PAGE_SIZE } from "../../lib/api";
import { formatListTime } from "../../lib/format";
import type { ClientNode, SessionSummary } from "../../lib/schema";
import { EmptyState, ErrorPanel, ForbiddenPanel } from "../../components/States";
import { SessionFilters, type FilterPatch } from "./SessionFilters";
import { agentLabel, formatRangeTime, isRelative, presetRange } from "./model";
import { useClientNodes, useSessionSummaries } from "./sessionsApi";

const route = getRouteApi("/app/sessions");
const col = createColumnHelper<SessionSummary>();
const COLUMNS = 7;
const CELL_CLASS: Record<string, string | undefined> = { sessionId: "cell-id", sessionTime: "sub mono", lastCallAt: "sub mono" };

// Session audit list (#16 S4; plan §3.4, design §V2.7). Only #16 summary fields are shown; the drawer
// (`open`) is S5.
export function SessionsPage() {
  const { t, i18n } = useTranslation();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const page = search.page ?? 1;
  const size = search.size ?? SESSIONS_PAGE_SIZE;
  const filtered = Boolean(search.preset || search.from || search.to || search.agent || search.nodeId || search.sessionKey);
  // A shared link may name a relative preset without its instants; compute them once, then they are fixed.
  const relative = isRelative(search.preset) ? search.preset : undefined;
  const needsRange = relative !== undefined && !search.from && !search.to;
  useEffect(() => {
    if (needsRange && relative) void navigate({ search: (s) => ({ ...s, ...presetRange(relative) }), replace: true });
  }, [needsRange, relative, navigate]);

  const q = useSessionSummaries(
    { agent: search.agent, nodeId: search.nodeId, sessionKey: search.sessionKey, from: search.from, to: search.to, page, size },
    !needsRange,
  );
  const nodes = useClientNodes();

  // A changed filter starts again at page 1 and closes any open session.
  const setFilter = (patch: FilterPatch) => void navigate({ search: (s) => ({ ...s, ...patch, page: undefined, open: undefined }) });

  const columns = useMemo(() => {
    const revoked = new Set((nodes.data ?? []).filter((n: ClientNode) => n.revoked).map((n) => n.id));
    const time = (iso: string) => <time dateTime={iso}>{formatListTime(Date.parse(iso), i18n.language)}</time>;
    return [
      col.accessor("sessionId", { header: () => t("sessions.colSession"), cell: (c) => <span className="mono">{c.getValue()}</span> }),
      col.accessor("agents", {
        header: () => t("sessions.colAgents"),
        cell: (c) =>
          c.getValue().length === 0 ? (
            <span className="unknown">{t("sessions.unknownAgent")}</span>
          ) : (
            <div className="two-line">{c.getValue().map((a) => <span key={a}>{agentLabel(a)}</span>)}</div>
          ),
      }),
      col.accessor("devices", {
        header: () => t("sessions.colDevices"),
        cell: (c) =>
          c.getValue().length === 0 ? (
            <span className="unknown">{t("sessions.noDevice")}</span>
          ) : (
            <div className="two-line">
              {c.getValue().map((d) => (
                <span key={d.nodeId}>
                  {d.name && <>{d.name} </>}
                  <small className="mono">{d.nodeId}</small>
                  {revoked.has(d.nodeId) && <> <span className="tag">{t("sessions.revoked")}</span></>}
                </span>
              ))}
            </div>
          ),
      }),
      col.display({
        id: "user",
        header: () => t("sessions.colUser"),
        cell: () => (
          <span className="tag" title={t("sessions.unassociatedHint")}>
            {t("sessions.unassociated")}
            <span className="sr-only">，{t("sessions.unassociatedHint")}</span>
          </span>
        ),
      }),
      col.accessor("callCount", {
        header: () => t("sessions.colCalls"),
        cell: (c) => (c.getValue() === 0 ? <span className="faint">{t("sessions.zeroCalls")}</span> : c.getValue()),
      }),
      col.accessor("sessionTime", { header: () => t("sessions.colStart"), cell: (c) => time(c.getValue()) }),
      col.accessor("lastCallAt", {
        header: () => t("sessions.colLast"),
        cell: (c) => {
          const v = c.getValue();
          return v ? time(v) : <span className="unknown">{t("sessions.noCalls")}</span>;
        },
      }),
    ];
  }, [t, i18n.language, nodes.data]);

  const items = q.data?.items ?? [];
  const table = useReactTable({ data: items, columns, getCoreRowModel: getCoreRowModel(), getRowId: (s) => s.sessionId });
  const total = q.data?.total ?? 0;
  const start = (page - 1) * size;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("sessions.title")}</h1>
          <p className="lede">{t("sessions.lede")}</p>
        </div>
      </div>
      <p className="scope-line">
        <span>
          {t("sessions.tenant")} <strong>{t("shell.singleTenant")}</strong>
        </span>
        <span className="dot" aria-hidden />
        <span>{t("sessions.order")}</span>
        <span className="dot" aria-hidden />
        <span>{rangeText(t, i18n.language, search.from, search.to)}</span>
      </p>
      <section className="panel" aria-labelledby="ses-h">
        <h2 id="ses-h" className="sr-only">
          {t("sessions.listHeading")}
        </h2>
        <SessionFilters search={search} onFilter={setFilter} nodes={nodes} filtered={filtered} />
        {isApiStatus(q.error, 403) ? (
          <div className="p-5">
            <ForbiddenPanel title={t("sessions.forbiddenTitle")} body={t("sessions.forbiddenBody")} />
          </div>
        ) : q.isError && !q.data ? (
          <div className="p-5">
            <ErrorPanel title={t("sessions.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : (
          <>
            {q.isError && (
              <div className="px-5 pt-4">
                <ErrorPanel title={t("sessions.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
              </div>
            )}
            {q.isPending ? (
              <Skeleton label={t("sessions.loading")} rows={size} />
            ) : items.length === 0 ? (
              <Empty filtered={filtered} beyondEnd={total > 0} />
            ) : (
              <>
                <div className="table-wrap" tabIndex={0} role="region" aria-label={t("sessions.scroll")} aria-busy={q.isFetching}>
                  <table className="data">
                    <caption className="sr-only">{t("sessions.caption")}</caption>
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
                        <tr key={r.id}>
                          {r.getVisibleCells().map((c) => (
                            <td key={c.id} className={CELL_CLASS[c.column.id]}>
                              {flexRender(c.column.columnDef.cell, c.getContext())}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="table-foot">
                  <span>
                    {t("sessions.pageRange", { start: start + 1, end: start + items.length, total })} · {t("sessions.order")}
                  </span>
                  <span className="pager">
                    {page > 1 && (
                      <Link className="btn btn-secondary" to="/sessions" search={(s) => ({ ...s, page: page - 1 === 1 ? undefined : page - 1, open: undefined })}>
                        {t("sessions.prev")}
                      </Link>
                    )}
                    {start + items.length < total && (
                      <Link className="btn btn-secondary" to="/sessions" search={(s) => ({ ...s, page: page + 1, open: undefined })}>
                        {t("sessions.next")}
                      </Link>
                    )}
                  </span>
                </div>
              </>
            )}
          </>
        )}
      </section>
    </>
  );
}

function rangeText(t: TFunction, lng: string, from?: string, to?: string) {
  if (from && to) return t("sessions.range", { from: formatRangeTime(from, lng), to: formatRangeTime(to, lng) });
  if (from) return t("sessions.rangeFrom", { from: formatRangeTime(from, lng) });
  if (to) return t("sessions.rangeTo", { to: formatRangeTime(to, lng) });
  return t("sessions.rangeAll");
}

function Empty({ filtered, beyondEnd }: { filtered: boolean; beyondEnd: boolean }) {
  const { t } = useTranslation();
  if (beyondEnd)
    return (
      <EmptyState title={t("sessions.pageEmptyTitle")}>
        <p>{t("sessions.pageEmptyBody")}</p>
        <Link className="btn btn-secondary mt-5" to="/sessions" search={(s) => ({ ...s, page: undefined, open: undefined })}>
          {t("sessions.firstPage")}
        </Link>
      </EmptyState>
    );
  return (
    <EmptyState title={filtered ? t("sessions.filteredTitle") : t("sessions.emptyTitle")}>
      <p>{filtered ? t("sessions.filteredBody") : t("sessions.emptyBody")}</p>
      {filtered && (
        <Link className="btn btn-secondary mt-5" to="/sessions" search={{}}>
          {t("sessions.reset")}
        </Link>
      )}
    </EmptyState>
  );
}

// Loading: skeleton rows with the final row height (design §5, no layout shift).
function Skeleton({ label, rows }: { label: string; rows: number }) {
  return (
    <div className="table-wrap" role="status" aria-label={label}>
      <table className="data" aria-hidden>
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i}>
              {Array.from({ length: COLUMNS }, (_, j) => (
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

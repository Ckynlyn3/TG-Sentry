import { Fragment, type FormEvent } from "react";
import { getRouteApi, Link, useParams } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { isApiStatus } from "../../lib/api";
import { formatListTime } from "../../lib/format";
import type { InventorySearch } from "../../router";
import { EmptyState, ErrorPanel, ForbiddenPanel } from "../../components/States";
import { useClientNodes } from "../sessions/sessionsApi";
import { ASSET_PAGE_SIZE, INVENTORY_PAGE_SIZE, useAgentAssets, useDiscoveredAgents } from "./api";
import { AssetDrawer } from "./AssetDrawer";
import { Freshness, Restricted, ScanTime } from "./parts";
import { INVENTORY_CATEGORIES, SCAN_STATES, type AgentAsset, type DiscoveredAgent } from "./schema";

const route = getRouteApi("/app/inventory");
const COLUMNS = 8;
const COLS = ["colAgent", "colAccount", "colHome", "colFound", "colEvidence", "colScanState", "colScan", "colFreshness"] as const;
type Col = (typeof COLS)[number];
// Rows in tbody use th for the device band and the agent; reset the sticky column-head styling there.
const ROW_HEAD = "!static ![background:none] ![color:inherit] ![font-size:inherit]";

// Asset scan ledger (#38/#41 S11, plan §3.10, design §4–5): discovered agents grouped by device, each
// followed by its per-(category, scope) scan state. Every state is a label, never a blank or a zero.
// Narrowed to one agent, its assets are listed under their category and open the asset drawer (S12).
export function InventoryPage() {
  const { t, i18n } = useTranslation();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const q = useDiscoveredAgents(search);
  const assetsQ = useAgentAssets(search);
  const { assetId } = useParams({ strict: false });
  const nodes = useClientNodes();
  const filtered = Boolean(search.node || search.account || search.agent || search.category || search.state);
  // page_token is bound to the filters (internal/core/discovery_list.go discoveryToken).
  const setFilter = (patch: Partial<InventorySearch>) => void navigate({ search: (s) => ({ ...s, ...patch, cursor: undefined }) });

  const items = q.data?.items ?? [];
  const assets = assetsQ.data?.items ?? [];
  const next = q.data?.next_page_token || undefined;
  const names = new Map((nodes.data ?? []).map((n) => [n.id, n.name]));
  // Server order (latest scan first) is kept inside each device; devices appear in first-seen order.
  const groups = new Map<string, DiscoveredAgent[]>();
  for (const a of items) groups.set(a.nodeId, [...(groups.get(a.nodeId) ?? []), a]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("inventory.title")}</h1>
          <p className="lede">{t("inventory.lede")}</p>
        </div>
      </div>
      <p className="scope-line">
        <span>
          {t("inventory.tenant")} <strong>{t("shell.singleTenant")}</strong>
        </span>
        <span className="dot" aria-hidden />
        <span>{t("inventory.order")}</span>
        {q.dataUpdatedAt > 0 && (
          <>
            <span className="dot" aria-hidden />
            <span>{t("inventory.updated", { time: formatListTime(q.dataUpdatedAt, i18n.language) })}</span>
          </>
        )}
      </p>
      <section className="panel" aria-labelledby="inv-h">
        <h2 id="inv-h" className="sr-only">
          {t("inventory.listHeading")}
        </h2>
        <Filters search={search} onFilter={setFilter} filtered={filtered && items.length > 0} />
        {isApiStatus(q.error, 403) ? (
          <div className="p-5">
            <ForbiddenPanel title={t("inventory.forbiddenTitle")} body={t("inventory.forbiddenBody")} />
          </div>
        ) : q.isError && !q.data ? (
          <div className="p-5">
            <ErrorPanel title={t("inventory.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : (
          <>
            {q.isError && (
              <div className="px-5 pt-4">
                <ErrorPanel title={t("inventory.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
              </div>
            )}
            {assetsQ.isError && (
              <div className="px-5 pt-4">
                <ErrorPanel title={t("inventory.drawer.assetsError")} error={assetsQ.error} onRetry={() => void assetsQ.refetch()} />
              </div>
            )}
            {q.isPending ? (
              <Skeleton label={t("inventory.loading")} />
            ) : items.length === 0 ? (
              <EmptyState title={filtered ? t("inventory.filteredTitle") : t("inventory.emptyTitle")}>
                <p>{filtered ? t("inventory.filteredBody") : t("inventory.emptyBody")}</p>
                {filtered && (
                  <Link className="btn btn-secondary mt-5" to="/inventory" search={{}}>
                    {t("inventory.clear")}
                  </Link>
                )}
              </EmptyState>
            ) : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label={t("inventory.scroll")} aria-busy={q.isFetching}>
                <table className="data">
                  <caption className="sr-only">{t("inventory.caption")}</caption>
                  <thead>
                    <tr>
                      {COLS.map((k) => (
                        <th key={k} id={`inv-${k}`} scope="col">
                          {t(`inventory.${k}`)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  {[...groups].map(([nodeId, agents], i) => (
                    <tbody key={nodeId}>
                      <tr>
                        {/* WAI multi-level table pattern: one row group per device. Not sticky like column heads. */}
                        <th scope="rowgroup" id={`inv-dev-${i}`} colSpan={COLUMNS} className="!static">
                          {t("inventory.device")} {names.get(nodeId) && <>{names.get(nodeId)} </>}
                          <small className="mono">{nodeId}</small>
                        </th>
                      </tr>
                      {agents.map((a) => (
                        <AgentRows key={a.id} agent={a} deviceHeader={`inv-dev-${i}`} assets={assets.filter((x) => x.discoveredAgentId === a.id)} />
                      ))}
                    </tbody>
                  ))}
                </table>
              </div>
            )}
            {!q.isPending && (items.length > 0 || search.cursor) && (
              <div className="table-foot">
                <span>
                  {t("inventory.pageCount", { count: items.length })} · {t("inventory.order")}
                  {assetsQ.data?.next_page_token && <> · <span>{t("inventory.drawer.assetsMore", { count: ASSET_PAGE_SIZE })}</span></>}
                </span>
                <span className="pager">
                  {search.cursor && (
                    <Link className="btn btn-secondary" from="/inventory" to="/inventory" search={(s) => ({ ...s, cursor: undefined })}>
                      {t("inventory.first")}
                    </Link>
                  )}
                  {next ? (
                    <Link className="btn btn-secondary" from="/inventory" to="/inventory" search={(s) => ({ ...s, cursor: next })}>
                      {t("inventory.next")}
                    </Link>
                  ) : (
                    <span>{t("inventory.end")}</span>
                  )}
                </span>
              </div>
            )}
          </>
        )}
      </section>
      <AssetDrawer id={assetId} onClose={() => void navigate({ to: "/inventory", search: (s) => s })} />
    </>
  );
}

// Category rows sit under their agent: each cell names its column, agent and device headers (WCAG H43),
// since the agent row header's scope does not reach the rows below it.
function AgentRows({ agent: a, deviceHeader, assets }: { agent: DiscoveredAgent; deviceHeader: string; assets: AgentAsset[] }) {
  const { t } = useTranslation();
  const relPath = a.evidence.relPath;
  const agentHeader = `inv-ag-${a.id}`;
  const headers = (col: Col) => `inv-${col} ${agentHeader} ${deviceHeader}`;
  return (
    <>
      <tr>
        <th scope="row" id={agentHeader} className={ROW_HEAD}>
          <div className="two-line">
            {/* Native link: narrows the ledger to this agent's exact id (the `agent` filter). */}
            <Link className="rowlink" from="/inventory" to="/inventory" search={(s) => ({ ...s, agent: a.id, cursor: undefined })}>
              {a.family}
            </Link>
            <small>{a.version === "unknown" ? t("inventory.versionUnknown") : t("inventory.version", { version: a.version })}</small>
          </div>
        </th>
        <td>
          <div className="two-line">
            {a.observedLocalAccount === undefined ? <Restricted /> : <span>{a.observedLocalAccount}</span>}
            <small className="mono">{a.accountId}</small>
          </div>
        </td>
        <td className="mono">{a.homePath === undefined ? <Restricted /> : a.homePath}</td>
        <td>
          <div className="two-line">
            <span className={a.found === "found" ? undefined : "unknown"}>{t(`inventory.found.${a.found}`)}</span>
            <small>{t(`inventory.agentState.${a.state}`)}</small>
          </div>
        </td>
        <td>
          <div className="two-line">
            <span className="mono">{a.evidence.kind}</span>
            {relPath === undefined ? <Restricted /> : relPath ? <small className="mono">{relPath}</small> : <small>{t("inventory.noEvidencePath")}</small>}
          </div>
        </td>
        <td>
          <span className="faint">{t("inventory.perCategory")}</span>
        </td>
        <td className="sub mono">
          <ScanTime iso={a.scanCompletedAt} />
        </td>
        <td>
          <Freshness value={a.freshness} />
        </td>
      </tr>
      {a.categories.map((c) => (
        <Fragment key={`${c.category}/${c.scope}`}>
        <tr>
          <td className="pl-8" headers={headers("colAgent")}>
            <div className="two-line">
              <span>{t(`inventory.categories.${c.category}`)}</span>
              <small>{t(`inventory.scope.${c.scope}`)}</small>
            </div>
          </td>
          {/* Account, home, found and evidence belong to the agent, not to a category. */}
          <td colSpan={4} />
          <td headers={headers("colScanState")}>
            <div className="two-line">
              <span className={c.scanState === "scanned" ? undefined : "unknown"}>{t(`inventory.scanState.${c.scanState}`)}</span>
              {c.reason && <small>{t(`inventory.reason.${c.reason}`)}</small>}
            </div>
          </td>
          <td className="sub mono" headers={headers("colScan")}>
            <ScanTime iso={c.lastScanCompletedAt} />
          </td>
          <td headers={headers("colFreshness")}>
            <Freshness value={c.freshness} />
          </td>
        </tr>
        {assets
          .filter((x) => x.category === c.category && x.scope === c.scope)
          .map((x) => (
            <tr key={x.assetId}>
              <td className="pl-12" headers={headers("colAgent")}>
                <Link className="rowlink mono" from="/inventory" to="/inventory/$assetId" params={{ assetId: x.assetId }} search={(s) => s} data-asset-link={x.assetId}>
                  {x.name}
                </Link>
              </td>
              <td colSpan={COLUMNS - 1} />
            </tr>
          ))}
        </Fragment>
      ))}
    </>
  );
}

interface FiltersProps {
  search: InventorySearch;
  onFilter: (patch: Partial<InventorySearch>) => void;
  filtered: boolean;
}

function Filters({ search, onFilter, filtered }: FiltersProps) {
  const { t } = useTranslation();
  const applyIds = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const v = (k: string) => {
      const s = f.get(k);
      return typeof s === "string" && s.trim() ? s.trim() : undefined;
    };
    onFilter({ node: v("node"), account: v("account"), agent: v("agent") });
  };
  return (
    <div className="toolbar" role="search" aria-label={t("inventory.filters")}>
      <label className="field">
        <span className="label">{t("inventory.category")}</span>
        <select className="input" value={search.category ?? ""} onChange={(e) => onFilter({ category: INVENTORY_CATEGORIES.find((c) => c === e.target.value) })}>
          <option value="">{t("inventory.any")}</option>
          {INVENTORY_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {t(`inventory.categories.${c}`)}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span className="label">{t("inventory.state")}</span>
        <select className="input" value={search.state ?? ""} onChange={(e) => onFilter({ state: SCAN_STATES.find((s) => s === e.target.value) })}>
          <option value="">{t("inventory.any")}</option>
          {SCAN_STATES.map((s) => (
            <option key={s} value={s}>
              {t(`inventory.scanState.${s}`)}
            </option>
          ))}
        </select>
      </label>
      {/* key resets the uncontrolled inputs when the URL changes (back/forward, clear). */}
      <form className="row" onSubmit={applyIds} key={`${search.node}|${search.account}|${search.agent}`}>
        {(["node", "account", "agent"] as const).map((k) => (
          <label key={k} className="field">
            <span className="label">{t(`inventory.${k}`)}</span>
            <input name={k} className="input mono" defaultValue={search[k] ?? ""} aria-describedby="inv-id-hint" autoComplete="off" spellCheck={false} />
          </label>
        ))}
        <span className="field">
          <button className="btn btn-secondary" type="submit">
            {t("inventory.apply")}
          </button>
          <span className="hint" id="inv-id-hint">
            {t("inventory.idHint")}
          </span>
        </span>
      </form>
      {filtered && (
        <span className="live-toggle">
          <Link className="btn btn-ghost" to="/inventory" search={{}}>
            {t("inventory.clear")}
          </Link>
        </span>
      )}
    </div>
  );
}

// Loading: skeleton rows with the final row height (design §5, no layout shift).
function Skeleton({ label }: { label: string }) {
  return (
    <div className="table-wrap" role="status" aria-label={label}>
      <table className="data" aria-hidden>
        <tbody>
          {Array.from({ length: INVENTORY_PAGE_SIZE }, (_, i) => (
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

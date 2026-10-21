import { useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { Copy, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { ApiError, isApiStatus } from "../../lib/api";
import { announce } from "../../lib/announce";
import { formatFullTime } from "../../lib/format";
import { ErrorPanel, ForbiddenPanel } from "../../components/States";
import { getAgentAsset } from "./api";
import { Freshness, Restricted, ScanTime } from "./parts";
import type { AgentAsset } from "./schema";

const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;

interface Props {
  id: string | undefined;
  onClose: () => void;
}

// Asset detail drawer (#38/#41 S12, plan §3.10). Same modal pattern as EventDrawer (WAI-ARIA APG dialog via
// Radix): focus starts on close, Esc closes, focus returns to the asset link that opened it. Opened from the
// path (/inventory/{id}), so a shared link reproduces the view; GET /api/v1/agent-assets/{id} loads it.
export function AssetDrawer({ id, onClose }: Props) {
  const { t } = useTranslation();
  const closeRef = useRef<HTMLButtonElement>(null);
  // Closing leaves /inventory/{id} before Radix restores focus, so keep the id that was open.
  const openedId = useRef(id);
  if (id) openedId.current = id;
  const q = useQuery({ queryKey: ["agent-asset", id], queryFn: () => getAgentAsset(id ?? ""), enabled: Boolean(id) });
  // TanStack Query keeps the last successful data after a failed refetch. A refusal (404/403) or a contract break
  // is authoritative and replaces it, so a reopened drawer never shows details or paths the server now withholds.
  const refused = isApiStatus(q.error, 404) || isApiStatus(q.error, 403) || (q.error instanceof ApiError && q.error.kind === "contract");
  const a = refused ? undefined : q.data;

  return (
    <Dialog.Root open={Boolean(id)} onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="drawer-overlay" />
        <Dialog.Content
          className="drawer"
          aria-describedby={undefined}
          onOpenAutoFocus={(ev) => {
            ev.preventDefault();
            closeRef.current?.focus();
          }}
          onCloseAutoFocus={(ev) => {
            ev.preventDefault();
            const last = openedId.current;
            const link = last ? document.querySelector<HTMLElement>(`[data-asset-link="${CSS.escape(last)}"]`) : null;
            (link ?? document.getElementById("main"))?.focus();
          }}
        >
          <div className="drawer-head">
            <div className="grow">
              {a && (
                <div className="row mb-2">
                  <span className="tag">{t(`inventory.categories.${a.category}`)}</span>
                  <span className="faint mono">{a.assetId}</span>
                </div>
              )}
              <Dialog.Title asChild>
                <h2>{a ? a.name : t("inventory.drawer.title")}</h2>
              </Dialog.Title>
            </div>
            <Dialog.Close ref={closeRef} className="icon-btn" aria-label={t("inventory.drawer.close")}>
              <X {...ICON} />
            </Dialog.Close>
          </div>
          {/* Focusable so keyboard users can scroll a long body (axe scrollable-region-focusable). */}
          <div className="drawer-body" tabIndex={0} role="region" aria-label={t("inventory.drawer.bodyLabel")}>
            {a ? (
              <Detail asset={a} />
            ) : isApiStatus(q.error, 404) ? (
              <p role="alert">{t("inventory.drawer.notFound")}</p>
            ) : isApiStatus(q.error, 403) ? (
              <ForbiddenPanel title={t("inventory.drawer.forbidden")} body={t("inventory.forbiddenBody")} />
            ) : q.isError ? (
              <ErrorPanel title={t("inventory.drawer.failed")} error={q.error} onRetry={() => void q.refetch()} />
            ) : (
              <p role="status">{t("inventory.drawer.loading")}</p>
            )}
          </div>
          <div className="drawer-foot">
            <button
              className="btn btn-ghost"
              type="button"
              onClick={() =>
                (navigator.clipboard?.writeText(window.location.href) ?? Promise.reject(new Error("no clipboard"))).then(
                  () => announce(t("drawer.copied")),
                  () => announce(t("drawer.copyFailed")),
                )
              }
            >
              <Copy {...ICON} />
              {t("drawer.copyLink")}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Detail({ asset: a }: { asset: AgentAsset }) {
  const { t, i18n } = useTranslation();
  // Absent size/mtime/descriptor were not reported by the endpoint: a state, never a zero.
  const notReported = <span className="unknown">{t("inventory.drawer.notReported")}</span>;
  const keys = (list: string[]) =>
    list.length ? (
      <span className="row">
        {list.map((k) => (
          <span key={k} className="tag mono">
            {k}
          </span>
        ))}
      </span>
    ) : (
      <span className="faint">{t("inventory.drawer.none")}</span>
    );
  return (
    <>
      <section aria-labelledby="ad-asset">
        <h3 className="section-title" id="ad-asset">
          {t("inventory.drawer.asset")}
        </h3>
        <dl className="kv">
          <dt>{t("inventory.drawer.category")}</dt>
          <dd>
            {t(`inventory.categories.${a.category}`)} <span className="faint">{t(`inventory.scope.${a.scope}`)}</span>
          </dd>
          <dt>{t("inventory.drawer.hashKind")}</dt>
          <dd>{t(`inventory.drawer.hashKinds.${a.hashKind}`)}</dd>
          <dt>{t("inventory.drawer.hash")}</dt>
          <dd className="mono break-all">{a.hash}</dd>
          <dt>{t("inventory.drawer.size")}</dt>
          <dd>{a.size === undefined ? notReported : t("inventory.drawer.bytes", { size: a.size.toLocaleString(i18n.language) })}</dd>
          <dt>{t("inventory.drawer.mtime")}</dt>
          <dd>{a.mtime === undefined ? notReported : <time dateTime={a.mtime}>{formatFullTime(Date.parse(a.mtime), i18n.language)}</time>}</dd>
          <dt>{t("inventory.drawer.path")}</dt>
          <dd className="mono break-all">{a.sourceRelPath === undefined ? <Restricted /> : a.sourceRelPath || <span className="faint">{t("inventory.noEvidencePath")}</span>}</dd>
        </dl>
      </section>
      {(a.descriptor || a.category === "mcp") && (
        <section aria-labelledby="ad-mcp">
          <h3 className="section-title" id="ad-mcp">
            {t("inventory.drawer.mcp")}
          </h3>
          <p className="faint">{t("inventory.drawer.mcpNote")}</p>
          {a.descriptor ? (
            <dl className="kv mt-3">
              <dt>{t("inventory.drawer.serverName")}</dt>
              <dd className="mono">{a.descriptor.name}</dd>
              <dt>{t("inventory.drawer.transport")}</dt>
              <dd className="mono">{a.descriptor.transport}</dd>
              <dt>{t("inventory.drawer.envKeys")}</dt>
              <dd>{keys(a.descriptor.envKeys)}</dd>
              <dt>{t("inventory.drawer.headerKeys")}</dt>
              <dd>{keys(a.descriptor.headerKeys)}</dd>
            </dl>
          ) : (
            <p className="mt-3">{notReported}</p>
          )}
        </section>
      )}
      <section aria-labelledby="ad-scan">
        <h3 className="section-title" id="ad-scan">
          {t("inventory.drawer.scan")}
        </h3>
        <dl className="kv">
          <dt>{t("inventory.drawer.scanState")}</dt>
          <dd>
            <span className={a.scanState === "scanned" ? undefined : "unknown"}>{t(`inventory.scanState.${a.scanState}`)}</span>
            {a.reason && <span className="faint"> · {t(`inventory.reason.${a.reason}`)}</span>}
          </dd>
          <dt>{t("inventory.drawer.freshness")}</dt>
          <dd>
            <Freshness value={a.freshness} />
          </dd>
          <dt>{t("inventory.drawer.lastScan")}</dt>
          <dd className="mono">
            <ScanTime iso={a.scanCompletedAt} />
          </dd>
          <dt>{t("inventory.drawer.agent")}</dt>
          <dd>
            {a.family} <span className="faint mono">{a.discoveredAgentId}</span>
          </dd>
          <dt>{t("inventory.drawer.device")}</dt>
          <dd className="mono">{a.nodeId}</dd>
          <dt>{t("inventory.drawer.account")}</dt>
          <dd className="mono">{a.accountId}</dd>
        </dl>
      </section>
    </>
  );
}

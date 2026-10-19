import { useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { Copy, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { getRiskEvent, isApiStatus } from "../../lib/api";
import { announce } from "../../lib/announce";
import { formatFullTime, isoTime } from "../../lib/format";
import type { RiskEvent } from "../../lib/schema";
import { ErrorPanel, ForbiddenPanel } from "../../components/States";
import { AgentCell, CategoryText, SeverityChip, VerdictStamp } from "./parts";
import { analyticOf, verdictOf, type Verdict } from "./model";

const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;

interface Props {
  id: string | undefined;
  cached: RiskEvent | undefined;
  onClose: () => void;
}

// In-place detail drawer (design H1, F4). Modal dialog per WAI-ARIA APG (Radix Dialog): focus starts on
// the close button, Esc closes, focus returns to the row link that opened it. Opened from the URL
// (`?event=`), so a shared link reproduces the view; GET /api/v1/risk-events/{id} covers events that
// are not on the current page.
export function EventDrawer({ id, cached, onClose }: Props) {
  const { t, i18n } = useTranslation();
  const closeRef = useRef<HTMLButtonElement>(null);
  // Closing clears ?event= before Radix restores focus, so keep the id that was open.
  const openedId = useRef(id);
  if (id) openedId.current = id;
  const q = useQuery({
    queryKey: ["risk-event", id],
    queryFn: () => getRiskEvent(id ?? ""),
    enabled: Boolean(id),
    placeholderData: cached,
  });
  const e = q.data;

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
            const link = last ? document.querySelector<HTMLElement>(`[data-event-link="${CSS.escape(last)}"]`) : null;
            (link ?? document.getElementById("main"))?.focus();
          }}
        >
          <div className="drawer-head">
            <div className="grow">
              {e && (
                <div className="row mb-2">
                  <VerdictStamp event={e} />
                  <SeverityChip event={e} />
                  <span className="faint mono">{e.id}</span>
                </div>
              )}
              <Dialog.Title asChild>
                <h2>{e ? (analyticOf(e).name ?? t("events.unknownAnalytic")) : t("drawer.loading")}</h2>
              </Dialog.Title>
              {e && (
                <p className="faint">
                  <time dateTime={isoTime(e.data.time)}>{formatFullTime(e.data.time, i18n.language)}</time>
                </p>
              )}
            </div>
            <Dialog.Close ref={closeRef} className="icon-btn" aria-label={t("drawer.close")}>
              <X {...ICON} />
            </Dialog.Close>
          </div>
          {/* Long payloads scroll this region; it is focusable so keyboard users can scroll it (axe
              scrollable-region-focusable, found on the live demo at 320 px). */}
          <div className="drawer-body" tabIndex={0} role="region" aria-label={t("drawer.bodyLabel")}>
            {e ? (
              <Detail event={e} />
            ) : isApiStatus(q.error, 404) ? (
              <p role="alert">{t("drawer.notFound")}</p>
            ) : isApiStatus(q.error, 403) ? (
              <ForbiddenPanel title={t("drawer.forbidden")} body={t("events.forbiddenBody")} />
            ) : q.isError ? (
              <ErrorPanel title={t("drawer.failed")} error={q.error} onRetry={() => void q.refetch()} />
            ) : (
              <p role="status">{t("drawer.loading")}</p>
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

const RESULT_KEY: Record<Verdict, string> = {
  block: "drawer.resultBlock",
  alert: "drawer.resultAlert",
  log: "drawer.resultLog",
  detected: "drawer.resultDetected",
  unknown: "drawer.resultUnknown",
};

function Detail({ event: e }: { event: RiskEvent }) {
  const { t } = useTranslation();
  const d = e.data;
  const v = verdictOf(e);
  const detector = d.metadata.product.feature?.name;
  const user = d.actor?.user?.name ?? d.actor?.user?.uid;
  const device = d.device?.name ?? d.device?.uid;
  const toolCall = d.unmapped?.tg_sentry?.tool_call_id;
  const missing = <span className="unknown">{t("drawer.notReported")}</span>;
  return (
    <>
      <section aria-labelledby="ed-trace">
        <h3 className="section-title" id="ed-trace">
          {t("drawer.trace")}
        </h3>
        {/* Decision trace strip (design §5): rule → detector → policy → result. The risk-event contract
            carries no policy reference yet, so that step says so instead of guessing. */}
        <ol className="trace">
          <li>
            <small>{t(`analytic.${analyticOf(e).kind}`)}</small>
            <strong>{analyticOf(e).name ?? t("events.unknownAnalytic")}</strong>
            <small>
              <CategoryText event={e} />
            </small>
          </li>
          <li>
            <small>{t("drawer.detector")}</small>
            <strong>{detector ?? missing}</strong>
          </li>
          <li>
            <small>{t("drawer.policy")}</small>
            <strong>{missing}</strong>
          </li>
          <li className={v === "block" ? "res-block" : v === "alert" ? "res-alert" : undefined}>
            <small>{t("drawer.result")}</small>
            <strong>{t(RESULT_KEY[v])}</strong>
            {d.status_detail && <small>{d.status_detail}</small>}
          </li>
        </ol>
      </section>
      <section aria-labelledby="ed-reason">
        <h3 className="section-title" id="ed-reason">
          {t("drawer.reason")}
        </h3>
        <p className={d.message ? undefined : "unknown"}>{d.message ?? t("drawer.noReason")}</p>
        {d.metadata.labels && d.metadata.labels.length > 0 && (
          <p className="row mt-3">
            <span className="faint">{t("drawer.labels")}</span>
            {d.metadata.labels.map((l) => (
              <span key={l} className="tag">
                {l}
              </span>
            ))}
          </p>
        )}
      </section>
      <section aria-labelledby="ed-ctx">
        <h3 className="section-title" id="ed-ctx">
          {t("drawer.context")}
        </h3>
        <dl className="kv">
          <dt>{t("drawer.user")}</dt>
          <dd>{user ?? <span className="unknown">{t("events.unknownUser")}</span>}</dd>
          <dt>{t("drawer.device")}</dt>
          <dd className={device ? "mono" : undefined}>{device ?? <span className="unknown">{t("events.unknownDevice")}</span>}</dd>
          <dt>{t("drawer.agent")}</dt>
          <dd>
            <AgentCell event={e} />
            {d.actor?.app_name && d.actor.app_uid && <span className="faint mono"> {d.actor.app_uid}</span>}
          </dd>
          <dt>{t("drawer.session")}</dt>
          <dd className="mono">{d.metadata.correlation_uid}</dd>
          {toolCall && (
            <>
              <dt>{t("drawer.toolCall")}</dt>
              <dd className="mono">{toolCall}</dd>
            </>
          )}
          <dt>{t("drawer.finding")}</dt>
          <dd className="mono">{d.finding_info.uid}</dd>
          <dt>{t("drawer.eventId")}</dt>
          <dd className="mono">{e.id}</dd>
          <dt>{t("drawer.source")}</dt>
          <dd className="mono">{e.source}</dd>
        </dl>
      </section>
    </>
  );
}

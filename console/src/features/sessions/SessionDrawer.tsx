import { useEffect, useRef, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState, ErrorPanel, ForbiddenPanel } from "../../components/States";
import { ApiError, isApiStatus, listSessionCalls } from "../../lib/api";
import { callsPageSchema, type CallItem, type InputState, type OutputState } from "../../lib/schema";
import { agentLabel } from "./model";

const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;

interface Props {
  sessionKey: string | undefined;
  onClose: () => void;
}

// Radix Dialog anatomy: https://www.radix-ui.com/primitives/docs/components/dialog (Anatomy).
// Focus, Escape and accessible-name behavior: https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/
// (Keyboard Interaction; WAI-ARIA Roles, States, and Properties), matching EventDrawer.
export function SessionDrawer({ sessionKey, onClose }: Props) {
  const { t } = useTranslation();
  const closeRef = useRef<HTMLButtonElement>(null);
  const openedKey = useRef(sessionKey);
  if (sessionKey) openedKey.current = sessionKey;
  const [page, setPage] = useState(1);
  const [previousKey, setPreviousKey] = useState(sessionKey);
  // Reset before fetching a changed session: https://react.dev/reference/react/useState#storing-information-from-previous-renders
  if (previousKey !== sessionKey) {
    setPreviousKey(sessionKey);
    setPage(1);
  }
  const q = useQuery({
    queryKey: ["session-calls", sessionKey, page],
    queryFn: () => listSessionCalls(sessionKey ?? "", page),
    // https://tanstack.com/query/latest/docs/framework/react/guides/paginated-queries (Better Paginated Queries with placeholderData).
    placeholderData: keepPreviousData,
    select: (data) => callsPageSchema.parse(data),
    enabled: Boolean(sessionKey),
  });
  const refused = isApiStatus(q.error, 404) || isApiStatus(q.error, 403) || (q.error instanceof ApiError && q.error.kind === "contract");
  const calls = refused ? undefined : q.data;

  return (
    <Dialog.Root open={Boolean(sessionKey)} onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="drawer-overlay" />
        <Dialog.Content
          className="drawer"
          aria-describedby={undefined}
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            closeRef.current?.focus();
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            const last = openedKey.current;
            const link = last ? document.querySelector<HTMLElement>(`[data-session-link="${CSS.escape(last)}"]`) : null;
            (link ?? document.getElementById("main"))?.focus();
          }}
        >
          <div className="drawer-head">
            <div className="grow">
              <Dialog.Title asChild>
                <h2>{t("sessions.drawer.title")}</h2>
              </Dialog.Title>
              {sessionKey && <p className="faint mono">{sessionKey}</p>}
            </div>
            <Dialog.Close ref={closeRef} className="icon-btn" aria-label={t("sessions.drawer.close")}>
              <X {...ICON} />
            </Dialog.Close>
          </div>
          <div className="drawer-body" tabIndex={0} role="region" aria-label={t("sessions.drawer.bodyLabel")}>
            {calls ? (
              calls.items.length > 0 ? (
                <CallsTable items={calls.items} total={calls.total} page={calls.page} pageSize={calls.pageSize} busy={q.isPlaceholderData} onPageChange={setPage} />
              ) : (
                <EmptyState title={t("sessions.drawer.emptyTitle")}>
                  <p>{t("sessions.drawer.emptyBody")}</p>
                </EmptyState>
              )
            ) : isApiStatus(q.error, 404) ? (
              <p role="alert">{t("sessions.drawer.notFound")}</p>
            ) : isApiStatus(q.error, 403) ? (
              <ForbiddenPanel title={t("sessions.drawer.forbidden")} body={t("sessions.forbiddenBody")} />
            ) : q.isError ? (
              <ErrorPanel title={t("sessions.drawer.failed")} error={q.error} onRetry={() => void q.refetch()} />
            ) : (
              <p role="status">{t("sessions.drawer.loading")}</p>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function CallsTable({ items, total, page, pageSize, busy, onPageChange }: { items: CallItem[]; total: number; page: number; pageSize: number; busy: boolean; onPageChange: (page: number) => void }) {
  const { t } = useTranslation();
  const start = (page - 1) * pageSize;
  const hasPrevious = page > 1;
  const hasNext = start + items.length < total;
  const previousRef = useRef<HTMLButtonElement>(null);
  const nextRef = useRef<HTMLButtonElement>(null);
  const focusedControl = useRef<"previous" | "next" | null>(null);
  // https://www.w3.org/WAI/WCAG22/Understanding/focus-order.html: move focus when a boundary removes its control.
  useEffect(() => {
    if (!hasPrevious && focusedControl.current === "previous") {
      nextRef.current?.focus();
      focusedControl.current = nextRef.current ? "next" : null;
    } else if (!hasNext && focusedControl.current === "next") {
      previousRef.current?.focus();
      focusedControl.current = previousRef.current ? "previous" : null;
    }
  }, [hasPrevious, hasNext]);
  return (
    <>
      <div className="table-wrap" tabIndex={0} role="region" aria-label={t("sessions.drawer.scroll")}>
        <table className="data session-calls" aria-busy={busy}>
          <caption className="sr-only">{t("sessions.drawer.caption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("sessions.drawer.colCall")}</th>
              <th scope="col">{t("sessions.drawer.colInput")}</th>
              <th scope="col">{t("sessions.drawer.colResult")}</th>
              <th scope="col">{t("sessions.drawer.colDecision")}</th>
              <th scope="col">{t("sessions.drawer.colExecution")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((call) => (
              <tr key={call.id}>
                <td>
                  <div className="two-line">
                    <strong>{call.toolName}</strong>
                    <small>
                      {agentLabel(call.agent)} · <span className="mono">{call.callId}</span>
                    </small>
                  </div>
                </td>
                <td><Input call={call} /></td>
                <td><Result call={call} /></td>
                <td>{t(`sessions.decision.${call.decision}`)}</td>
                <td>{t(`sessions.execution.${call.execution}`)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="table-foot">
        <span>{t("sessions.pageRange", { start: start + 1, end: start + items.length, total })}</span>
        <span className="pager">
          {hasPrevious && (
            <button
              ref={previousRef}
              className="btn btn-secondary"
              type="button"
              onFocus={() => { focusedControl.current = "previous"; }}
              onBlur={() => { focusedControl.current = null; }}
              onClick={() => onPageChange(page - 1)}
            >
              {t("sessions.prev")}
            </button>
          )}
          {hasNext && (
            <button
              ref={nextRef}
              className="btn btn-secondary"
              type="button"
              disabled={busy}
              onFocus={() => { focusedControl.current = "next"; }}
              onBlur={() => { focusedControl.current = null; }}
              onClick={() => onPageChange(page + 1)}
            >
              {t("sessions.next")}
            </button>
          )}
        </span>
      </div>
    </>
  );
}

function StateBadge({ state }: { state: InputState | OutputState }) {
  const { t } = useTranslation();
  return <span className="tag">{t(`sessions.contentState.${state}`)}</span>;
}

function Payload({ label, text }: { label: string; text: string }) {
  return (
    <div className="mt-3">
      <small className="faint">{label}</small>
      <pre className="call-payload">{text}</pre>
    </div>
  );
}

function Input({ call }: { call: CallItem }) {
  const { t } = useTranslation();
  const captured = call.inputState === "captured";
  const empty = call.userMessage === undefined && call.context === undefined && call.argumentsObj == null;
  return (
    <>
      <StateBadge state={call.inputState} />
      {captured && call.userMessage !== undefined && <Payload label={t("sessions.drawer.userMessage")} text={call.userMessage} />}
      {captured && call.context !== undefined && <Payload label={t("sessions.drawer.context")} text={call.context} />}
      {captured && call.argumentsObj != null && <Payload label={t("sessions.drawer.arguments")} text={JSON.stringify(call.argumentsObj, null, 2)} />}
      {captured && empty && <p className="faint">{t("sessions.drawer.noInput")}</p>}
      {call.scriptFiles && call.scriptFiles.length > 0 && <ScriptMetadata files={call.scriptFiles} />}
    </>
  );
}

function Result({ call }: { call: CallItem }) {
  const { t } = useTranslation();
  return (
    <>
      <StateBadge state={call.outputState} />
      {call.outputState === "captured" &&
        (call.result === undefined ? <p className="faint">{t("sessions.drawer.noResult")}</p> : <pre className="call-payload">{call.result}</pre>)}
    </>
  );
}

function ScriptMetadata({ files }: { files: NonNullable<CallItem["scriptFiles"]> }) {
  const { t } = useTranslation();
  return (
    <div className="mt-3">
      <small className="faint">{t("sessions.drawer.scriptFiles")}</small>
      {files.map((file, index) => (
        <dl className="kv mt-3" key={`${file.path}-${index}`}>
          <dt>{t("sessions.drawer.path")}</dt>
          <dd className="mono">{file.path}</dd>
          {file.sha256 !== undefined && (
            <>
              <dt>SHA-256</dt>
              <dd className="mono">{file.sha256}</dd>
            </>
          )}
          {file.bytes !== undefined && (
            <>
              <dt>{t("sessions.drawer.bytesLabel")}</dt>
              <dd>{t("sessions.drawer.bytes", { size: file.bytes })}</dd>
            </>
          )}
          <dt>{t("sessions.drawer.completeness")}</dt>
          <dd>{t(file.complete ? "sessions.drawer.complete" : "sessions.drawer.incomplete")}</dd>
          {file.truncated !== undefined && (
            <>
              <dt>{t("sessions.drawer.truncation")}</dt>
              <dd>{t(file.truncated ? "sessions.drawer.truncated" : "sessions.drawer.notTruncated")}</dd>
            </>
          )}
          {file.readError !== undefined && (
            <>
              <dt>{t("sessions.drawer.readError")}</dt>
              <dd>{file.readError}</dd>
            </>
          )}
        </dl>
      ))}
    </div>
  );
}

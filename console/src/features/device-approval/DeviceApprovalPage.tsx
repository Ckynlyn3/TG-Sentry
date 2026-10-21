import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getRouteApi } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { isApiStatus, meQuery } from "../../lib/api";
import { ErrorPanel, ForbiddenPanel } from "../../components/States";
import { confirmDeviceAssociation, decideDeviceGrant, getAssociationPreview, lookupDeviceGrant } from "./api";
import { userCodeSchema, type AssociationPreview, type DeviceGrant, type DeviceGrantDecision } from "./schema";

const route = getRouteApi("/app/device");
const associationRoute = getRouteApi("/device/associate");
type Outcome = "approved" | "denied" | "expired" | "already" | "forbidden" | "changed" | "associated" | "associationInvalid";
type State = { kind: "entry" } | { kind: "review"; grant: DeviceGrant; etag: string } | { kind: "result"; outcome: Outcome } | { kind: "error"; error: unknown };

function OutcomeView({ outcome }: { outcome: Outcome }) {
  const { t } = useTranslation();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, [outcome]);
  return (
    <div role="status" aria-live="polite" aria-label={t("device.status")}>
      <h2 ref={heading} tabIndex={-1}>{t(`device.${outcome}Title`)}</h2>
      {outcome === "forbidden" ? <ForbiddenPanel title={t("device.forbiddenTitle")} body={t("device.forbiddenBody")} /> : <p className="lede">{t(`device.${outcome}Body`)}</p>}
    </div>
  );
}

// RFC 8628 §3.3/§3.3.1: GET and prefill never authorize; compare the displayed code before either decision.
function DeviceReview({ grant, pending, onDecision, onBack }: { grant: DeviceGrant; pending: boolean; onDecision: (decision: DeviceGrantDecision) => void; onBack: () => void }) {
  const { t } = useTranslation();
  const heading = useRef<HTMLHeadingElement>(null);
  const [confirmed, setConfirmed] = useState(false);
  useEffect(() => { heading.current?.focus(); }, []);
  return (
    <section aria-labelledby="device-review" className="space-y-4">
      <h2 id="device-review" ref={heading} tabIndex={-1}>{t("device.reviewTitle")}</h2>
      <dl className="kv">
        <dt>{t("device.code")}</dt><dd className="mono font-medium">{grant.userCode}</dd>
        <dt>{t("device.name")}</dt><dd>{grant.name || t("device.unknown")}</dd>
        <dt>{t("device.platform")}</dt><dd>{grant.platform || t("device.unknown")}</dd>
        <dt>{t("device.source")}</dt><dd className="mono">{grant.source || t("device.unknown")}</dd>
        <dt>{t("device.associationAccount")}</dt><dd>{grant.associatedUser ? <>{grant.associatedUser.name ? `${grant.associatedUser.name} (${grant.associatedUser.subject})` : grant.associatedUser.subject}<br /><span className="mono">{grant.associatedUser.issuer}</span></> : t("device.unassociated")}</dd>
      </dl>
      <p className="faint">{t("device.metadataNote")}</p>
      <p>{t("device.warning")}</p>
      <label className="flex items-start gap-3">
        <input type="checkbox" checked={confirmed} disabled={pending} onChange={(e) => setConfirmed(e.target.checked)} />
        <span>{t("device.confirmCode", { code: grant.userCode })}</span>
      </label>
      <div className="flex flex-wrap gap-3">
        <button className="btn btn-primary" type="button" disabled={!confirmed || pending} onClick={() => confirmed && onDecision("approve")}>{t("device.approve")}</button>
        <button className="btn btn-secondary" type="button" disabled={!confirmed || pending} onClick={() => confirmed && onDecision("deny")}>{t("device.deny")}</button>
        <button className="btn btn-secondary" type="button" disabled={pending} onClick={onBack}>{t("device.otherCode")}</button>
      </div>
    </section>
  );
}

function DeviceApprovalFlow({ initialCode }: { initialCode: string }) {
  const { t } = useTranslation();
  const navigate = route.useNavigate();
  const queryClient = useQueryClient();
  const [code, setCode] = useState(initialCode);
  const [invalid, setInvalid] = useState(false);
  const [state, setState] = useState<State>({ kind: "entry" });
  const input = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const inFlight = useRef(false);
  useEffect(() => {
    if (state.kind === "entry") input.current?.focus();
    if (state.kind === "error") heading.current?.focus();
  }, [state]);

  function onError(error: unknown) {
    if (isApiStatus(error, 401)) {
      queryClient.clear();
      const normalized = userCodeSchema.safeParse(code);
      void navigate({ to: "/login", search: { redirect: `/device?user_code=${encodeURIComponent(normalized.success ? normalized.data : code)}` } });
    } else if (isApiStatus(error, 403)) setState({ kind: "result", outcome: "forbidden" });
    else if (isApiStatus(error, 404)) setState({ kind: "result", outcome: "expired" });
    else if (isApiStatus(error, 409)) setState({ kind: "result", outcome: "already" });
    // #72 U4 412: the reviewed grant changed (for example a late association).
    // Never auto-retry against the stale tag; the operator must review again.
    else if (isApiStatus(error, 412)) setState({ kind: "result", outcome: "changed" });
    else setState({ kind: "error", error });
  }
  const lookup = useMutation({
    mutationFn: lookupDeviceGrant,
    retry: false,
    onSuccess: ({ grant, etag }) => setState(grant.status === "pending" ? { kind: "review", grant, etag } : { kind: "result", outcome: grant.status === "consumed" ? "already" : grant.status }),
    onError,
    onSettled: () => { inFlight.current = false; },
  });
  const decision = useMutation({
    mutationFn: ({ grantId, decision, etag }: { grantId: string; decision: DeviceGrantDecision; etag: string }) => decideDeviceGrant(grantId, decision, etag),
    retry: false,
    onSuccess: (result) => setState({ kind: "result", outcome: result.status }),
    onError,
    onSettled: () => { inFlight.current = false; },
  });
  const pending = lookup.isPending || decision.isPending;
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current || state.kind !== "entry") return;
    const parsed = userCodeSchema.safeParse(code);
    if (!parsed.success) { setInvalid(true); input.current?.focus(); return; }
    inFlight.current = true;
    lookup.mutate(parsed.data);
  }
  function decide(value: DeviceGrantDecision) {
    if (inFlight.current || state.kind !== "review") return;
    inFlight.current = true;
    decision.mutate({ grantId: state.grant.grantId, decision: value, etag: state.etag });
  }

  return (
    <>
      <p className="sr-only" role="status" aria-live="polite">{pending ? t(lookup.isPending ? "device.lookupBusy" : "device.decisionBusy") : ""}</p>
      {state.kind === "entry" && (
        <form onSubmit={submit} noValidate className="space-y-4" aria-busy={pending}>
          <div className="field">
            <label htmlFor="device-code">{t("device.code")}</label>
            <input id="device-code" ref={input} className="input mono" value={code} disabled={pending} required autoComplete="off" autoCapitalize="characters" spellCheck={false}
              aria-invalid={invalid} aria-describedby={invalid ? "device-code-hint device-code-error" : "device-code-hint"}
              onChange={(e) => { setCode(e.target.value); setInvalid(false); }} />
            <span className="hint" id="device-code-hint">{t("device.codeHint")}</span>
            {invalid && <span className="error" id="device-code-error" role="alert">{t("device.invalidCode")}</span>}
          </div>
          <button className="btn btn-primary" type="submit" disabled={pending}>{t(pending ? "device.lookupBusy" : "device.lookup")}</button>
        </form>
      )}
      {state.kind === "review" && <DeviceReview grant={state.grant} pending={pending} onDecision={decide} onBack={() => setState({ kind: "entry" })} />}
      {state.kind === "result" && <>
        <OutcomeView outcome={state.outcome} />
        {state.outcome === "changed" && <button className="btn btn-primary" type="button" disabled={pending} onClick={() => {
          if (inFlight.current) return;
          const parsed = userCodeSchema.safeParse(code);
          if (!parsed.success) { setState({ kind: "entry" }); return; }
          inFlight.current = true;
          lookup.mutate(parsed.data);
        }}>{t("device.freshLookup")}</button>}
      </>}
      {state.kind === "error" && (
        <div className="space-y-4">
          <h2 ref={heading} tabIndex={-1}>{t("device.errorTitle")}</h2>
          <p>{t("device.errorBody")}</p>
          {/* An uncertain write is never replayed. Retry returns to entry for an explicit fresh lookup. */}
          <ErrorPanel title={t("device.errorTitle")} error={state.error} onRetry={() => setState({ kind: "entry" })} />
        </div>
      )}
    </>
  );
}


// #72 S2: public code entry uses native form navigation; only a verified server-owned
// continuation may preview/confirm. The query selects a view, never grants authority.
function AssociationEntry() {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const [invalid, setInvalid] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { input.current?.focus(); }, []);
  return <form method="post" action="/api/v1/device-grants/association/begin" className="space-y-4" noValidate onSubmit={(event) => {
    const parsed = userCodeSchema.safeParse(code);
    if (!parsed.success) { event.preventDefault(); setInvalid(true); input.current?.focus(); return; }
    if (input.current) input.current.value = parsed.data;
  }}>
    {/* Existing RFC 8628 public client ID (internal/server/device_grants.go). */}
    <input type="hidden" name="client_id" value="aegishook" />
    <div className="field">
      <label htmlFor="association-code">{t("device.code")}</label>
      <input id="association-code" name="userCode" className="input mono" ref={input} value={code} required autoComplete="off" autoCapitalize="characters" spellCheck={false}
        aria-invalid={invalid} aria-describedby={invalid ? "association-hint association-error" : "association-hint"} onChange={(event) => { setCode(event.target.value); setInvalid(false); }} />
      <span className="hint" id="association-hint">{t("device.codeHint")}</span>
      {invalid && <span className="error" id="association-error" role="alert">{t("device.invalidCode")}</span>}
    </div>
    <button type="submit" className="btn btn-primary">{t("device.associationBegin")}</button>
  </form>;
}

type AssociationState = { kind: "load" } | { kind: "preview"; preview: AssociationPreview } | { kind: "done" } | { kind: "denied" } | { kind: "error"; error: unknown };
// RFC 8628 §3.2/§3.3: the continuation itself is no longer usable, so the only recovery is a fresh code
// (restart link). 401 joins the server's own refusals: the session behind it expired or is unbound.
const unusable = (error: unknown) => [401, 403, 404, 409].some((status) => isApiStatus(error, status));

function AssociationFlow() {
  const { t } = useTranslation();
  const heading = useRef<HTMLHeadingElement>(null);
  const [state, setState] = useState<AssociationState>({ kind: "load" });
  const inFlight = useRef(false);
  // #72 S2: a 401 here is this page's own outcome, not a console-login trip; lib/queryClient.ts keeps
  // "device-association" out of the global redirect because a roleless employee cannot sign in (no_role).
  const preview = useQuery({ queryKey: ["device-association"], queryFn: getAssociationPreview, retry: false });
  const confirm = useMutation({
    mutationFn: confirmDeviceAssociation,
    retry: false,
    onSuccess: () => setState({ kind: "done" }),
    onError: (error) => setState(unusable(error) ? { kind: "denied" } : { kind: "error", error }),
    onSettled: () => { inFlight.current = false; },
  });
  useEffect(() => {
    if (preview.isSuccess) setState({ kind: "preview", preview: preview.data });
    else if (preview.isError) setState(unusable(preview.error) ? { kind: "denied" } : { kind: "error", error: preview.error });
  }, [preview.isSuccess, preview.isError, preview.data, preview.error]);
  useEffect(() => { if (state.kind !== "load") heading.current?.focus(); }, [state.kind]);

  if (state.kind === "load") return <p className="lede" role="status" aria-live="polite">{t("device.associationLoading")}</p>;
  if (state.kind === "denied") {
    return <><OutcomeView outcome="associationInvalid" /><a className="btn btn-secondary" href="/device/associate">{t("device.associationRestart")}</a></>;
  }
  if (state.kind === "error") {
    return (
      <div className="space-y-4">
        <h2 ref={heading} tabIndex={-1}>{t("device.errorTitle")}</h2>
        <p>{t("device.errorBody")}</p>
        {/* A failed confirmation is never replayed automatically; reload is an explicit fresh continuation. */}
        <ErrorPanel title={t("device.errorTitle")} error={state.error} onRetry={() => window.location.reload()} />
      </div>
    );
  }
  if (state.kind === "done") {
    return <OutcomeView outcome="associated" />;
  }
  const { grant, user } = state.preview;
  return (
    <section aria-labelledby="device-association" className="space-y-4">
      <h2 id="device-association" ref={heading} tabIndex={-1}>{t("device.associationTitle")}</h2>
      <p className="lede">{t("device.associationLede")}</p>
      <dl className="kv">
        <dt>{t("device.associationAccount")}</dt><dd>{user.name ? `${user.name} (${user.subject})` : user.subject}<br /><span className="mono">{user.issuer}</span></dd>
        <dt>{t("device.name")}</dt><dd>{grant.name || t("device.unknown")}</dd>
        <dt>{t("device.platform")}</dt><dd>{grant.platform || t("device.unknown")}</dd>
        <dt>{t("device.code")}</dt><dd className="mono font-medium">{grant.userCode}</dd>
      </dl>
      <p className="faint">{t("device.associationNote")}</p>
      <button className="btn btn-primary" type="button" disabled={confirm.isPending}
        onClick={() => { if (inFlight.current) return; inFlight.current = true; confirm.mutate(state.preview.confirmation); }}>
        {t(confirm.isPending ? "device.associationBusy" : "device.associationConfirm")}
      </button>
    </section>
  );
}

export function DeviceApprovalPage() {
  const { t } = useTranslation();
  const { user_code } = route.useSearch();
  const identity = useQuery(meQuery).data;
  const canApprove = identity?.role === "admin" && identity.kind === "human";
  return (
    <>
      <div className="page-head"><div><h1>{t("device.title")}</h1><p className="lede">{t("device.lede")}</p></div></div>
      <section className="panel panel-pad" aria-label={t("device.title")}>
        {canApprove ? <DeviceApprovalFlow key={user_code ?? ""} initialCode={user_code ?? ""} /> : <OutcomeView outcome="forbidden" />}
      </section>
    </>
  );
}

// #72 S2: standalone page (no console shell, no /me dependency). The server-owned
// continuation decides access; nothing here reads the console identity.
export function DeviceAssociationPage() {
  const { t } = useTranslation();
  const { continuation } = associationRoute.useSearch();
  return (
    <>
      <div className="page-head"><div><h1>{t("device.title")}</h1><p className="lede">{t("device.associationPageLede")}</p></div></div>
      <main id="main" tabIndex={-1}>
        <section className="panel panel-pad" aria-label={t("device.title")}>{continuation === "confirm" ? <AssociationFlow /> : <AssociationEntry />}</section>
      </main>
    </>
  );
}

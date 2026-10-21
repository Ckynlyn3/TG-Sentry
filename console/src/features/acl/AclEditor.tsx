import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { TriangleAlert, X } from "lucide-react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { aclQuery, isApiStatus, publishAcl, reviewAcl } from "../../lib/api";
import { announce } from "../../lib/announce";
import { errorMessage } from "../../lib/errors";
import { aclInputOf, aclSubjectSchema, aclTargetSchema, type AclEffect, type AclInput, type AclRule, type AclSubjectKind, type ClientNode } from "../../lib/schema";

const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;

export type EditorMode = { kind: "create" } | { kind: "edit" | "toggle" | "delete"; rule: AclRule };

interface Draft {
  name: string;
  description: string;
  enabled: boolean;
  subject: AclSubjectKind;
  agentIds: string[];
  tags: string[];
  effect: AclEffect;
  target: "all" | "tools";
  tools: string[];
}

// Lists stay arrays end to end (review F2): stored values with commas or newlines are never re-split, and a row the
// user does not touch is sent back exactly as stored. An empty list shows one blank row to type into.
const rows = (v: string[] | undefined) => (v?.length ? v : [""]);

const draftOf = (r?: AclRule): Draft => ({
  name: r?.name ?? "",
  description: r?.description ?? "",
  enabled: r?.enabled ?? true,
  subject: r?.subject.kind ?? "all",
  agentIds: r?.subject.agentIds ?? [],
  tags: rows(r?.subject.tags),
  effect: r?.effect ?? "allow",
  target: r?.target.kind ?? "all",
  tools: rows(r?.target.tools),
});

// Tool names are exact hook strings (plan LD6; openapi ACLTarget: no trimming or case folding): only blank rows drop.
const toolsOf = (v: string[]) => v.filter((l) => l.trim() !== "");
// Tags may not carry surrounding whitespace (internal/core/protection.go validTagNames), so typed rows are trimmed;
// stored tags already satisfy that, so trimming leaves them unchanged.
const tagsOf = (v: string[]) => v.map((x) => x.trim()).filter(Boolean);

function errorsOf(d: Draft) {
  const e: Partial<Record<"name" | "agents" | "tags" | "tools", string>> = {};
  if (!d.name.trim()) e.name = "acl.nameRequired";
  if (d.subject === "agents" && d.agentIds.length === 0) e.agents = "acl.agentsRequired";
  if (d.subject === "tags" && tagsOf(d.tags).length === 0) e.tags = "acl.tagsRequired";
  if (d.target === "tools" && toolsOf(d.tools).length === 0) e.tools = "acl.toolsRequired";
  return e;
}

const inputOf = (d: Draft): AclInput => ({
  name: d.name,
  description: d.description,
  enabled: d.enabled,
  subject: d.subject === "agents" ? { kind: "agents", agentIds: d.agentIds } : d.subject === "tags" ? { kind: "tags", tags: tagsOf(d.tags) } : { kind: "all" },
  effect: d.effect,
  target: d.target === "tools" ? { kind: "tools", tools: toolsOf(d.tools) } : { kind: "all" },
});

function previewOf(t: TFunction, d: Draft, names: ReadonlyMap<string, string>) {
  const { agents, tags, tools } = errorsOf(d);
  if (agents || tags || tools) return t("acl.previewIncomplete");
  const sep = t("acl.listSep");
  const subject =
    d.subject === "agents"
      ? t("acl.previewAgents", { list: d.agentIds.map((id) => names.get(id) ?? id).join(sep) })
      : d.subject === "tags"
        ? t("acl.previewTags", { list: tagsOf(d.tags).join(sep) })
        : t("acl.previewAll");
  const target = d.target === "tools" ? t("acl.previewTools", { list: toolsOf(d.tools).join(sep) }) : t("acl.previewAllTools");
  return t(d.effect === "deny" ? "acl.previewDeny" : "acl.previewAllow", { subject, target });
}

// Diff fields are RFC 6901 pointers over the server's ACL object (internal/core/protection_review.go protectionObject
// "acl" + protectionDiff): nested paths when both sides are objects, whole /subject and /target on create and delete.
const FIELD: Record<string, string> = {
  "/name": "acl.name",
  "/description": "acl.colDescription",
  "/enabled": "acl.colEnabled",
  "/effect": "acl.effect",
  "/subject": "acl.subject",
  "/subject/kind": "acl.subject",
  "/subject/agentIds": "acl.subjectAgents",
  "/subject/tags": "acl.tagsLabel",
  "/target": "acl.target",
  "/target/kind": "acl.target",
  "/target/tools": "acl.toolsLabel",
};
const fieldLabel = (t: TFunction, field: string) => t(FIELD[field] ?? field, { defaultValue: field });
const KIND: Record<string, string> = { allow: "acl.allow", deny: "acl.deny", all: "acl.subjectAll", agents: "acl.subjectAgents", tags: "acl.subjectTags" };

function valueText(t: TFunction, field: string, v: unknown, names: ReadonlyMap<string, string>): string {
  const sep = t("acl.listSep");
  const agents = (ids: string[]) => ids.map((id) => names.get(id) ?? id).join(sep);
  if (v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0)) return t("acl.none");
  if (typeof v === "boolean") return t(v ? "acl.enabled" : "acl.disabled");
  if (field === "/subject") {
    const s = aclSubjectSchema.safeParse(v);
    if (s.success)
      return s.data.kind === "agents"
        ? t("acl.agentsList", { list: agents(s.data.agentIds ?? []) })
        : s.data.kind === "tags"
          ? t("acl.tagsList", { list: (s.data.tags ?? []).join(sep) })
          : t("acl.subjectAll");
  }
  if (field === "/target") {
    const s = aclTargetSchema.safeParse(v);
    if (s.success) return s.data.kind === "tools" ? t("acl.toolsList", { list: (s.data.tools ?? []).join(sep) }) : t("acl.targetAll");
  }
  if (Array.isArray(v)) return field === "/subject/agentIds" ? agents(v.map(String)) : v.map(String).join(sep);
  if (field === "/target/kind") return t(v === "all" ? "acl.targetAll" : "acl.targetTools");
  const kind = (field === "/effect" || field === "/subject/kind") && KIND[String(v)];
  return kind ? t(kind) : typeof v === "object" ? JSON.stringify(v) : String(v);
}

interface Props {
  mode: EditorMode;
  opener: HTMLElement;
  etag: string | null;
  nodes: UseQueryResult<ClientNode[]>;
  names: ReadonlyMap<string, string>;
  onClose: () => void;
}

// Editor + review→confirm in the console's drawer (Radix Dialog, as EventDrawer: WAI-ARIA APG modal dialog — focus
// moves in, Esc closes, focus returns to the opener). Publication follows design §7 "Publish policy /
// template": review diff, If-Match CAS, no auto-retry on 412, draft kept; permission-expanding changes need the
// explicit confirmDowngrade acknowledgement (plan §3.6).
export function AclEditor({ mode, opener, etag, nodes, names, onClose }: Props) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const rule = mode.kind === "create" ? undefined : mode.rule;
  const [draft, setDraft] = useState(() => draftOf(rule));
  const [step, setStep] = useState<"form" | "review">(mode.kind === "create" || mode.kind === "edit" ? "form" : "review");
  const [showErrors, setShowErrors] = useState(false);
  const [ack, setAck] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  // Set on a published delete: the opener's row is about to go, even if the refetch lands after close (#91).
  const deleted = useRef(false);

  const input: AclInput = mode.kind === "delete" ? { delete: true } : mode.kind === "toggle" ? { ...aclInputOf(mode.rule), enabled: !mode.rule.enabled } : inputOf(draft);
  const review = useMutation({ mutationFn: (tag: string | null) => reviewAcl(input, tag ?? "", rule?.id) });
  const publish = useMutation({
    mutationFn: () => {
      const r = review.data;
      if (!r) throw new Error("no review");
      return publishAcl({ id: rule?.id, delete: mode.kind === "delete" }, { reviewId: r.data.id, confirmDowngrade: ack }, r.etag ?? "");
    },
    onSuccess: (r) => {
      announce(t("acl.published", { revision: r.data.revision }));
      deleted.current = mode.kind === "delete";
      void qc.invalidateQueries({ queryKey: aclQuery.queryKey });
      onClose();
    },
  });

  // Toggle and delete open straight on the review; the ref keeps a dev StrictMode re-run from reviewing twice.
  const started = useRef(false);
  useEffect(() => {
    if (step === "review" && !started.current && !review.data) {
      started.current = true;
      review.mutate(etag);
    }
  }, [step, etag, review]);
  useEffect(() => (step === "form" ? nameRef : cancelRef).current?.focus(), [step]);

  const errors = showErrors ? errorsOf(draft) : {};
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (Object.keys(errorsOf(draft)).length) return setShowErrors(true);
    setAck(false);
    publish.reset();
    review.reset();
    started.current = true;
    setStep("review");
    review.mutate(etag);
  };
  // After 412/428/409 nothing is retried silently: fetch the current revision, then review the same draft again.
  const reReview = async () => {
    setAck(false);
    publish.reset();
    const fresh = await qc.fetchQuery({ ...aclQuery, staleTime: 0 }).catch(() => undefined);
    review.mutate(fresh?.etag ?? etag);
  };

  const r = review.data?.data;
  const failure = publish.error ?? review.error;
  const stale = isApiStatus(failure, 412) || isApiStatus(failure, 428);
  const retryable = stale || isApiStatus(failure, 409);
  const ruleName = rule?.name ?? draft.name;
  const title =
    step === "form"
      ? mode.kind === "create"
        ? t("acl.newTitle")
        : t("acl.editRule", { name: ruleName })
      : t(mode.kind === "delete" ? "acl.deleteTitle" : "acl.reviewTitle", { name: mode.kind === "edit" || mode.kind === "create" ? draft.name : ruleName });

  return (
    <Dialog.Root open onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="drawer-overlay" />
        <Dialog.Content className="drawer" aria-describedby={undefined} onOpenAutoFocus={(e) => {
            // Radix Portal mounts the content after this component's first effect, so first focus lands here.
            e.preventDefault();
            (step === "form" ? nameRef : cancelRef).current?.focus();
          }}
          onCloseAutoFocus={(e) => {
            e.preventDefault();
            // Opened programmatically (no Dialog.Trigger), so the page passes the clicked opener. A deleted row's opener is
            // gone or about to be, so focus the page's main landmark instead (APG modal dialog: invoking element no longer exists).
            (opener.isConnected && !deleted.current ? opener : document.getElementById("main"))?.focus();
          }}
        >
          <div className="drawer-head">
            <div className="grow">
              <Dialog.Title asChild>
                <h2>{title}</h2>
              </Dialog.Title>
              {step === "review" && r && <p className="faint">{t("acl.reviewBase", { revision: r.baseRevision })}</p>}
            </div>
            <Dialog.Close className="icon-btn" aria-label={t("acl.close")}>
              <X {...ICON} />
            </Dialog.Close>
          </div>
          {step === "form" ? (
            <form className="contents" onSubmit={submit} noValidate>
              <div className="drawer-body" tabIndex={0} role="region" aria-label={t("acl.basic")}>
                <Field id="acl-name" label={t("acl.name")} error={errors.name && t(errors.name)}>
                  {(p) => <input ref={nameRef} className="input" value={draft.name} onChange={(e) => set({ name: e.target.value })} {...p} />}
                </Field>
                <Field id="acl-desc" label={t("acl.description")}>
                  {(p) => <input className="input" value={draft.description} onChange={(e) => set({ description: e.target.value })} {...p} />}
                </Field>
                <Choice legend={t("acl.subject")} name="subject" value={draft.subject} onChange={(v) => set({ subject: v })} options={[["all", t("acl.subjectAll")], ["agents", t("acl.subjectAgents")], ["tags", t("acl.subjectTags")]]} />
                {draft.subject === "agents" && <AgentPicker nodes={nodes} selected={draft.agentIds} onChange={(agentIds) => set({ agentIds })} error={errors.agents && t(errors.agents)} />}
                {draft.subject === "tags" && (
                  <ListField id="acl-tags" label={t("acl.tagsLabel")} add={t("acl.addTag")} hint={t("acl.tagsHint")} error={errors.tags && t(errors.tags)} values={draft.tags} onChange={(tags) => set({ tags })} />
                )}
                <Choice legend={t("acl.effect")} name="effect" value={draft.effect} onChange={(v) => set({ effect: v })} options={[["allow", t("acl.allow")], ["deny", t("acl.deny")]]} />
                <Choice legend={t("acl.target")} name="target" value={draft.target} onChange={(v) => set({ target: v })} options={[["all", t("acl.targetAll")], ["tools", t("acl.targetTools")]]} />
                {draft.target === "tools" && (
                  <ListField id="acl-tools" mono label={t("acl.toolsLabel")} add={t("acl.addTool")} hint={t("acl.toolsHint")} error={errors.tools && t(errors.tools)} values={draft.tools} onChange={(tools) => set({ tools })} />
                )}
                <label className="field-inline">
                  <input type="checkbox" checked={draft.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
                  <span>{t("acl.enabledLabel")}</span>
                </label>
                <section aria-labelledby="acl-preview">
                  <h3 className="section-title" id="acl-preview">
                    {t("acl.preview")}
                  </h3>
                  <p>{previewOf(t, draft, names)}</p>
                  {!draft.enabled && <p className="faint">{t("acl.previewOff")}</p>}
                </section>
              </div>
              <div className="drawer-foot">
                <Dialog.Close className="btn btn-ghost" type="button">
                  {t("acl.cancel")}
                </Dialog.Close>
                <button className="btn btn-primary" type="submit">
                  {t("acl.review")}
                </button>
              </div>
            </form>
          ) : (
            <>
              <div className="drawer-body" tabIndex={0} role="region" aria-label={t("acl.diffCaption")}>
                {mode.kind === "delete" && (
                  <div className="banner banner-warn">
                    <TriangleAlert {...ICON} />
                    <p className="grow">{t("acl.deleteNotice")}</p>
                  </div>
                )}
                {review.isPending && <p role="status">{t("acl.reviewing")}</p>}
                {r && r.downgrades.length > 0 && (
                  <div className="banner banner-warn">
                    <TriangleAlert {...ICON} />
                    <div className="grow">
                      <p className="font-medium">{t("acl.downgradeTitle")}</p>
                      <p>{t("acl.downgradeBody")}</p>
                      <ul className="mono">
                        {r.downgrades.map((d) => (
                          <li key={d}>{d}</li>
                        ))}
                      </ul>
                      <label className="field-inline mt-3">
                        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                        <span>{t("acl.downgradeAck")}</span>
                      </label>
                    </div>
                  </div>
                )}
                {r && (
                  <table className="data compact">
                    <caption className="sr-only">{t("acl.diffCaption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("acl.colField")}</th>
                        <th scope="col">{t("acl.colBefore")}</th>
                        <th scope="col">{t("acl.colAfter")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {r.diff.map((d) => (
                        <tr key={d.field}>
                          <th scope="row">{fieldLabel(t, d.field)}</th>
                          <td>{valueText(t, d.field, d.before, names)}</td>
                          <td>{valueText(t, d.field, d.after, names)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {r && <p className="faint">{t("acl.publishNote")}</p>}
                {failure && (
                  <div className="banner banner-error" role="alert">
                    <div className="grow">
                      <p className="font-medium">{t(publish.error ? "acl.publishFailed" : "acl.reviewFailed")}</p>
                      <p>{stale ? t("acl.stale") : errorMessage(t, failure)}</p>
                    </div>
                    {retryable && (
                      <button className="btn btn-secondary" type="button" onClick={() => void reReview()}>
                        {t("acl.reReview")}
                      </button>
                    )}
                  </div>
                )}
              </div>
              <div className="drawer-foot">
                {(mode.kind === "create" || mode.kind === "edit") && (
                  <button className="btn btn-ghost" type="button" onClick={() => setStep("form")}>
                    {t("acl.back")}
                  </button>
                )}
                <Dialog.Close ref={cancelRef} className="btn btn-ghost" type="button">
                  {t("acl.cancel")}
                </Dialog.Close>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={!r || review.isPending || publish.isPending || (r.downgrades.length > 0 && !ack)}
                  onClick={() => publish.mutate()}
                >
                  {publish.isPending ? t("acl.publishing") : t(mode.kind === "delete" ? "acl.delete" : "acl.publish")}
                </button>
              </div>
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

type FieldProps = { id: string; "aria-invalid"?: true; "aria-describedby"?: string };

function Field({ id, label, hint, error, children }: { id: string; label: string; hint?: string; error?: string; children: (p: FieldProps) => JSX.Element }) {
  const described = [hint && `${id}-hint`, error && `${id}-err`].filter(Boolean).join(" ") || undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, "aria-describedby": described, ...(error ? { "aria-invalid": true } : {}) })}
      {hint && (
        <span className="hint" id={`${id}-hint`}>
          {hint}
        </span>
      )}
      {error && (
        <span className="error" id={`${id}-err`}>
          {error}
        </span>
      )}
    </div>
  );
}

function Choice<V extends string>({ legend, name, value, onChange, options }: { legend: string; name: string; value: V; onChange: (v: V) => void; options: [V, string][] }) {
  return (
    <fieldset className="field">
      <legend className="label">{legend}</legend>
      <div className="row">
        {options.map(([v, label]) => (
          <label key={v} className="field-inline">
            <input type="radio" name={name} value={v} checked={value === v} onChange={() => onChange(v)} />
            <span>{label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

// Agents are enrolled, non-revoked nodes (openapi ACLSubject: revoked IDs are rejected server-side).
function AgentPicker({ nodes, selected, onChange, error }: { nodes: UseQueryResult<ClientNode[]>; selected: string[]; onChange: (ids: string[]) => void; error?: string }) {
  const { t } = useTranslation();
  const live = (nodes.data ?? []).filter((n) => !n.revoked);
  const toggle = (id: string, on: boolean) => onChange(on ? [...selected, id] : selected.filter((x) => x !== id));
  // Already-selected IDs that are revoked or unknown are shown with a remove control (the server rejects them,
  // review F3) and are never offered as a new choice.
  const unavailable = nodes.data ? selected.filter((id) => !live.some((n) => n.id === id)) : [];
  const nameOf = (id: string) => nodes.data?.find((n) => n.id === id)?.name ?? id;
  return (
    <fieldset className="field" aria-describedby={error ? "acl-agents-hint acl-agents-err" : "acl-agents-hint"}>
      <legend className="label">{t("acl.agentsPick")}</legend>
      {nodes.isError ? (
        <p className="hint">{t("acl.agentsFailed")}</p>
      ) : live.length === 0 && !nodes.isPending ? (
        <p className="hint">{t("acl.agentsNone")}</p>
      ) : (
        live.map((n) => (
          <label key={n.id} className="field-inline">
            <input type="checkbox" checked={selected.includes(n.id)} onChange={(e) => toggle(n.id, e.target.checked)} />
            <span>{n.name}</span>
            <small className="mono faint">{n.id}</small>
          </label>
        ))
      )}
      {unavailable.map((id) => (
        <p key={id} className="field-inline">
          <span>{nameOf(id)}</span>
          <small className="mono faint">{id}</small>
          <span className="tag">{t("acl.agentUnavailable")}</span>
          <button className="link-btn" type="button" aria-label={t("acl.removeAgent", { name: nameOf(id) })} onClick={() => toggle(id, false)}>
            {t("acl.remove")}
          </button>
        </p>
      ))}
      <span className="hint" id="acl-agents-hint">
        {t("acl.agentsHint")}
      </span>
      {error && (
        <span className="error" id="acl-agents-err">
          {error}
        </span>
      )}
    </fieldset>
  );
}

interface ListFieldProps {
  id: string;
  label: string;
  add: string;
  hint: string;
  error?: string;
  values: string[];
  onChange: (values: string[]) => void;
  mono?: boolean;
}

// One input row per value (review F2): a value is never split on a delimiter, so commas or other separators inside a
// tag or tool name stay part of that value.
function ListField({ id, label, add, hint, error, values, onChange, mono }: ListFieldProps) {
  const { t } = useTranslation();
  const described = [`${id}-hint`, error && `${id}-err`].filter(Boolean).join(" ");
  return (
    <fieldset className="field" aria-describedby={described}>
      <legend className="label">{label}</legend>
      {values.map((v, i) => {
        const item = `${label} ${i + 1}`;
        return (
          <div key={i} className="field-inline">
            <input
              className={mono ? "input mono grow" : "input grow"}
              aria-label={item}
              aria-invalid={error ? true : undefined}
              spellCheck={false}
              value={v}
              onChange={(e) => onChange(values.map((x, j) => (j === i ? e.target.value : x)))}
            />
            {values.length > 1 && (
              <button className="link-btn" type="button" aria-label={t("acl.removeItem", { item })} onClick={() => onChange(values.filter((_, j) => j !== i))}>
                {t("acl.remove")}
              </button>
            )}
          </div>
        );
      })}
      <button className="btn btn-secondary" type="button" onClick={() => onChange([...values, ""])}>
        {add}
      </button>
      <span className="hint" id={`${id}-hint`}>
        {hint}
      </span>
      {error && (
        <span className="error" id={`${id}-err`}>
          {error}
        </span>
      )}
    </fieldset>
  );
}

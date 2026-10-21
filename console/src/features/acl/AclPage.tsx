import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { Info, Plus } from "lucide-react";
import { useTranslation } from "react-i18next";
import { aclQuery, isApiStatus, listClientNodes, meQuery } from "../../lib/api";
import { ACL_EFFECTS, ACL_SUBJECTS, type AclRule } from "../../lib/schema";
import { EmptyState, ErrorPanel, ForbiddenPanel } from "../../components/States";
import { AclEditor, type EditorMode } from "./AclEditor";
import { AclRow, type RowAction } from "./AclRow";

const route = getRouteApi("/app/acl");
const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;
const SUBJECT_LABEL = { all: "acl.subjectAll", agents: "acl.subjectAgents", tags: "acl.subjectTags" } as const;

// Tool access control (#44 plan §3.9; design "Tool ACL console"). Filters live in the URL. Mutate controls are shown
// only to admins: server RBAC gives GET to readonly, /review to auditor and publication to admin
// (internal/server/rbac.go), so an auditor could review but never publish — the page offers neither.
export function AclPage() {
  const { t } = useTranslation();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const canEdit = useQuery(meQuery).data?.role === "admin";
  const q = useQuery(aclQuery);
  const nodes = useQuery({ queryKey: ["client-nodes"], queryFn: listClientNodes });
  // The opener comes from the click: WebKit/Safari does not focus a button on mouse click (#90), so activeElement
  // cannot identify it, and the APG modal dialog pattern returns focus to the invoking element on close.
  const [editor, setEditor] = useState<{ mode: EditorMode; opener: HTMLElement } | null>(null);
  const [text, setText] = useState(search.q ?? "");

  const names = useMemo(() => new Map((nodes.data ?? []).map((n) => [n.id, n.name])), [nodes.data]);
  const page = q.data?.data;
  const needle = search.q?.toLowerCase();
  const rows = (page?.items ?? []).filter(
    (r) =>
      (!needle || r.name.toLowerCase().includes(needle) || r.id.toLowerCase().includes(needle)) &&
      (!search.subject || r.subject.kind === search.subject) &&
      (!search.effect || r.effect === search.effect),
  );
  const onAction = (action: RowAction, rule: AclRule, opener: HTMLElement) => setEditor({ mode: { kind: action, rule }, opener });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("acl.title")}</h1>
          <p className="lede">{t("acl.lede")}</p>
        </div>
        {canEdit && (
          <button className="btn btn-primary" type="button" onClick={(e) => setEditor({ mode: { kind: "create" }, opener: e.currentTarget })}>
            <Plus {...ICON} />
            {t("acl.create")}
          </button>
        )}
      </div>
      <p className="scope-line">
        <span>
          {t("acl.tenant")} <strong>{t("shell.singleTenant")}</strong>
        </span>
        {page && (
          <>
            <span className="dot" aria-hidden />
            <span className="mono">{t("acl.revision", { revision: page.revision })}</span>
          </>
        )}
        <span className="dot" aria-hidden />
        <span>{t("acl.order")}</span>
      </p>
      <section className="panel" aria-labelledby="acl-h">
        <h2 id="acl-h" className="sr-only">
          {t("acl.caption")}
        </h2>
        <div className="toolbar" role="search" aria-label={t("acl.filters")}>
          <label className="field">
            <span className="label">{t("acl.filterName")}</span>
            <input
              className="input"
              type="search"
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                void navigate({ search: (s) => ({ ...s, q: e.target.value.trim() || undefined }), replace: true });
              }}
            />
          </label>
          <label className="field">
            <span className="label">{t("acl.filterSubject")}</span>
            <select className="input" value={search.subject ?? ""} onChange={(e) => void navigate({ search: (s) => ({ ...s, subject: ACL_SUBJECTS.find((k) => k === e.target.value) }) })}>
              <option value="">{t("acl.any")}</option>
              {ACL_SUBJECTS.map((k) => (
                <option key={k} value={k}>
                  {t(SUBJECT_LABEL[k])}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="label">{t("acl.filterEffect")}</span>
            <select className="input" value={search.effect ?? ""} onChange={(e) => void navigate({ search: (s) => ({ ...s, effect: ACL_EFFECTS.find((k) => k === e.target.value) }) })}>
              <option value="">{t("acl.any")}</option>
              {ACL_EFFECTS.map((k) => (
                <option key={k} value={k}>
                  {t(`acl.${k}`)}
                </option>
              ))}
            </select>
          </label>
        </div>
        {isApiStatus(q.error, 403) ? (
          <div className="p-5">
            <ForbiddenPanel title={t("acl.forbiddenTitle")} body={t("acl.forbiddenBody")} />
          </div>
        ) : q.isError && !page ? (
          <div className="p-5">
            <ErrorPanel title={t("acl.errorTitle")} error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : !page ? (
          <p className="panel-pad faint" role="status">
            {t("acl.loading")}
          </p>
        ) : (
          <>
            {page.virtualDefault && (
              <div className="px-5 pt-4">
                <div className="banner banner-info">
                  <Info {...ICON} />
                  <div className="grow">
                    <p className="font-medium">{t("acl.virtualTitle")}</p>
                    <p>{t("acl.virtualBody")}</p>
                  </div>
                </div>
              </div>
            )}
            {page.items.length === 0 ? (
              <EmptyState title={t("acl.emptyTitle")}>
                <p>{t("acl.emptyBody")}</p>
              </EmptyState>
            ) : rows.length === 0 ? (
              <EmptyState title={t("acl.filteredTitle")}>
                <p>{t("acl.filteredBody")}</p>
                <Link className="btn btn-secondary mt-5" to="/acl" search={{}} onClick={() => setText("")}>
                  {t("acl.reset")}
                </Link>
              </EmptyState>
            ) : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label={t("acl.scroll")} aria-busy={q.isFetching}>
                <table className="data">
                  <caption className="sr-only">{t("acl.caption")}</caption>
                  <thead>
                    <tr>
                      {(["colName", "colDescription", "colSubject", "colTarget", "colEffect", "colUpdated", "colEnabled"] as const).map((k) => (
                        <th key={k} scope="col">
                          {t(`acl.${k}`)}
                        </th>
                      ))}
                      {canEdit && <th scope="col">{t("acl.colActions")}</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <AclRow key={r.id} rule={r} names={names} canEdit={canEdit} onAction={onAction} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {page.total > page.items.length && (
              <p className="table-foot">{t("acl.more", { shown: page.items.length, total: page.total })}</p>
            )}
          </>
        )}
      </section>
      {editor && <AclEditor mode={editor.mode} opener={editor.opener} etag={q.data?.etag ?? null} nodes={nodes} names={names} onClose={() => setEditor(null)} />}
    </>
  );
}

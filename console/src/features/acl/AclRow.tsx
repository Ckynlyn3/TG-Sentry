import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { formatListTime } from "../../lib/format";
import type { AclRule } from "../../lib/schema";

export type RowAction = "edit" | "toggle" | "delete";

// Agent IDs are enrolled node IDs (internal/core/types.go ACLSubject); show the device name when known.
function subjectText(t: TFunction, rule: AclRule, names: ReadonlyMap<string, string>): string {
  const sep = t("acl.listSep");
  if (rule.subject.kind === "agents") return t("acl.agentsList", { list: (rule.subject.agentIds ?? []).map((id) => names.get(id) ?? id).join(sep) });
  if (rule.subject.kind === "tags") return t("acl.tagsList", { list: (rule.subject.tags ?? []).join(sep) });
  return t("acl.subjectAll");
}

// The virtual default (never published) carries Go's zero time (internal/core/protection.go EffectiveACLRules).
const neverPublished = (iso: string) => Date.parse(iso) < 0;

interface Props {
  rule: AclRule;
  names: ReadonlyMap<string, string>;
  canEdit: boolean;
  onAction: (action: RowAction, rule: AclRule, opener: HTMLElement) => void;
}

export function AclRow({ rule, names, canEdit, onAction }: Props) {
  const { t, i18n } = useTranslation();
  const tools = rule.target.tools ?? [];
  return (
    <tr>
      <td>
        <div className="two-line">
          <span>{rule.name}</span>
          <small className="mono">{rule.id}</small>
        </div>
      </td>
      <td className="sub">{rule.description || <span className="faint">{t("acl.none")}</span>}</td>
      <td>{subjectText(t, rule, names)}</td>
      <td className={rule.target.kind === "tools" ? "mono" : undefined}>{rule.target.kind === "tools" ? tools.join(t("acl.listSep")) : t("acl.targetAll")}</td>
      <td>
        <span className="tag">{t(rule.effect === "deny" ? "acl.deny" : "acl.allow")}</span>
      </td>
      <td className="sub mono">
        {neverPublished(rule.updatedAt) ? (
          <span className="faint">{t("acl.neverPublished")}</span>
        ) : (
          <time dateTime={rule.updatedAt}>{formatListTime(Date.parse(rule.updatedAt), i18n.language)}</time>
        )}
      </td>
      <td>{rule.enabled ? t("acl.enabled") : <span className="faint">{t("acl.disabled")}</span>}</td>
      {canEdit && (
        <td>
          <span className="row">
            <button className="link-btn" type="button" aria-label={t("acl.editRule", { name: rule.name })} onClick={(e) => onAction("edit", rule, e.currentTarget)}>
              {t("acl.edit")}
            </button>
            <button
              className="link-btn"
              type="button"
              aria-label={t(rule.enabled ? "acl.disableRule" : "acl.enableRule", { name: rule.name })}
              onClick={(e) => onAction("toggle", rule, e.currentTarget)}
            >
              {t(rule.enabled ? "acl.disable" : "acl.enable")}
            </button>
            <button className="link-btn" type="button" aria-label={t("acl.deleteRule", { name: rule.name })} onClick={(e) => onAction("delete", rule, e.currentTarget)}>
              {t("acl.delete")}
            </button>
          </span>
        </td>
      )}
    </tr>
  );
}

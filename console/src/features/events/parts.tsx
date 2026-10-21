import { Ban, CircleHelp, Eye, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { CATEGORIES, type RiskEvent } from "../../lib/schema";
import { agentOf, pipsOf, severityOf, verdictOf, type Verdict } from "./model";

const STAMP = { size: 12, strokeWidth: 1.75, "aria-hidden": true, focusable: false } as const;

// Verdict = colour + icon + text (design H3, WCAG 1.4.1). Only a confirmed block gets the solid stamp.
// v2 (§V2.5): only block and alert are framed; the other outcomes are quiet icon + text.
const STAMP_CLASS: Record<Verdict, string> = { block: "stamp-block", alert: "stamp-alert", log: "stamp-quiet", detected: "stamp-quiet", unknown: "stamp-quiet" };

export function VerdictStamp({ event }: { event: RiskEvent }) {
  const { t } = useTranslation();
  const v = verdictOf(event);
  const Icon = v === "block" ? Ban : v === "alert" ? TriangleAlert : v === "unknown" ? CircleHelp : Eye;
  return (
    <span className={`stamp ${STAMP_CLASS[v]}`}>
      <Icon {...STAMP} />
      {t(`verdict.${v}`)}
    </span>
  );
}

// Severity = 4-pip glyph + text (design H3).
export function SeverityChip({ event }: { event: RiskEvent }) {
  const { t } = useTranslation();
  const s = severityOf(event);
  const on = pipsOf(s);
  return (
    <span className={`sev${s === "unknown" ? " unknown" : ""}`}>
      <span className="sev-pips" aria-hidden>
        {[0, 1, 2, 3].map((i) => (
          <span key={i} className={i < on ? "on" : undefined} />
        ))}
      </span>
      {t(`severity.${s}`)}
    </span>
  );
}

// finding_info.types carries the protection categories; known ids get their label, others show raw.
export function CategoryText({ event }: { event: RiskEvent }) {
  const { t } = useTranslation();
  const types = event.data.finding_info.types ?? [];
  if (types.length === 0) return <>{t("events.noCategory")}</>;
  return <>{types.map((c) => (CATEGORIES.some((k) => k === c) ? t(`categories.${c}`) : c)).join(" · ")}</>;
}

export function AgentCell({ event }: { event: RiskEvent }) {
  const { t } = useTranslation();
  const a = agentOf(event);
  switch (a.kind) {
    case "named":
      return <span>{a.text}</span>;
    case "unenrolled":
      return (
        <span className="tag" title={t("events.unenrolledHint")}>
          {t("events.unenrolled")}
          <span className="sr-only">，{t("events.unenrolledHint")}</span>
        </span>
      );
    case "unknown":
      return <span className="unknown">{t("events.unknownAgent")}</span>;
  }
}

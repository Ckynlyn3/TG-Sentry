import { useTranslation } from "react-i18next";
import { formatListTime } from "../../lib/format";
import type { DiscoveredAgent } from "./schema";

export function ScanTime({ iso }: { iso: string | null }) {
  const { t, i18n } = useTranslation();
  if (iso === null) return <span className="unknown">{t("inventory.notScanned")}</span>;
  return <time dateTime={iso}>{formatListTime(Date.parse(iso), i18n.language)}</time>;
}

// Freshness is the read-side age of the data (plan §9.1), shown in its own column, apart from scanState.
export function Freshness({ value }: { value: DiscoveredAgent["freshness"] }) {
  const { t } = useTranslation();
  return <span className={value === "fresh" ? undefined : "unknown"}>{t(`inventory.freshness.${value}`)}</span>;
}

// Design §5 field-level forbidden: the value is withheld for this role, which is not the same as empty.
export function Restricted() {
  const { t } = useTranslation();
  return (
    <span className="tag" title={t("inventory.restrictedHint")}>
      {t("inventory.restricted")}
      <span className="sr-only">，{t("inventory.restrictedHint")}</span>
    </span>
  );
}

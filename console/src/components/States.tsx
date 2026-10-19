import type { ReactNode } from "react";
import { CircleAlert, Lock } from "lucide-react";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../lib/errors";

const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;

// Design §5 "Error": inline in the failed panel, the rest of the page stays; retry offered.
export function ErrorPanel({ title, error, onRetry }: { title: string; error: unknown; onRetry: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="banner banner-error" role="alert">
      <CircleAlert {...ICON} />
      <div className="grow">
        <p className="font-medium">{title}</p>
        <p>{errorMessage(t, error)}</p>
      </div>
      <button className="btn btn-secondary" type="button" onClick={onRetry}>
        {t("events.retry")}
      </button>
    </div>
  );
}

// Design §5 "Forbidden": says what is withheld and who can grant it.
export function ForbiddenPanel({ title, body }: { title: string; body: string }) {
  return (
    <div className="banner banner-warn" role="alert">
      <Lock {...ICON} />
      <div className="grow">
        <p className="font-medium">{title}</p>
        <p>{body}</p>
      </div>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

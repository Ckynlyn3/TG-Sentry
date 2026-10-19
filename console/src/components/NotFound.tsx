import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

export function NotFound() {
  const { t } = useTranslation();
  return (
    <main className="empty-state" id="main">
      <h1 className="text-page mb-2">{t("notFound.title")}</h1>
      <p className="mb-5">{t("notFound.body")}</p>
      <Link to="/events" className="btn btn-secondary">
        {t("notFound.back")}
      </Link>
    </main>
  );
}

import type { TFunction } from "i18next";
import { ApiError } from "./api";

// Error text names what failed without leaking a stack; the server's own message is shown verbatim
// (it is already redacted server-side, internal/server/server.go fail()).
export function errorMessage(t: TFunction, e: unknown): string {
  if (!(e instanceof ApiError)) return t("errors.http", { status: "?" });
  switch (e.kind) {
    case "network":
      return t("errors.network");
    case "contract":
      return t("errors.contract", { field: e.message || "?" });
    case "http":
      return e.message ? `${t("errors.http", { status: e.status })} ${e.message}` : t("errors.http", { status: e.status });
  }
}

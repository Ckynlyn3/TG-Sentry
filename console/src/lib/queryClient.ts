import { QueryCache, QueryClient } from "@tanstack/react-query";
import { ApiError, isApiStatus } from "./api";

export function createQueryClient(onUnauthorized: () => void) {
  // Queries that answer a 401 themselves, next to the shell's own /me auth guard:
  // - me: the guard already routes to login.
  // - device-association: the public employee continuation. An employee without a console role cannot
  //   sign in (no_role, internal/server/oidc.go), so that page shows its own restart guidance instead
  //   (#72 S2 re-check: a global redirect stranded them on a login that always fails).
  const selfHandled = ["me", "device-association"];
  return new QueryClient({
    // A session that expires mid-use (12 h, internal/server/server.go) sends the operator back to login.
    queryCache: new QueryCache({
      onError: (e, query) => isApiStatus(e, 401) && !selfHandled.includes(String(query.queryKey[0])) && onUnauthorized(),
    }),
    defaultOptions: {
      queries: {
        // TanStack Query's default of 3 retries, but never for a 4xx refusal or a contract break.
        retry: (n, e) => !(e instanceof ApiError && (e.kind === "contract" || (e.status >= 400 && e.status < 500))) && n < 3,
        refetchOnWindowFocus: false,
      },
    },
  });
}

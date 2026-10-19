import { QueryCache, QueryClient } from "@tanstack/react-query";
import { ApiError, isApiStatus } from "./api";

export function createQueryClient(onUnauthorized: () => void) {
  return new QueryClient({
    // A session that expires mid-use (12 h, internal/server/server.go) sends the operator back to login.
    queryCache: new QueryCache({
      onError: (e, query) => isApiStatus(e, 401) && query.queryKey[0] !== "me" && onUnauthorized(),
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

import type { RouterHistory } from "@tanstack/react-router";
import { createQueryClient } from "./lib/queryClient";
import { createAppRouter } from "./router";

// One wiring for the app and its tests: an expired session (401 from any data query) clears cached
// tenant data and returns to login with the current location as the post-login target.
export function createApp(history?: RouterHistory) {
  const queryClient = createQueryClient(() => {
    queryClient.clear();
    void router.navigate({ to: "/login", search: { redirect: router.state.location.href } });
  });
  const router = createAppRouter(queryClient, history);
  return { queryClient, router };
}

import { describe, expect, it } from "vitest";
import { ApiError } from "./api";
import { createQueryClient } from "./queryClient";

// The cache-wide 401 handler is the console's only "session expired → login" trigger
// (app.ts:10). Every query must keep it, except the public device-association continuation:
// an employee without a console role cannot sign in (/api/v1/auth/callback answers no_role),
// so that page shows its own restart guidance instead (DeviceApprovalPage.tsx AssociationFlow).
const expired = () => Promise.reject(new ApiError("http", 401, "unauthorized"));
const fetchWith = (client: ReturnType<typeof createQueryClient>, key: string) =>
  client.fetchQuery({ queryKey: [key], queryFn: expired }).catch(() => undefined);

describe("expired-session redirect", () => {
  it("sends console queries to login but leaves the device-association continuation to its own guidance", async () => {
    let redirects = 0;
    const client = createQueryClient(() => { redirects++; });

    await fetchWith(client, "me");
    expect(redirects).toBe(0); // the shell's own probe already handles 401 (auth guard)
    await fetchWith(client, "device-association");
    expect(redirects).toBe(0); // #72 S2 re-check: roleless employees never reach console login
    await fetchWith(client, "risk-events");
    await fetchWith(client, "session-summaries");
    expect(redirects).toBe(2); // every other query is unchanged
  });
});

import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../../test/setup";
import { decideDeviceGrant, lookupDeviceGrant } from "./api";

const grant = { grantId: "grant-1", userCode: "BCDF-GHJK", name: "Laptop", platform: "linux", source: "127.0.0.1", status: "pending", associatedUser: null };

describe("device approval API uses the frozen #40 contract", () => {
  it("posts normalized userCode with same-origin cookies, never a query or device code", async () => {
    server.use(http.post("*/api/v1/device-grants/lookup", async ({ request }) => {
      expect(request.credentials).toBe("same-origin");
      expect(new URL(request.url).search).toBe("");
      expect(await request.json()).toEqual({ userCode: "BCDF-GHJK" });
      return HttpResponse.json(grant, { headers: { ETag: '"grant-tag"' } });
    }));
    expect(await lookupDeviceGrant("bcdfghjk")).toEqual({ grant, etag: '"grant-tag"' });
  });
  it("carries the reviewed ETag as If-Match and no association field (#72 U4)", async () => {
    server.use(http.post("*/api/v1/device-grants/decision", async ({ request }) => {
      expect(request.headers.get("If-Match")).toBe('"grant-tag"');
      expect(await request.json()).toEqual({ grantId: grant.grantId, decision: "approve" });
      return HttpResponse.json({ grantId: grant.grantId, status: "approved" });
    }));
    expect(await decideDeviceGrant(grant.grantId, "approve", '"grant-tag"')).toEqual({ grantId: grant.grantId, status: "approved" });
  });
  it("fails closed when the lookup omits the reviewed validator", async () => {
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json(grant)));
    await expect(lookupDeviceGrant(grant.userCode)).rejects.toMatchObject({ kind: "contract" });
  });
  it("rejects a lookup for a different displayed code", async () => {
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ ...grant, userCode: "LMNP-QRST" })));
    await expect(lookupDeviceGrant(grant.userCode)).rejects.toMatchObject({ kind: "contract" });
  });
  it("rejects decision responses for a different grant", async () => {
    server.use(http.post("*/api/v1/device-grants/decision", () => HttpResponse.json({ grantId: "other-grant", status: "approved" })));
    await expect(decideDeviceGrant(grant.grantId, "approve", '"grant-tag"')).rejects.toMatchObject({ kind: "contract" });
  });
  it("rejects a response recording the opposite decision", async () => {
    server.use(http.post("*/api/v1/device-grants/decision", () => HttpResponse.json({ grantId: grant.grantId, status: "denied" })));
    await expect(decideDeviceGrant(grant.grantId, "approve", '"grant-tag"')).rejects.toMatchObject({ kind: "contract" });
  });
});

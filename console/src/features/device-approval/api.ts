import { ApiError, request, requestTagged } from "../../lib/api";
import { associationConfirmSchema, associationPreviewSchema, deviceGrantDecisionInputSchema, deviceGrantDecisionSchema, deviceGrantLookupInputSchema, deviceGrantSchema, userCodeSchema, type DeviceGrant, type DeviceGrantDecision } from "./schema";

// #72 U4: the admin decision requires the reviewed grant ETag (missing 428, stale
// or weak 412, RFC 9110 §13.1.1). The lookup response ETag is that strong
// validator, so it is carried from review to decision and never re-fetched.
export interface ReviewedDeviceGrant {
  grant: DeviceGrant;
  etag: string;
}

export async function lookupDeviceGrant(code: string): Promise<ReviewedDeviceGrant> {
  const input = deviceGrantLookupInputSchema.parse({ userCode: code });
  const { data: grant, etag } = await requestTagged("/api/v1/device-grants/lookup", deviceGrantSchema, { method: "POST", body: JSON.stringify(input) });
  const returnedCode = userCodeSchema.safeParse(grant.userCode);
  if (!grant.grantId || !returnedCode.success || returnedCode.data !== input.userCode) throw new ApiError("contract", 200, "userCode");
  // Fail closed: a decision without the reviewed validator would be a 428.
  if (!etag) throw new ApiError("contract", 200, "etag");
  return { grant: { ...grant, userCode: returnedCode.data }, etag };
}

export async function decideDeviceGrant(grantId: string, decision: DeviceGrantDecision, etag: string): Promise<ReturnType<typeof deviceGrantDecisionSchema.parse>> {
  const input = deviceGrantDecisionInputSchema.parse({ grantId, decision });
  const result = await requestTagged("/api/v1/device-grants/decision", deviceGrantDecisionSchema, { method: "POST", headers: { "If-Match": etag }, body: JSON.stringify(input) }).then((r) => r.data);
  if (result.grantId !== grantId || result.status !== (decision === "approve" ? "approved" : "denied")) throw new ApiError("contract", 200, "grantId/status");
  return result;
}

// #72 S2: the verified employee previews the bound grant and confirms once. The
// grant is selected by server state; the body returns the single-use preview confirmation.
export const getAssociationPreview = () => request("/api/v1/device-grants/association/confirm", associationPreviewSchema);
export const confirmDeviceAssociation = (confirmation: string) =>
  request("/api/v1/device-grants/association/confirm", associationConfirmSchema, { method: "POST", body: JSON.stringify({ confirm: true, confirmation }) });

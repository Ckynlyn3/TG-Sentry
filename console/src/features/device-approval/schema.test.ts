import { describe, expect, it } from "vitest";
import contract from "../../../../docs/design/protection.openapi.json";
import { deviceGrantDecisionInputSchema, deviceGrantDecisionSchema, deviceGrantLookupInputSchema, deviceGrantSchema, userCodeSchema } from "./schema";

const grant = { grantId: "grant-1", userCode: "BCDF-GHJK", name: "Build laptop", platform: "linux", source: "127.0.0.1", status: "pending", associatedUser: null };

describe("#40 frozen device-grant contract", () => {
  it.each(["BCDF-GHJK", "bcdf-ghjk", "bcdfghjk", "  bcdf-ghjk  "])("normalizes %s to the display code", (code) => {
    expect(userCodeSchema.parse(code)).toBe("BCDF-GHJK");
  });
  it.each(["", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-1234", "BCDF GHJK", "BCDF_GHJK", "ßCDFGHJ", "ＢＣＤＦＧＨＪＫ"])("rejects invalid code %s", (code) => {
    expect(userCodeSchema.safeParse(code).success).toBe(false);
  });
  it("matches exact property names and required fields in OpenAPI", () => {
    const pairs = [
      [deviceGrantLookupInputSchema, contract.components.schemas.DeviceGrantLookupInput],
      [deviceGrantSchema, contract.components.schemas.DeviceGrantLookupResponse],
      [deviceGrantDecisionInputSchema, contract.components.schemas.DeviceGrantDecisionInput],
      [deviceGrantDecisionSchema, contract.components.schemas.DeviceGrantDecisionResponse],
    ] as const;
    for (const [schema, wire] of pairs) {
      expect(Object.keys(schema.shape).sort()).toEqual(Object.keys(wire.properties).sort());
      expect(Object.keys(schema.shape).sort()).toEqual([...wire.required].sort());
      expect(wire.additionalProperties).toBe(false);
    }
    expect(deviceGrantSchema.shape.status.options).toEqual(contract.components.schemas.DeviceGrantLookupResponse.properties.status.enum);
    expect(deviceGrantDecisionSchema.shape.status.options).toEqual(contract.components.schemas.DeviceGrantDecisionResponse.properties.status.enum);
    expect(deviceGrantDecisionInputSchema.shape.decision.options).toEqual(contract.components.schemas.DeviceGrantDecisionInput.properties.decision.enum);
  });
  it("parses every documented lookup status, not legacy field names", () => {
    for (const status of contract.components.schemas.DeviceGrantLookupResponse.properties.status.enum) {
      expect(deviceGrantSchema.parse({ ...grant, status }).status).toBe(status);
    }
    expect(deviceGrantLookupInputSchema.safeParse({ user_code: grant.userCode }).success).toBe(false);
    expect(deviceGrantSchema.safeParse({ ...grant, device_code: "never-in-browser" }).success).toBe(false);
    for (const key of Object.keys(grant)) {
      expect(deviceGrantSchema.safeParse(Object.fromEntries(Object.entries(grant).filter(([k]) => k !== key))).success).toBe(false);
    }
    expect(deviceGrantSchema.safeParse({ ...grant, status: "unknown" }).success).toBe(false);
  });
  it("accepts null at the rebased association boundary", () => {
    expect(deviceGrantSchema.parse(grant).associatedUser).toBeNull();
  });
  it("accepts a valid associated principal without rendering or treating it as the approver", () => {
    const associatedUser = { issuer: "https://idp.example", subject: "user-1", name: "Device owner" };
    expect(deviceGrantSchema.parse({ ...grant, associatedUser }).associatedUser).toEqual(associatedUser);
    expect(deviceGrantSchema.safeParse({ ...grant, associatedUser: { issuer: associatedUser.issuer, subject: associatedUser.subject } }).success).toBe(true);
  });
  it("rejects malformed associated principals", () => {
    for (const associatedUser of [{ issuer: "", subject: "user-1" }, { issuer: "https://idp.example" }, { issuer: "https://idp.example", subject: 7 }, { issuer: "https://idp.example", subject: "user-1", token: "forbidden" }]) {
      expect(deviceGrantSchema.safeParse({ ...grant, associatedUser }).success).toBe(false);
    }
  });
  it("accepts approve/deny only and never an association or If-Match input field (#72 is separate)", () => {
    for (const decision of ["approve", "deny"]) expect(deviceGrantDecisionInputSchema.parse({ grantId: grant.grantId, decision }).decision).toBe(decision);
    expect(deviceGrantDecisionInputSchema.safeParse({ grantId: grant.grantId, decision: "approve", userId: "person-1" }).success).toBe(false);
    expect(deviceGrantDecisionInputSchema.safeParse({ grantId: grant.grantId, decision: "pending" }).success).toBe(false);
    expect(deviceGrantDecisionSchema.safeParse({ grantId: grant.grantId, status: "consumed" }).success).toBe(false);
  });
});

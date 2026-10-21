import { z } from "zod";

// #40 D5 / RFC 8628 §6.1: eight ASCII consonants, case-insensitive; ignore the display hyphen.
// Reject non-ASCII before uppercasing (e.g. ß must not turn into an accepted SS).
export const userCodeSchema = z.string().trim().regex(/^[BCDFGHJKLMNPQRSTVWXZ-]+$/i)
  .transform((code) => code.replace(/-/g, "").toUpperCase())
  .pipe(z.string().regex(/^[BCDFGHJKLMNPQRSTVWXZ]{8}$/))
  .transform((code) => `${code.slice(0, 4)}-${code.slice(4)}`);

// Frozen schemas: docs/design/protection.openapi.json DeviceGrant*. The rebased #72 S1 lookup
// includes a nullable server-owned principal displayed in the administrator review.
const associatedUserSchema = z.object({ issuer: z.string().min(1), subject: z.string().min(1), name: z.string().optional() }).strict();
export const deviceGrantLookupInputSchema = z.object({ userCode: userCodeSchema }).strict();
export const deviceGrantSchema = z.object({
  grantId: z.string(),
  userCode: z.string(),
  name: z.string(),
  platform: z.string(),
  source: z.string(),
  status: z.enum(["pending", "approved", "denied", "expired", "consumed"]),
  associatedUser: associatedUserSchema.nullable(),
}).strict();
// #72 S2 association continuation. The preview is server-owned: the grant comes
// from the bound transaction, never from the page; the verified principal and
// session-bound single-use confirmation are returned together for review.
// Both the preview's grant and the confirm response are the same core.DeviceGrantLookup
// shape the admin lookup returns (device_grants.go:83), so reuse that frozen schema.
export const associationPreviewSchema = z.object({ grant: deviceGrantSchema, user: associatedUserSchema, confirmation: z.string().min(1) }).strict();
export const associationConfirmSchema = deviceGrantSchema;
export type AssociationPreview = z.infer<typeof associationPreviewSchema>;

export const deviceGrantDecisionInputSchema = z.object({ grantId: z.string(), decision: z.enum(["approve", "deny"]) }).strict();
export const deviceGrantDecisionSchema = z.object({ grantId: z.string(), status: z.enum(["approved", "denied"]) }).strict();
export type DeviceGrant = z.infer<typeof deviceGrantSchema>;
export type DeviceGrantDecision = z.infer<typeof deviceGrantDecisionInputSchema>["decision"];

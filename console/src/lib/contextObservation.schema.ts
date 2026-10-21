import { z } from "zod";
import { instantSchema } from "./schema";

const sensitiveSpanSchema = z.object({ startUTF16: z.number().int(), endUTF16: z.number().int() }).strict();
const sensitiveFindingSchema = z.object({
  category: z.string(), tag: z.string(), entityType: z.string(), span: sensitiveSpanSchema.optional(), score: z.number(), ruleId: z.string().optional(),
}).strict();
export const contextSensitiveResultSchema = z.object({
  findings: z.array(sensitiveFindingSchema), decision: z.string(), unavailable: z.boolean(), reason: z.string().optional(), ruleId: z.string().optional(),
}).strict();

export const contextObservationSourceSchema = z.object({
  adapter: z.enum(["openclaw", "pi", "claude", "codex", "cursor", "opencode", "trae"]),
  adapterVersion: z.string(), hook: z.string(), sourceRevision: z.string(),
}).strict();

export const contextObservationMetaSchema = z.object({
  id: z.string(), kind: z.enum(["instructions", "tool_definitions"]), coverage: z.enum(["observed", "prepared", "submitted"]),
  contentState: z.enum(["captured", "policy_omitted", "not_yet_available", "permission_restricted", "never_captured"]),
  source: contextObservationSourceSchema, sessionId: z.string(), instanceId: z.string(),
  reviewId: z.string().optional(), nativeAttemptId: z.string().optional(), epochDigest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  observedAt: instantSchema, sensitiveInfo: contextSensitiveResultSchema.optional(),
}).strict();

const systemInstructionsSchema = z.array(z.union([
  z.object({ type: z.literal("text"), content: z.string() }).passthrough(),
  z.object({ type: z.string() }).passthrough(),
]));
const toolDefinitionsSchema = z.array(z.union([
  z.object({ type: z.literal("function"), name: z.string(), description: z.string().nullable().optional(), parameters: z.union([z.boolean(), z.record(z.unknown())]).nullable().optional() }).passthrough(),
  z.object({ type: z.string(), name: z.string() }).passthrough(),
]));

const observationSchema = contextObservationMetaSchema.extend({
  instructions: z.object({ attribute: z.literal("gen_ai.system_instructions"), parts: systemInstructionsSchema }).strict().optional(),
  toolDefinitions: z.object({ attribute: z.literal("gen_ai.tool.definitions"), items: toolDefinitionsSchema }).strict().optional(),
}).strict();

export const contextObservationSchema = observationSchema.superRefine((observation, ctx) => {
  const captured = observation.contentState === "captured";
  if (!captured) {
    if (Object.hasOwn(observation, "instructions") || Object.hasOwn(observation, "toolDefinitions")) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "non-captured observation has a payload key" });
    }
  } else if (!observation.epochDigest || (observation.kind === "instructions"
    ? !observation.instructions || Object.hasOwn(observation, "toolDefinitions")
    : !observation.toolDefinitions || Object.hasOwn(observation, "instructions"))) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "captured observation requires a digest and exactly its kind's payload" });
  }

  const source = observation.source;
  if (source.adapter === "openclaw") {
    const hook = observation.kind === "instructions" ? "llm_input.systemPrompt" : "llm_input.tools";
    if (source.adapterVersion !== "2026.10.4" || source.sourceRevision !== "383c124cc32ffee3f8e56f549b88da94d269a4af" || source.hook !== hook || observation.coverage !== "observed") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "unadmitted OpenClaw observation source", path: ["source"] });
    }
  } else if (source.adapter === "pi") {
    const hook = observation.kind === "instructions" ? "before_agent_start.systemPrompt" : "getAllTools()∩getActiveTools()";
    if (source.adapterVersion !== "1.3.0" || source.sourceRevision !== "16f5f0af4d85ca583d045ceb5ed6d646fcaf7761" || source.hook !== hook || observation.coverage !== "prepared") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "unadmitted Pi observation source", path: ["source"] });
    }
  } else if (source.hook !== "" || (observation.contentState !== "never_captured" && observation.contentState !== "permission_restricted")) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "unavailable adapter requires no hook and never_captured or capability-restricted metadata", path: ["source"] });
  }
});

export type ContextObservationSource = z.infer<typeof contextObservationSourceSchema>;
export type ContextObservationMeta = z.infer<typeof contextObservationMetaSchema>;
export type ContextObservation = z.infer<typeof contextObservationSchema>;

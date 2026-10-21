import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import openclaw from "../../../internal/core/testdata/context-observations/openclaw.json";
import pi from "../../../internal/core/testdata/context-observations/pi.json";
import unavailable from "../../../internal/core/testdata/context-observations/unavailable.json";
import systemInstructions from "../../../internal/core/testdata/context-observations/gen-ai-system-instructions.json";
import toolDefinitions from "../../../internal/core/testdata/context-observations/gen-ai-tool-definitions.json";
import protectionContract from "../../../docs/design/protection.openapi.json";
import wireNegatives from "../../../internal/core/testdata/context-observations/wire-negatives.json";
import { contextObservationSchema } from "./contextObservation.schema";
import { instantSchema } from "./schema";

const observations = [...openclaw, ...pi].flatMap((fixture) => fixture.observations).concat(unavailable);
const instruction = contextObservationSchema.parse(openclaw[0]?.observations[0]);
const tools = contextObservationSchema.parse(openclaw[0]?.observations[1]);

const contract = z.object({
  openapi: z.literal("3.1.0"),
  components: z.object({ schemas: z.record(z.record(z.unknown())) }).passthrough(),
}).passthrough().parse(protectionContract);
const ajv = new Ajv({ allErrors: true, schemaId: "auto" });
ajv.addFormat("date-time", (value: string) => instantSchema.safeParse(value).success);
ajv.addSchema({ $id: "urn:tg-sentry:context-observation", components: contract.components });
const validateWire = ajv.compile({ $ref: "urn:tg-sentry:context-observation#/components/schemas/ContextObservation" });

function expectBoundary(value: unknown, accepted: boolean) {
  expect(contextObservationSchema.safeParse(value).success).toBe(accepted);
  expect(validateWire(value), ajv.errorsText(validateWire.errors)).toBe(accepted);
}

function metadataOnly(state: string) {
  const meta = { ...instruction };
  delete meta.instructions;
  delete meta.epochDigest;
  return { ...meta, contentState: state };
}

describe("context-observation shared contracts", () => {
  it("parses every synthetic admitted and unavailable source without changing the wire value", () => {
    for (const observation of observations) {
      expect(contextObservationSchema.parse(observation)).toEqual(observation);
      expect(validateWire(observation), ajv.errorsText(validateWire.errors)).toBe(true);
    }
    expect(contextObservationSchema.parse(pi[0]?.observations[0]).coverage).toBe("prepared");
    expect(contextObservationSchema.parse(pi[0]?.observations[1]).coverage).toBe("prepared");
    expect(contextObservationSchema.parse(tools).coverage).toBe("observed");
    expect(contextObservationSchema.parse(openclaw[1]?.observations[1]).contentState).toBe("never_captured");
    expect(contextObservationSchema.parse(openclaw[2]?.observations[0])).toMatchObject({
      contentState: "captured", toolDefinitions: { attribute: "gen_ai.tool.definitions", items: [] },
    });
    for (const observation of unavailable) {
      expect(contextObservationSchema.parse(observation)).toMatchObject({ contentState: "never_captured", source: { hook: "" } });
      expectBoundary({ ...observation, contentState: "captured", epochDigest: tools.epochDigest, toolDefinitions: tools.toolDefinitions }, false);
    }
  });

  it.each(["policy_omitted", "not_yet_available", "permission_restricted", "never_captured"])("accepts %s only without a payload key", (state) => {
    const meta = metadataOnly(state);
    expect(contextObservationSchema.parse(meta)).toEqual(meta);
    expectBoundary(meta, true);
    for (const value of [instruction.instructions, null]) {
      expectBoundary({ ...meta, instructions: value }, false);
    }
    expect(contextObservationSchema.safeParse({ ...meta, instructions: undefined }).success).toBe(false);
    expectBoundary({ ...meta, toolDefinitions: { attribute: "gen_ai.tool.definitions", items: [] } }, false);
  });

  it("accepts capability-projected metadata and sensitivity details without a content object", () => {
    const restricted = { ...metadataOnly("permission_restricted"), epochDigest: instruction.epochDigest };
    expect(contextObservationSchema.parse(restricted)).toEqual(restricted);
    expectBoundary(restricted, true);
    const omitted = {
      ...metadataOnly("policy_omitted"),
      sensitiveInfo: { findings: [], decision: "reject", unavailable: true, reason: "Credential pattern scan unavailable.", ruleId: "E_SECRET_SCAN" },
    };
    expect(contextObservationSchema.parse(omitted)).toEqual(omitted);
    expectBoundary(omitted, true);
    for (const observation of unavailable) {
      const projected = { ...observation, contentState: "permission_restricted" };
      expect(contextObservationSchema.parse(projected)).toEqual(projected);
      expectBoundary(projected, true);
    }
  });

  it.each([
    ["missing digest", { ...instruction, epochDigest: undefined }],
    ["uppercase digest", { ...instruction, epochDigest: "A".repeat(64) }],
    ["missing payload", { ...instruction, instructions: undefined }],
    ["both payloads", { ...instruction, toolDefinitions: tools.toolDefinitions }],
    ["both payload keys with null tools", { ...instruction, toolDefinitions: null }],
    ["both payload keys with null instructions", { ...tools, instructions: null }],
    ["wrong kind", { ...instruction, kind: "tool_definitions" }],
    ["wrong attribute", { ...instruction, instructions: { ...instruction.instructions, attribute: "gen_ai.input.messages" } }],
    ["null parts", { ...instruction, instructions: { ...instruction.instructions, parts: null } }],
    ["untyped part", { ...instruction, instructions: { ...instruction.instructions, parts: [{ content: "safe" }] } }],
    ["unnamed tool", { ...tools, toolDefinitions: { ...tools.toolDefinitions, items: [{ type: "function" }] } }],
    ["unknown state", { ...instruction, contentState: "not_recorded" }],
    ["payload tenant", { ...instruction, tenant: "default" }],
    ["envelope extension", { ...instruction, historyMessages: [] }],
    ["source extension", { ...instruction, source: { ...instruction.source, tenant: "default" } }],
    ["missing source field", { ...instruction, source: { ...instruction.source, hook: undefined } }],
    ["null source field", { ...instruction, source: { ...instruction.source, adapterVersion: null } }],
    ["unknown adapter", { ...instruction, source: { ...instruction.source, adapter: "unknown" } }],
    ["unadmitted version", { ...instruction, source: { ...instruction.source, adapterVersion: "other" } }],
    ["unadmitted revision", { ...instruction, source: { ...instruction.source, sourceRevision: "other" } }],
    ["upgraded coverage", { ...instruction, coverage: "submitted" }],
    ["missing timestamp", { ...instruction, observedAt: undefined }],
    ["invalid timestamp", { ...instruction, observedAt: "2026-10-21T01:02:03+99:99" }],
    ["null native ID", { ...instruction, nativeAttemptId: null }],
  ])("rejects %s at both boundaries", (_, value) => expectBoundary(value, false));

  it("rejects the same shared wire negatives as the Go decoder", () => {
    expect(wireNegatives.length).toBeGreaterThan(0);
    for (const negative of wireNegatives) {
      expectBoundary(negative.value, false);
    }
  });

  it("preserves overlapping anyOf, explicit nulls, arbitrary extensions, and array order", () => {
    const parts = [{ type: "text" }, { type: "text", content: null, extension: { labels: ["safe"], enabled: true } }, { type: "vendor", value: 1 }];
    const items = [
      { type: "function", name: "nullable", description: null, parameters: null },
      { type: "function", name: "boolean-schema", parameters: false },
      { type: "function", name: "generic-overlap", description: 7, parameters: { type: 7 } },
      { type: "vendor", name: "custom", extension: { labels: ["safe"] } },
    ];
    const instructionsValue = { ...instruction, instructions: { attribute: "gen_ai.system_instructions", parts } };
    const toolsValue = { ...tools, toolDefinitions: { attribute: "gen_ai.tool.definitions", items } };
    expect(contextObservationSchema.parse(instructionsValue)).toEqual(instructionsValue);
    expect(contextObservationSchema.parse(toolsValue)).toEqual(toolsValue);
    expectBoundary(instructionsValue, true);
    expectBoundary(toolsValue, true);
  });

  it("keeps vendor associations explicit and does not invent an ID from timestamps or content", () => {
    for (const observation of observations) {
      const parsed = contextObservationSchema.parse(observation);
      expect(parsed).toEqual(observation);
      expect(Object.hasOwn(parsed, "nativeAttemptId")).toBe(false);
    }
    const associated = { ...instruction, reviewId: "review-link", nativeAttemptId: "vendor-supplied-attempt" };
    expect(contextObservationSchema.parse(associated)).toEqual(associated);
    expectBoundary(associated, true);
  });
});

describe("additive OpenAPI components and pinned OTel JSON Schema", () => {
  it("validates and resolves every new component without adding a route or page envelope", () => {
    const names = ["ContextObservationSource", "ContextObservationMeta", "ContextObservation", "ContextInstructions", "ContextToolDefinitions", "SystemInstructions", "ToolDefinitions", "SensitiveSpan", "SensitiveFinding", "SensitiveResult"];
    for (const name of names) {
      const schema = contract.components.schemas[name];
      expect(schema, name).toBeDefined();
      if (!schema) throw new Error(`missing ${name}`);
      expect(ajv.validateSchema(schema), ajv.errorsText()).toBe(true);
      expect(() => ajv.compile({ $ref: `urn:tg-sentry:context-observation#/components/schemas/${name}` })).not.toThrow();
    }
    expect(contract.components.schemas).not.toHaveProperty("ContextObservationPage");
    const paths = z.record(z.unknown()).parse(contract.paths);
    expect(Object.keys(paths).filter((path) => path.includes("context-observations"))).toEqual([]);
    expectBoundary(instruction, true);
  });

  it("embeds the pinned schemas unchanged apart from resource IDs", () => {
    const instructionSchema = contract.components.schemas.SystemInstructions;
    const definitionSchema = contract.components.schemas.ToolDefinitions;
    if (!instructionSchema || !definitionSchema) throw new Error("missing OTel components");
    const { $id: instructionsId, ...actualInstructions } = instructionSchema;
    const { $id: toolsId, ...actualTools } = definitionSchema;
    expect(instructionsId).toBe("https://raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/547934afa90a34298441caf80c43b27255c3a292/model/gen-ai/gen-ai-system-instructions.json");
    expect(toolsId).toBe("https://raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/547934afa90a34298441caf80c43b27255c3a292/model/gen-ai/gen-ai-tool-definitions.json");
    expect(actualInstructions).toEqual(systemInstructions);
    expect(actualTools).toEqual(toolDefinitions);
    const validateInstructions = ajv.compile({ $ref: "urn:tg-sentry:context-observation#/components/schemas/SystemInstructions" });
    const validateTools = ajv.compile({ $ref: "urn:tg-sentry:context-observation#/components/schemas/ToolDefinitions" });
    expect(validateInstructions([{ type: "text" }])).toBe(true);
    expect(validateTools([{ type: "function", name: "overlap", description: 7, parameters: { type: 7 } }])).toBe(true);
    const validateFunction = ajv.compile({ $ref: `${String(definitionSchema.$id)}#/$defs/FunctionToolDefinition` });
    expect(validateFunction({ type: "function", name: "schema", description: null, parameters: { type: "object", properties: { path: { type: "string" } } } })).toBe(true);
    expect(validateFunction({ type: "function", name: "boolean", description: null, parameters: false })).toBe(true);
    expect(validateFunction({ type: "function", name: "invalid", parameters: { type: 7 } })).toBe(false);
    expect(validateFunction({ type: "function", name: "invalid", description: 7 })).toBe(false);
  });

  it("matches every field in the Go sensitivity shape", () => {
    const value = {
      ...metadataOnly("policy_omitted"),
      sensitiveInfo: {
        findings: [{ category: "category::sensitive-info", tag: "secret", entityType: "private-key", span: { startUTF16: 0, endUTF16: 1 }, score: 1, ruleId: "R_SECRET_PRIVATE_KEY" }],
        decision: "reject", unavailable: false, reason: "synthetic omission", ruleId: "R_SECRET_PRIVATE_KEY",
      },
    };
    expect(contextObservationSchema.parse(value)).toEqual(value);
    expectBoundary(value, true);
    expectBoundary({ ...value, sensitiveInfo: { ...value.sensitiveInfo, findings: [{ entityType: "private-key" }] } }, false);
  });
});

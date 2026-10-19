import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { platform } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import { captureScripts, HOOK_VERSION, isLoopbackHost } from "../index.ts";

const ID = "tg-sentry";
// OpenClaw hook reference: 15 s gate default. HTTP/poll/size precedents:
// adapter/index.ts (5 s), internal/bridge/bridge.go (500 ms, 2 MiB).
const HOOK_TIMEOUT_MS = 15000;
const DECISION_TIMEOUT_MS = 5000;
const POLL_MS = 500;
const MAX_RESPONSE_BYTES = 2 << 20;
const hash = (...parts: string[]) => createHash("sha256").update(parts.join("\0")).digest("hex");
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function settings(api: OpenClawPluginApi) {
  const config = api.pluginConfig;
  if (!object(config) || typeof config.endpoint !== "string" || typeof config.token !== "string" || !config.token.trim())
    throw new Error("invalid connection");
  const endpoint = new URL(config.endpoint);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/" ||
      (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && isLoopbackHost(endpoint.hostname))))
    throw new Error("invalid endpoint");
  if (config.nodeId !== undefined && (typeof config.nodeId !== "string" || !/^[a-f0-9]{32}$/.test(config.nodeId)))
    throw new Error("invalid node identity");
  const hooks = api.config.plugins?.entries?.[ID]?.hooks;
  const budget = hooks?.timeouts?.before_tool_call ?? hooks?.timeoutMs ?? HOOK_TIMEOUT_MS;
  if (!Number.isInteger(budget) || budget <= DECISION_TIMEOUT_MS)
    throw new Error("decision deadline must be below the effective hook timeout");
  return { endpoint: endpoint.origin, token: config.token, nodeId: config.nodeId as string | undefined };
}

async function request(config: ReturnType<typeof settings>, path: string, signal: AbortSignal, body?: unknown): Promise<unknown> {
  const response = await fetch(`${config.endpoint}/api/v1${path}`, {
    method: body === undefined ? "GET" : "POST", redirect: "error", signal,
    headers: { Authorization: `Bearer ${config.token}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status !== 200 || !response.body) throw new Error("decision service unavailable");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error("oversized decision");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function verdict(value: unknown, expectedId: string) {
  if (!object(value) || value.id !== expectedId || typeof value.decision !== "string" ||
      !["approve", "reject", "pending"].includes(value.decision) ||
      typeof value.deadline !== "string" || !Number.isFinite(Date.parse(value.deadline)))
    throw new Error("invalid decision");
  if (Date.now() > Date.parse(value.deadline)) throw new Error("expired decision");
  if (value.decision !== "pending" && (typeof value.comment !== "string" || !value.comment.trim() ||
      typeof value.ruleId !== "string" || !value.ruleId ||
      (value.decision === "approve" && value.execution !== "awaiting_execution")))
    throw new Error("incomplete or replayed decision");
  return value;
}

export default {
  id: ID,
  name: "TG-Sentry",
  register(api: OpenClawPluginApi) {
    // Registration is synchronous and does no network or credential-file I/O.
    api.on("before_tool_call", async (event, ctx) => {
      try {
        const config = settings(api);
        const session = ctx.sessionId ?? ctx.sessionKey;
        const callId = ctx.toolCallId;
        if (!session || !callId || !ctx.agentId || !event.toolName || !object(event.params) ||
            (event.toolCallId !== undefined && event.toolCallId !== callId)) throw new Error("missing tool identity");
        const workspace = api.runtime.agent.resolveAgentWorkspaceDir(api.config, ctx.agentId);
        if (!isAbsolute(workspace)) throw new Error("missing workspace");
        if (event.toolName === "exec" && (event.toolKind !== undefined ||
            (event.params.host !== undefined && (typeof event.params.host !== "string" ||
              !["auto", "gateway"].includes(event.params.host)))))
          throw new Error("remote or ambiguous exec is not supported");
        if (event.toolName === "exec" && event.params.workdir !== undefined &&
            (typeof event.params.workdir !== "string" || !event.params.workdir.trim())) throw new Error("invalid workdir");
        const cwd = realpathSync(event.toolName === "exec" && typeof event.params.workdir === "string"
          ? resolve(workspace, event.params.workdir) : workspace);
        const instanceId = hash(config.nodeId ?? "", "openclaw", session, cwd);
        const expectedId = hash(instanceId, callId);
        const signal = AbortSignal.any([AbortSignal.timeout(DECISION_TIMEOUT_MS), ...(ctx.abortSignal ? [ctx.abortSignal] : [])]);
        signal.throwIfAborted();
        await request(config, "/instances", signal, {
          id: instanceId, agent: "openclaw", sessionId: session, cwd, platform: platform(),
          nodeId: config.nodeId, hookVersion: HOOK_VERSION, connectionMode: "events",
        });
        let review = verdict(await request(config, "/reviews", signal, {
          instanceId, callId, toolName: event.toolName, argumentsObj: event.params,
          ...captureScripts(cwd, event.toolName === "exec" ? "bash" : event.toolName, event.params),
        }), expectedId);
        while (review.decision === "pending") {
          await delay(POLL_MS, undefined, { signal });
          review = verdict(await request(config, `/reviews/${expectedId}?instanceId=${instanceId}`, signal), expectedId);
        }
        signal.throwIfAborted();
        if (review.decision === "reject") return { block: true, blockReason: `TG-Sentry: ${review.comment}` };
        // Only an explicit approval permits this hook; native permissions remain.
        if (review.decision === "approve") return undefined;
        throw new Error("unknown decision");
      } catch {
        // Never expose service payloads, tool arguments, URLs, or bearer tokens.
        return { block: true, blockReason: "TG-Sentry: review denied or unavailable; tool blocked." };
      }
    }, { timeoutMs: HOOK_TIMEOUT_MS });
  },
};

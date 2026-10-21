import type {
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { isIPv4, isIPv6 } from "node:net";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";

type Review = {
  id: string;
  decision: "pending" | "approve" | "reject";
  comment: string;
  deadline: string;
};
export const HOOK_VERSION = "0.1.0";

const MAX_SCRIPT_BYTES = 1 << 20;
const MAX_SCRIPT_FILES = 8;
const SCRIPT_INTERPRETER = /^(python[0-9.]*|bash|sh|zsh|fish|node|nodejs|ruby|perl|php|pwsh|powershell)$/;
const SCRIPT_EXTENSIONS = new Set([
  ".sh", ".bash", ".zsh", ".fish", ".py", ".py3", ".js", ".mjs",
  ".cjs", ".ts", ".tsx", ".rb", ".pl", ".php", ".ps1", ".lua",
]);

export type ReviewScript = {
  path: string;
  sha256?: string;
  bytes?: number;
  content?: string;
  complete: boolean;
  truncated?: boolean;
  readError?: string;
};

function literalToken(token: string): string | undefined {
  if (!token || /[$`*?\[\]~]/.test(token)) return undefined;
  if ((token.startsWith("\"") && token.endsWith("\"")) || (token.startsWith("'") && token.endsWith("'"))) return token.slice(1, -1);
  return token;
}

function commandTokens(command: string): string[] {
  const out: string[] = [];
  const re = /"(?:\\.|[^"\\])*"|'[^']*'|[^\s]+/g;
  for (const match of command.matchAll(re)) out.push(match[0]);
  return out;
}

function captureReferences(command: string, workingDir: string): Array<{ path?: string; problem?: string; direct?: boolean }> {
  if (/[$`]|\$\(|\$\{|[*?\[\]]/.test(command)) return [{ problem: "执行脚本路径包含动态展开，无法确定实际文件" }];
  const tokens = commandTokens(command);
  const refs: Array<{ path?: string; problem?: string; direct?: boolean }> = [];
  let dir = workingDir;
  const add = (raw: string | undefined, direct = false) => {
    const value = literalToken(raw || "");
    if (!value) {
      refs.push({ problem: "执行脚本路径包含动态展开，无法确定实际文件" });
      return;
    }
    refs.push({ path: resolve(dir, value), direct });
  };
  for (let i = 0; i < tokens.length; i++) {
    const raw = literalToken(tokens[i]);
    if (!raw) {
      refs.push({ problem: "动态命令入口，无法确定是否执行脚本" });
      continue;
    }
    const base = basename(raw);
    if (base === "cd") {
      const next = literalToken(tokens[++i] || "");
      dir = next && next !== "-" ? resolve(dir, next) : "";
      continue;
    }
    if (base === "source" || base === ".") {
      add(tokens[++i]);
      continue;
    }
    if (["env", "sudo", "exec", "nohup", "timeout"].includes(base)) continue;
    if (SCRIPT_INTERPRETER.test(base)) {
      for (i++; i < tokens.length; i++) {
        const value = literalToken(tokens[i]);
        if (!value) {
          refs.push({ problem: "解释器参数包含动态展开，无法确定实际脚本" });
          break;
        }
        if (["-c", "-e", "--eval", "--print"].includes(value)) {
          if (value === "-c" && tokens[i + 1]) {
            const inline = literalToken(tokens[++i]);
            if (inline) refs.push(...captureReferences(inline, dir));
            else refs.push({ problem: "Shell 内联执行内容不确定" });
          }
          break;
        }
        if (value === "-m" || value === "-") {
          refs.push({ problem: "解释器未提供可确定的本地脚本文件" });
          break;
        }
        if (value.startsWith("-")) continue;
        add(tokens[i]);
        break;
      }
      continue;
    }
    if (raw.includes("/") || SCRIPT_EXTENSIONS.has(extname(raw).toLowerCase())) add(tokens[i], true);
  }
  return refs;
}

export function captureScripts(workingDir: string, tool: string, args: Record<string, unknown>) {
  if (!["Bash", "bash", "shell", "shell_open", "shell_send", "command", "script", "powershell", "PowerShell", "execute_command", "run_command", "terminal", "cmd"].includes(tool)) return { scriptFiles: [] as ReviewScript[], scriptCaptureStatus: "not_applicable" };
  const key = tool === "shell_send" ? "text" : "command";
  let command = typeof args[key] === "string" ? String(args[key]) : "";
  if (!command.trim()) {
    for (const candidate of ["script", "code", "cmd"]) {
      if (typeof args[candidate] === "string") { command = String(args[candidate]); break; }
    }
  }
  if (!command.trim()) return { scriptFiles: [] as ReviewScript[], scriptCaptureStatus: "not_applicable" };
  const refs = captureReferences(command, workingDir);
  const files: ReviewScript[] = [];
  const seen = new Set<string>();
  let status = "complete";
  let total = 0;
  for (const ref of refs) {
    const key = `${ref.path || ""}:${ref.problem || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const file: ReviewScript = { path: ref.path || "<无法确定的脚本>", complete: false };
    if (ref.problem) {
      file.readError = ref.problem;
      status = "incomplete";
      files.push(file);
      continue;
    }
    if (files.length >= MAX_SCRIPT_FILES) {
      file.readError = "本次调用超过 8 个脚本文件";
      status = "incomplete";
      files.push(file);
      break;
    }
    try {
      const info = statSync(ref.path!);
      if (!info.isFile()) throw new Error("不是普通文件");
      if (info.size > MAX_SCRIPT_BYTES) {
        file.bytes = info.size;
        file.truncated = true;
        file.readError = "脚本超过完整快照限制（1 MiB）";
        status = "incomplete";
        files.push(file);
        continue;
      }
      const content = readFileSync(ref.path!);
      file.bytes = content.length;
      if (ref.direct && (content.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) || content.subarray(0, 2).equals(Buffer.from([0x4d, 0x5a])))) continue;
      if (tool === "shell_send") throw new Error("交互会话可能已切换目录或连接远端，无法确认本机文件就是实际执行脚本");
      const text = content.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(content) || content.includes(0)) throw new Error("脚本不是有效 UTF-8 文本");
      if (content.length > MAX_SCRIPT_BYTES || total + content.length > MAX_SCRIPT_BYTES) {
        file.truncated = true;
        file.readError = "脚本超过完整快照总量限制（1 MiB），未附加部分内容";
        status = "incomplete";
        files.push(file);
        continue;
      }
      file.sha256 = createHash("sha256").update(content).digest("hex");
      file.content = text;
      file.complete = true;
      total += content.length;
      files.push(file);
    } catch (error) {
      file.readError = error instanceof Error ? error.message : "脚本读取失败";
      status = "incomplete";
      files.push(file);
    }
  }
  return files.length ? { scriptFiles: files, scriptCaptureStatus: status } : { scriptFiles: [], scriptCaptureStatus: "not_applicable" };
}

export function isLoopbackHost(host: string): boolean {
  const value = host.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    value === "localhost" ||
    (isIPv4(value) && value.startsWith("127.")) ||
    (isIPv6(value) &&
      (value === "::1" || /^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(value)))
  );
}

export function validateDecision(value: unknown): Review {
  const r = value as Review;
  if (
    !r ||
    typeof r.id !== "string" ||
    !r.id ||
    !["pending", "approve", "reject"].includes(r.decision) ||
    typeof r.comment !== "string" ||
    !Number.isFinite(Date.parse(r.deadline))
  )
    throw new Error("审查服务返回非法裁决");
  return r;
}

// Keep only the latest user message for local audit / human review. The server
// excludes it from model input; previous tool calls and results are not collected.
export function reviewContext(branch: readonly any[]) {
  for (let i = branch.length - 1; i >= 0; i--) {
    const entry = branch[i];
    if (entry.type !== "message" || entry.message.role !== "user") continue;
    const m = entry.message;
    const content =
      typeof m.content === "string"
        ? m.content
        : (Array.isArray(m.content) ? m.content : [])
            .filter((b: any) => b.type === "text")
            .map((b: any) => b.text)
            .join("\n");
    return { userMessage: content.slice(0, 6000) };
  }
  return { userMessage: "" };
}

type BridgeDecision = { decision: "approve" | "reject"; comment: string };

export default function aegisHook(pi: ExtensionAPI) {
  // Pi ExtensionAPI handlers may await promises; trust discovery stays inert.
  // Subprocess contract/limits mirror adapter/opencode.mjs, not a TS verifier.
  let controller = new AbortController();
  let session: { sessionId: string; cwd: string } | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;
  // Restore Pi's activity tracking (a9660ab index.ts:231,235,319–320,348–356).
  let status = "idle";
  let pending = 0;
  const children = new Set<ChildProcess>();
  const calls = new Map<string, BridgeDecision>();
  // Remember the real directory while the installed symlink exists. Removing an
  // entry must not disable the already-loaded extension before Pi reloads it.
  let directory: string | undefined;
  const root = () => directory ??= dirname(realpathSync(fileURLToPath(import.meta.url)));
  function setStatus(ctx: ExtensionContext, text: string) {
    if (ctx.hasUI) ctx.ui.setStatus("aegishook", text);
  }
  async function run(event: Record<string, unknown>, passive = false, signal = controller.signal): Promise<BridgeDecision | undefined> {
    signal.throwIfAborted();
    if (!session) throw new Error("Pi session not started");
    const directory = root();
    const runtime: unknown = JSON.parse(readFileSync(join(directory, "runtime.json"), "utf8"));
    if (!runtime || typeof runtime !== "object" || !("binary" in runtime) ||
        typeof runtime.binary !== "string" || !isAbsolute(runtime.binary))
      throw new Error("AegisHook: invalid absolute hook runtime; tool blocked");
    const binary = runtime.binary;
    // Fail before creating a process for non-JSON extension-supplied input.
    const input = JSON.stringify({ ...event, ...session });
    return new Promise((resolve, reject) => {
      const child = spawn(binary, ["hook", "--agent", "pi", "--connection", join(directory, "connection.json")], {
        stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
      });
      children.add(child);
      let stdout = "", stderr = "", overflow = false, timedOut = false;
      const abort = () => child.kill("SIGKILL");
      signal.addEventListener("abort", abort, { once: true });
      const timeout = setTimeout(() => { timedOut = true; abort(); }, passive ? 10000 : 86520000);
      const cleanup = () => {
        clearTimeout(timeout);
        signal.removeEventListener("abort", abort);
        children.delete(child);
      };
      child.stdout.on("data", (b) => {
        stdout += b;
        if (stdout.length > 2 * 1024 * 1024) { overflow = true; abort(); }
      });
      child.stderr.on("data", (b) => { stderr = (stderr + b).slice(-16000); });
      child.stdin.on("error", () => {}); // close/error determines the fail-closed result.
      child.once("error", (error) => { cleanup(); reject(error); });
      child.once("close", (code) => {
        cleanup();
        if (signal.aborted || timedOut || overflow)
          return reject(new Error("AegisHook: hook cancelled or output limit exceeded; tool blocked"));
        if (passive) {
          if (code === 0) return resolve(undefined);
          return reject(new Error(stderr.trim() || "AegisHook: lifecycle/result delivery failed"));
        }
        try {
          const result: unknown = JSON.parse(stdout);
          if (!result || typeof result !== "object" || !("decision" in result) || !("comment" in result) ||
              typeof result.comment !== "string" || !result.comment ||
              !((code === 0 && result.decision === "approve") || (code === 2 && result.decision === "reject")))
            throw new Error("AegisHook: invalid hook decision; tool blocked");
          resolve({ decision: result.decision, comment: result.comment });
        } catch (error) { reject(error); }
      });
      child.stdin.end(input);
    });
  }
  pi.on("session_start", async (_event, ctx) => {
    if (timer) clearInterval(timer);
    controller.abort();
    controller = new AbortController();
    session = { sessionId: ctx.sessionManager.getSessionId(), cwd: ctx.cwd };
    status = "idle";
    pending = 0;
    calls.clear();
    const signal = controller.signal;
    const register = async () => {
      try {
        await run({ hook_event_name: "session_start", state: pending ? "awaiting_review" : status }, true, signal);
        if (!signal.aborted) setStatus(ctx, "AegisHook · 防护已连接");
      } catch { if (!signal.aborted) setStatus(ctx, "AegisHook · 审查不可用，工具将被拒绝"); }
    };
    await register();
    if (signal.aborted) return;
    let beating = false;
    timer = setInterval(async () => {
      if (beating || signal.aborted) return;
      beating = true;
      try { await register(); } finally { beating = false; }
    }, 10000);
    timer.unref?.();
  });
  pi.on("session_shutdown", async () => {
    if (timer) clearInterval(timer);
    timer = undefined;
    const closing = controller;
    closing.abort();
    for (const child of children) child.kill("SIGKILL");
    calls.clear();
    try { await run({ hook_event_name: "session_shutdown" }, true, AbortSignal.timeout(1000)); }
    catch { /* Lease expires server-side if the shutdown cannot be delivered. */ }
    if (controller === closing) session = undefined;
  });
  pi.on("agent_start", async () => { status = "running"; });
  pi.on("agent_settled", async () => { status = "idle"; });
  pi.on("tool_call", async (event, ctx) => {
    const signal = controller.signal;
    pending++;
    try {
      const result = await run({ hook_event_name: "tool_call", toolCallId: event.toolCallId,
        toolName: event.toolName, input: event.input, ...reviewContext(ctx.sessionManager.getBranch()) }, false, signal);
      signal.throwIfAborted(); // A session boundary must never yield a late permit.
      if (!result) throw new Error("Missing hook decision");
      calls.set(event.toolCallId, result);
      setStatus(ctx, result.decision === "approve" ? "AegisHook · 已允许本次调用" : "AegisHook · 已拦截");
      if (result.decision === "reject") return { block: true, reason: result.comment };
      return undefined;
    } catch (error) {
      setStatus(ctx, "AegisHook · 本次调用已拒绝");
      return { block: true, reason: `AegisHook: ${error instanceof Error ? error.message : "review failed"}; tool blocked` };
    } finally {
      if (signal === controller.signal) pending--;
    }
  });
  pi.on("tool_execution_end", async (event, ctx) => {
    const call = calls.get(event.toolCallId);
    if (!call) return;
    calls.delete(event.toolCallId);
    const signal = controller.signal;
    let result: string;
    try {
      result = typeof event.result === "string" ? event.result : JSON.stringify(event.result) ?? "";
    } catch {
      result = "[Result unavailable: serialization failed]";
    }
    // Pre-#66 index.ts at a9660ab:434–449 bounded result text to 12,000 chars.
    // Keep terminal status below the shared input limit; Go still redacts it.
    result = result.slice(0, 12000);
    // Existing Pi delivery retry count; Go owns review IDs, redaction and pairing.
    for (let n = 0; n < 3 && !signal.aborted; n++) {
      try {
        await run({ hook_event_name: "tool_execution_end", toolCallId: event.toolCallId,
          result, isError: event.isError,
          executionState: call.decision === "reject" ? "not_executed" : event.isError ? "failed" : "succeeded" }, true, signal);
        return;
      } catch { /* Retry only result delivery, never authorization. */ }
    }
    if (!signal.aborted) setStatus(ctx, "AegisHook · 执行结果回传失败");
  });
}

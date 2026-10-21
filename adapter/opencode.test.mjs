import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { channel } from "node:diagnostics_channel";
import { startTestOIDC, loginTestAdmin } from "../scripts/test-oidc.mjs";

const root = dirname(fileURLToPath(import.meta.url));
// Captured before fake timers: readiness polling must use the real clock.
const realSetTimeout = globalThis.setTimeout;
const wait = (ms) => new Promise((resolve) => realSetTimeout(resolve, ms));

// Run the shipped plugin against an executable fixture at the Go hook boundary,
// exactly as installation lays it out (runtime.json beside the module).
async function timeoutFixture(t, script) {
  const dir = await mkdtemp(join(tmpdir(), "aegis-opencode-timeout-"));
  const binary = join(dir, "hook fixture.mjs");
  await writeFile(binary, `#!${process.execPath}\n${script}`, { mode: 0o700 });
  await writeFile(join(dir, "runtime.json"), JSON.stringify({ binary }));
  await writeFile(join(dir, "connection.json"), "{}");
  await copyFile(join(root, "opencode.mjs"), join(dir, "opencode.mjs"));
  // Native channel observes the real ChildProcess, so tests assert the actual
  // exit rather than the advisory child.killed flag.
  const children = [];
  const observe = (message) => children.push(message.process);
  channel("child_process").subscribe(observe);
  t.after(async () => {
    channel("child_process").unsubscribe(observe);
    for (const child of children)
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
  });
  const logs = [];
  const client = { app: { log: async (...args) => logs.push(args) } };
  const hooks = await (await import(pathToFileURL(join(dir, "opencode.mjs")).href)).default({
    directory: dir,
    client,
  });
  const spawned = async () => {
    for (let n = 0; n < 400 && !children.length; n++) await wait(5);
    assert.ok(children.length, "adapter did not spawn the hook child");
    return children[0];
  };
  return { dir, hooks, children, logs, spawned };
}

const hanging = `
process.on("SIGTERM", () => {}); // A SIGTERM-resistant hook must still be stopped.
let input = "";
process.stdin.on("data", (b) => (input += b));
process.stdin.on("end", () => { setInterval(() => {}, 1000); });
`;

async function waitExit(child) {
  for (let n = 0; n < 400 && child.exitCode === null && child.signalCode === null; n++)
    await wait(5);
  return child;
}

test("OpenCode active timeout kills a SIGTERM-resistant child and blocks execution", { timeout: 15000 }, async (t) => {
  const { hooks, spawned } = await timeoutFixture(t, hanging);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.after(() => t.mock.timers.reset());
  const pending = hooks["tool.execute.before"](
    { sessionID: "timeout", callID: "active", tool: "bash" },
    { args: { command: "fixture" } },
  );
  const child = await spawned();
  t.mock.timers.tick(86520000); // Existing active budget; unchanged.
  await assert.rejects(pending, /timed out/);
  await waitExit(child);
  assert.equal(child.signalCode, "SIGKILL", "child survived the budget");
});

test("OpenCode passive timeout kills child and completes delivery failure", { timeout: 15000 }, async (t) => {
  const { hooks, logs, spawned } = await timeoutFixture(t, hanging);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.after(() => t.mock.timers.reset());
  const pending = hooks.event({
    event: { type: "session.created", properties: { info: { id: "fixture" } } },
  });
  const child = await spawned();
  t.mock.timers.tick(10000); // Existing passive budget; unchanged.
  await pending; // Passive delivery completes as a logged failure, never throws.
  await waitExit(child);
  assert.equal(child.signalCode, "SIGKILL", "child survived the budget");
  assert.equal(logs.length, 1, "passive failure was not delivered to the client");
  assert.equal(logs[0][0].body.level, "error");
  assert.match(logs[0][0].body.message, /timed out/);
});

test("OpenCode timeout cannot accept late approval", { timeout: 15000 }, async (t) => {
  // The hook prints an approval and exits 0, but an inherited pipe keeps the
  // parent's 'close' pending until after the budget expires.
  const { hooks, spawned } = await timeoutFixture(
    t,
    `
const { spawn } = await import("node:child_process");
process.on("SIGTERM", () => {});
spawn(process.execPath, ["-e", "setTimeout(() => {}, 400)"], { stdio: "inherit" });
let input = "";
process.stdin.on("data", (b) => (input += b));
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify({ decision: "approve", comment: "late" }));
  process.exit(0);
});
`,
  );
  let close;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.after(() => t.mock.timers.reset());
  const pending = hooks["tool.execute.before"](
    { sessionID: "timeout", callID: "late", tool: "bash" },
    { args: { command: "fixture" } },
  );
  let outcome;
  pending.then(
    () => (outcome = "resolved"),
    (error) => (outcome = `rejected: ${error.message}`),
  );
  const child = await spawned();
  child.once("close", (code, signal) => (close = { code, signal }));
  await waitExit(child); // Approval printed and exit 0 already happened...
  assert.equal(child.exitCode, 0);
  assert.equal(close, undefined, "close should still await the inherited pipe");
  t.mock.timers.tick(86520000); // ...then the budget expires before 'close'.
  await assert.rejects(pending, /timed out/);
  await waitExit(child);
  for (let n = 0; n < 400 && !close; n++) await wait(5);
  assert.deepEqual(close, { code: 0, signal: null }, "late exit never arrived");
  assert.match(outcome, /^rejected: .*timed out/, "late approval was accepted");
});

test("OpenCode callbacks, both scopes, parameter binding, outcomes and offline denial", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aegis opencode's-"));
  const project = join(dir, "project");
  await mkdir(project);
  const base = "http://127.0.0.1:18798";
  const binary = fileURLToPath(new URL("../bin/aegishook", import.meta.url));
  const oidc = await startTestOIDC({ binary, dataDir: join(dir, "data"), base });
  const server = spawn(
    binary,
    ["serve", "--data-dir", join(dir, "data"), "--addr", "127.0.0.1:18798"],
    {
      env: {
        ...process.env,
        ...oidc.env,
        XDG_CONFIG_HOME: join(dir, "config"),
        OPENCODE_CONFIG_DIR: join(dir, "config", "opencode"),
      },
      stdio: "pipe",
    },
  );
  let hooks;
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try {
        if ((await fetch(base)).ok) {
          ready = true;
          break;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 30));
    }
    assert.equal(ready, true);
    const cookie = await loginTestAdmin(base);
    async function api(path, body) {
      const r = await fetch(base + "/api/v1" + path, {
        method: body ? "POST" : "GET",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      assert.equal(r.status, 200);
      return r.json();
    }
    const global = await api("/installations", {
      agent: "opencode",
      scope: "global",
    });
    const local = await api("/installations", {
      agent: "opencode",
      scope: "project",
      project,
    });
    assert.ok(global.entry.endsWith(".js"));
    const one = await import(pathToFileURL(global.entry));
    const two = await import(pathToFileURL(local.entry));
    assert.equal(one.default, two.default);
    const client = { app: { log: async () => {} } };
    hooks = await one.default({ directory: project, client });
    const duplicate = await two.default({ directory: project, client });
    assert.equal(hooks, duplicate);
    await hooks["chat.message"](
      { sessionID: "fixture" },
      { parts: [{ type: "text", text: "fixture password=secret-value" }] },
    );
    let executed = false;
    await assert.rejects(async () => {
      await hooks["tool.execute.before"](
        { sessionID: "fixture", callID: "deny", tool: "bash" },
        { args: { command: "passwd fixture" } },
      );
      executed = true;
    }, /R1/);
    assert.equal(executed, false);
    const input = { sessionID: "fixture", callID: "read", tool: "read" };
    const args = { filePath: "README.md" };
    await Promise.all([
      hooks["tool.execute.before"](input, { args }),
      duplicate["tool.execute.before"](input, { args }),
    ]);
    await assert.rejects(
      hooks["tool.execute.before"](input, { args: { filePath: "different" } }),
      /parameters changed/,
    );
    let calls = await api("/calls");
    assert.equal(calls.length, 2);
    assert.equal(
      calls.find((c) => c.callId === "read").execution,
      "awaiting_execution",
    );
    assert.equal(
      calls
        .find((c) => c.callId === "read")
        .userMessage.includes("secret-value"),
      false,
    );
    await hooks["tool.execute.after"](
      { ...input, args },
      { title: "fixture", output: "fixture read", metadata: {} },
    );
    const failure = { sessionID: "fixture", callID: "failed", tool: "read" };
    await hooks["tool.execute.before"](failure, { args });
    await hooks.event({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            type: "tool",
            sessionID: "fixture",
            callID: "failed",
            tool: "read",
            state: { status: "error", error: "fixture tool error" },
          },
        },
      },
    });
    calls = await api("/calls");
    assert.equal(calls.find((c) => c.callId === "read").execution, "succeeded");
    assert.equal(calls.find((c) => c.callId === "failed").execution, "failed");
    assert.equal(
      calls.find((c) => c.callId === "deny").execution,
      "not_executed",
    );
    const sessions = await api("/instances");
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].installations.length, 2);
    assert.equal(sessions[0].connectionMode, "events");
    await hooks.dispose();
    assert.equal((await api("/instances"))[0].state, "disconnected");
    const runtimePath = join(dir, "data", "adapter", "runtime.json");
    const runtimeBytes = await readFile(runtimePath);
    await rm(runtimePath);
    hooks = await one.default({ directory: project, client });
    await assert.rejects(
      hooks["tool.execute.before"](
        { sessionID: "missing-runtime", callID: "missing", tool: "read" },
        { args },
      ),
      /AegisHook/,
    );
    await writeFile(runtimePath, runtimeBytes);
    server.kill("SIGTERM");
    await once(server, "exit");
    await assert.rejects(
      hooks["tool.execute.before"](
        { sessionID: "offline", callID: "offline", tool: "read" },
        { args },
      ),
      /AegisHook/,
    );
  } finally {
    if (hooks) await hooks.dispose();
    if (server.exitCode === null) {
      server.kill("SIGTERM");
      await once(server, "exit");
    }
    await oidc.stop();
    await rm(dir, { recursive: true, force: true });
  }
});

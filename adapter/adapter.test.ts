import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm, mkdir, copyFile, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire, findPackageJSON } from "node:module";
import { spawn, execFile } from "node:child_process";
import { channel } from "node:diagnostics_channel";
import { promisify } from "node:util";
import { once } from "node:events";
import { captureScripts, isLoopbackHost, validateDecision, reviewContext } from "./index";
import { startTestOIDC, loginTestAdmin } from "../scripts/test-oidc.mjs";
const root = dirname(fileURLToPath(import.meta.url));
const piPackageJSON = join(root, "node_modules/@earendil-works/pi-coding-agent/package.json");
const piRequire = createRequire(piPackageJSON);
const { loadExtensions } = await import(
  pathToFileURL(
    join(
      root,
      "node_modules/@earendil-works/pi-coding-agent/dist/core/extensions/loader.js",
    ),
  ).href
);

test("review context omits all prior tool calls and results", () => {
  const message = (value: any) => ({ type: "message", message: value });
  const branch: any[] = [message({ role: "user", content: "旧任务" })];
  for (let i = 0; i < 8; i++) {
    branch.push(
      message({
        role: "assistant",
        content: [{ type: "toolCall", id: `${i}`, name: "bash", arguments: { command: `echo previous-${i}` } }],
      }),
      message({
        role: "toolResult",
        toolCallId: `${i}`,
        isError: false,
        content: [{ type: "text", text: `previous-result-${i}` }],
      }),
    );
  }
  branch.push(
    message({ role: "user", content: [{ type: "text", text: "当前任务" }] }),
  );
  // Do not read command/result contents even while locating the last user message.
  for (const role of ["assistant", "toolResult"]) {
    branch.push(message({
      role,
      get content() { throw new Error("read historical content"); },
    }));
  }
  assert.deepEqual(reviewContext(branch), { userMessage: "当前任务" });
});

test("review context keeps only bounded user text for local audit", () => {
  assert.deepEqual(reviewContext([]), { userMessage: "" });
  assert.deepEqual(
    reviewContext([{ type: "message", message: { role: "user", content: "a".repeat(7000) } }]),
    { userMessage: "a".repeat(6000) },
  );
  assert.deepEqual(
    reviewContext([
      { type: "message", message: { role: "user", content: "old user text" } },
      { type: "message", message: { role: "user", content: [{ type: "image", data: "fixture" }] } },
    ]),
    { userMessage: "" },
  );
});

test("custom loopback endpoints remain local", () => {
  for (const host of [
    "localhost",
    "127.0.0.1",
    "127.0.0.2",
    "[::1]",
    "[::ffff:7f00:2]",
  ]) {
    assert.equal(
      isLoopbackHost(new URL(`http://${host}:18800`).hostname),
      true,
      host,
    );
  }
  for (const host of [
    "0.0.0.0",
    "192.168.1.2",
    "[::]",
    "[::ffff:c0a8:102]",
    "localhost.evil.example",
    "127.0.0.1.evil.example",
  ]) {
    assert.equal(
      isLoopbackHost(new URL(`http://${host}:18800`).hostname),
      false,
      host,
    );
  }
});

test("invalid decisions are fail-closed", () => {
  for (const value of [
    null,
    {},
    {
      id: "r",
      decision: "allow",
      comment: "ok",
      deadline: new Date().toISOString(),
    },
    { id: "r", decision: "approve", deadline: "invalid" },
  ])
    assert.throws(() => validateDecision(value));
});

test("script snapshots capture literal files and reject dynamic paths", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aegis-script-test-"));
  try {
    await writeFile(join(dir, "check.py"), "print('fixture')\n");
    const complete = captureScripts(dir, "Bash", { command: "python check.py" });
    assert.equal(complete.scriptCaptureStatus, "complete");
    assert.equal(complete.scriptFiles.length, 1);
    assert.equal(complete.scriptFiles[0].complete, true);
    assert.equal(complete.scriptFiles[0].content, "print('fixture')\n");
    const incomplete = captureScripts(dir, "Bash", { command: "python $SCRIPT" });
    assert.equal(incomplete.scriptCaptureStatus, "incomplete");
    assert.equal(incomplete.scriptFiles[0].complete, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Exercise the same Pi loader/symlink resolution as installation, with an
// executable test double only at the external Go process boundary.
async function bridgeFixture(t: any, behavior = "approve") {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "pi-bridge-")));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const binary = join(dir, "hook runner.mjs");
  const log = join(dir, "events.jsonl");
  await writeFile(binary, `#!${process.execPath}
import { appendFileSync } from 'node:fs';
let input = ''; process.stdin.on('data', b => input += b);
process.stdin.on('end', () => {
  const event = JSON.parse(input);
  appendFileSync(${JSON.stringify(log)}, JSON.stringify({argv:process.argv.slice(2),event})+'\\n');
  if (event.hook_event_name !== 'tool_call') { console.log('{}'); return; }
  if (${JSON.stringify(behavior)} === 'hang') { setInterval(() => {}, 10000); return; }
  if (${JSON.stringify(behavior)} === 'malformed') { console.log('{}'); return; }
  if (${JSON.stringify(behavior)} === 'nonzero') { console.log('{"decision":"approve","comment":"fixture"}'); process.exitCode=1; return; }
  console.log(JSON.stringify({decision:${JSON.stringify(behavior)},comment:'fixture'}));
  if (${JSON.stringify(behavior)} === 'reject') process.exitCode=2;
});
`, {mode:0o700});
  await writeFile(join(dir, "runtime.json"), JSON.stringify({binary}));
  await writeFile(join(dir, "connection.json"), '{}');
  const entry = join(dir, "index.ts");
  await copyFile(join(root, "index.ts"), entry);
  const loaded = await loadExtensions([entry], dir);
  assert.deepEqual(loaded.errors, []);
  const handlers = loaded.extensions[0].handlers;
  const ctx: any = {cwd:dir, hasUI:false, sessionManager:{getSessionId:()=>"pi-fixture-session",getBranch:()=>[]}};
  const emit = async (name:string,event:any={}) => {
    let result;
    for (const h of handlers.get(name) || []) result = await h({type:name,...event},ctx);
    return result as any;
  };
  t.after(() => emit("session_shutdown"));
  await emit("session_start");
  return {dir, log, emit};
}

test("Pi bridge spawns configured absolute binary and preserves session/result correlation", async (t) => {
  const {dir, log, emit} = await bridgeFixture(t);
  const call = {toolCallId:"call-1",toolName:"read",input:{path:"README.md"}};
  assert.equal(await emit("tool_call",call), undefined);
  await emit("tool_execution_end",{toolCallId:"unknown",isError:false,result:"not paired"});
  await emit("tool_execution_end",{toolCallId:call.toolCallId,isError:false,result:"paired result"});
  await emit("tool_execution_end",{toolCallId:call.toolCallId,isError:false,result:"duplicate"});
  const records = (await readFile(log,"utf8")).trim().split("\n").map(s=>JSON.parse(s));
  for (const r of records) {
    assert.deepEqual(r.argv,["hook","--agent","pi","--connection",join(dir,"connection.json")]);
    assert.equal(r.event.sessionId,"pi-fixture-session");
    assert.equal(r.event.cwd,dir);
  }
  const review = records.find(r=>r.event.hook_event_name==="tool_call").event;
  assert.deepEqual(review.input,call.input);
  const results = records.filter(r=>r.event.hook_event_name==="tool_execution_end");
  assert.equal(results.length,1);
  assert.equal(results[0].event.toolCallId,call.toolCallId);
  assert.equal(results[0].event.result,"paired result");
});

for (const behavior of ["malformed","nonzero","reject"]) {
  test(`Pi bridge ${behavior} stdout/exit blocks execution`,async (t)=>{
    const {emit} = await bridgeFixture(t,behavior);
    assert.equal((await emit("tool_call",{toolCallId:"c",toolName:"read",input:{}})).block,true);
  });
}

test("Pi bridge spawn failure blocks execution",async(t)=>{
  const {dir,emit} = await bridgeFixture(t);
  await writeFile(join(dir,"runtime.json"),JSON.stringify({binary:join(dir,"missing")}));
  assert.equal((await emit("tool_call",{toolCallId:"c",toolName:"read",input:{}})).block,true);
});

test("Pi bridge shutdown cancels pending review without a late permit",async(t)=>{
  const {emit,log} = await bridgeFixture(t,"hang");
  const pending = emit("tool_call",{toolCallId:"c",toolName:"read",input:{}});
  // Observe the real child accepting the call before cancelling it.
  for (let n=0;n<100;n++) {
    if ((await readFile(log,"utf8")).includes('"tool_call"')) break;
    await new Promise(r=>setTimeout(r,20));
  }
  assert.match(await readFile(log,"utf8"), /"tool_call"/);
  await emit("session_shutdown");
  assert.equal((await pending).block,true);
});

test("Pi bridge hook timeout kills the child and blocks execution",async(t)=>{
  const {emit} = await bridgeFixture(t,"hang");
  t.mock.timers.enable({apis:["setTimeout"]});
  const pending = emit("tool_call",{toolCallId:"c",toolName:"read",input:{}});
  t.mock.timers.tick(86520000); // OpenCode's existing active-hook budget, not a new limit.
  assert.equal((await pending).block,true);
  t.mock.timers.reset();
});

for (const kind of ["cyclic", "BigInt", "throwing toJSON"]) {
  test(`Pi review fix serialization ${kind} blocks with zero spawns`, async (t) => {
    const {emit} = await bridgeFixture(t);
    // Native Node channel observes real children even through Pi's jiti loader.
    const children = channel("child_process");
    let spawns = 0;
    const spawned = () => { spawns++; };
    children.subscribe(spawned);
    t.after(() => children.unsubscribe(spawned));
    const cyclic: any = {};
    cyclic.self = cyclic;
    const input = kind === "cyclic" ? cyclic : kind === "BigInt" ? {value: 1n} : {
      toJSON() { throw new Error("fixture serialization failure"); },
    };
    const result = await emit("tool_call", {toolCallId:"invalid", toolName:"read", input});
    assert.equal(result.block, true);
    assert.equal(spawns, 0, "serialization failure spawned a child");
  });
}

test("Pi review fix 3 MiB result preserves terminal state within the bridge limit", async (t) => {
  const {emit, log} = await bridgeFixture(t);
  assert.equal(await emit("tool_call", {toolCallId:"large", toolName:"read", input:{}}), undefined);
  await emit("tool_execution_end", {toolCallId:"large", result:"x".repeat(3 * 1024 * 1024), isError:false});
  const records = (await readFile(log,"utf8")).trim().split("\n").map(s=>JSON.parse(s));
  const report = records.find(r=>r.event.hook_event_name === "tool_execution_end").event;
  assert.equal(report.executionState, "succeeded");
  assert.equal(report.result.length, 12000, "restore pre-#66 index.ts:449 bound");
  assert.ok(Buffer.byteLength(JSON.stringify(report)) < 2 * 1024 * 1024);
});

async function heartbeatFixture(t: any, behavior = "approve") {
  const original = globalThis.setInterval;
  let heartbeat: (() => Promise<void>) | undefined;
  t.mock.method(globalThis, "setInterval", (callback: () => Promise<void>, ...args: any[]) => {
    if (args[0] === 10000) heartbeat = callback;
    return Reflect.apply(original, globalThis, [callback, ...args]);
  });
  const fixture = await bridgeFixture(t, behavior);
  assert.ok(heartbeat, "extension did not schedule its heartbeat");
  const beat = async () => {
    await heartbeat!();
    const records = (await readFile(fixture.log,"utf8")).trim().split("\n").map(s=>JSON.parse(s));
    return records.filter(r=>r.event.hook_event_name === "session_start").at(-1).event.state;
  };
  return {...fixture, beat};
}

test("Pi review fix heartbeat preserves running and settled states", async (t) => {
  const {emit, beat} = await heartbeatFixture(t);
  await emit("agent_start");
  assert.equal(await beat(), "running");
  await emit("agent_settled");
  assert.equal(await beat(), "idle");
});

test("Pi review fix heartbeat preserves pending-review precedence", async (t) => {
  const {emit, beat} = await heartbeatFixture(t, "hang");
  await emit("agent_start");
  const pending = emit("tool_call", {toolCallId:"pending", toolName:"read", input:{}});
  try {
    assert.equal(await beat(), "awaiting_review");
    await emit("agent_settled");
    assert.equal(await beat(), "awaiting_review");
  } finally {
    await emit("session_shutdown");
    assert.equal((await pending).block, true);
  }
});

test("Pi loader, real agent loop, Go review, feedback and lifecycle", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aegis-adapter-test-"));
  const endpoint = "http://127.0.0.1:18792";
  const data = join(dir, "data");
  await mkdir(data);
  await writeFile(join(data, "hook.token"), "test-hook");
  const binary = resolve(root, "../bin/aegishook");
  const oidc = await startTestOIDC({ binary, dataDir: data, base: endpoint });
  const proc = spawn(
    binary,
    [
      "serve",
      "--data-dir",
      data,
      "--agent-dir",
      join(dir, "pi"),
      "--addr",
      "127.0.0.1:18792",
    ],
    { env: { ...process.env, ...oidc.env }, stdio: "pipe" },
  );
  let ended = false;
  proc.on("exit", () => {
    ended = true;
  });
  let shutdown: (() => Promise<void>) | undefined;
  try {
    for (let n = 0; n < 100; n++) {
      try {
        if ((await fetch(endpoint)).ok) break;
      } catch {}
      if (ended) throw new Error("test service exited");
      await new Promise((r) => setTimeout(r, 30));
    }
    const cookie = await loginTestAdmin(endpoint);
    async function admin(path: string, method = "GET", body?: unknown) {
      const r = await fetch(endpoint + "/api/v1" + path, {
        method,
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      assert.ok(r.ok, await r.clone().text());
      return r.json();
    }
    const enrollment = await admin("/client-enrollments", "POST", { name: "Pi loader fixture", type: "one-off" });
    const clientDir = join(dir, "client");
    // Feed the synthetic enrollment code only to this owned fixture process.
    const installer = spawn(binary, ["client", "install", "--agent", "pi", "--scope", "project", "--project", dir,
      "--client-dir", clientDir, "--endpoint", endpoint, "--code-stdin"], { stdio: "pipe" });
    let installError = "";
    installer.stderr.on("data", b => installError += b);
    installer.stdin.end(enrollment.code);
    const [installExit] = await once(installer, "exit");
    assert.equal(installExit, 0, installError);
    const clientEntry = join(dir, ".pi/extensions/aegishook.ts");
    const remoteLoaded = await loadExtensions([clientEntry], dir);
    assert.deepEqual(remoteLoaded.errors, []);
    const remoteCtx: any = {cwd:dir,hasUI:false,sessionManager:{getSessionId:()=>"enrolled-pi-session",getBranch:()=>[]}};
    const remoteEmit = async (name:string,event:any={}) => {
      let result:any;
      for (const h of remoteLoaded.extensions[0].handlers.get(name) || []) result = await h({type:name,...event}, remoteCtx);
      return result;
    };
    try {
      await remoteEmit("session_start");
      assert.equal(await remoteEmit("tool_call",{toolCallId:"enrolled-read",toolName:"read",input:{path:"README.md"}}), undefined);
      await remoteEmit("tool_execution_end",{toolCallId:"enrolled-read",result:"password=fixture-result-secret\n" + "x".repeat(3 * 1024 * 1024),isError:false});
      const cached = JSON.parse(await readFile(join(clientDir,"adapter/bundle.json"),"utf8"));
      assert.ok(cached, "enrolled Pi did not persist verified bundle");
      const result = (await admin("/calls")).find((c:any)=>c.callId==="enrolled-read");
      assert.equal(result.execution,"succeeded");
      assert.ok(result.result.length < 2 * 1024 * 1024);
      assert.ok(!result.result.includes("fixture-result-secret"), "Go result redaction was bypassed");
    } finally { await remoteEmit("session_shutdown"); }
    await promisify(execFile)(binary,["client","uninstall","--agent","pi","--scope","project","--project",dir,"--client-dir",clientDir]);

    const installed = await admin("/installations", "POST", {
      scope: "project",
      project: dir,
    });
    const loaded = await loadExtensions([installed.entry], dir);
    assert.deepEqual(loaded.errors, []);
    assert.equal(loaded.extensions.length, 1);
    const handlers = loaded.extensions[0].handlers;
    const visible: any[] = [];
    const statuses: string[] = [];
    const ctx: any = {
      cwd: dir,
      hasUI: true,
      ui: { setStatus: (_id: string, s: string) => statuses.push(s) },
      sessionManager: {
        getSessionId: () => "integration-session",
        getBranch: () => visible,
      },
    };
    const emit = async (name: string, event: any = {}) => {
      let result: any;
      for (const h of handlers.get(name) || [])
        result = await h({ type: name, ...event }, ctx);
      return result;
    };
    shutdown = () => emit("session_shutdown", { reason: "quit" });
    await emit("session_start", { reason: "startup" });
    assert.ok(
      statuses.some((s) => s.includes("防护已连接")),
      "adapter did not register after real Pi load",
    );
    const { Agent } = await import(
      pathToFileURL(
        join(
          dirname(
            piRequire.resolve("@earendil-works/pi-agent-core/package.json"),
          ),
          "dist/index.js",
        ),
      ).href
    );
    const ai = await import(
      pathToFileURL(
        join(
          // pi-ai is ESM-only and doesn't export ./package.json; findPackageJSON resolves it as
          // pi-coding-agent sees it (nested or hoisted), without relying on the install layout.
          dirname(findPackageJSON("@earendil-works/pi-ai", piPackageJSON)!),
          "dist/index.js",
        ),
      ).href
    );
    const model: any = {
      id: "fixture",
      name: "fixture",
      api: "openai-completions",
      provider: "fixture",
      baseUrl: "http://127.0.0.1",
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 32000,
      maxTokens: 1000,
    };
    let turn = 0,
      deleted = 0,
      reads = 0;
    const agent = new Agent({
      initialState: {
        model,
        tools: [
          {
            name: "delete_user",
            description: "isolated test double",
            label: "delete",
            parameters: {
              type: "object",
              properties: { user: { type: "string" } },
              required: ["user"],
            },
            execute: async () => {
              deleted++;
              return { content: [{ type: "text", text: "deleted" }] };
            },
          },
          {
            name: "read",
            description: "isolated read double",
            label: "read",
            parameters: {
              type: "object",
              properties: { path: { type: "string" } },
              required: ["path"],
            },
            execute: async () => {
              reads++;
              return {
                content: [
                  { type: "text", text: "read-only verification complete" },
                ],
              };
            },
          },
        ],
      },
      streamFn: () => {
        const stream = ai.createAssistantMessageEventStream();
        const n = turn++;
        const message: any = {
          role: "assistant",
          api: model.api,
          provider: model.provider,
          model: model.id,
          timestamp: Date.now(),
          usage: {
            input: 1,
            output: 1,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 2,
            cost: {
              input: 0,
              output: 0,
              cacheRead: 0,
              cacheWrite: 0,
              total: 0,
            },
          },
          stopReason: n < 2 ? "toolUse" : "stop",
          content:
            n === 0
              ? [
                  {
                    type: "toolCall",
                    id: "delete-call",
                    name: "delete_user",
                    arguments: { user: "isolated-fixture" },
                  },
                ]
              : n === 1
                ? [
                    {
                      type: "toolCall",
                      id: "read-call",
                      name: "read",
                      arguments: { path: "README.md" },
                    },
                  ]
                : [
                    {
                      type: "text",
                      text: "Adjusted to read-only verification.",
                    },
                  ],
        };
        queueMicrotask(() => {
          stream.push({ type: "done", reason: message.stopReason, message });
          stream.end(message);
        });
        return stream;
      },
      beforeToolCall: async (c: any) =>
        emit("tool_call", {
          toolCallId: c.toolCall.id,
          toolName: c.toolCall.name,
          input: c.args,
        }),
    });
    agent.subscribe(async (event: any) => {
      if (event.type === "message_end")
        visible.push({ type: "message", message: event.message });
      if (event.type === "tool_execution_end")
        await emit("tool_execution_end", event);
    });
    await agent.prompt("Validate account permissions using isolated tools.");
    assert.equal(deleted, 0, "dangerous tool must never execute");
    assert.equal(
      reads,
      1,
      "agent must be able to continue with read-only operation",
    );
    const denied = agent.state.messages.find(
      (m: any) => m.role === "toolResult" && m.toolCallId === "delete-call",
    );
    assert.equal(denied?.isError, true);
    assert.match(JSON.stringify(denied), /R3/);
    let calls: any[] = [];
    for (let n = 0; n < 100; n++) {
      calls = await admin("/calls");
      if (calls.find((c:any)=>c.callId==="read-call")?.execution === "succeeded") break;
      await new Promise(r=>setTimeout(r,20));
    }
    assert.equal(
      calls.find((c: any) => c.callId === "delete-call").execution,
      "not_executed",
    );
    assert.equal(
      calls.find((c: any) => c.callId === "read-call").execution,
      "succeeded",
    );
    // Entry removal does not remove already-loaded handlers.
    await admin("/installations/" + installed.id, "DELETE");
    const still = await emit("tool_call", {
      toolCallId: "after-uninstall",
      toolName: "delete_user",
      input: { user: "isolated" },
    });
    assert.equal(still.block, true);
    const states = await admin("/installations");
    assert.equal(
      states.find((i: any) => i.id === installed.id).status,
      "waiting_reload",
    );
    // Unknown calls pause, and receive only an approval bound to their exact arguments.
    const waiting = emit("tool_call", {
      toolCallId: "manual",
      toolName: "bash",
      input: { command: "echo fixture" },
    });
    let manual: any;
    for (let n = 0; n < 100; n++) {
      manual = (await admin("/calls")).find((c: any) => c.callId === "manual");
      if (manual) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(manual.decision, "pending");
    await admin("/approvals/" + manual.id + "/decision", "POST", {
      digest: manual.digest,
      decision: "reject",
      comment: "仅允许只读验证",
    });
    assert.equal((await waiting).block, true);
    await shutdown();
    shutdown = undefined;
    const instances = await admin("/instances");
    assert.ok(instances.every((i: any) => !i.online));
    await emit("session_start", { reason: "reload" });
    proc.kill("SIGTERM");
    await once(proc, "exit");
    const offline = await emit("tool_call", {
      toolCallId: "offline",
      toolName: "read",
      input: { path: "README.md" },
    });
    assert.equal(offline.block, true);
  } finally {
    if (shutdown) await shutdown().catch(() => {});
    if (!ended) {
      proc.kill("SIGTERM");
      await once(proc, "exit");
    }
    await oidc.stop();
    await rm(dir, { recursive: true, force: true });
  }
});

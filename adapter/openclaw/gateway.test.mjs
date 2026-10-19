// Real OpenClaw Gateway agent turns; local SSE fixture, no real model/credentials.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
const root = fileURLToPath(new URL('../../', import.meta.url));
const pkg = join(root, '.cache/openclaw/package');
const cache = join(root, '.cache');
const dir = await mkdtemp(join(cache, 'openclaw-gateway-'));
const workspace = join(dir, 'workspace');
await mkdir(workspace);
await writeFile(join(workspace, 'read.txt'), 'benign read fixture');
const configPath = join(dir, 'openclaw.json');
// SSE protocol and local model fixture adapted from cc-safety-net (MIT; NOTICE).
let nextTool;
let issued = false;
const toolReplies = [];
const chunk = (delta, finish_reason = null) => `data: ${JSON.stringify({
  id: 'chatcmpl-fixture', object: 'chat.completion.chunk', created: 0, model: 'stub-model',
  choices: [{ index: 0, delta, finish_reason }],
})}\n\n`;
const model = createServer(async (req, res) => {
  let body = ''; for await (const b of req) body += b;
  const payload = JSON.parse(body);
  toolReplies.push(...(payload.messages ?? []).filter(m => m.role === 'tool'));
  res.setHeader('content-type', 'text/event-stream');
  if (!issued) {
    issued = true;
    res.end(chunk({ role: 'assistant', tool_calls: [{ index: 0, id: 'call_fixture', type: 'function',
      function: { name: nextTool.tool, arguments: JSON.stringify(nextTool.args) } }] }) +
      chunk({}, 'tool_calls') + 'data: [DONE]\n\n');
  } else res.end(chunk({ role: 'assistant', content: 'fixture complete' }) + chunk({}, 'stop') + 'data: [DONE]\n\n');
});
await new Promise(resolve => model.listen(0, '127.0.0.1', resolve));
const children = [];
const logs = [];
const start = (command, args, env = {}) => {
  const child = spawn(command, args, { cwd: root, env: { ...process.env, HOME: dir,
    OPENCLAW_STATE_DIR: dir, OPENCLAW_CONFIG_PATH: configPath,
    OPENCLAW_SKIP_CHANNELS: '1', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(child);
  child.on('error', error => logs.push(String(error)));
  child.stdout.on('data', b => logs.push(b.toString()));
  child.stderr.on('data', b => logs.push(b.toString()));
  return child;
};
const fixture = start(join(root, '.cache/openclaw/decision-fixture'), [join(dir, 'decision-data')]);
const first = await once(fixture.stdout, 'data', { signal: AbortSignal.timeout(60000) });
const upstream = JSON.parse(first[0].toString()).endpoint;
let mode = 'real';
let seenReviews = 0;
const proxy = createServer(async (req, res) => {
  if (mode === 'down') { req.socket.destroy(); return; }
  if (mode === 'timeout') return;
  if (mode === 'malformed' && req.url === '/api/v1/reviews') { res.end('{'); return; }
  let body = ''; for await (const b of req) body += b;
  if (req.url === '/api/v1/reviews') seenReviews++;
  try {
    const response = await fetch(`${upstream}${req.url}`, { method: req.method,
      headers: { 'authorization': 'Bearer fixture-hook-not-secret', 'content-type': 'application/json' },
      body: req.method === 'POST' ? body : undefined });
    res.writeHead(response.status, { 'content-type': 'application/json' });
    res.end(await response.text());
  } catch { res.writeHead(503).end('{}'); }
});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
const probe = tcpServer(); await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
await writeFile(configPath, JSON.stringify({
  gateway: { mode: 'local', bind: 'loopback', port, auth: { mode: 'token', token: 'gateway-fixture-not-secret' },
    tools: { allow: ['exec'] }, controlUi: { enabled: false } },
  agents: { defaults: { workspace, model: { primary: 'stub/stub-model' } } },
  models: { providers: { stub: { baseUrl: `http://127.0.0.1:${model.address().port}/v1`,
    api: 'openai-completions', apiKey: 'fixture-not-a-real-key',
    models: [{ id: 'stub-model', name: 'Fixture', contextWindow: 128000, maxTokens: 4096 }] } } },
  tools: { profile: 'full', codeMode: { enabled: false }, exec: { host: 'gateway', security: 'full', ask: 'off' } },
  plugins: { allow: ['tg-sentry'], load: { paths: [join(root, 'adapter/openclaw')] },
    entries: { 'tg-sentry': { enabled: true, hooks: { timeouts: { before_tool_call: 15000 } },
      config: { endpoint: `http://127.0.0.1:${proxy.address().port}`, token: 'fixture-hook-not-secret' } } } },
}));
let gateway;
const results = [];
try {
  gateway = start(process.execPath, [join(pkg, 'openclaw.mjs'), 'gateway', 'run', '--allow-unconfigured', '--port', String(port)]);
  // cc-safety-net live Gateway precedent: 180 s readiness / 250 ms probes.
  const readyUntil = Date.now() + 180000;
  for (;;) {
    if (gateway.exitCode !== null) throw new Error(`gateway exited ${gateway.exitCode}: ${logs.join('')}`);
    if (await fetch(`http://127.0.0.1:${port}/health`).then(r => r.ok).catch(() => false)) break;
    if (Date.now() >= readyUntil) throw new Error(`gateway readiness timeout: ${logs.join('')}`);
    await delay(250);
  }
  async function invoke(tool, args, id) {
    nextTool = { tool, args }; issued = false; toolReplies.length = 0;
    const child = start(process.execPath, [join(pkg, 'openclaw.mjs'), 'agent', '--agent', 'main',
      '--session-key', `agent:main:issue8-${id}`, '--message', 'Run the fixture tool once.', '--timeout', '120', '--json']);
    const [code] = await once(child, 'exit', { signal: AbortSignal.timeout(180000) });
    assert.equal(code, 0, logs.join(''));
    assert.ok(issued, 'local model must issue a real tool call');
    assert.ok(toolReplies.length, 'gateway must return a tool result to the local provider');
    const blocked = /TG-Sentry/.test(JSON.stringify(toolReplies));
    const result = { blocked, body: { toolReplies: [...toolReplies] } };
    results.push({ id, ...result });
    return result;
  }
  const denied = join(workspace, 'denied');
  const deny = await invoke('exec', { command: 'printf DENIED_MARKER > denied' }, 'denied');
  assert.equal(deny.blocked, true, JSON.stringify(deny));
  assert.match(JSON.stringify(deny.body), /TG-Sentry/);
  await assert.rejects(access(denied));
  const benign = join(workspace, 'benign');
  const allow = await invoke('exec', { command: 'printf BENIGN_MARKER > benign' }, 'benign');
  assert.equal(allow.blocked, false, JSON.stringify(allow));
  assert.equal(await readFile(benign, 'utf8'), 'BENIGN_MARKER');
  const read = await invoke('read', { path: join(workspace, 'read.txt') }, 'read');
  assert.equal(read.blocked, false, JSON.stringify(read));
  assert.match(JSON.stringify(read.body), /benign read fixture/);
  assert.equal(seenReviews, 3, 'real gateway must hit real TG-Sentry reviews');
  for (const failure of ['down', 'timeout', 'malformed']) {
    mode = failure;
    const marker = join(workspace, failure);
    const result = await invoke('exec', { command: `printf BENIGN_MARKER > ${failure}` }, failure);
    assert.equal(result.blocked, true, JSON.stringify(result));
    assert.match(JSON.stringify(result.body), /TG-Sentry/);
    await assert.rejects(access(marker));
  }
  console.log(JSON.stringify({ openclaw: '2026.10.4', gateway: 'real agent CLI via gateway + local SSE provider', decisionService: 'real TG-Sentry server.New/core.Engine', results }, null, 2));
} finally {
  proxy.closeAllConnections(); proxy.close(); model.closeAllConnections(); model.close();
  for (const child of children.reverse()) if (child.exitCode === null) child.kill('SIGTERM');
  await writeFile(join(dir, 'gateway.log'), logs.join(''));
  console.error(`Gateway fixture evidence: ${dir}`);
}

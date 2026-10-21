import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL, fileURLToPath } from 'node:url';
import plugin from './index.ts';

const hash = (...parts) => createHash('sha256').update(parts.join('\0')).digest('hex');
const requests = [];
let responseMode = 'approve';
const server = createServer(async (req, res) => {
  let raw = ''; for await (const b of req) raw += b;
  const body = raw ? JSON.parse(raw) : undefined;
  requests.push({ path: req.url, body, auth: req.headers.authorization });
  if (responseMode === 'http') { res.writeHead(503).end(); return; }
  if (responseMode === 'slow') return;
  res.setHeader('content-type', 'application/json');
  if (req.url === '/api/v1/instances') { res.end('{}'); return; }
  if (responseMode === 'malformed') { res.end('{'); return; }
  const id = body ? hash(body.instanceId, body.callId) : req.url.split('/')[4].split('?')[0];
  res.end(JSON.stringify({ id: responseMode === 'wrong-id' ? 'other' : id,
    decision: responseMode === 'unknown' ? 'allow' : responseMode,
    comment: 'fixture decision', ruleId: 'fixture-rule', execution: 'awaiting_execution',
    deadline: new Date(Date.now() + 15000).toISOString() }));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const endpoint = `http://127.0.0.1:${server.address().port}`;
test.after(() => { server.closeAllConnections(); server.close(); });
function register(config = {}, hooks = {}) {
  const handlers = new Map();
  plugin.register({ pluginConfig: { endpoint, token: 'fixture-not-secret', ...config },
    config: { plugins: { entries: { 'tg-sentry': { hooks } } } },
    runtime: { agent: { resolveAgentWorkspaceDir: () => process.cwd() } },
    on: (name, handler, opts) => handlers.set(name, { handler, opts }) });
  return handlers.get('before_tool_call');
}
const ctx = { toolName: 'exec', agentId: 'main', sessionKey: 'agent:main:test', toolCallId: 'call' };
const event = { toolName: 'exec', params: { command: 'printf benign' }, toolCallId: 'call' };
test('typed hook registers native timeout and uses the existing HTTP review contract', async () => {
  responseMode = 'approve'; requests.length = 0;
  const hook = register();
  assert.equal(hook.opts.timeoutMs, 15000);
  assert.equal(await hook.handler(event, ctx), undefined);
  assert.equal(requests[0].path, '/api/v1/instances');
  assert.equal(requests[0].body.agent, 'openclaw');
  assert.equal(requests[1].path, '/api/v1/reviews');
  assert.deepEqual(requests[1].body.argumentsObj, event.params);
  assert.equal(requests[1].auth, 'Bearer fixture-not-secret');
  assert.equal(requests[1].body.toolName, 'exec');
});
test('reject, malformed, mismatched, unknown and HTTP error decisions explicitly block', async () => {
  for (const mode of ['reject', 'malformed', 'wrong-id', 'unknown', 'http']) {
    responseMode = mode;
    const result = await register().handler(event, ctx);
    assert.equal(result.block, true, mode); assert.ok(result.blockReason, mode);
  }
});
test('non-string decision and exec host values fail closed without coercion', async () => {
  for (const decision of [['reject'], ['pending'], ['approve'], { decision: 'approve' }, null]) {
    responseMode = decision;
    const result = await register().handler(event, ctx);
    assert.equal(result?.block, true, JSON.stringify(decision));
  }
  responseMode = 'approve';
  for (const host of [['auto'], ['gateway'], { host: 'auto' }, null]) {
    const result = await register().handler({ ...event, params: { ...event.params, host } }, ctx);
    assert.equal(result?.block, true, JSON.stringify(host));
  }
});
test('service down explicitly blocks', async () => {
  const result = await register({ endpoint: 'http://127.0.0.1:1' }).handler(event, ctx);
  assert.equal(result.block, true);
});
test('HTTP deadline and pending review deadline block within the host budget', async () => {
  for (const mode of ['slow', 'pending']) {
    responseMode = mode;
    const result = await register().handler(event, ctx);
    assert.equal(result.block, true, mode);
  }
});
test('unsafe configuration, missing host identity, remote exec and cancelled calls block', async () => {
  responseMode = 'approve';
  for (const config of [{ endpoint: 'http://remote.invalid' }, { endpoint: `${endpoint}/path` }, { token: '' }]) {
    assert.equal((await register(config).handler(event, ctx)).block, true);
  }
  assert.equal((await register({}, { timeouts: { before_tool_call: 5000 } }).handler(event, ctx)).block, true);
  assert.equal((await register().handler(event, { ...ctx, toolCallId: undefined })).block, true);
  assert.equal((await register().handler({ ...event, params: { command: 'echo remote', host: 'node' } }, ctx)).block, true);
  assert.equal((await register().handler(event, { ...ctx, abortSignal: AbortSignal.abort() })).block, true);
});
test('pinned published runner honors a native veto and configured throw/timeout failure policy', async () => {
  const path = fileURLToPath(new URL('../../.cache/openclaw/package/dist/hooks-CM9Qxrxp.mjs', import.meta.url));
  assert.equal(createHash('sha256').update(await readFile(path)).digest('hex'),
    '3dd10c30b51f4ba7a8f471792d1052a33cc0a0382cc051a8db8411a17cccbf0b');
  const { t: createHookRunner } = await import(pathToFileURL(path).href);
  const { handler, opts } = register();
  const runner = (fn, policy = 'fail-closed') => createHookRunner({ plugins: [], typedHooks: [{ pluginId: 'tg-sentry',
    hookName: 'before_tool_call', handler: fn, ...opts }] }, {
    // Exact initializeGlobalHookRunner policy from the pinned package.
    failurePolicyByHook: { before_tool_call: policy },
  });
  responseMode = 'reject';
  // Fail-open handles thrown/timed-out hooks, never an explicit native veto.
  for (const policy of ['fail-open', 'fail-closed'])
    assert.equal((await runner(handler, policy).runBeforeToolCall(event, ctx)).block, true, policy);
  await assert.rejects(runner(() => { throw Error('fixture failure'); }).runBeforeToolCall(event, ctx), /fixture failure/);
  // Publish the same per-hook 15s budget; no shortened test-only policy value.
  await assert.rejects(runner(() => new Promise(() => {})).runBeforeToolCall(event, ctx), /timed out/);
});

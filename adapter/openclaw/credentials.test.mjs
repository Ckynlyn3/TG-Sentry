// Real pinned OpenClaw host agent turn, adapted from gateway.test.mjs.
// Synthetic credential; assertions/logs never include the injected value.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
const root = fileURLToPath(new URL('../../', import.meta.url));
const pkg = join(root, '.cache/openclaw/package');
const dir = await mkdtemp(join(root, '.cache/openclaw-credentials-'));
const workspace = join(dir, 'workspace');
const plugin = join(dir, 'observer');
await mkdir(join(workspace, 'skills', 'fixture-skill'), { recursive: true });
await mkdir(plugin);
await writeFile(join(plugin, 'package.json'), JSON.stringify({name:'vault-observer',version:'1.0.0',type:'module',openclaw:{extensions:['./index.js']}}));
await writeFile(join(workspace, 'skills', 'fixture-skill', 'SKILL.md'), `---
name: fixture-skill
description: Synthetic credentials fixture.
metadata: {"openclaw":{"primaryEnv":"TG_VAULT_FIXTURE_KEY","requires":{"env":["TG_VAULT_FIXTURE_KEY"]}}}
---
Use the fixture tool. Never print environment values.
`);
await writeFile(join(plugin, 'openclaw.plugin.json'), JSON.stringify({ id: 'vault-observer', activation:{onStartup:true}, configSchema: { type: 'object', additionalProperties: false, properties: {} } }));
// Observe gateway process.env both at a real tool boundary and after completion.
// These hooks use the pinned OpenClaw plugin API, not reimplemented injection.
await writeFile(join(plugin, 'index.js'), `export default { id:'vault-observer', register(api) {
 let injected=false;
 api.on('before_tool_call', () => { injected ||= process.env.TG_VAULT_FIXTURE_KEY === 'synthetic-openclaw-vault-45'; });
 api.registerHttpRoute({path:'/vault-fixture-status',auth:'gateway',match:'exact',handler(_req,res) {
  res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify({injected,restored:process.env.TG_VAULT_FIXTURE_KEY === undefined}));
 }});
}};
`);
const configPath = join(dir, 'openclaw.json');
const children = [];
const logs = [];
const start = (command, args) => {
 const child = spawn(command, args, { cwd: root, env: { ...process.env, HOME: dir,
  OPENCLAW_STATE_DIR: dir, OPENCLAW_CONFIG_PATH: configPath, OPENCLAW_SKIP_CHANNELS: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
 children.push(child);
 child.on('error', error => logs.push(String(error)));
 child.stdout.on('data', b => logs.push(b.toString()));
 child.stderr.on('data', b => logs.push(b.toString()));
 return child;
};
const fixture = start(join(root, '.cache/openclaw/decision-fixture'), [join(dir, 'data'), 'credentials']);
const first = await once(fixture.stdout, 'data', { signal: AbortSignal.timeout(60000) });
const { credentialId, connection } = JSON.parse(first[0].toString());
let issued = false;
let sawTool = false;
const chunk = (delta, finish_reason = null) => `data: ${JSON.stringify({id:'fixture',object:'chat.completion.chunk',created:0,model:'stub-model',choices:[{index:0,delta,finish_reason}]})}\n\n`;
const model = createServer(async (req, res) => {
 let body = ''; for await (const b of req) body += b;
 const payload = JSON.parse(body);
 sawTool ||= (payload.messages ?? []).some(m => m.role === 'tool');
 res.setHeader('content-type','text/event-stream');
 if (!issued) {
  issued = true;
  res.end(chunk({role:'assistant',tool_calls:[{index:0,id:'call_fixture',type:'function',function:{name:'exec',arguments:JSON.stringify({command:'printf fixture-ok'})}}]})+chunk({},'tool_calls')+'data: [DONE]\n\n');
 } else res.end(chunk({role:'assistant',content:'fixture complete'})+chunk({},'stop')+'data: [DONE]\n\n');
});
await new Promise(resolve => model.listen(0,'127.0.0.1',resolve));
const probe = tcpServer(); await new Promise(resolve => probe.listen(0,'127.0.0.1',resolve));
const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
await writeFile(configPath, JSON.stringify({
 gateway:{mode:'local',bind:'loopback',port,auth:{mode:'token',token:'fixture-gateway-token'},tools:{allow:['exec']},controlUi:{enabled:false}},
 agents:{defaults:{workspace,model:{primary:'stub/stub-model'}}},
 models:{providers:{stub:{baseUrl:`http://127.0.0.1:${model.address().port}/v1`,api:'openai-completions',apiKey:'fixture-model-key',models:[{id:'stub-model',name:'Fixture',contextWindow:128000,maxTokens:4096}]}}},
 tools:{profile:'full',codeMode:{enabled:false},exec:{host:'gateway',security:'full',ask:'off'}},
 plugins:{allow:['vault-observer'],load:{paths:[plugin]},entries:{'vault-observer':{enabled:true}}},
 secrets:{providers:{tgsentry:{source:'exec',command:'/opt/vault45/aegishook',args:['client','secret-resolve','--connection',connection,'--agent','main'],jsonOnly:true}}},
 skills:{entries:{'fixture-skill':{apiKey:{source:'exec',provider:'tgsentry',id:credentialId}}}}
}));
try {
 const gateway = start(process.execPath,[join(pkg,'openclaw.mjs'),'gateway','run','--allow-unconfigured','--port',String(port)]);
 // Reuse gateway.test.mjs's sourced 180 s readiness and 250 ms probes.
 const deadline = Date.now()+180000;
 for (;;) {
  if (gateway.exitCode !== null) throw new Error(`gateway exited ${gateway.exitCode}`);
  if (await fetch(`http://127.0.0.1:${port}/health`).then(r=>r.ok).catch(()=>false)) break;
  if (Date.now()>=deadline) throw new Error('gateway readiness timeout');
  await delay(250);
 }
 const status = async () => {
  for (;;) {
   const response = await fetch(`http://127.0.0.1:${port}/vault-fixture-status`,{headers:{Authorization:'Bearer fixture-gateway-token'}});
   if (response.status === 200) return response.json();
   if (response.status !== 503 || Date.now() >= deadline) throw new Error(`observer operational readiness status ${response.status}`);
   await delay(250);
  }
 };
 assert.deepEqual(await status(),{injected:false,restored:true});
 const child = start(process.execPath,[join(pkg,'openclaw.mjs'),'agent','--agent','main','--session-key','agent:main:vault45','--message','Use fixture-skill and run the fixture tool once.','--timeout','120','--json']);
 const [code] = await once(child,'exit',{signal:AbortSignal.timeout(180000)});
 assert.equal(code,0,'real agent CLI failed');
 assert.ok(issued && sawTool,'real tool lifecycle not exercised');
 const observed = await status();
 assert.deepEqual(observed,{injected:true,restored:true},'host env injection/restoration failed');
 assert.ok(!logs.join('').includes('synthetic-openclaw-vault-45'),'runtime logs leaked value');
 console.log(JSON.stringify({openclaw:'2026.10.4',agent:'main',hostTurn:true,sandbox:false,envInjected:observed.injected,envRestored:observed.restored,resolver:'real aegishook exec provider',credentialId}));
} finally {
 model.closeAllConnections(); model.close();
 for (const child of children.reverse()) if (child.exitCode===null) child.kill('SIGTERM');
 // Only persist sanitized diagnostics; the synthetic value still must not leak.
 await writeFile(join(dir,'gateway.log'),logs.join('').replaceAll('synthetic-openclaw-vault-45','[REDACTED]'));
 console.error(`Credential fixture evidence: ${dir}`);
}

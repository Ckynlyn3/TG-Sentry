# TG-Sentry OpenClaw adapter

Native typed `api.on("before_tool_call")` gate, tested with OpenClaw **2026.10.4**.
The package tarball/integrity and source precedents are pinned in
`upstream-lock.json`; the fixture's reused MIT notice is in `NOTICE`.

## Manual installation

Use a TG-Sentry build containing the OpenClaw agent-name registration in this
change. Start its existing decision service normally; this plugin does not
create a second policy engine. Keep the **whole checkout's `adapter/` directory**:
`index.ts` reuses its sibling Pi adapter's stateless script-capture and loopback
validation helpers. This is a repository-linked plugin, not a standalone npm
package. Do not copy only `adapter/openclaw/` to another directory.

With the matching OpenClaw CLI, link the trusted checkout:

```sh
openclaw plugins install --link /absolute/checkout/adapter/openclaw --force
openclaw plugins enable tg-sentry
```

Merge the following into your operator-controlled OpenClaw configuration. Preserve
other plugin allowlist entries. Supply the existing hook token through OpenClaw's
environment substitution; do not commit it or put it on the command line.

```json
{
  "plugins": {
    "allow": ["tg-sentry"],
    "entries": {
      "tg-sentry": {
        "enabled": true,
        "hooks": { "timeouts": { "before_tool_call": 15000 } },
        "config": {
          "endpoint": "https://your-decision-service.example",
          "token": "${TG_SENTRY_HOOK_TOKEN}"
        }
      }
    }
  }
}
```

Local HTTP is accepted only on literal loopback/localhost, matching the existing
adapters; remote services require verified HTTPS. Redirects are forbidden. For a
registered remote TG-Sentry node, also configure its existing `nodeId`.
`before_tool_call` does not need conversation access. Reload the plugin after
source/config changes and confirm an actual denied tool, not just install status.

## Decision and timeout contract

The plugin registers an `openclaw` instance, submits the unchanged native tool
name and arguments to `/api/v1/reviews`, and polls pending reviews. It uses the
same deterministic scopes/rules and configured human/model fallback as the other
adapters. It does not implement a parallel command denylist. Explicit reject,
invalid or replayed approval, expired review, service error, malformed JSON,
redirect, cancelled call, and timeout all return `{block:true, blockReason}`.
Only a matching, complete `approve` with `execution:"awaiting_execution"` permits
the hook; native OpenClaw permissions still apply. Script evidence reuses the
existing capture helper (`exec` is treated as `bash` for capture only).

[OpenClaw's hook contract](https://docs.openclaw.ai/plugins/hooks/reference#registration-and-execution)
defaults this gate to **15000 ms** and blocks on throw/timeout. Operator
`hooks.timeouts.before_tool_call` overrides `hooks.timeoutMs`, which overrides
`api.on`'s authored timeout. Timeout does **not** cancel plugin work. Consequently
this adapter also bounds its **whole HTTP decision lifecycle to 5000 ms** (the
existing Pi HTTP deadline), including body reads and pending polls, and combines
that signal with the host's cancellation signal. An effective host budget of
5000 ms or less is rejected by the gate. Human review that cannot finish within
the decision deadline blocks; increasing only the host timeout does not extend
that deadline. The 500 ms poll and 2 MiB response cap come from the Go bridge.

## Verification

Run from the checkout on the documented Colima host (no globals or real tokens):

```sh
bash adapter/openclaw/test-docker.sh
```

The script verifies the pinned OpenClaw tarball's SHA-512 before extraction, uses
an empty worktree Docker config and container-local dependency installation with
lifecycle scripts disabled, checks against the **published SDK types**, runs the
Node contract/error tests and Go race/vet checks, then drives **real Gateway
agent turns** with a local OpenAI-compatible SSE provider. It uses the real
TG-Sentry HTTP handler/decision engine with synthetic test tokens and explicit
fixture-only rules. Denied exec and each error mode must leave a sentinel absent;
benign exec must write its sentinel, and a native read must return fixture text.
The test does not treat loading, an LLM's claim, or install status as execution
proof. Test state/logs stay under ignored `.cache/openclaw-gateway-*`.

The package's optional OpenTelemetry peer requirements conflict under npm's
strict resolver; the test-only dependency setup uses `--legacy-peer-deps` as a
named local fixture exception. This does not change the pinned OpenClaw bytes,
plugin behavior, or any test assertion. Native exec is not exposed by this
release's `/tools/invoke` implementation despite the broader HTTP documentation;
the harness therefore uses the documented agent CLI and custom-provider path,
not a synthetic call to our handler.

Boundaries: local gateway/auto exec only (no node-host or code-mode exec); missing
host identity blocks. This change covers pre-tool decisions only; it does not
add session/prompt/result telemetry, standalone packaging, auto-installation,
or managed deployment. An unloaded/disabled plugin provides no protection.
Rollback: disable `tg-sentry` and remove its linked installation/config entry;
that deliberately removes this enforcement layer, without modifying policy data.

Sources: [typed hook/tool policy](https://docs.openclaw.ai/plugins/hooks/tool-policy),
[local custom providers](https://docs.openclaw.ai/concepts/model-providers/custom-providers#local-proxies-lm-studio-vllm-litellm-etc),
[agent CLI](https://docs.openclaw.ai/cli/agent), and
[cc-safety-net native adapter/live fixture](https://github.com/kenryu42/cc-safety-net/tree/9ef6d15eeb32ee9aec43d667631a6e9a0aad7da2/src/hosts/openclaw).

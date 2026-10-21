# TG-Sentry Hermes adapter (`pre_tool_call` deny path)

Fail-closed review of every Hermes Agent tool call through the TG-Sentry decision
API. A `reject` verdict blocks the tool; so does a missing, malformed, expired,
mismatched or timed-out answer. Only an explicit `approve` lets the call through,
and Hermes' own permissions still apply.

Contract reused verbatim from `adapter/openclaw` (no new protocol):
`POST /api/v1/instances` → `POST /api/v1/reviews` (`core.ReviewInput`), poll while
`pending`, accept only a matching, unexpired verdict (`internal/core/reviews.go`).

## Install (manual)

Hermes 0.22.2 plugins live in `~/.hermes/plugins/<name>/` and are **opt-in**.

```sh
mkdir -p ~/.hermes/plugins
ln -s "$PWD/adapter/hermes" ~/.hermes/plugins/tg-sentry   # or copy the directory
hermes plugins enable tg-sentry
hermes plugins doctor adapter/hermes --ci
```

`plugin.yaml` declares `pre_tool_call`; the same hook is registered in `register(ctx)`.

## Configuration (environment)

| Variable | Required | Meaning |
|---|---|---|
| `TG_SENTRY_ENDPOINT` | yes | Decision-service base URL. `https://` anywhere; `http://` only on a loopback host (`localhost`, `127.0.0.0/8`, `::1`). No path, query, credentials or fragment. |
| `TG_SENTRY_HOOK_TOKEN` | yes | Hook bearer token. Never logged, never put in a block message. |
| `TG_SENTRY_NODE_ID` | no | 32 lowercase hex characters, when the service enrolled this node. |

Exit codes and general Hermes settings are unchanged by this plugin. Hermes bounds
`pre_tool_call` with `plugins.hook_callback_timeout` (default 30 s); the adapter's
own budget is one monotonic **5000 ms** total across registration, submission,
every poll and every response read, so it always finishes below the host timeout.

## Verify a real denial, not just an install

An enabled plugin is not enforcement. Confirm an actual denied call:

1. Start a decision service with a rejecting rule and point `TG_SENTRY_ENDPOINT`
   and `TG_SENTRY_HOOK_TOKEN` at it.
2. Ask Hermes to run a tool the rule rejects and confirm the tool result is
   `TG-Sentry: <rule comment>` and the side effect did not happen.
3. Ask for an allowed call and confirm it runs.

`adapter/hermes/test_plugin.py` exercises the deny, approve, pending, timeout,
oversized-body, redirect and bad-verdict paths against a local HTTP fixture.
It is stdlib only: `python3 -m unittest adapter/hermes/test_plugin.py` (Python ≥ 3.11).

## Scope (slice 1)

`pre_tool_call` only. `post_tool_call`, `pre_llm_call` (advisory — Hermes gives it
no deny return), `post_llm_call`, script capture for `terminal`, and install
automation are later slices. The hook does not receive a working directory, so
`cwd` is the Hermes process working directory in a local-terminal configuration;
other backends and `TERMINAL_CWD` are out of scope.

## Provenance

Upstream Hermes Agent v0.22.2 (`d923a5eb487a17c0a68801bba9ef0f56c81040a8`, MIT);
mapping precedent Akto `apps/mcp-endpoint-shield/hermes` (MIT) — hook names and
kwarg names only, no code copied, and its fail-open error policy is deliberately
not ported. Pinned references and budget sources: `upstream-lock.json`.

# Protection categories

Same taxonomy as Volcengine AgentSentry's protection-template editor (captured from the live console, 2026-10-19; see [research/FEATURE-INVENTORY.md](research/FEATURE-INVENTORY.md)). Names below are the console's own English labels so a customer moving from AgentSentry sees the same choices.

**Model:** a *template* holds rules from the five categories, each rule with an action; a *policy* binds templates to agents, tags or everyone. Actions: **block** or **alert** (AgentSentry: coding agents support block only — we support alert on both because our hooks can return allow + event). Supply-chain rules act per risk level: block or log only.

Detection order for every check: deterministic rules → BTPII models → LLM judge (ambiguous only). The judge never turns a rule `block` into `allow`.

## 1. Sensitive info (敏感信息防护) — `category::sensitive-info`
| Built-in type | Detection | Validation source |
|---|---|---|
| Bank card number | BTPII | ISO/IEC 7812 Luhn check |
| ID number | BTPII | GB 11643-1999 checksum (18-digit) |
| E-mail address | BTPII | RFC 5322 addr-spec |
| Mobile phone number | BTPII | MIIT number ranges / libphonenumber |
| Other private data | BTPII native API (names, addresses, org, DOB, WeChat ID…) — not available via the `/analyze` compat contract | research/BTPII-NSFA.md §4 |
| Custom | regex + keyword list (thesaurus) | AgentSentry custom rules |

Also: secrets/credentials (API keys, tokens, private keys) — AegisHook's existing secret matchers; AgentSentry lists credential-leak DLP as "coming soon".
Where checked: prompt submit, tool input (file write, network, MCP args), tool output, final response. Redaction of responses/outputs (AgentSentry `REPLACE`) only where the client exposes a synchronous rewrite hook (e.g. OpenClaw `tool_result_persist`, OpenCode plugin text replacement); elsewhere output checks are detection-only. The per-client surfaces, version pins, field-only withholding policy and original-leaf operation are frozen in the [tool-output rewrite contract (#69 S1)](research/AGENT-HOOK-CONTRACTS.md#tool-output-rewrite-contract-69-s1); that design contract is not implemented runtime coverage.
Standards: OWASP LLM02 (Sensitive Information Disclosure); PIPL Art. 28/51; GB/T 35273 App. A/B.

## 2. High-risk operations (高危操作拦截) — `category::high-risk-ops`
| # | Operation | Primary detection |
|---|---|---|
| 1 | Plugin poisoning | supply-chain scan result + install-path rules |
| 2 | Sensitive actions | rules on sensitive paths (`~/.ssh`, credential stores, browser profiles) + judge |
| 3 | Silent exfiltration | shell AST: `curl/wget/nc/scp` with local-file payloads; network tool args |
| 4 | File deletion and system destruction | shell AST: `rm -rf`, `mkfs`, `dd of=/dev/*`, `del /s`, `Format-Volume` |
| 5 | System control and shutdown/restart | `shutdown`, `reboot`, `systemctl`, `launchctl`, `Stop-Computer` |
| 6 | Privilege modification | `chmod/chown` on system paths, `sudo`, `icacls`, UAC bypass patterns |
| 7 | Remote code download and execution | `curl … \| sh`, `iex (iwr …)`, download-then-exec sequences |
| 8 | Reverse connection and remote control | reverse-shell patterns (`bash -i >& /dev/tcp`, `nc -e`), remote-admin tools |
| 9 | User and privilege management | `useradd`, `net user`, `dscl`, group changes |
| 10 | Batch execution and automated destruction | loops/xargs over destructive commands; mass edits |
| 11 | Disabling security plugins | touching TG-Sentry/EDR config, hooks files, services |
| 12 | Public network exposure | binding `0.0.0.0`, tunnels (`ngrok`, `cloudflared`), firewall opens |
| 13 | Internal network scanning | `nmap`, `masscan`, ping sweeps |
| 14 | Persistence | cron, launchd plists, Run keys, scheduled tasks, shell rc edits |
| 15 | Data exfiltration | archive + upload chains, cloud CLI uploads |
| 16 | Toolchain risks | multi-call correlation within a session (e.g. read secret → network send) |
| — | Custom | natural-language behaviour rules judged by LLM (AgentSentry: up to 20, Advanced tier) |

Shell parsing: `mvdan.cc/sh` AST (kept from AegisHook) for POSIX shells; PowerShell/cmd need their own matchers (Windows is a primary platform). Standards: OWASP Agentic ASI02 (tool misuse), ASI03 (privilege compromise), ASI05 (unexpected code execution); MITRE ATLAS AML.T0053, AML.T0086.

## 3. Prompt attack (提示词攻击防护) — `category::prompt-attack`
Fourteen selectable tags. Detection follows the AegisHook / ARTEX / AgentSentry approach (owner decision 2026-10-19):
- **Terminal deterministic patterns** for pinned instruction-override and unrestricted-role phrases, plus execution-context remote-download/execute and raw-disk commands. Encoding, format characters, conversation markers, queried Markdown URLs and bare code APIs are **classifier indicators only**, not standalone blocks. Adversarial prefixes/suffixes have no invented symbol-density threshold.
- **LLM classifier** (self-hosted model by default, #52) that labels input with the 14 tags directly, as Volcengine's LLM Application Firewall does (`/OpenTOP/V1/Lumen/Moderate`, research/FEATURE-INVENTORY.md) and as AegisHook/ARTEX's judge does for tool calls. Selecting a tag in a policy means findings with that tag trigger the action.
- **Optional: NSFA-0.8B sidecar** per tenant (`inclusionAI/SingGuard-NSFA-0.8B`, TG-Java `/classify` contract; research/BTPII-NSFA.md §6). Its three query heads add evidence; they do not provide per-tag labels. The response head (*Inducing harmful content*) is off by default and must be enabled explicitly.

TG-Java's NSFA diagnostics (separate datasets, not comparable across languages): EN detection 88.2% [85.2, 90.7] with benign FP 3.68% [2.37, 5.67]; ZH detection 36.3% [29.8, 43.3] with benign FP 0% [0, 1.10]. That ZH result is why NSFA is optional, not primary.

1. Default tags of prompt injection
2. Role-playing
3. Privilege escalation
4. Adversarial prefix/suffix attack
5. Target hijacking
6. Obfuscation and encoding
7. Few-shot attack
8. Prompt stealing
9. URL rendering and requesting
10. Incomplete inputs
11. Reverse induction
12. Codified description
13. Inducing harmful content
14. Remote code execution

Integrated server checks cover submitted user prompts and tool-review envelopes, plus passive tool-result reporting. Codex/OpenCode prompt-submit is detection-only because no documented prompt-block contract is established (Q4; docs/codex-hooks.md). File-surface detection is available to callers; a skill/memory-file ingestion hook is not claimed. Tool-result/fetched-content findings are observational where the client has no synchronous pre-context intervention hook; this is a documented gap from AgentSentry result blocking. See [rules.md](rules.md#prompt-attack-integration-issue-21) for opt-in rule IDs, deadline propagation, independent findings and the NSFA enforce gate. Per-tag precision/recall comes from the M3 eval (#26), including a Chinese set. Standards: OWASP LLM01; Agentic ASI01 (goal hijack); MITRE ATLAS AML.T0051, AML.T0054, AML.T0057.

## 4. Behavior detection (行为检测) — `category::behavior`
| Rule | What it does (AgentSentry) | MVP |
|---|---|---|
| Sensitivity labeling | Lark doc labels L1–L4 → allow / log / block | later (needs Lark integration) |
| Outgoing file detection | files sent to the model or other services are scanned with category 1 rules | M3 |
| Complex file protection | files > 5 MB or special formats handled specially | M3 (size/type gate; precedent 5 MB from AgentSentry) |

## 5. Supply chain (供应链防护) — `category::supply-chain`
Scan objects: **Skills, Built-in tools, Plugins (scan only, no block), MCP, Memory files (digital-employee agents only)**. Results graded critical / high / medium / low; per grade the action is block or log only. AgentSentry default: critical/high → block, medium/low → log only — we use the same default. As in AgentSentry, built-in tools of coding agents are scan-only (no block), plugins are scan-only, and memory files apply to digital-employee agents only.
Detection: Cisco AI Defense `skill-scanner` and `mcp-scanner` (Apache-2.0) in isolated workers + hash allowlist ("admitted assets"). Standards: OWASP LLM03 (supply chain); OWASP MCP Top 10; Agentic ASI04.

## Controls outside templates
These are separate console pages in AgentSentry and separate features here:
- **Access control (tool ACL)** — subject (all / enrolled-node agents / tags) → allow/deny → tools; deny wins. See the [implementation binding](#tool-acl-implementation-binding-44).
- **Credentials vault** — API key / OAuth2 secrets injected into agents/skills at runtime instead of living in config.
- **Network access** — deny domains/CIDRs per agent (AgentSentry: OpenClaw/Hermes only). Deferred.
- **Log whitelist** — agents/users excluded from audit logging but still blocked on risk.

## Secrets implementation binding (#22)

This binding qualifies the sensitive-info coverage description above; it does not add a sixth template category. The built-in `secret` matcher uses these nine frozen Gitleaks detector IDs under `category::sensitive-info`:

| Rule ID | Detector ID |
|---|---|
| `R_SECRET_AWS_ACCESS_TOKEN` | `aws-access-token` |
| `R_SECRET_GITHUB_PAT` | `github-pat` |
| `R_SECRET_GITHUB_FINE_GRAINED_PAT` | `github-fine-grained-pat` |
| `R_SECRET_GITLAB_PAT` | `gitlab-pat` |
| `R_SECRET_OPENAI_API_KEY` | `openai-api-key` |
| `R_SECRET_ANTHROPIC_API_KEY` | `anthropic-api-key` |
| `R_SECRET_ANTHROPIC_ADMIN_API_KEY` | `anthropic-admin-api-key` |
| `R_SECRET_PRIVATE_KEY` | `private-key` |
| `R_SECRET_JWT` | `jwt` |

All nine default to **`Enabled=true`, `Decision=reject`**, not alert. S4 supersedes the plan's earlier alert default: `normalizeRule` forces recognized secret rules (including template copies resolved through `SourceRuleID`) to `reject`, while preserving enabled state and tool scope. This is a pre-action policy denial, not evidence that an adapter enforced it. **Pattern detected ≠ verified**: no network credential-validity check is performed.

The core scans original review-envelope keys and string values, including arguments, submitted prompt/context and captured scripts, before retention redaction. Core result scanning is observational: a hit omits stored content and preserves the reported execution state; it cannot prevent an already executed tool or prove a client rewrite. The bridge also scans prompts before caching and tool output before masking. **`final_response` remains uncovered**; neither the surface name nor the taxonomy above proves an adapter supplies it. The prompt-cache server handoff is not claimed here while lead investigation is pending.

Named local exceptions: `secret-rule-subset` selects only these nine detectors (no Slack rules); `secret-allowlist-no-path` retains upstream content allowlists/stopwords but omits path/commit checks for runtime text; `secret-result-span-omitted` omits spans from core result findings. Core review-envelope findings likewise omit original-leaf locations rather than mislabel them as envelope offsets.

Sources: `internal/core/policy.go` (`secretRules`, `secretRulePattern`, `normalizeRule`), `sensitive_review.go` (`secretSensitiveResult`), `reviews.go` (`Result`), `internal/bridge/bridge.go`; detector patterns/allowlists from [Gitleaks config at b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml), pinned in `internal/secrets/rules.go` and `allowlist.go`. See [event binding](EVENT-SCHEMA.md#secret-finding-event-binding-issue-22) for what is actually emitted.

## Tool ACL implementation binding (#44)

ACL is an **authorization control outside the five template categories**, not a detector category. Subjects are `all`, enrolled-node `agents`, or `tags`; targets are all tools or exact hook tool-name strings. Enabled matching deny beats allow; the lowest matching rule ID for the winning effect supplies deterministic provenance. With no matching permit, access is denied (XACML 3.0 Appendix C deny-overrides / deny-unless-permit, OWASP ASVS 4.0.3 V4.1.3/V4.1.5).

**Default lifecycle (S2a/A5):** while `ACL.Initialized=false`, `EffectiveACLRules` returns the virtual enabled `acl-default-all-pass` (`all → allow → all tools`). There is no engine-open ACL seed, ACL revision change or initialization audit. First confirmed ACL publication materializes `Initialized=true` and stored rules. Deleting the last rule, including the virtual default, persists an initialized-empty ACL that denies all and is not reseeded on restart. This supersedes the plan's one-time engine-open seeding wording; unrelated template/policy publications do not materialize the default. The list/detail API exposes this distinction as `virtualDefault`.

After scope checks, ACL deny returns terminal `reject`, `reviewPath="acl"`, and the matching `ruleId` (empty for implicit deny), without human/model authorization. ACL allow only continues existing safety checks; it cannot override their denial. Sensitive-info omission and independent custom findings remain active. The ACL verdict itself is audit-only, not a `risk.v1` finding; see [event binding](EVENT-SCHEMA.md#tool-acl-decision-and-event-binding-issue-44).

Offline remains **fail-closed**, not offline ACL evaluation: ACL is absent from signed bundle rules, cached rules can only deny, and a non-match cannot authorize. V1 trusts the adapter to report the tool name faithfully; it has no rename-resistant or MCP-server-qualified identity, wildcard syntax or `users` subject. A renamed tool can miss a per-tool deny and match a broad allow.

Sources: `internal/core/acl.go` (`EvaluateACL`), `types.go`, `protection.go` (`EffectiveACLRules`, `reviewACL`, `ConfirmProtection`), `reviews.go`, `events.go`, `policy_bundle.go` (`PolicyBundleDeny`); `internal/bridge/bridge.go` offline denial path; `internal/server/acl.go` and [protection OpenAPI](design/protection.openapi.json). ACL console work remains [planned (S5)](design/CONSOLE-DESIGN.md#tool-acl-console-issue-44--planned-s5).

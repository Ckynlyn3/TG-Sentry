package core

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Modified upstream fragments: see THIRD_PARTY_NOTICES.md. These match explicit
// phrases, not intent. Complete phrases in quotes/negations can still match;
// this layer does not promise semantic disambiguation or benchmark recall.
//
// Tag coverage (issue #21 plan §§1–2; no sources were taken from eval items):
//
//	1 default-prompt-injection   EN terminal: Rebuff/Vigil override, AgentSentry bypass; ZH indicator only
//	2 role-playing               terminal: AgentSentry unrestricted-role phrase
//	3 privilege-escalation       classifier-only: no pinned explicit mode-switch list
//	4 adversarial-prefix-suffix  classifier-only: plan §1 (no documented pattern)
//	5 target-hijacking           classifier-only: no pinned imperative phrase list
//	6 obfuscation-encoding       indicator: LLM Guard Cf; RFC 4648/3986; Go hex syntax
//	7 few-shot-attack            indicator: Vigil role markers; Microsoft mockup
//	8 prompt-stealing            classifier-only: no pinned imperative phrase list
//	9 url-rendering              indicator: Vigil Markdown query URL
//
// 10 incomplete-inputs          classifier-only: plan §1 (payload splitting)
// 11 reverse-induction          classifier-only: plan §1 (AML.T0054)
// 12 codified-description       classifier-only: plan §1 (OWASP LLM01)
// 13 inducing-harmful-content   classifier-only: plan §1 (Llama Guard taxonomy)
// 14 remote-code-execution      terminal: existing remote-exec/disk-write; bare APIs indicator only
//
// Source-gap check for tags 3/5/8 and Python exec literals: Rebuff's heuristic
// list, Vigil data/yara/*.yar, LLM Guard ban_substrings.py:12–35 and model-only
// prompt_injection.py:119–195, AgentSentry detect.ts:74–83 at the pinned commits
// below contain no suitable list. Broad nouns are deliberately not terminal.
var promptAttackPatterns = []struct {
	id, tag string
	re      *regexp.Regexp
}{
	// source: protectai/rebuff@4d2fe064abf164e7381556d23e48e210080f8afa:python-sdk/rebuff/detect_pi_heuristics.py:16–69; deadbits/vigil-llm@f2b4c134d060bae81d29fad07003f3c657e63fc8:data/yara/instruction_bypass.yar:9.
	// source: ling101w/AgentSentry-@50553611c7eb4a25fdfdde37934c1b919a9dcd3e:openclaw-plugin/core/detect.ts:75,81 (all qualifier). Narrowed to prior instructions; broad ZH forms are indicators below.
	// taxonomy: OWASP LLM01:2025; Microsoft Prompt Shields "attempt to change system rules"; AML.T0051.
	{"instruction-override", "default-prompt-injection", regexp.MustCompile(`\b(?:ignore|disregard|skip|forget|neglect|overlook|omit|bypass|pay no attention to|do not follow|do not obey) (?:all )?(?:prior|previous|preceding|above|foregoing|earlier|initial) (?:instructions?|directives?|commands?)\b`)},
	// source: ling101w/AgentSentry-@50553611c7eb4a25fdfdde37934c1b919a9dcd3e:openclaw-plugin/core/detect.ts:78,81 (32 gap unchanged).
	// taxonomy: OWASP LLM01:2025; Microsoft Prompt Shields "attempt to change system rules".
	{"safety-bypass", "default-prompt-injection", regexp.MustCompile(`\bbypass (?:policy|guardrail|safety|restriction)\b`)},
	// source: ling101w/AgentSentry-@50553611c7eb4a25fdfdde37934c1b919a9dcd3e:openclaw-plugin/core/detect.ts:79,76 (role phrase; bilingual style and 48 gap). ZH translated, not a new role list.
	// taxonomy: Microsoft Prompt Shields "Role-Play"; AML.T0054.
	{"unrestricted-role", "role-playing", regexp.MustCompile(`\bact as (?:an? )?(?:unfiltered|jailbroken|developer mode)\b|(?:扮演|假装|你现在是).{0,48}(?:不受限制|已越狱|开发者模式)`)},
}

var promptAttackIndicators = []struct {
	kind, tag, surface string
	re                 *regexp.Regexp
}{
	// source: ling101w/AgentSentry-@50553611c7eb4a25fdfdde37934c1b919a9dcd3e:openclaw-plugin/core/detect.ts:81 (32 gap unchanged; prior-instruction translation from Rebuff verbs/objects).
	// taxonomy: OWASP LLM01:2025; Microsoft "attempt to change system rules". Broad ZH gaps cannot distinguish closing alerts/windows or ignoring blank lines; classifier evidence only (S1 review fix).
	{"chinese-override", "default-prompt-injection", "", regexp.MustCompile(`(?:忽略|绕过|禁用|关闭).{0,32}(?:安全策略|策略|规则|限制|防护|审计|监督)|忽略.{0,32}(?:之前|先前|上面)的?(?:指令|规则|命令)`)},
	// source: issue21-prompt-attack-plan.md "Lead amendment — over-engineering audit" (38ca591f5d783921e550612eed17c43be50756e7529ce62893d8fe4ecde319b7): bare os.system(/subprocess/eval(/__import__ occurrences.
	// taxonomy: OWASP LLM01:2025; an API mention is not injection. Classifier evidence only, never a terminal finding.
	{"code-literals", "remote-code-execution", "", regexp.MustCompile(`\bos\.system\s*\(|\bsubprocess\b|\beval\s*\(|\b__import__\b`)},
	// source: RFC 4648 §4 (four-character Base64 quanta, two/three-character final padded quantum); RFC 3986 §2.1 (percent triplet); https://go.dev/ref/spec#Integer_literals (0x hex prefix).
	// taxonomy: OWASP LLM01:2025 obfuscation; Microsoft Prompt Shields "Encoding attacks". Lexical candidates only: no length cutoff, decoding, or validity claim.
	{"encoded-text", "obfuscation-encoding", "", regexp.MustCompile(`(?:[a-z0-9+/]{4})*(?:[a-z0-9+/]{2}==|[a-z0-9+/]{3}=)|(?:%[0-9a-f]{2})+|\b0x[0-9a-f]+\b`)},
	// source: deadbits/vigil-llm@f2b4c134d060bae81d29fad07003f3c657e63fc8:data/yara/system_instructions.yar:12–16; issue #21 plan §1 tag 7 (User/Assistant/Human and 用户/助手 labels).
	// taxonomy: Microsoft Prompt Shields "embedding a conversation mockup". One marker is evidence, never a terminal threshold.
	{"conversation-markers", "few-shot-attack", "", regexp.MustCompile(`(?:^| )(?:user|assistant|human|用户|助手):|<\|im_start\|>|\[inst\]`)},
	// source: deadbits/vigil-llm@f2b4c134d060bae81d29fad07003f3c657e63fc8:data/yara/mdexfil.yar:10 (adapt image-only q= form to image/link query URL, plan §1 tag 9).
	// taxonomy: OWASP LLM01:2025 indirect injection / Markdown exfiltration. Ordinary queried links also match, so evidence only.
	{"markdown-query-url", "url-rendering", "", regexp.MustCompile(`!?\[[^\]]*\]\(https?://[^\s)]+\?[^\s)]*\)`)},
	// source: issue21-prompt-attack-plan.md §1 tag 9 (fetch/visit URL in tool_result); RFC 3986 §3 (URL scheme).
	// taxonomy: Microsoft Prompt Shields document "information gathering"; OWASP LLM01:2025 indirect injection. ZH translated; no terminal phrase claim.
	{"url-request", "url-rendering", "tool_result", regexp.MustCompile(`(?:\b(?:fetch|visit)\b|访问|请求).*(?:https?://)`)},
}

// Normalize only a copy. source: Unicode UAX #15 (NFKC); Rebuff pinned
// detect_pi_heuristics.py:97–107 (lowercase/whitespace); LLM Guard pinned
// invisible_text.py:21,31–37 (Cf removal, restricted to Cf by plan §2).
func normalizePromptAttackText(text string) string {
	text = strings.ToLower(norm.NFKC.String(text))
	text = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, text)
	return strings.Join(strings.Fields(text), " ")
}

// scanPromptAttackPatterns is deliberately policy-free. S4 attributes tags to
// enabled effective rules and merges decisions. Indicators are never findings;
// neither source text nor normalized offsets are returned or persisted here.
func scanPromptAttackPatterns(in PromptAttackInput) PromptAttackResult {
	text := normalizePromptAttackText(in.Text)
	out := PromptAttackResult{}
	seen := map[string]bool{}
	add := func(tag string) {
		if !seen[tag] {
			out.Findings = append(out.Findings, PromptAttackFinding{Category: "category::prompt-attack", Tag: tag, Type: "pattern", Score: 1})
			seen[tag] = true
		}
	}
	for _, p := range promptAttackPatterns {
		if p.re.MatchString(text) {
			add(p.tag)
		}
	}
	// source: protectai/llm-guard@168c1034ffdb33837e7ae6fd6a16b80567c1be03:llm_guard/input_scanners/invisible_text.py:21,31–37.
	// taxonomy: Microsoft "Encoding attacks"; Unicode §23.9 (tag characters are Cf). Inspect original before stripping.
	if strings.ContainsFunc(in.Text, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) {
		out.Evidence = append(out.Evidence, PromptAttackEvidence{Type: "indicator:format-characters", Tag: "obfuscation-encoding", Score: 1})
	}
	for _, p := range promptAttackIndicators {
		if (p.surface == "" || p.surface == in.Surface) && p.re.MatchString(text) {
			out.Evidence = append(out.Evidence, PromptAttackEvidence{Type: "indicator:" + p.kind, Tag: p.tag, Score: 1})
		}
	}
	if promptAttackRCE(in.Text) {
		add("remote-code-execution")
	}
	return out
}

func promptAttackRCE(text string) bool {
	// source: TG-Sentry@9d9d97cca794e1e57860635d14bc0107cd121117:internal/core/rule_matchers.go:131–139,205–210,272–273; internal/core/high_risk_shell.go:286–290.
	// taxonomy: OWASP LLM01:2025 code injection / LLM05. Reuse parsed remote
	// execution and raw-disk writes only, not generic dangerous commands or
	// network-to-network pipes. Preserve original comments, newlines and quotes:
	// normalizing shell whitespace first would change executable syntax.
	in := ReviewInput{ToolName: "bash", Arguments: map[string]any{"command": text}}
	// This indicator needs a confident effect; parse errors are not RCE findings.
	hits, _ := detailedBuiltinMatches(in, "", func(p, _ string) string { return p }, "linux")
	return hits["R_HIGH_RISK_REMOTE_EXEC"] != "" || hits["R_SYS_DD"] != ""
}

package core

import "time"

// ReviewHookBudget is the shared AgentSentry-derived hook ceiling, below the
// 5-second host timeout: docs/research/ENDPOINT-RUNTIME-AgentSentry.md §§4–5.
// Named local exception review-hook-budget; issue #21 plan §§3, 10.
// A variable only so a CPU-bound test under -race can widen both the bridge
// and server deadlines at once (mirror CI 39567422399, 39570619178).
var ReviewHookBudget = 4500 * time.Millisecond

// PromptAttackInput mirrors the detector input without retaining text in JSON.
type PromptAttackInput struct {
	Text     string `json:"-"`        // Plan §§3, 5: ephemeral, original detection input.
	Language string `json:"language"` // Plan §5: detector language.
	Surface  string `json:"surface"`  // Plan §5: prompt, tool_result, or file.
	Tenant   string `json:"tenant"`   // Plan §5: detector tenant.
}

// PromptAttackSpan mirrors eval.Span without importing the consumer package.
// Plan §§2, 5: normalization changes offsets, so #21 always leaves it zero-valued.
type PromptAttackSpan struct {
	StartUTF16 int `json:"start_utf16"` // Plan §5: compatibility coordinate, always zero.
	EndUTF16   int `json:"end_utf16"`   // Plan §5: compatibility coordinate, always zero.
}

// PromptAttackFinding identifies a tag and the effective rule that matched it.
type PromptAttackFinding struct {
	Category         string  `json:"category"` // Plan §5: category::prompt-attack.
	Tag              string  `json:"tag"`      // Plan §§1, 5: one of the fourteen slugs.
	PromptAttackSpan         // Plan §§2, 5: empty compatibility span.
	Type             string  `json:"type,omitempty"`         // Plan §§5, 10: pattern, classifier, or nsfa source.
	Score            float64 `json:"score"`                  // Plan §§4, 5: source score.
	RuleID           string  `json:"ruleId,omitempty"`       // Plan §§5, 10: matched effective rule ID.
	SourceRuleID     string  `json:"sourceRuleId,omitempty"` // Plan §5: builtin identity only.
}

// PromptAttackEvidence also retains NSFA heads that have no prompt-attack tag.
type PromptAttackEvidence struct {
	Type  string  `json:"type"`           // Plan §4: evidence source/type.
	Score float64 `json:"score"`          // Plan §4: head probability.
	Tag   string  `json:"tag,omitempty"`  // Plan §4: optional mapped tag.
	Head  string  `json:"head,omitempty"` // Plan §10: head identity for finding occurrence IDs.
}

// PromptAttackResult adds evidence to the field-for-field detector result.
type PromptAttackResult struct {
	Findings    []PromptAttackFinding  `json:"findings"`           // Plan §5: matched tag findings.
	Evidence    []PromptAttackEvidence `json:"evidence,omitempty"` // Plan §§4, 5: includes evidence-only heads.
	Decision    string                 `json:"decision"`           // Plan §5: detector decision, not independent authorization.
	Unavailable bool                   `json:"unavailable"`        // Plan §§3–5: incomplete detection is never clean.
	Reason      string                 `json:"reason,omitempty"`   // Plan §§3–5: unavailable or skipped reason.
}

// Display names come from docs/PROTECTION-CATEGORIES.md §3; slugs and rule IDs
// are fixed by issue21-prompt-attack-plan.md §1.
var promptAttackTags = []struct{ displayName, slug, ruleID string }{
	{"Default tags of prompt injection", "default-prompt-injection", "R_PA_DEFAULT"},
	{"Role-playing", "role-playing", "R_PA_ROLEPLAY"},
	{"Privilege escalation", "privilege-escalation", "R_PA_PRIVESC"},
	{"Adversarial prefix/suffix attack", "adversarial-prefix-suffix", "R_PA_ADVERSARIAL"},
	{"Target hijacking", "target-hijacking", "R_PA_HIJACK"},
	{"Obfuscation and encoding", "obfuscation-encoding", "R_PA_ENCODING"},
	{"Few-shot attack", "few-shot-attack", "R_PA_FEWSHOT"},
	{"Prompt stealing", "prompt-stealing", "R_PA_STEALING"},
	{"URL rendering and requesting", "url-rendering", "R_PA_URL"},
	{"Incomplete inputs", "incomplete-inputs", "R_PA_INCOMPLETE"},
	{"Reverse induction", "reverse-induction", "R_PA_REVERSE"},
	{"Codified description", "codified-description", "R_PA_CODIFIED"},
	{"Inducing harmful content", "inducing-harmful-content", "R_PA_HARMFUL"},
	{"Remote code execution", "remote-code-execution", "R_PA_RCE"},
}

// Plan §2: tag rules are opt-in; S0 does not add them to BuiltinRules.
func promptAttackRules() []Rule {
	rules := make([]Rule, 0, len(promptAttackTags))
	for _, tag := range promptAttackTags {
		rules = append(rules, Rule{ID: tag.ruleID, Name: tag.displayName, Decision: "reject", Builtin: true,
			Matcher: "prompt-attack", Pattern: tag.slug, Target: "arguments", Categories: []string{"category::prompt-attack"}})
	}
	return rules
}

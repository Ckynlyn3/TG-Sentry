package core

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPromptAttackTags(t *testing.T) {
	// Slugs and rule IDs are fixed by issue21-prompt-attack-plan.md §1.
	want := []struct{ slug, ruleID string }{
		{"default-prompt-injection", "R_PA_DEFAULT"},
		{"role-playing", "R_PA_ROLEPLAY"},
		{"privilege-escalation", "R_PA_PRIVESC"},
		{"adversarial-prefix-suffix", "R_PA_ADVERSARIAL"},
		{"target-hijacking", "R_PA_HIJACK"},
		{"obfuscation-encoding", "R_PA_ENCODING"},
		{"few-shot-attack", "R_PA_FEWSHOT"},
		{"prompt-stealing", "R_PA_STEALING"},
		{"url-rendering", "R_PA_URL"},
		{"incomplete-inputs", "R_PA_INCOMPLETE"},
		{"reverse-induction", "R_PA_REVERSE"},
		{"codified-description", "R_PA_CODIFIED"},
		{"inducing-harmful-content", "R_PA_HARMFUL"},
		{"remote-code-execution", "R_PA_RCE"},
	}
	doc, err := os.ReadFile("../../docs/PROTECTION-CATEGORIES.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "## 3. Prompt attack")
	if !ok {
		t.Fatal("prompt attack taxonomy section missing")
	}
	section, _, ok = strings.Cut(section, "## 4.")
	if !ok {
		t.Fatal("prompt attack taxonomy section end missing")
	}
	names := regexp.MustCompile(`(?m)^\d+\. (.+)$`).FindAllStringSubmatch(section, -1)
	if len(promptAttackTags) != 14 || len(names) != len(want) {
		t.Fatalf("tag counts: table=%d doc=%d want=%d", len(promptAttackTags), len(names), len(want))
	}
	slugs, ids := map[string]bool{}, map[string]bool{}
	for i, tag := range promptAttackTags {
		if tag.displayName != names[i][1] || tag.slug != want[i].slug || tag.ruleID != want[i].ruleID {
			t.Errorf("tag %d: got %+v; want %q / %+v", i+1, tag, names[i][1], want[i])
		}
		if slugs[tag.slug] || ids[tag.ruleID] {
			t.Errorf("duplicate slug or rule ID: %+v", tag)
		}
		slugs[tag.slug], ids[tag.ruleID] = true, true
	}
}

func TestPromptAttackRules(t *testing.T) {
	rules := promptAttackRules()
	if len(rules) != len(promptAttackTags) {
		t.Fatalf("rules=%d tags=%d", len(rules), len(promptAttackTags))
	}
	for i, tag := range promptAttackTags {
		want := Rule{ID: tag.ruleID, Name: tag.displayName, Decision: "reject", Builtin: true,
			Matcher: "prompt-attack", Pattern: tag.slug, Target: "arguments", Categories: []string{"category::prompt-attack"}}
		if !reflect.DeepEqual(rules[i], want) {
			t.Errorf("rule %d: got %+v; want %+v", i+1, rules[i], want)
		}
	}
	// Each caller owns its rule/category slices; edits cannot alter the catalog.
	rules[0].Categories[0] = "changed"
	if fresh := promptAttackRules(); fresh[0].Categories[0] != "category::prompt-attack" {
		t.Fatal("prompt attack rule categories shared between calls")
	}
	var integrated []Rule
	for _, rule := range BuiltinRules() {
		if rule.Matcher == "prompt-attack" {
			integrated = append(integrated, rule)
		}
	}
	wantIntegrated := promptAttackRules()
	for i := range wantIntegrated {
		wantIntegrated[i] = normalizeRule(wantIntegrated[i])
	}
	if !reflect.DeepEqual(integrated, wantIntegrated) {
		t.Fatal("S4 builtin prompt-attack catalog differs from fixed opt-in tag rules")
	}
}

func TestReviewHookBudget(t *testing.T) {
	// Existing bridge budget: docs/research/ENDPOINT-RUNTIME-AgentSentry.md §§4–5.
	if ReviewHookBudget != 4500*time.Millisecond {
		t.Fatalf("hook budget=%s; want 4500ms", ReviewHookBudget)
	}
}

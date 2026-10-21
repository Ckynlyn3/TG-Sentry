package core

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func promptFindingInput(t *testing.T, status string, entity string) ReviewInput {
	t.Helper()
	wire := map[string]any{"toolName": "Read", "argumentsObj": map[string]any{}, "userMessage": "[REDACTED]", "prompt_scan": map[string]any{"status": status, "findings": []any{map[string]any{"entity_type": entity, "surface": "prompt"}}}}
	body, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var in ReviewInput
	if err := json.Unmarshal(body, &in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestPromptScanUsesExistingSecretRuleSelection(t *testing.T) {
	for _, preset := range secretRules() {
		for _, variant := range []string{"default", "template", "disabled", "other-tool"} {
			t.Run(preset.Pattern+"/"+variant, func(t *testing.T) {
				rule := preset
				switch variant {
				case "template":
					rule.ID, rule.SourceRuleID = "T_fixture_"+preset.ID, preset.ID
				case "disabled":
					rule.Enabled = false
				case "other-tool":
					rule.Tool = "Write"
				}
				prompt := promptFindingInput(t, "Complete", preset.Pattern)
				tool := ReviewInput{ToolName: "Read", Arguments: map[string]any{"text": runtimeSecretCandidate(preset.Pattern)}}
				got := secretSensitiveResult(context.Background(), prompt, []Rule{rule})
				want := secretSensitiveResult(context.Background(), tool, []Rule{rule})
				if !reflect.DeepEqual(got, want) {
					t.Fatal("prompt metadata and original tool secret use different rule selection")
				}
				if (variant == "default" || variant == "template") && (got == nil || got.RuleID != rule.ID || got.Decision != "reject") {
					t.Fatal("enabled prompt secret did not use the existing reject default")
				}
			})
		}
	}
}

func TestPromptScanReplayIdentity(t *testing.T) {
	for _, status := range []string{"Complete", "Interrupted"} {
		t.Run(status, func(t *testing.T) {
			e := engine(t)
			in := input("prompt-replay", "Read", map[string]any{})
			first, err := e.Submit(in)
			if err != nil || first.Decision != "approve" {
				t.Fatal("clean baseline did not approve")
			}
			same, err := e.Submit(in)
			if err != nil || same.ID != first.ID || same.Digest != first.Digest || same.Decision != first.Decision || same.RuleID != first.RuleID {
				t.Fatal("identical clean replay was not idempotent")
			}
			changed := in
			changed.PromptScan = promptFindingInput(t, status, "github-pat").PromptScan
			got, err := e.Submit(changed)
			if err == nil || got.Decision == "approve" {
				t.Fatal("changed prompt scan replay reused cached approval")
			}
			changed.CallID = "prompt-replay-" + status
			denied, err := e.Submit(changed)
			if err != nil || denied.Decision != "reject" {
				t.Fatal("new prompt finding did not reject")
			}
			replayed, err := e.Submit(changed)
			if err != nil || replayed.ID != denied.ID || replayed.Digest != denied.Digest || replayed.Decision != denied.Decision || replayed.RuleID != denied.RuleID {
				t.Fatal("identical prompt metadata replay was not idempotent")
			}
		})
	}
}

func TestPromptScanRejectsAmbiguousJSON(t *testing.T) {
	for _, wire := range []string{
		`{"status":"Interrupted","status":"Complete","findings":[]}`,
		`{"status":"Complete","findings":[{"entity_type":"github-pat","surface":"prompt"}],"findings":[]}`,
		`{"status":"Complete","findings":[{"entity_type":"github-pat","entity_type":"jwt","surface":"prompt"}]}`,
		`{"status":"Complete"}`,
		`{"status":"Complete","findings":null}`,
	} {
		var scan PromptScan
		if err := json.Unmarshal([]byte(wire), &scan); err == nil {
			t.Fatal("ambiguous or incomplete prompt scan JSON was accepted")
		}
	}
}

func TestDecodeReviewJSONKeepsCaseDistinctArgumentKeys(t *testing.T) {
	var in ReviewInput
	if err := DecodeReviewJSON([]byte(`{"toolName":"Read","argumentsObj":{"data":{"ID":"one","id":"two"}}}`), &in); err != nil {
		t.Fatalf("case-distinct argument keys rejected: %v", err)
	}
	if got := in.Arguments["data"]; !reflect.DeepEqual(got, map[string]any{"ID": "one", "id": "two"}) {
		t.Fatalf("argument keys merged: %#v", got)
	}
	if err := DecodeReviewJSON([]byte(`{"toolName":"Read","argumentsObj":{"id":"one","id":"two"}}`), &in); err == nil {
		t.Fatal("exact duplicate argument key accepted")
	}
	if err := DecodeReviewJSON([]byte(`{"toolName":"Read","argumentsObj":{},"prompt_scan":{"status":"Complete","Status":"Interrupted","findings":[]}}`), &in); err == nil {
		t.Fatal("case-alias prompt_scan metadata accepted")
	}
}

func TestPromptScanInterruptedFailsClosed(t *testing.T) {
	in := promptFindingInput(t, "Interrupted", "github-pat")
	decision, result := reviewSensitiveContext(context.Background(), in, secretRules(), BTPIIConfig{}, nil)
	if decision == nil || decision.Decision != "reject" || decision.RuleID != "E_SECRET_SCAN" || result == nil || !result.Unavailable || len(result.Findings) != 0 {
		t.Fatal("interrupted prompt scan was reported as clean or retained partial findings")
	}
}

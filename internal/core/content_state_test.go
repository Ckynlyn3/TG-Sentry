package core

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestReviewContentStates(t *testing.T) {
	clean := &SensitiveResult{}
	finding := &SensitiveResult{Findings: []SensitiveFinding{{Category: SensitiveInfoCategory}}}
	for _, tc := range []struct {
		name          string
		review        Review
		input, output string
	}{
		{"raw retained", Review{ReviewInput: ReviewInput{Arguments: map[string]any{"value": "safe"}}, Result: "safe", Execution: "succeeded"}, "captured", "captured"},
		{"empty arguments", Review{ReviewInput: ReviewInput{Arguments: map[string]any{}}, Execution: "awaiting_execution"}, "captured", "not_yet_available"},
		{"empty succeeded output", Review{Execution: "succeeded"}, "never_captured", "captured"},
		{"empty failed output", Review{Execution: "failed"}, "never_captured", "captured"},
		{"never captured", Review{Decision: "reject", Execution: "not_executed"}, "never_captured", "never_captured"},
		{"user message", Review{ReviewInput: ReviewInput{UserMessage: "safe"}}, "captured", "never_captured"},
		{"context", Review{ReviewInput: ReviewInput{Context: "safe"}}, "captured", "never_captured"},
		{"script metadata", Review{ReviewInput: ReviewInput{Scripts: []ReviewScript{{Path: "safe.sh"}}}}, "captured", "never_captured"},
		{"clean sensitive partial", Review{ReviewInput: ReviewInput{Arguments: map[string]any{}}, SensitiveInfo: clean, Result: "[REDACTED]", Execution: "succeeded"}, "captured", "policy_omitted"},
		{"findings omission", Review{SensitiveInfo: finding, Result: "[REDACTED]", Execution: "succeeded"}, "policy_omitted", "policy_omitted"},
		{"unavailable omission", Review{SensitiveInfo: &SensitiveResult{Unavailable: true}, Execution: "not_executed"}, "policy_omitted", "never_captured"},
		{"reason omission", Review{SensitiveInfo: &SensitiveResult{Reason: "skipped"}, Execution: "not_executed"}, "policy_omitted", "never_captured"},
		{"pending", Review{ReviewInput: ReviewInput{Arguments: map[string]any{}}, Decision: "pending", Execution: "not_executed"}, "captured", "not_yet_available"},
		{"awaiting", Review{Execution: "awaiting_execution"}, "never_captured", "not_yet_available"},
		{"sensitive pending", Review{SensitiveInfo: finding, Decision: "pending", Execution: "not_executed"}, "policy_omitted", "not_yet_available"},
		{"sensitive awaiting", Review{ReviewInput: ReviewInput{Arguments: map[string]any{}}, SensitiveInfo: clean, Execution: "awaiting_execution"}, "captured", "not_yet_available"},
		{"sensitive empty terminal", Review{SensitiveInfo: clean, Execution: "succeeded"}, "never_captured", "policy_omitted"},
		{"result precedes pending", Review{SensitiveInfo: clean, Result: "[REDACTED]", Decision: "pending"}, "never_captured", "policy_omitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(ReviewListView(tc.review))
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got["inputState"] != tc.input || got["outputState"] != tc.output {
				t.Fatalf("states = %v / %v, want %s / %s", got["inputState"], got["outputState"], tc.input, tc.output)
			}
		})
	}
}

func TestReviewListViewDoesNotMutateContent(t *testing.T) {
	r := Review{ReviewInput: ReviewInput{Scripts: []ReviewScript{{Path: "safe.sh", Content: "echo safe"}}}, ModelInput: json.RawMessage(`{"safe":true}`)}
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	view := ReviewListView(r)
	after, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("response projection mutated stored input")
	}
	if view.Scripts[0].Content != "" || view.ModelInput != nil {
		t.Fatal("list projection retained detailed model/script content")
	}
}

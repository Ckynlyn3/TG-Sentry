package server

import (
	"context"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"aegishook/internal/core"
	"aegishook/internal/secrets"
)

func TestSecretActiveRulesTestHTTP(t *testing.T) {
	// Same in-memory-only fixture seed/alphabet/length as core/policy_test.go
	// and secrets/fixture_test.go; never a provisioned credential.
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rng := rand.New(rand.NewSource(22))
	var text strings.Builder
	text.WriteString("ghp_")
	for range 36 {
		text.WriteByte(alphabet[rng.Intn(len(alphabet))])
	}
	candidate := text.String()
	findings, status := secrets.Scan(context.Background(), candidate)
	if status != secrets.Complete || len(findings) != 1 || findings[0].RuleID != "github-pat" {
		t.Fatal("HTTP regression requires a positive secret fixture")
	}
	h := newProtectionHTTP(t)
	for _, args := range []map[string]any{{"text": candidate}, {candidate: "benign"}} {
		// Exercise the actual authenticated route that loads Engine.Rules and
		// calls core.Evaluate, not a test-only evaluator wrapper.
		got := h.call("POST", "/api/v1/rules/test", core.ReviewInput{ToolName: "fixture", Arguments: args}, 200, "")
		if got["decision"] != "reject" || got["ruleId"] != "R_SECRET_GITHUB_PAT" {
			t.Error("rules/test failed to deny a secret")
		}
		raw, err := json.Marshal(got)
		if err != nil || strings.Contains(string(raw), candidate) {
			t.Fatal("rules/test response leaked secret")
		}
	}
	got := h.call("POST", "/api/v1/rules/test", core.ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": "benign"}}, 200, "")
	if got["decision"] != "pending" {
		t.Fatal("benign rules/test control changed")
	}
}

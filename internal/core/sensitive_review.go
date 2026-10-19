package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"aegishook/internal/secrets"
)

// The existing scope/rule engine decides custom regex/keyword matches on the
// original selected field. BTPII is only called after deterministic rules and
// never replaces a deny. Tenant selection is store-owned, not caller-provided.
func reviewSensitive(in ReviewInput, rules []Rule, cfg BTPIIConfig, decision *Decision) (*Decision, *SensitiveResult) {
	return reviewSensitiveContext(context.Background(), in, rules, cfg, decision)
}
func reviewSensitiveContext(ctx context.Context, in ReviewInput, rules []Rule, cfg BTPIIConfig, decision *Decision) (*Decision, *SensitiveResult) {
	return reviewSensitiveContextResult(ctx, in, rules, cfg, decision, secretSensitiveResult(ctx, in, rules))
}

func reviewSensitiveContextResult(ctx context.Context, in ReviewInput, rules []Rule, cfg BTPIIConfig, decision *Decision, result *SensitiveResult) (*Decision, *SensitiveResult) {
	remote := []Rule{}
	active := result != nil
	if active && (decision == nil || decision.Decision != "reject") {
		decision = &Decision{Decision: "reject", RuleID: result.RuleID, Comment: "Credential pattern detected; content omitted."}
	}
	for _, saved := range rules {
		r := normalizeRule(saved)
		if !r.Enabled || r.Tool != "" && r.Tool != in.ToolName {
			continue
		}
		if r.Matcher == "btpii" {
			remote = append(remote, r)
		}
		if r.Matcher == "btpii" || (r.Matcher != "secret" && hasExact(SensitiveInfoCategory, r.Categories...)) {
			active = true
		}
	}
	if !active {
		return decision, nil
	}
	if result == nil {
		result = &SensitiveResult{Findings: []SensitiveFinding{}, Decision: "approve"}
	}
	for _, r := range rules {
		if hasExact(SensitiveInfoCategory, r.Categories...) && r.Matcher != "btpii" && matchesCustomRule(in, r) {
			result.Findings = append(result.Findings, SensitiveFinding{Category: SensitiveInfoCategory, Tag: "custom", EntityType: "CUSTOM", Score: 1, RuleID: r.ID})
		}
	}
	if decision != nil && decision.Decision == "reject" {
		// Keep the terminal deny with no network call, but omit the raw snapshot:
		// remote detection was skipped, not a claim of clean content.
		result.Reason = "deterministic denial; sensitive snapshot omitted"
		result.Decision = "reject"
		return decision, result
	}
	if len(remote) > 0 {
		// One structured surface keeps all chunks under one hook budget and avoids
		// accidentally scanning secrets only after they have already been redacted.
		text, _ := json.Marshal(struct {
			Tool            string
			Args            map[string]any
			Prompt, Context string
			Scripts         []ReviewScript
		}{in.ToolName, in.Arguments, in.UserMessage, in.Context, in.Scripts})
		detected, err := (SensitiveDetector{BTPII: cfg, Rules: remote}).Detect(ctx, SensitiveInput{Text: string(text), Surface: "tool_input", Tenant: eventTenant()})
		detected.Findings = append(detected.Findings, result.Findings...)
		result = &detected
		// Review-envelope offsets must not be mistaken for original-field offsets.
		for i := range result.Findings {
			result.Findings[i].Span = nil
		}
		if err != nil {
			return &Decision{Decision: "reject", RuleID: "E_BTPII", Comment: btpiiUnavailable.Error()}, result
		}
		if result.RuleID != "" && (decision == nil || decisionStrength(result.Decision) >= decisionStrength(decision.Decision)) {
			verdict := result.Decision
			if verdict == "redact" {
				verdict = "alert"
			}
			decision = &Decision{Decision: verdict, RuleID: result.RuleID, Comment: "Sensitive information detected; content omitted."}
		}
	}
	return decision, result
}

func sensitiveRuleSnapshot(rules []Rule, contentOmitted bool) []Rule {
	snapshot := append([]Rule(nil), rules...)
	for i, r := range snapshot {
		if !contentOmitted && !hasExact(SensitiveInfoCategory, r.Categories...) {
			continue
		}
		if contentOmitted {
			// Rule echoes share the input projection's correlation-safe masking.
			snapshot[i].Tool, snapshot[i].Field = sensitiveIdentifier(r.Tool), sensitiveIdentifier(r.Field)
		}
		snapshot[i].Name, snapshot[i].Message = "Sensitive-info rule", ""
		if r.Matcher != "btpii" {
			snapshot[i].Pattern = "[REDACTED]"
		}
	}
	return snapshot
}

func omitSensitiveInput(in ReviewInput) ReviewInput {
	in.Arguments = map[string]any{"content": "[REDACTED]"}
	in.UserMessage, in.Context = "[REDACTED]", "[REDACTED]"
	in.Scripts = nil
	// These are untrusted metadata too. Hash instead of teaching a PII detector
	// about identifier formats; reuse the existing correlation-safe hash pattern.
	in.ToolName = sensitiveIdentifier(in.ToolName)
	in.CallID = sensitiveIdentifier(in.CallID)
	return in
}
func sensitiveIdentifier(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Scan original leaves, not JSON-escaped text (notably multiline PEM). This
// envelope reuses ScanTree's key/value traversal and retains no candidate values.
func secretReviewInput(in ReviewInput) map[string]any {
	scripts := make([]any, 0, len(in.Scripts))
	for _, script := range in.Scripts {
		scripts = append(scripts, map[string]any{"path": script.Path, "content": script.Content, "readError": script.ReadError, "sha256": script.SHA256})
	}
	return map[string]any{"tool": in.ToolName, "arguments": in.Arguments, "prompt": in.UserMessage, "context": in.Context, "scripts": scripts}
}

func secretSensitiveResult(ctx context.Context, in ReviewInput, rules []Rule) *SensitiveResult {
	// An omitted stored review retains the tool digest, not its raw name.
	// Compare the same server-owned digest so output scope is not lost.
	selected := []Rule{}
	for _, saved := range rules {
		r := normalizeRule(saved)
		if r.Enabled && (r.Tool == "" || r.Tool == in.ToolName || sensitiveIdentifier(r.Tool) == in.ToolName) && secretRulePattern(r) != "" {
			selected = append(selected, r)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	sortRules(selected)
	findings, status := secrets.ScanTree(ctx, secretReviewInput(in), "tool_input")
	if status != secrets.Complete {
		return &SensitiveResult{Findings: []SensitiveFinding{}, Decision: "reject", RuleID: "E_SECRET_SCAN", Unavailable: true, Reason: "Credential pattern scan unavailable."}
	}
	result := &SensitiveResult{Findings: []SensitiveFinding{}, Decision: "reject"}
	for _, r := range selected {
		for _, finding := range findings {
			if finding.RuleID != secretRulePattern(r) {
				continue
			}
			// Original leaf offsets cannot describe the omitted review envelope.
			result.Findings = append(result.Findings, SensitiveFinding{Category: SensitiveInfoCategory, Tag: "secret", EntityType: finding.EntityType, RuleID: r.ID, Score: 1})
			if result.RuleID == "" {
				result.RuleID = r.ID
			}
		}
	}
	if len(result.Findings) == 0 {
		return nil
	}
	return result
}

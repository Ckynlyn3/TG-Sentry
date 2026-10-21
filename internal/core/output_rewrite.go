package core

import (
	"context"
	"errors"
	"fmt"
	"io"

	"aegishook/internal/secrets"
)

// Named local contract 69-transform-tool-output; see AGENT-HOOK-CONTRACTS.md.
const ToolOutputJSONBytes = 2 << 20 // Existing bridge serialized UTF-8 envelope ceiling.
const ToolOutputWithheld = "[REDACTED]"

type ToolOutputRequest struct {
	Operation string `json:"operation"`
	Text      string `json:"text"`
}
type ToolOutputResponse struct {
	Outcome string  `json:"outcome"`
	Text    *string `json:"text,omitempty"`
}

func toolOutputReplacement(outcome, text string) ToolOutputResponse {
	return ToolOutputResponse{Outcome: outcome, Text: &text}
}
func outputEnforcing(rules []Rule) bool {
	for _, r := range rules {
		if hasExact(r.Decision, "reject", "redact") {
			return true
		}
	}
	return false
}
func outputFailure(rules []Rule, unavailable bool) ToolOutputResponse {
	if outputEnforcing(rules) {
		return toolOutputReplacement("withheld", ToolOutputWithheld)
	}
	if unavailable {
		return ToolOutputResponse{Outcome: "unavailable"}
	}
	return ToolOutputResponse{Outcome: "unchanged"}
}

// Resolve current server-owned scope exactly as Result does, independent of the
// terminal state. No retained input/envelope findings become output offsets.
func (e *Engine) TransformToolOutput(ctx context.Context, id string, body io.Reader) (ToolOutputResponse, error) {
	// Like the existing /result boundary, consume untrusted I/O before taking
	// the shared writer lock; a slow body must not stall unrelated operations.
	data, decodeErr := ReadToolOutputJSON(body)
	request := ToolOutputRequest{}
	if decodeErr == nil {
		request, decodeErr = DecodeToolOutputRequest(data)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	review, err := e.Review(id)
	if err != nil {
		return ToolOutputResponse{}, err
	}
	var instance Instance
	if err = e.get("instances", review.InstanceID, &instance); err != nil {
		return ToolOutputResponse{}, err
	}
	rules, err := e.Rules()
	if err != nil {
		return ToolOutputResponse{}, err
	}
	scopes, err := e.Scopes()
	if err != nil {
		return ToolOutputResponse{}, err
	}
	applicable := []Scope{}
	for _, scope := range scopes {
		if scope.NodeID == instance.NodeID {
			applicable = append(applicable, scope)
		}
	}
	rules, err = e.protectionRules(rules, applicable, instance.NodeID)
	if err != nil {
		return ToolOutputResponse{}, err
	}
	rules = outputSensitiveRules(rules, review.ToolName)
	response := outputFailure(rules, false)
	detected := SensitiveResult{}
	if decodeErr == nil {
		response, detected = transformToolOutput(ctx, request.Text, rules, e.Settings.BTPII)
	}
	if review.LogSuppression != nil {
		return response, nil
	}
	// Audit only metadata. Do not persist original/replacement text or replay input
	// findings, and never change the issued authorization or actual execution state.
	detail := fmt.Sprintf("outcome=%s; findings=%d; detector_unavailable=%t", response.Outcome, len(detected.Findings), detected.Unavailable)
	if decodeErr != nil {
		detail += "; invalid_input=true"
	}
	audit := Audit{Actor: SystemActor("hook"), ID: ID(), Action: "tool.output.transform", Subject: review.ID, Detail: detail, CreatedAt: e.clock()}
	if err = e.put("audit", audit.ID, audit); err != nil {
		return response, errors.New("tool output audit unavailable")
	}
	return response, nil
}

func outputSensitiveRules(rules []Rule, tool string) []Rule {
	selected := []Rule{}
	for _, saved := range rules {
		r := normalizeRule(saved)
		if !r.Enabled || r.Tool != "" && r.Tool != tool && sensitiveIdentifier(r.Tool) != tool {
			continue
		}
		// Result's existing output projection has one arguments.result field.
		// Input-only fields and structural tool-name matchers do not apply here.
		if r.Target != "arguments" || !hasExact(r.Field, "", "result") || !hasExact(SensitiveInfoCategory, r.Categories...) {
			continue
		}
		selected = append(selected, r)
	}
	return selected
}

func transformToolOutput(ctx context.Context, text string, rules []Rule, cfg BTPIIConfig) (ToolOutputResponse, SensitiveResult) {
	local, remote := []Rule{}, []Rule{}
	for _, r := range rules {
		if r.Matcher == "secret" {
			local = append(local, r)
		} else {
			remote = append(remote, r)
		}
	}
	// Scan the original leaf (including multiline PEM) before serialization.
	if len(local) > 0 {
		findings, status := secrets.Scan(ctx, text)
		if status != secrets.Complete {
			return outputFailure(rules, true), SensitiveResult{Unavailable: true}
		}
		for _, r := range local {
			for _, f := range findings {
				if f.RuleID == secretRulePattern(r) {
					return toolOutputReplacement("withheld", ToolOutputWithheld), SensitiveResult{Findings: []SensitiveFinding{{EntityType: "CUSTOM", RuleID: r.ID}}}
				}
			}
		}
	}
	if len(remote) == 0 {
		return ToolOutputResponse{Outcome: "unchanged"}, SensitiveResult{}
	}
	result, err := (SensitiveDetector{Rules: remote, BTPII: cfg}).Detect(ctx, SensitiveInput{Text: text, Surface: "tool_result", Tenant: eventTenant()})
	if err != nil || result.Unavailable {
		// Local credential rules were already satisfied by a complete clean scan;
		// only unsatisfied detector rules decide this failure's output action.
		return outputFailure(remote, true), result
	}
	selected := []SensitiveFinding{}
	for _, f := range result.Findings {
		for _, r := range remote {
			// BTPII attributes each label to its first matching rule; an equal-strength
			// alert must not hide another applicable redact binding for that tag.
			if r.ID != f.RuleID && !(r.Matcher == "btpii" && r.Pattern == f.Tag) {
				continue
			}
			if r.Decision == "reject" {
				return toolOutputReplacement("withheld", ToolOutputWithheld), result
			}
			if r.Decision == "redact" {
				selected = append(selected, f)
			}
		}
	}
	if len(selected) == 0 {
		return ToolOutputResponse{Outcome: "unchanged"}, result
	}
	rewritten, err := RedactSensitive(text, selected)
	if err != nil {
		return outputFailure(rules, false), result
	}
	return toolOutputReplacement("rewritten", rewritten), result
}

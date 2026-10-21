package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"aegishook/internal/core"
)

func TestResultFindingsUseExistingSecretObservation(t *testing.T) {
	for entity := range secretHTTPFixtures() {
		for _, state := range []string{"succeeded", "failed"} {
			t.Run(entity+"/"+state, func(t *testing.T) {
				h := newProtectionHTTP(t)
				if err := h.engine.Register(core.Instance{ID: "result-findings", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
					t.Fatal(err)
				}
				in := core.ReviewInput{InstanceID: "result-findings", CallID: core.ID(), ToolName: "Read", Arguments: map[string]any{"text": "benign"}}
				got := h.call("POST", "/api/v1/reviews", in, 200, "fixture-hook")
				if got["decision"] != "approve" {
					t.Fatal("clean input did not approve")
				}
				id := got["id"].(string)
				original, err := h.engine.Review(id)
				if err != nil || original.DecidedAt == nil {
					t.Fatal("approved baseline has no decision timestamp")
				}
				// Match bridge.go: original output leaves are already omitted before
				// serialization; only value-free metadata can recover the detection.
				body := map[string]any{"instanceId": in.InstanceID, "state": state, "result": `{"text":"[REDACTED]"}`, "findings": []any{
					map[string]any{"entity_type": entity, "surface": "tool_result", "kind": "value", "field_digest": strings.Repeat("a", 64), "span": map[string]any{"start": 0, "end": len(secretHTTPFixtures()[entity])}},
				}}
				for range 2 { // Existing result terminal-state retries are no-ops.
					h.call("POST", "/api/v1/reviews/"+id+"/result", body, 200, "fixture-hook")
				}
				saved, err := h.engine.Review(id)
				wantRule := "R_SECRET_" + strings.ToUpper(strings.ReplaceAll(entity, "-", "_"))
				if err != nil || saved.Execution != state || saved.Result != "[REDACTED]" || saved.SensitiveInfo == nil || len(saved.SensitiveInfo.Findings) != 1 {
					t.Fatal("result metadata did not omit content with honest execution state")
				}
				if saved.Decision != original.Decision || saved.RuleID != original.RuleID || saved.ReviewPath != original.ReviewPath || saved.DecidedAt == nil || !saved.DecidedAt.Equal(*original.DecidedAt) {
					t.Fatal("metadata-only result finding changed the original approved verdict")
				}
				finding := saved.SensitiveInfo.Findings[0]
				if finding.EntityType != entity || finding.RuleID != wantRule || finding.Tag != "secret" || finding.Span != nil || saved.PromptScan != nil {
					t.Fatal("result finding lost attribution or retained envelope offsets/prompt metadata")
				}
				events, err := h.engine.RiskEvents(0, "", core.RiskEventFilter{})
				if err != nil || len(events.Items) != 1 || events.Items[0].Data.ActionID != 3 || events.Items[0].Data.DispositionID != 17 || events.Items[0].Data.FindingInfo.Analytic.UID != wantRule {
					t.Fatal("result metadata did not emit exactly one observed/logged event")
				}
				audits, err := h.engine.Audits()
				if err != nil {
					t.Fatal(err)
				}
				assertMetadataHTTPAbsent(t, secretHTTPFixtures()[entity], saved)
				assertMetadataHTTPAbsent(t, secretHTTPFixtures()[entity], audits)
				assertMetadataHTTPAbsent(t, secretHTTPFixtures()[entity], events)
			})
		}
	}
}

func TestResultFindingsRespectSecretRuleScope(t *testing.T) {
	for _, variant := range []string{"enabled", "disabled", "other-tool", "clean-legacy"} {
		t.Run(variant, func(t *testing.T) {
			h := newProtectionHTTP(t)
			if err := h.engine.Register(core.Instance{ID: "result-scope", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
				t.Fatal(err)
			}
			rules, err := h.engine.Rules()
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range rules {
				if rule.ID != "R_SECRET_GITHUB_PAT" {
					continue
				}
				rule.Enabled = variant != "disabled"
				rule.Tool = "Read"
				if variant == "other-tool" {
					rule.Tool = "Write"
				}
				if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
					t.Fatal(err)
				}
			}
			got := h.call("POST", "/api/v1/reviews", core.ReviewInput{InstanceID: "result-scope", CallID: core.ID(), ToolName: "Read", Arguments: map[string]any{}}, 200, "fixture-hook")
			body := map[string]any{"instanceId": "result-scope", "state": "succeeded", "result": "benign"}
			if variant != "clean-legacy" {
				body["findings"] = []any{map[string]any{"entity_type": "github-pat", "surface": "tool_result"}}
			}
			id := got["id"].(string)
			h.call("POST", "/api/v1/reviews/"+id+"/result", body, 200, "fixture-hook")
			saved, err := h.engine.Review(id)
			if err != nil || saved.Execution != "succeeded" {
				t.Fatal("result state not persisted")
			}
			wantHit := variant == "enabled"
			if (saved.SensitiveInfo != nil) != wantHit || saved.Decision != "approve" {
				t.Fatal("result metadata bypassed rule enablement/tool scope or changed legacy clean results")
			}
		})
	}
}

func TestResultFindingsRejectDuplicateJSONMembers(t *testing.T) {
	h := newProtectionHTTP(t)
	for _, metadata := range []string{
		`"findings":[{"entity_type":"github-pat","surface":"tool_result"}],"findings":[]`,
		`"findings":[{"entity_type":"github-pat","surface":"tool_result"}],"` + string('\\') + `u0066indings":[]`,
		`"findings":[{"entity_type":"github-pat","entity_type":"jwt","surface":"tool_result"}]`,
		`"findings":[{"entity_type":"github-pat","surface":"tool_result","span":{"start":0,"end":40,"end":1}}]`,
	} {
		body := `{"instanceId":"result-duplicates","state":"succeeded","result":"[REDACTED]",` + metadata + `}`
		req, err := http.NewRequest("POST", h.url+"/api/v1/reviews/fixture/result", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer fixture-hook")
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		var decoded map[string]string
		if err != nil || resp.StatusCode != http.StatusBadRequest || json.Unmarshal(response, &decoded) != nil || decoded["error"] != "JSON 请求无效或超过 2 MB" {
			t.Fatal("duplicate result metadata did not produce the existing fixed HTTP 400")
		}
	}
}

func TestResultFindingsDoNotReplayInputCustomAlert(t *testing.T) {
	for _, result := range []string{"[REDACTED]", "benign"} {
		t.Run(result, func(t *testing.T) {
			h := newProtectionHTTP(t)
			if err := h.engine.Register(core.Instance{ID: "result-no-replay", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
				t.Fatal(err)
			}
			custom := core.Rule{ID: "U_PRIVATE", Name: "fixture", Matcher: "contains", Pattern: "private-fixture", Decision: "alert", Enabled: true, Categories: []string{core.SensitiveInfoCategory}}
			if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), custom); err != nil {
				t.Fatal(err)
			}
			got := h.call("POST", "/api/v1/reviews", core.ReviewInput{InstanceID: "result-no-replay", CallID: core.ID(), ToolName: "Read", Arguments: map[string]any{"text": "private-fixture"}}, 200, "fixture-hook")
			before, err := h.engine.RiskEvents(0, "", core.RiskEventFilter{})
			if err != nil || got["decision"] != "approve" || len(before.Items) != 1 || before.Items[0].Data.FindingInfo.Analytic.UID != custom.ID {
				t.Fatal("input custom alert was not exercised")
			}
			body := map[string]any{"instanceId": "result-no-replay", "state": "succeeded", "result": result}
			wantNew := 0
			if result == "[REDACTED]" {
				body["findings"] = []any{map[string]any{"entity_type": "github-pat", "surface": "tool_result"}}
				wantNew = 1
			}
			h.call("POST", "/api/v1/reviews/"+got["id"].(string)+"/result", body, 200, "fixture-hook")
			audits, err := h.engine.Audits()
			if err != nil {
				t.Fatal(err)
			}
			newEvents := 0
			for _, audit := range audits {
				if audit.Action != "review.result" {
					continue
				}
				for _, event := range audit.Events {
					if event.Type != "tg.sentry.risk.v1" {
						continue
					}
					newEvents++
					if event.Data.ActionID != 3 || event.Data.DispositionID != 17 || event.Data.FindingInfo.Analytic.UID != "R_SECRET_GITHUB_PAT" {
						t.Fatal("result event replayed an input alert or changed observation semantics")
					}
				}
			}
			if newEvents != wantNew {
				t.Fatal("result emitted the wrong number of new observations")
			}
		})
	}
}

func TestResultFindingsPreserveLegacyRawResultVerdict(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "raw-result", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	got := h.call("POST", "/api/v1/reviews", core.ReviewInput{InstanceID: "raw-result", CallID: core.ID(), ToolName: "Read", Arguments: map[string]any{}}, 200, "fixture-hook")
	id := got["id"].(string)
	candidate := secretHTTPFixtures()["github-pat"]
	body := map[string]any{"instanceId": "raw-result", "state": "succeeded", "result": candidate, "findings": []any{map[string]any{"entity_type": "aws-access-token", "surface": "tool_result"}}}
	h.call("POST", "/api/v1/reviews/"+id+"/result", body, 200, "fixture-hook")
	saved, err := h.engine.Review(id)
	if err != nil || saved.Decision != "reject" || saved.RuleID != "R_SECRET_GITHUB_PAT" || saved.ReviewPath != "rule" || saved.Execution != "succeeded" || saved.Result != "[REDACTED]" {
		t.Fatal("metadata changed the legacy raw-result retention verdict")
	}
	events, err := h.engine.RiskEvents(0, "", core.RiskEventFilter{})
	if err != nil || len(events.Items) != 1 || events.Items[0].Data.FindingInfo.Analytic.UID != "R_SECRET_GITHUB_PAT" || events.Items[0].Data.DispositionID != 17 {
		t.Fatal("metadata changed the legacy raw-result event attribution")
	}
	assertMetadataHTTPAbsent(t, candidate, saved)
}

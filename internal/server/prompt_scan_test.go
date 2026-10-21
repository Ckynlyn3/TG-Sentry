package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"aegishook/internal/core"
)

func TestClientFindingFieldsCannotCarrySecret(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "prompt-scan", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	candidate := secretHTTPFixtures()["github-pat"]
	valid := map[string]any{"entity_type": "github-pat", "surface": "prompt", "kind": "value", "field_digest": strings.Repeat("a", 64), "span": map[string]any{"start": 0, "end": 40}}
	cases := map[string]any{}
	for _, field := range []string{"entity_type", "surface", "kind", "field_digest", "extra", candidate} {
		finding := map[string]any{}
		for key, value := range valid {
			finding[key] = value
		}
		finding[field] = candidate
		cases[field] = finding
	}
	for name, span := range map[string]any{
		"negative":         map[string]any{"start": -1, "end": 40},
		"empty":            map[string]any{"start": 40, "end": 40},
		"over-bound":       map[string]any{"start": 0, "end": (2 << 20) + 1},
		"fraction":         map[string]any{"start": 0.5, "end": 40},
		"missing-end":      map[string]any{"start": 0},
		"null-start":       map[string]any{"start": nil, "end": 40},
		"extra-span":       map[string]any{"start": 0, "end": 40, "text": candidate},
		"null-span":        nil,
		"string-span":      candidate,
		"credential-start": map[string]any{"start": candidate, "end": 40},
		"credential-end":   map[string]any{"start": 0, "end": candidate},
	} {
		cases[name] = map[string]any{"entity_type": "github-pat", "surface": "prompt", "span": span}
	}
	var fixedError string
	for name, finding := range cases {
		// Do not print attacker-controlled field names or payloads in diagnostics.
		name = strings.ReplaceAll(name, candidate, "credential-key")
		t.Run(name, func(t *testing.T) {
			for _, result := range []bool{false, true} {
				path := "/api/v1/reviews"
				body := map[string]any{"instanceId": "prompt-scan", "callId": core.ID(), "toolName": "Read", "argumentsObj": map[string]any{}}
				if result {
					path += "/fixture/result"
					body = map[string]any{"instanceId": "prompt-scan", "state": "succeeded", "result": "benign", "findings": []any{finding}}
				} else {
					body["prompt_scan"] = map[string]any{"status": "Complete", "findings": []any{finding}}
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequest("POST", h.url+path, bytes.NewReader(raw))
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
				if err != nil || resp.StatusCode != http.StatusBadRequest || strings.Contains(string(response), candidate) {
					t.Fatal("invalid finding was not rejected privately with HTTP 400")
				}
				if fixedError == "" {
					fixedError = string(response)
				} else if string(response) != fixedError {
					t.Fatal("finding validation error is not fixed")
				}
			}
		})
	}
	reviews, err := h.engine.Reviews()
	if err != nil || len(reviews) != 0 {
		t.Fatal("invalid findings reached review persistence")
	}
	audits, err := h.engine.Audits()
	if err != nil {
		t.Fatal(err)
	}
	events, err := h.engine.RiskEvents(0, "", core.RiskEventFilter{})
	if err != nil || len(events.Items) != 0 {
		t.Fatal("invalid findings emitted risk events")
	}
	assertMetadataHTTPAbsent(t, candidate, audits)
}

func TestPromptScanCleanPayloadCompatibility(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "clean-prompt-scan", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	for _, scan := range []any{nil, map[string]any{"status": "Complete", "findings": []any{}}} {
		body := map[string]any{"instanceId": "clean-prompt-scan", "callId": core.ID(), "toolName": "Read", "argumentsObj": map[string]any{}, "userMessage": "benign prompt"}
		// scanPrompt returns no prompt_scan at all for a clean/legacy cache.
		if scan != nil {
			body["prompt_scan"] = scan
		}
		got := h.call("POST", "/api/v1/reviews", body, 200, "fixture-hook")
		if got["decision"] != "approve" {
			t.Fatal("clean bridge prompt payload no longer approves")
		}
	}
}

func TestPromptScanDuplicateJSONMembers(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "scan-duplicates", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	fixedError := h.call("POST", "/api/v1/reviews", map[string]any{"prompt_scan": map[string]any{"status": "invalid", "findings": []any{}}}, 400, "fixture-hook")
	fixedBody, err := json.Marshal(fixedError)
	if err != nil {
		t.Fatal(err)
	}
	for name, scan := range map[string]string{
		"status":         `{"status":"Interrupted","status":"Complete","findings":[]}`,
		"findings":       `{"status":"Complete","findings":[{"entity_type":"github-pat","surface":"prompt"}],"findings":[]}`,
		"top-level":      `{"status":"Interrupted","findings":[]},"prompt_scan":null`,
		"finding":        `{"status":"Complete","findings":[{"entity_type":"github-pat","entity_type":"jwt","surface":"prompt"}]}`,
		"span":           `{"status":"Complete","findings":[{"entity_type":"github-pat","surface":"prompt","span":{"start":0,"end":40,"end":1}}]}`,
		"escaped-status": `{"status":"Interrupted","\u0073tatus":"Complete","findings":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"instanceId":"scan-duplicates","callId":"duplicate","toolName":"Read","argumentsObj":{},"prompt_scan":` + scan + `}`
			req, err := http.NewRequest("POST", h.url+"/api/v1/reviews", strings.NewReader(body))
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
			if err != nil || resp.StatusCode != http.StatusBadRequest || strings.TrimSpace(string(response)) != string(fixedBody) {
				t.Fatal("duplicate JSON member did not produce fixed HTTP 400")
			}
		})
	}
	reviews, err := h.engine.Reviews()
	if err != nil || len(reviews) != 0 {
		t.Fatal("duplicate JSON reached review persistence")
	}
}

func TestPromptScanStatusValidation(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "scan-status", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	for _, scan := range []any{
		map[string]any{"status": "Complete"},
		map[string]any{"status": "Complete", "findings": nil},
		map[string]any{"status": "Interrupted"},
		map[string]any{"status": "Interrupted", "findings": nil},
		map[string]any{"status": "unknown", "findings": []any{}},
		map[string]any{"findings": []any{}},
		map[string]any{"status": "Complete", "findings": []any{}, "text": secretHTTPFixtures()["github-pat"]},
	} {
		got := h.call("POST", "/api/v1/reviews", map[string]any{"instanceId": "scan-status", "callId": core.ID(), "toolName": "Read", "argumentsObj": map[string]any{}, "prompt_scan": scan}, 400, "fixture-hook")
		assertMetadataHTTPAbsent(t, secretHTTPFixtures()["github-pat"], got)
	}
}

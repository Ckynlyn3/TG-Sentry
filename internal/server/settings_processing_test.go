package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"encoding/json"
	"net/http"
	"testing"
	"testing/fstest"
)

func TestSettingsProcessingContract(t *testing.T) {
	for _, tc := range []struct {
		name            string
		consent         map[string]any
		class, override string
		want            int
	}{
		{"opt_in", map[string]any{"enabled": true}, "external", "self_hosted", http.StatusOK},
		{"default", nil, "", "", http.StatusOK},
		{"unknown_class", nil, "cloud", "", http.StatusBadRequest},
		{"unknown_override", nil, "self_hosted", "cloud", http.StatusBadRequest},
		{"spoof_actor", map[string]any{"enabled": true, "actor": map[string]string{"kind": "human", "subject": "forged"}}, "external", "", http.StatusBadRequest},
		{"spoof_timestamp", map[string]any{"enabled": true, "updatedAt": "2026-10-20T00:00:00Z"}, "external", "", http.StatusBadRequest},
		{"unknown_consent_field", map[string]any{"enabled": true, "permission": true}, "external", "", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := core.Open(teststore.Dir(t, t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
			body := map[string]any{"mode": "human", "prompt": core.DefaultPrompt, "approvalSeconds": 600, "modelSeconds": 5,
				"model": map[string]any{"protocol": "openai", "baseUrl": "https://selected.invalid/v1", "model": "fixture", "processingClass": tc.class}}
			// Existing clients' unrelated extension fields remain compatible.
			body["legacyClientExtension"] = true
			if tc.consent != nil {
				body["externalProcessing"] = tc.consent
			}
			if tc.override != "" {
				body["promptAttack"] = map[string]any{"model": map[string]any{"protocol": "openai", "baseUrl": "https://classifier.invalid/v1", "model": "fixture", "processingClass": tc.override}}
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			before := e.Config().Version
			w := rbacRequest(s.Handler(), rbacCookie(s, "human", core.RoleAdmin), "PUT", "http://127.0.0.1/api/v1/settings", string(raw), "127.0.0.1:12345")
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			if tc.want != http.StatusOK {
				if e.Config().Version != before {
					t.Fatal("invalid request mutated settings")
				}
				return
			}
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["model"].(map[string]any)["processingClass"] != tc.class {
				t.Fatal("model processing class lost")
			}
			consent, ok := got["externalProcessing"].(map[string]any)
			if !ok {
				t.Fatal("missing external-processing state")
			}
			if tc.consent != nil && (consent["enabled"] != true || consent["actor"].(map[string]any)["subject"] != "fixture-subject" || consent["updatedAt"] == nil) {
				t.Fatalf("server attribution missing: %v", consent)
			}
		})
	}
}

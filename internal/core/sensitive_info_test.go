package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic identifiers use an unassigned all-zero region/IIN, never real records.
func syntheticCard() string { return syntheticCheck("000000000000001", false) }
func syntheticID() string   { return syntheticCheck("00000020000229001", true) }
func syntheticCheck(body string, cn bool) string {
	for _, c := range "0123456789X" {
		value := body + string(c)
		if cn && ValidCNID(value) || !cn && ValidLuhn(value) {
			return value
		}
	}
	panic("synthetic checksum generation failed")
}
func fakeBTPII(t *testing.T, handler http.HandlerFunc) BTPIIConfig {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	// This is a disposable test canary, not a workload credential.
	path := filepath.Join(t.TempDir(), "synthetic-auth")
	if err := os.WriteFile(path, []byte("synthetic-test-only"), 0600); err != nil {
		t.Fatal(err)
	}
	return BTPIIConfig{Endpoint: server.URL, TokenFile: path}
}
func TestSensitiveValidators(t *testing.T) {
	card, id := syntheticCard(), syntheticID()
	for _, tc := range []struct {
		value string
		valid bool
	}{{card, true}, {card[:15] + "9", false}, {"", false}, {"x", false}, {"00000000000000x", false}} {
		if ValidLuhn(tc.value) != tc.valid {
			t.Fatalf("Luhn mismatch on synthetic case %#v", tc)
		}
	}
	xID := syntheticCheck("00000020000229007", true)
	if !strings.HasSuffix(xID, "X") {
		t.Fatal("synthetic X case was not exercised")
	}
	for _, value := range []string{id, xID, strings.ToLower(xID), syntheticCheck("00000020000101001", true)} {
		if !ValidCNID(value) {
			t.Fatal("valid synthetic CN ID rejected")
		}
	}
	for _, value := range []string{"", id[:17], id[:17] + "!", "x" + id[1:], syntheticCheck("00000020000230001", false)} {
		if ValidCNID(value) {
			t.Fatal("invalid synthetic CN ID accepted")
		}
	}
}
func TestSensitiveAnalyzeUTF16AndRedaction(t *testing.T) {
	text := "😀 fake@example.invalid suffix"
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic-test-only" {
			t.Error("wrong analyzer contract")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["text"] != text || body["language"] != "en" {
			t.Error("wrong request")
		}
		w.Write([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":3,"end":23,"score":0.9}]`))
	})
	result, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: text, Language: "en", Surface: "tool_result", Tenant: "default"})
	if err != nil || result.Unavailable || len(result.Findings) != 1 || result.Findings[0].Tag != "email" {
		t.Fatal(result, err)
	}
	redacted, err := RedactSensitive(text, result.Findings)
	if err != nil || redacted != "😀 [EMAIL_ADDRESS] suffix" {
		t.Fatal(redacted, err)
	}
	if result.Findings[0].Span.StartUTF16 != 3 {
		t.Fatal("offset not UTF16")
	}
}
func TestSensitiveUnavailableIsNotClean(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `[{}]`, `[] trailing`, `[{"entity_type":"EMAIL_ADDRESS","start":1,"end":2,"score":1}]`, `[{"entity_type":"EMAIL_ADDRESS","start":0,"end":2,"score":2}]`, `[{"entity_type":"EMAIL_ADDRESS","start":0,"end":2}]`} {
		t.Run(body, func(t *testing.T) {
			cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			result, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: "😀", Language: "en"})
			if err == nil || !result.Unavailable || result.Decision != "reject" || len(result.Findings) != 0 {
				t.Fatal("malformed response became clean", result, err)
			}
		})
	}
}
func TestSensitiveCustomAndUnknown(t *testing.T) {
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"entity_type":"FUTURE_LABEL","start":0,"end":4,"score":1}]`))
	})
	result, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: "fake", Language: "zh"})
	if err != nil || len(result.Findings) != 1 || result.Findings[0].Tag != "other" || result.Findings[0].EntityType != "FUTURE_LABEL" {
		t.Fatal(result, err)
	}
	rules := []Rule{{ID: "U_FAKE", Matcher: "keywords", Pattern: "internal-only\nsynthetic-private", Enabled: true, Decision: "alert", Categories: []string{SensitiveInfoCategory}}}
	result, err = (SensitiveDetector{Rules: rules}).Detect(context.Background(), SensitiveInput{Text: "fake synthetic-private"})
	if err != nil || result.Decision != "alert" || len(result.Findings) != 1 {
		t.Fatal(result, err)
	}
	redacted, err := RedactSensitive("fake synthetic-private", result.Findings)
	if err != nil || redacted != "fake [CUSTOM]" {
		t.Fatal(redacted, err)
	}
}
func TestSensitiveReviewAndEvents(t *testing.T) {
	for _, decision := range []string{"reject", "alert", "approve", "redact"} {
		t.Run(decision, func(t *testing.T) {
			e := engine(t)
			cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Text string `json:"text"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				start := strings.Index(body.Text, "fake@example.invalid")
				json.NewEncoder(w).Encode([]map[string]any{{"entity_type": "EMAIL_ADDRESS", "start": start, "end": start + len("fake@example.invalid"), "score": 1}})
			})
			e.Settings.BTPII = cfg
			if err := e.SaveRule(testActorContext(), Rule{ID: "R_PII_EMAIL", Name: "Synthetic email", Enabled: true, Matcher: "btpii", Pattern: "email", Decision: decision}); err != nil {
				t.Fatal(err)
			}
			r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "synthetic", ToolName: "read", Arguments: map[string]any{"value": "fake@example.invalid"}})
			want := "approve"
			if decision == "reject" {
				want = "reject"
			}
			if err != nil || r.Decision != want || r.RuleID != "R_PII_EMAIL" || r.ReviewPath != "rule" {
				t.Fatal(r, err)
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "fake@example.invalid") {
				t.Fatal("PII retained in review")
			}
			events, err := e.RiskEvents(0, "", RiskEventFilter{Category: SensitiveInfoCategory})
			if err != nil || len(events.Items) != 1 {
				t.Fatal(events, err)
			}
		})
	}
}

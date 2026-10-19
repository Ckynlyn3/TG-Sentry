package core

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSensitiveChunkOverlapAndDedupe(t *testing.T) {
	// The first cut lands inside an emoji; subsequent overlapping chunks report
	// the same complete email, which must retain its original global UTF-16 span.
	text := strings.Repeat("x", btpiiChunkUnits-1) + "😀 fake@example.invalid " + strings.Repeat("y", btpiiChunkUnits)
	calls := 0
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if utf16Length(body.Text) > btpiiChunkUnits || strings.ContainsRune(body.Text, '�') {
			t.Error("invalid chunk cut")
		}
		i := strings.Index(body.Text, "fake@example.invalid")
		if i < 0 {
			w.Write([]byte(`[]`))
			return
		}
		start := utf16Length(body.Text[:i])
		json.NewEncoder(w).Encode([]map[string]any{{"entity_type": "EMAIL_ADDRESS", "start": start, "end": start + 20, "score": 1}})
	})
	result, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: text})
	if err != nil || len(result.Findings) != 1 || calls < 2 {
		t.Fatal(result, err, calls)
	}
	want := utf16Length(text[:strings.Index(text, "fake@example.invalid")])
	if result.Findings[0].Span.StartUTF16 != want {
		t.Fatal(result.Findings)
	}
	// Explicitly place a whole match in the overlap so two requests own it.
	text = strings.Repeat("x", btpiiChunkUnits-btpiiChunkOverlap) + "fake@example.invalid " + strings.Repeat("y", btpiiChunkUnits)
	result, err = (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: text})
	if err != nil || len(result.Findings) != 1 {
		t.Fatal("overlap was not deduplicated", result, err)
	}
}
func TestSensitiveCardIDValidationAtBoundary(t *testing.T) {
	card, id := syntheticCard(), syntheticID()
	text := card + " " + id + " invalid"
	for _, tc := range []struct {
		label      string
		start, end int
		want       int
	}{
		{"CREDIT_CARD", 0, len(card), 1},
		{"CREDIT_CARD", len(text) - 7, len(text), 0},
		{"CN_ID_CARD", len(card) + 1, len(card) + 1 + len(id), 1},
		{"CN_ID_CARD", 0, len(card), 0},
		{"US_SSN", len(card) + 1, len(card) + 1 + len(id), 1},
		{"PHONE_NUMBER", 0, len(card), 1},
		{"IP_ADDRESS", 0, len(card), 1},
	} {
		t.Run(tc.label+string(rune(tc.want+'0')), func(t *testing.T) {
			cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode([]map[string]any{{"entity_type": tc.label, "start": tc.start, "end": tc.end, "score": 1}})
			})
			cfg.Entities = []string{tc.label}
			result, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: text, Language: "zh"})
			if err != nil || len(result.Findings) != tc.want {
				t.Fatal(result, err)
			}
		})
	}
}
func TestSensitiveHTTPAndConfigurationFailures(t *testing.T) {
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect/analyze":
			http.Redirect(w, r, "/analyze", http.StatusTemporaryRedirect)
		case "/error/analyze":
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("synthetic-private-server-body"))
		case "/large/analyze":
			w.Write([]byte(strings.Repeat("x", btpiiResponseBytes+1)))
		default:
			w.Write([]byte(`[]`))
		}
	})
	for _, suffix := range []string{"/redirect", "/error", "/large"} {
		c := cfg
		c.Endpoint += suffix
		result, err := (SensitiveDetector{BTPII: c}).Detect(context.Background(), SensitiveInput{Text: "fake"})
		if err == nil || !result.Unavailable || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatal(result, err)
		}
	}
	for _, mutate := range []func(*BTPIIConfig){
		func(c *BTPIIConfig) { c.TokenFile = "missing-synthetic-file" },
		func(c *BTPIIConfig) { c.Endpoint = "http://remote.invalid" },
		func(c *BTPIIConfig) { c.Endpoint = "https://example.invalid?secret=fake" },
		func(c *BTPIIConfig) { c.Language = "fr" },
		func(c *BTPIIConfig) { c.Entities = []string{"not a label"} },
		func(c *BTPIIConfig) { threshold := -1.0; c.ScoreThreshold = &threshold },
	} {
		c := cfg
		mutate(&c)
		result, err := (SensitiveDetector{BTPII: c}).Detect(context.Background(), SensitiveInput{Text: "fake"})
		if err == nil || !result.Unavailable || err.Error() != btpiiUnavailable.Error() {
			t.Fatal(result, err)
		}
	}
	for _, secret := range []string{"", "bad token", strings.Repeat("x", btpiiResponseBytes+1)} {
		if err := os.WriteFile(cfg.TokenFile, []byte(secret), 0600); err != nil {
			t.Fatal(err)
		}
		result, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: "fake"})
		if err == nil || !result.Unavailable {
			t.Fatal(result, err)
		}
	}
}
func TestSensitiveEnvironmentRotationThresholdAndCancellation(t *testing.T) {
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer synthetic-test-only" && token != "Bearer rotated-synthetic-test-only" {
			t.Error("credential not loaded")
		}
		w.Write([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":0,"end":4,"score":0.5}]`))
	})
	t.Setenv("TG_SENTRY_BTPII_ENDPOINT", cfg.Endpoint+"/analyze")
	t.Setenv("TG_SENTRY_BTPII_TOKEN_FILE", cfg.TokenFile)
	threshold := 0.75 // Synthetic server score comparison, not a tuned production threshold.
	detector := SensitiveDetector{BTPII: BTPIIConfig{ScoreThreshold: &threshold}}
	result, err := detector.Detect(context.Background(), SensitiveInput{Text: "fake"})
	if err != nil || len(result.Findings) != 0 {
		t.Fatal(result, err)
	}
	if err := os.WriteFile(cfg.TokenFile, []byte("rotated-synthetic-test-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	detector.BTPII.ScoreThreshold = nil
	result, err = detector.Detect(context.Background(), SensitiveInput{Text: "fake"})
	if err != nil || len(result.Findings) != 1 {
		t.Fatal(result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = detector.Detect(ctx, SensitiveInput{Text: "fake"})
	if err == nil || !result.Unavailable {
		t.Fatal(result, err)
	}
}
func TestSensitiveRequestWholeSurfaceDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), btpiiBudget)
	defer cancel()
	started := time.Now()
	result, err := (SensitiveDetector{BTPII: cfg}).Detect(ctx, SensitiveInput{Text: "fake"})
	t.Logf("named local btpii-hook-budget: whole call elapsed=%s configured=%s", time.Since(started), btpiiBudget)
	if err == nil || !result.Unavailable || ctx.Err() != context.DeadlineExceeded {
		t.Fatal(result, err, ctx.Err())
	}
}
func TestSensitiveLocalRulesRedactionAndBadSpans(t *testing.T) {
	rules := []Rule{
		{ID: "U_ALLOW", Matcher: "contains", Pattern: "fake", Enabled: true, Decision: "approve", Categories: []string{SensitiveInfoCategory}},
		{ID: "U_BLOCK", Matcher: "regex", Pattern: "fake", Enabled: true, Decision: "reject", Categories: []string{SensitiveInfoCategory}},
		{ID: "U_DISABLED", Matcher: "regex", Pattern: "private", Decision: "reject", Categories: []string{SensitiveInfoCategory}},
	}
	result, err := (SensitiveDetector{Rules: rules}).Detect(context.Background(), SensitiveInput{Text: "fake fake"})
	if err != nil || result.Decision != "reject" || result.RuleID != "U_BLOCK" || len(result.Findings) != 4 {
		t.Fatal(result, err)
	}
	redacted, err := RedactSensitive("fake fake", result.Findings)
	if err != nil || redacted != "[CUSTOM] [CUSTOM]" {
		t.Fatal(redacted, err)
	}
	for _, pattern := range []string{"[", ""} {
		rules[0].Matcher = "regex"
		rules[0].Pattern = pattern
		_, err := (SensitiveDetector{Rules: rules[:1]}).Detect(context.Background(), SensitiveInput{Text: "fake"})
		if pattern == "[" && err == nil {
			t.Fatal("invalid regex accepted")
		}
	}
	for _, in := range []SensitiveInput{{Text: "fake", Tenant: "other-tenant"}, {Text: "fake", Surface: "unknown"}, {Text: string([]byte{0xff})}} {
		result, err := (SensitiveDetector{Rules: []Rule{}}).Detect(context.Background(), in)
		if err == nil || !result.Unavailable {
			t.Fatal(result, err)
		}
	}
	for _, finding := range []SensitiveFinding{{}, {EntityType: "CUSTOM", Span: &SensitiveSpan{1, 2}}, {EntityType: "bad-label", Span: &SensitiveSpan{0, 2}}, {EntityType: "CUSTOM", Span: &SensitiveSpan{0, 3}}} {
		if _, err := RedactSensitive("😀", []SensitiveFinding{finding}); err == nil {
			t.Fatal("invalid span accepted", finding)
		}
	}
	if _, err := RedactSensitive(string([]byte{0xff}), nil); err == nil {
		t.Fatal("invalid UTF8 accepted")
	}
	got, err := RedactSensitive("abcdef", []SensitiveFinding{{EntityType: "CUSTOM", Span: &SensitiveSpan{0, 4}}, {EntityType: "EMAIL_ADDRESS", Span: &SensitiveSpan{2, 6}}})
	if err != nil || got != "[REDACTED]" {
		t.Fatal(got, err)
	}
}

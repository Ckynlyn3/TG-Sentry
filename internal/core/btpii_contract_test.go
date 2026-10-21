package core

import (
	"context"
	"encoding/json"
	"io"
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

func TestBTPIIProtocolResolutionAndValidation(t *testing.T) {
	if got := (BTPIIConfig{}).resolved().Protocol; got != "presidio" {
		t.Fatal("default protocol", got)
	}
	t.Setenv("TG_SENTRY_BTPII_PROTOCOL", "native")
	if got := (BTPIIConfig{}).resolved().Protocol; got != "native" {
		t.Fatal("environment protocol", got)
	}
	if got := (BTPIIConfig{Protocol: "presidio"}).resolved().Protocol; got != "presidio" {
		t.Fatal("explicit settings must win over the environment", got)
	}
	for _, protocol := range []string{"", "presidio", "native"} {
		if err := (BTPIIConfig{Protocol: protocol}).validate(); err != nil {
			t.Fatal(protocol, err)
		}
	}
	if err := (BTPIIConfig{Protocol: "openai"}).validate(); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}
func TestBTPIINativeEntityDefaults(t *testing.T) {
	if got := (BTPIIConfig{}).resolved().Entities; len(got) != 5 {
		t.Fatal("compat default labels changed", got)
	}
	if got := (BTPIIConfig{Protocol: "native"}).resolved().Entities; got != nil {
		t.Fatal("native default must omit selectors", got)
	}
	if got := (BTPIIConfig{Protocol: "native", Entities: []string{"NAME"}}).resolved().Entities; len(got) != 1 {
		t.Fatal("explicit native selector dropped", got)
	}
}
func TestBTPIINativeRouteSelection(t *testing.T) {
	var paths []string
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Write([]byte(nativeOne()))
	})
	native := cfg
	native.Protocol = "native"
	if _, err := (SensitiveDetector{BTPII: native}).Detect(context.Background(), SensitiveInput{Text: "value", Language: "en"}); err != nil {
		t.Fatal(err)
	}
	exact := native
	exact.Endpoint = cfg.Endpoint + "/ner/text/"
	if _, err := (SensitiveDetector{BTPII: exact}).Detect(context.Background(), SensitiveInput{Text: "value", Language: "en"}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/ner/text" || paths[1] != "/ner/text" {
		t.Fatal("native route selection", paths)
	}
}
func TestBTPIIDisabledKeepsAnalyzeContract(t *testing.T) {
	t.Setenv("TG_SENTRY_BTPII_PROTOCOL", "")
	compat, nativeCalls, body := 0, 0, ""
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/analyze":
			compat++
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
		case "/ner/text":
			nativeCalls++
		}
		w.Write([]byte(`[]`))
	})
	if _, err := (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: "value", Language: "en"}); err != nil || compat != 1 || nativeCalls != 0 {
		t.Fatal(err, compat, nativeCalls)
	}
	// The compat request is byte-for-byte the legacy payload when native is off:
	// same field order, same default selectors, no new members.
	const legacy = `{"text":"value","language":"en","entities":["CREDIT_CARD","EMAIL_ADDRESS","IP_ADDRESS","PHONE_NUMBER","US_SSN"]}`
	if body != legacy {
		t.Fatal("compat request body changed", body)
	}
	if strings.Contains(body, `"protocol"`) {
		t.Fatal("protocol leaked into the compat request", body)
	}
}
func TestBTPIINativeInvalidConfigFailsClosedWithoutNetwork(t *testing.T) {
	t.Setenv("TG_SENTRY_BTPII_ENDPOINT", "")
	t.Setenv("TG_SENTRY_BTPII_TOKEN_FILE", "")
	t.Setenv("TG_SENTRY_BTPII_PROTOCOL", "")
	calls := 0
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(nativeOne())) })
	cfg.Protocol = "native"
	for _, mutate := range []func(*BTPIIConfig){
		func(c *BTPIIConfig) { c.Protocol = "unknown" },
		func(c *BTPIIConfig) { c.Entities = []string{"not a label"} },
		func(c *BTPIIConfig) { c.Language = "fr" },
		func(c *BTPIIConfig) { c.Endpoint = "" },
		func(c *BTPIIConfig) { c.TokenFile = "" },
	} {
		c := cfg
		mutate(&c)
		result, err := (SensitiveDetector{BTPII: c}).Detect(context.Background(), SensitiveInput{Text: "value", Language: "en"})
		if err == nil || !result.Unavailable || err.Error() != btpiiUnavailable.Error() {
			t.Fatal(result, err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid configuration reached the network", calls)
	}
}
func TestBTPIISettingsLegacyRoundTrip(t *testing.T) {
	var cfg BTPIIConfig
	if err := json.Unmarshal([]byte(`{"endpoint":"https://example.invalid","language":"zh"}`), &cfg); err != nil || cfg.Protocol != "" {
		t.Fatal(cfg, err)
	}
	if err := cfg.validate(); err != nil || cfg.resolved().Protocol != "presidio" {
		t.Fatal("legacy settings must stay on presidio", cfg, err)
	}
	encoded, err := json.Marshal(BTPIIConfig{Endpoint: "https://example.invalid", Language: "zh"})
	if err != nil || strings.Contains(string(encoded), "protocol") {
		t.Fatal("legacy settings must not gain a protocol key", string(encoded), err)
	}
}

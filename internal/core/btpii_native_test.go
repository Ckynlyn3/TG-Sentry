package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Synthetic native /ner/text wire builders (PII/app/schemas.py:147-163).
// No vendor endpoint and no real PII is involved.
func nativeEntity(label string, start, end int, likelihood float64) map[string]any {
	return map[string]any{
		"text":       "synthetic",
		"location":   map[string]any{"stt_idx": start, "end_idx": end},
		"label":      label,
		"likelihood": likelihood,
	}
}
func nativeItem(entities ...map[string]any) map[string]any {
	if entities == nil {
		entities = []map[string]any{}
	}
	return map[string]any{
		"entities":             entities,
		"entities_present":     len(entities) > 0,
		"characters_processed": 0,
		"languages_detected":   map[string]float64{},
	}
}
func nativeWire(items ...map[string]any) string {
	b, err := json.Marshal(items)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func nativeOne(entities ...map[string]any) string { return nativeWire(nativeItem(entities...)) }

// nativeServer wires the existing httptest fixture on the native protocol.
func nativeServer(t *testing.T, handler http.HandlerFunc) BTPIIConfig {
	t.Helper()
	cfg := fakeBTPII(t, handler)
	cfg.Protocol = "native"
	return cfg
}
func nativeDetect(t *testing.T, cfg BTPIIConfig, text string) (SensitiveResult, error) {
	t.Helper()
	return (SensitiveDetector{BTPII: cfg}).Detect(context.Background(), SensitiveInput{Text: text, Language: "en"})
}

func TestBTPIINativeDecodeAndMapping(t *testing.T) {
	text := "Alice alice@example.invalid"
	var body map[string]any
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ner/text" {
			t.Error("wrong native path", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.Write([]byte(nativeOne(nativeEntity("NAME", 0, 5, 0.85), nativeEntity("EMAIL_ADDRESS", 6, 27, 0.9))))
	})
	result, err := nativeDetect(t, cfg, text)
	if err != nil || len(result.Findings) != 2 {
		t.Fatal(result, err)
	}
	first, second := result.Findings[0], result.Findings[1]
	if first.EntityType != "NAME" || first.Tag != "other" || *first.Span != (SensitiveSpan{0, 5}) || first.Score != 0.85 {
		t.Fatal(first)
	}
	if second.EntityType != "EMAIL_ADDRESS" || second.Tag != "email" || *second.Span != (SensitiveSpan{6, 27}) || second.Score != 0.9 {
		t.Fatal(second)
	}
	if first.Category != SensitiveInfoCategory {
		t.Fatal("category lost", first)
	}
	// Single-string array, no compat fields, no selector when unset.
	raw, _ := json.Marshal(body)
	if !strings.Contains(string(raw), `"text":["`+text+`"]`) ||
		strings.Contains(string(raw), "language") || strings.Contains(string(raw), "entity_detection") {
		t.Fatal("native request shape", string(raw))
	}
}

func TestBTPIINativeTagMapping(t *testing.T) {
	other := []string{
		"NAME", "NAME_GIVEN", "NAME_FAMILY", "LOCATION", "LOCATION_ADDRESS", "LOCATION_CITY",
		"LOCATION_COUNTRY", "ORGANIZATION", "DOB", "WECHAT_ID", "DATE", "AGE", "BANK_ACCOUNT",
		"USCC", "OCCUPATION", "NUMERICAL_PII", "URL", "IP_ADDRESS", "MAC_ADDRESS",
		"JSON_WEB_TOKEN", "PRIVATE_KEY", "AUTH_TOKEN", "AWS_ACCESS_KEY", "GCP_API_KEY",
		"GITHUB_TOKEN", "SLACK_TOKEN", "API_KEY", "PASSWORD", "FUTURE_LABEL",
	}
	for _, label := range append([]string{"EMAIL_ADDRESS", "PHONE_NUMBER", "SSN"}, other...) {
		t.Run(label, func(t *testing.T) {
			want := "other"
			switch label {
			case "EMAIL_ADDRESS":
				want = "email"
			case "PHONE_NUMBER":
				want = "mobile"
			case "SSN":
				want = "id-number"
			}
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(nativeOne(nativeEntity(label, 0, 5, 0.6))))
			})
			result, err := nativeDetect(t, cfg, "value")
			if err != nil || len(result.Findings) != 1 || result.Findings[0].Tag != want || result.Findings[0].EntityType != label {
				t.Fatal(label, want, result, err)
			}
		})
	}
	for _, tc := range []struct {
		label string
		value string
		tag   string
		want  int
	}{
		{"CREDIT_CARD", syntheticCard(), "bank-card", 1},
		{"CREDIT_CARD", "0000000000000001x", "bank-card", 0}, // Luhn-failing, dropped
		{"CN_ID_CARD", syntheticID(), "id-number", 1},
		{"CN_ID_CARD", "0000002000022900x", "id-number", 0},
	} {
		t.Run(tc.label+tc.value, func(t *testing.T) {
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(nativeOne(nativeEntity(tc.label, 0, utf16Length(tc.value), 0.8))))
			})
			result, err := nativeDetect(t, cfg, tc.value)
			if err != nil || len(result.Findings) != tc.want {
				t.Fatal(tc, result, err)
			}
			if tc.want == 1 && result.Findings[0].Tag != tc.tag {
				t.Fatal(tc, result.Findings[0])
			}
		})
	}
}

func TestBTPIINativeCodePointConversion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		text     string
		start    int
		end      int
		wantSpan SensitiveSpan
	}{
		{"surrogate-pair", "😀abc", 1, 4, SensitiveSpan{2, 5}},
		{"cjk", "中文名字", 1, 3, SensitiveSpan{1, 3}},
		{"surrogate-then-cjk", "😀中文", 1, 3, SensitiveSpan{2, 4}},
		{"astral-span", "a😀b", 1, 2, SensitiveSpan{1, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(nativeOne(nativeEntity("NAME", tc.start, tc.end, 0.7))))
			})
			result, err := nativeDetect(t, cfg, tc.text)
			if err != nil || len(result.Findings) != 1 || *result.Findings[0].Span != tc.wantSpan {
				t.Fatal(tc, result, err)
			}
			redacted, err := RedactSensitive(tc.text, result.Findings)
			if err != nil || !strings.HasPrefix(redacted, tc.text[:0]) || !strings.Contains(redacted, "[NAME]") {
				t.Fatal(redacted, err)
			}
		})
	}
	// A converted span must redact the exact original runes, not shift them.
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nativeOne(nativeEntity("NAME", 1, 4, 0.7))))
	})
	result, err := nativeDetect(t, cfg, "😀abc")
	if err != nil || len(result.Findings) != 1 {
		t.Fatal(result, err)
	}
	if redacted, err := RedactSensitive("😀abc", result.Findings); err != nil || redacted != "😀[NAME]" {
		t.Fatal(redacted, err)
	}
}

func TestBTPIINativeFailClosed(t *testing.T) {
	long := strings.Repeat("[", 32)
	oversize := nativeWire(nativeItem()) + strings.Repeat(" ", btpiiResponseBytes)
	tooMany := make([]map[string]any, btpiiMaxFindings+1)
	for i := range tooMany {
		tooMany[i] = nativeEntity("NAME", 0, 1, 0.5)
	}
	for _, tc := range []struct{ name, body string }{
		{"not-json", "not json"},
		{"object-not-array", `{}`},
		{"no-items", `[]`},
		{"two-items", `[{"entities":[]},{"entities":[]}]`},
		{"null-entities", `[{"entities":null}]`},
		{"missing-entities", `[{}]`},
		{"duplicate-key", `[{"entities":[],"entities":[]}]`},
		{"trailing-json", `[{"entities":[]}]x`},
		{"oversize", oversize},
		{"too-many", nativeWire(nativeItem(tooMany...))},
		{"missing-label", `[{"entities":[{"location":{"stt_idx":0,"end_idx":1},"likelihood":0.5}]}]`},
		{"empty-label", `[{"entities":[{"label":"","location":{"stt_idx":0,"end_idx":1},"likelihood":0.5}]}]`},
		{"lowercase-label", `[{"entities":[{"label":"lower","location":{"stt_idx":0,"end_idx":1},"likelihood":0.5}]}]`},
		{"long-label", `[{"entities":[{"label":"` + strings.Repeat("A", 65) + `","location":{"stt_idx":0,"end_idx":1},"likelihood":0.5}]}]`},
		{"missing-location", `[{"entities":[{"label":"NAME","likelihood":0.5}]}]`},
		{"null-index", `[{"entities":[{"label":"NAME","location":{"stt_idx":null,"end_idx":1},"likelihood":0.5}]}]`},
		{"missing-index", `[{"entities":[{"label":"NAME","location":{"stt_idx":0},"likelihood":0.5}]}]`},
		{"negative-index", `[{"entities":[{"label":"NAME","location":{"stt_idx":-1,"end_idx":1},"likelihood":0.5}]}]`},
		{"out-of-range", `[{"entities":[{"label":"NAME","location":{"stt_idx":0,"end_idx":6},"likelihood":0.5}]}]`},
		{"inverted-span", `[{"entities":[{"label":"NAME","location":{"stt_idx":4,"end_idx":2},"likelihood":0.5}]}]`},
		{"equal-span", `[{"entities":[{"label":"NAME","location":{"stt_idx":2,"end_idx":2},"likelihood":0.5}]}]`},
		{"fractional-index", `[{"entities":[{"label":"NAME","location":{"stt_idx":1.5,"end_idx":2},"likelihood":0.5}]}]`},
		{"missing-score", `[{"entities":[{"label":"NAME","location":{"stt_idx":0,"end_idx":1}}]}]`},
		{"null-score", `[{"entities":[{"label":"NAME","location":{"stt_idx":0,"end_idx":1},"likelihood":null}]}]`},
		{"negative-score", `[{"entities":[{"label":"NAME","location":{"stt_idx":0,"end_idx":1},"likelihood":-0.1}]}]`},
		{"over-one-score", `[{"entities":[{"label":"NAME","location":{"stt_idx":0,"end_idx":1},"likelihood":1.1}]}]`},
		{"string-score", `[{"entities":[{"label":"NAME","location":{"stt_idx":0,"end_idx":1},"likelihood":"0.5"}]}]`},
		{"unterminated", `[{"entities":[`},
		{"long-error", long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) })
			result, err := nativeDetect(t, cfg, "value")
			if err == nil || !result.Unavailable || err.Error() != btpiiUnavailable.Error() || len(result.Findings) != 0 {
				t.Fatal(tc.name, result, err)
			}
		})
	}
	// A syntactically valid empty entity array is a clean negative result.
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(nativeOne())) })
	result, err := nativeDetect(t, cfg, "value")
	if err != nil || result.Unavailable || len(result.Findings) != 0 {
		t.Fatal(result, err)
	}
}

func TestBTPIINativeErrorShapesAndTimeout(t *testing.T) {
	for _, status := range []int{400, 413, 422, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte(`{"detail":"synthetic-private-server-body"}`))
			})
			result, err := nativeDetect(t, cfg, "value")
			if err == nil || !result.Unavailable || strings.Contains(err.Error(), "synthetic-private") {
				t.Fatal(status, result, err)
			}
		})
	}
	t.Run("redirect", func(t *testing.T) {
		cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ner/text", http.StatusTemporaryRedirect)
		})
		if result, err := nativeDetect(t, cfg, "value"); err == nil || !result.Unavailable {
			t.Fatal(result, err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), btpiiBudget)
		defer cancel()
		result, err := (SensitiveDetector{BTPII: cfg}).Detect(ctx, SensitiveInput{Text: "value"})
		if err == nil || !result.Unavailable || ctx.Err() != context.DeadlineExceeded {
			t.Fatal(result, err, ctx.Err())
		}
	})
}

func TestBTPIINativeThresholdAndSelector(t *testing.T) {
	// Default path keeps every valid result: the service filters, not the client.
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nativeOne(nativeEntity("PHONE_NUMBER", 0, 5, 0.4))))
	})
	result, err := nativeDetect(t, cfg, "value")
	if err != nil || len(result.Findings) != 1 || result.Findings[0].Score != 0.4 {
		t.Fatal("sub-0.5 native score must survive the default path", result, err)
	}
	threshold := 0.75
	cfg.ScoreThreshold = &threshold
	result, err = nativeDetect(t, cfg, "value")
	if err != nil || len(result.Findings) != 0 {
		t.Fatal("explicit threshold must filter", result, err)
	}
	// Explicit selectors translate to one ENABLE selector; default omits them.
	var body map[string]any
	cfg = nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(nativeOne()))
	})
	cfg.Entities = []string{"NAME", "LOCATION_ADDRESS"}
	if _, err := nativeDetect(t, cfg, "value"); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body["entity_detection"])
	if !strings.Contains(string(raw), `"type":"ENABLE"`) || !strings.Contains(string(raw), `"NAME"`) {
		t.Fatal("selector not sent", string(raw))
	}
}

func TestBTPIINativeChunkRebaseAndDedupe(t *testing.T) {
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text []string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Text) != 1 {
			t.Error("chunk request shape", err)
			w.Write([]byte(nativeOne()))
			return
		}
		i := strings.Index(body.Text[0], "fake@example.invalid")
		if i < 0 {
			w.Write([]byte(nativeOne()))
			return
		}
		w.Write([]byte(nativeOne(nativeEntity("EMAIL_ADDRESS", i, i+20, 1))))
	})
	text := strings.Repeat("x", btpiiChunkUnits) + "fake@example.invalid"
	result, err := nativeDetect(t, cfg, text)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].Span.StartUTF16 != btpiiChunkUnits {
		t.Fatal("chunk rebase", result, err)
	}
	// Whole match inside the overlap is owned by two chunks and must dedupe.
	text = strings.Repeat("x", btpiiChunkUnits-btpiiChunkOverlap) + "fake@example.invalid " + strings.Repeat("y", btpiiChunkUnits)
	result, err = nativeDetect(t, cfg, text)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].Span.StartUTF16 != btpiiChunkUnits-btpiiChunkOverlap {
		t.Fatal("overlap dedupe", result, err)
	}
}

func TestBTPIINativeFailureAfterChunkDiscardsPartial(t *testing.T) {
	calls := 0
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(nativeOne(nativeEntity("EMAIL_ADDRESS", 0, 5, 1))))
	})
	text := strings.Repeat("x", btpiiChunkUnits+10)
	result, err := nativeDetect(t, cfg, text)
	if err == nil || !result.Unavailable || len(result.Findings) != 0 || calls < 2 {
		t.Fatal("partial remote results must be discarded", result, err, calls)
	}
}

func TestBTPIINativeFindingsCarryNoRawValues(t *testing.T) {
	const secret = "synthetic-matched-value"
	text := "prefix " + secret
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nativeOne(nativeEntity("NAME", 7, 7+len(secret), 0.9))))
	})
	result, err := nativeDetect(t, cfg, text)
	if err != nil || len(result.Findings) != 1 {
		t.Fatal(result, err)
	}
	raw, err := json.Marshal(result)
	if err != nil || strings.Contains(string(raw), secret) {
		t.Fatal("finding retained a raw value", string(raw), err)
	}
}

func TestBTPIINativeMemberOrderIsStable(t *testing.T) {
	// Two entities at the same offset keep service order and both survive.
	cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nativeOne(nativeEntity("NAME", 0, 5, 0.9), nativeEntity("ORGANIZATION", 0, 5, 0.5))))
	})
	result, err := nativeDetect(t, cfg, "value")
	if err != nil || len(result.Findings) != 2 || result.Findings[0].EntityType != "NAME" || result.Findings[1].EntityType != "ORGANIZATION" {
		t.Fatal(result, err)
	}
}

// Consumed members are read by exact JSON member name. encoding/json matches
// struct fields case-insensitively, so a case-variant alias must never satisfy a
// required member or override the exact one (Go src/encoding/json, Unmarshal).
func TestBTPIINativeExactMemberNames(t *testing.T) {
	const valid = `{"label":"NAME","location":{"stt_idx":0,"end_idx":5},"likelihood":0.9}`
	for _, tc := range []struct {
		name    string
		body    string
		want    int
		entity  string
		wantErr bool
	}{
		{name: "null-then-empty-alias", body: `[{"entities":null,"Entities":[]}]`, wantErr: true},
		{name: "null-then-alias", body: `[{"entities":null,"Entities":[` + valid + `]}]`, wantErr: true},
		{name: "alias-then-null", body: `[{"Entities":[],"entities":null}]`, wantErr: true},
		{name: "alias-only", body: `[{"Entities":[]}]`, wantErr: true},
		{name: "findings-plus-erasing-alias", body: `[{"entities":[` + valid + `],"Entities":[]}]`, want: 1, entity: "NAME"},
		{name: "entity-label-alias-only", body: `[{"entities":[{"Label":"NAME","location":{"stt_idx":0,"end_idx":5},"likelihood":0.9}]}]`, wantErr: true},
		{name: "entity-label-alias-shadow", body: `[{"entities":[{"label":"NAME","Label":"EMAIL_ADDRESS","location":{"stt_idx":0,"end_idx":5},"likelihood":0.9}]}]`, want: 1, entity: "NAME"},
		{name: "location-index-alias-shadow", body: `[{"entities":[{"label":"NAME","location":{"Stt_idx":9,"stt_idx":0,"end_idx":5},"likelihood":0.9}]}]`, want: 1, entity: "NAME"},
		{name: "location-index-alias-only", body: `[{"entities":[{"label":"NAME","location":{"Stt_idx":0,"End_idx":5},"likelihood":0.9}]}]`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) })
			result, err := nativeDetect(t, cfg, "value")
			if tc.wantErr {
				if err == nil || !result.Unavailable || len(result.Findings) != 0 {
					t.Fatal(tc.name, result, err)
				}
				return
			}
			if err != nil || result.Unavailable || len(result.Findings) != tc.want {
				t.Fatal(tc.name, result, err)
			}
			if got := result.Findings[0]; got.EntityType != tc.entity || *got.Span != (SensitiveSpan{0, 5}) || got.Score != 0.9 {
				t.Fatal(tc.name, got)
			}
		})
	}
}

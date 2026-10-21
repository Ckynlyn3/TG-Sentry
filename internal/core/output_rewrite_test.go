package core

import (
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func outputRule(id, matcher, pattern, decision string) Rule {
	return Rule{ID: id, Name: "Output fixture", Matcher: matcher, Pattern: pattern, Decision: decision, Enabled: true, Categories: []string{SensitiveInfoCategory}, Target: "arguments"}
}

func TestTransformToolOutputPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, text, outcome, replacement string
		rules                            []Rule
	}{
		{"clean", "benign", "unchanged", "", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "redact")}},
		{"empty", "", "unchanged", "", []Rule{}},
		{"disabled", "private-fixture", "unchanged", "", []Rule{}},
		{"redact", "😀 private-fixture suffix", "rewritten", "😀 [CUSTOM] suffix", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "redact")}},
		{"alert", "private-fixture", "unchanged", "", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "alert")}},
		{"log", "private-fixture", "unchanged", "", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "approve")}},
		{"selected-only", "private-fixture public-fixture", "rewritten", "[CUSTOM] public-fixture", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "redact"), outputRule("U_PUBLIC", "contains", "public-fixture", "alert")}},
		{"overlap", "abcdef", "rewritten", "[CUSTOM]f", []Rule{outputRule("U_ONE", "contains", "abc", "redact"), outputRule("U_TWO", "contains", "cde", "redact")}},
		{"block", "private-fixture", "withheld", "[REDACTED]", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "reject"), outputRule("U_RED", "contains", "private-fixture", "redact")}},
		{"missing-redact", "private-fixture", "withheld", "[REDACTED]", []Rule{outputRule("R_PII_EMAIL", "btpii", "email", "redact")}},
		{"missing-alert", "private-fixture", "unavailable", "", []Rule{outputRule("R_PII_EMAIL", "btpii", "email", "alert")}},
		{"missing-log", "private-fixture", "unavailable", "", []Rule{outputRule("R_PII_EMAIL", "btpii", "email", "approve")}},
		{"invalid-utf8", string([]byte{0xff}), "withheld", "[REDACTED]", []Rule{outputRule("U_PRIVATE", "contains", "private-fixture", "redact")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := transformToolOutput(context.Background(), tc.text, tc.rules, BTPIIConfig{})
			raw, err := json.Marshal(got)
			var wire map[string]string
			if err != nil || json.Unmarshal(raw, &wire) != nil || wire["outcome"] != tc.outcome || wire["text"] != tc.replacement {
				t.Fatal("incorrect outcome or original-leaf replacement")
			}
			if _, present := wire["text"]; present != (tc.outcome == "rewritten" || tc.outcome == "withheld") {
				t.Fatal("incorrect text presence")
			}
		})
	}
}

func TestTransformToolOutputDetectorReplies(t *testing.T) {
	for _, tc := range []struct{ name, body, outcome, text string }{
		{"clean", `[]`, "unchanged", ""},
		{"original-unicode", `[{"entity_type":"EMAIL_ADDRESS","start":3,"end":23,"score":1}]`, "rewritten", "😀 [EMAIL_ADDRESS] suffix"},
		{"surrogate-split", `[{"entity_type":"EMAIL_ADDRESS","start":1,"end":23,"score":1}]`, "withheld", "[REDACTED]"},
		{"missing-span", `[{"entity_type":"EMAIL_ADDRESS","score":1}]`, "withheld", "[REDACTED]"},
		{"outside-span", `[{"entity_type":"EMAIL_ADDRESS","start":3,"end":3000,"score":1}]`, "withheld", "[REDACTED]"},
		{"negative-span", `[{"entity_type":"EMAIL_ADDRESS","start":-1,"end":23,"score":1}]`, "withheld", "[REDACTED]"},
		{"malformed", `{"raw":"must-not-be-logged"}`, "withheld", "[REDACTED]"},
		{"trailing", `[] {}`, "withheld", "[REDACTED]"},
		{"oversized", strings.Repeat(" ", 2<<20) + `[]`, "withheld", "[REDACTED]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) })
			got, _ := transformToolOutput(context.Background(), "😀 fake@example.invalid suffix", []Rule{outputRule("R_PII_EMAIL", "btpii", "email", "redact")}, cfg)
			if got.Outcome != tc.outcome || (got.Text != nil && *got.Text != tc.text) {
				t.Fatal("detector reply violated safe outcome")
			}
		})
	}
}

func TestToolOutputStrictJSON(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"operation":"transform_tool_output"}`, `{"operation":"transform_tool_output","text":null}`, `{"operation":"other","text":""}`, `{"Operation":"transform_tool_output","text":""}`, `{"operation":"transform_tool_output","text":"","rules":[]}`, `{"operation":"transform_tool_output","text":"one","text":"two"}`, `{"operation":"transform_tool_output","text":"\ud800"}`, `{"operation":"transform_tool_output","text":"\udc00"}`, string([]byte{'{', '"', 't', 'e', 'x', 't', '"', ':', '"', 0xff, '"', '}'})} {
		if _, err := DecodeToolOutputRequest([]byte(body)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	for _, text := range []string{"", "😀", "quote \" newline\n", "\\ud800", "�"} {
		raw, _ := json.Marshal(map[string]string{"operation": "transform_tool_output", "text": text})
		got, err := DecodeToolOutputRequest(raw)
		if err != nil || got.Text != text {
			t.Fatal("valid original text changed")
		}
	}
	if got, err := DecodeToolOutputRequest([]byte(`{"operation":"transform_tool_output","text":"😀"}`)); err != nil || got.Text != "😀" {
		t.Fatal("valid surrogate pair changed")
	}
	prefix := `{"operation":"transform_tool_output","text":"`
	suffix := `"}`
	atLimit := prefix + strings.Repeat("x", ToolOutputJSONBytes-len(prefix)-len(suffix)) + suffix
	if _, err := DecodeToolOutputRequest([]byte(atLimit)); err != nil {
		t.Fatal("exact envelope ceiling rejected")
	}
	if _, err := DecodeToolOutputRequest([]byte(atLimit + " ")); !errors.Is(err, ErrToolOutputOversized) {
		t.Fatal("byte ceiling exceeded without overflow")
	}
	if _, err := DecodeToolOutputRequest([]byte(`{"operation":"transform_tool_output","text":""} {}`)); !errors.Is(err, ErrToolOutputTrailing) {
		t.Fatal("trailing JSON not distinguished")
	}
	if _, err := ReadToolOutputJSON(strings.NewReader(strings.Repeat(" ", (2<<20)+1))); !errors.Is(err, ErrToolOutputOversized) {
		t.Fatal("overflow not distinguished")
	}
	for _, body := range []string{`{"outcome":"unchanged","text":"raw"}`, `{"outcome":"unavailable","text":"raw"}`, `{"outcome":"withheld","text":"raw"}`, `{"outcome":"rewritten"}`, `{"outcome":"rewritten","text":null}`, `{"outcome":"unknown"}`, `{"outcome":"unchanged","raw":"match"}`, `{"outcome":"unchanged","outcome":"rewritten"}`, `{"outcome":"rewritten","text":"\ud800"}`, `{"outcome":"unchanged"} {}`} {
		if _, err := DecodeToolOutputResponse([]byte(body)); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	for _, body := range []string{`{"outcome":"unchanged"}`, `{"outcome":"unavailable"}`, `{"outcome":"rewritten","text":""}`, `{"outcome":"withheld","text":"[REDACTED]"}`} {
		if _, err := DecodeToolOutputResponse([]byte(body)); err != nil {
			t.Fatal("valid response rejected")
		}
	}
}

func TestEngineTransformToolOutputScopeAndAudit(t *testing.T) {
	e := engine(t)
	r, err := e.Submit(input("rewrite", "Read", map[string]any{"file_path": "README.md"}))
	if err != nil {
		t.Fatal(err)
	}
	rule := outputRule("U_OUTPUT", "contains", "private-fixture", "redact")
	rule.Tool = "Read"
	if err = e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	request := `{"operation":"transform_tool_output","text":"😀 private-fixture"}`
	for _, terminal := range []bool{false, true} {
		if terminal {
			if err = e.Result(r.ID, "instance", "succeeded", "benign"); err != nil {
				t.Fatal(err)
			}
		}
		before, _ := e.Review(r.ID)
		got, err := e.TransformToolOutput(context.Background(), r.ID, strings.NewReader(request))
		if err != nil || got.Outcome != "rewritten" || got.Text == nil || *got.Text != "😀 [CUSTOM]" {
			t.Fatal("rewrite not independent of terminal reporting")
		}
		after, _ := e.Review(r.ID)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("rewrite changed stored review or execution")
		}
	}
	for _, field := range []string{"", "result"} {
		changed := rule
		changed.Field = field
		if err := e.SaveRule(testActorContext(), changed); err != nil {
			t.Fatal(err)
		}
		got, err := e.TransformToolOutput(context.Background(), r.ID, strings.NewReader(request))
		if err != nil || got.Outcome != "rewritten" {
			t.Fatal("applicable result-field rule was skipped")
		}
	}
	for _, variant := range []string{"disabled", "other-tool", "unbound", "wrong-surface", "command-field", "prompt-field"} {
		changed := rule
		switch variant {
		case "disabled":
			changed.Enabled = false
		case "other-tool":
			changed.Tool = "Write"
		case "unbound":
			changed.ScopeOnly = true
		case "wrong-surface":
			changed.Target = "toolName"
		case "command-field":
			changed.Field = "command"
		case "prompt-field":
			changed.Field = "prompt"
		}
		if err = e.SaveRule(testActorContext(), changed); err != nil {
			t.Fatal(err)
		}
		got, err := e.TransformToolOutput(context.Background(), r.ID, strings.NewReader(request))
		if err != nil || got.Outcome != "unchanged" {
			t.Fatal("inapplicable rule rewrote text", variant)
		}
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(audits)
	if strings.Contains(string(raw), "private-fixture") {
		t.Fatal("raw text leaked into rewrite audits")
	}
	if _, err = e.TransformToolOutput(context.Background(), "missing", strings.NewReader(request)); err == nil {
		t.Fatal("missing review accepted")
	}
}

func TestTransformToolOutputDoesNotReturnUnscannedSuffix(t *testing.T) {
	original := strings.Repeat("x", 12000) + "private-fixture"
	got, _ := transformToolOutput(context.Background(), original, []Rule{outputRule("U_OUTPUT", "contains", "private-fixture", "redact")}, BTPIIConfig{})
	if got.Outcome != "rewritten" || got.Text == nil || *got.Text != strings.Repeat("x", 12000)+"[CUSTOM]" {
		t.Fatal("report excerpt boundary truncated output scanning")
	}
}

func TestTransformToolOutputCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, action := range []string{"redact", "alert", "approve"} {
		got, _ := transformToolOutput(ctx, "private-fixture", []Rule{outputRule("U_OUTPUT", "contains", "private-fixture", action)}, BTPIIConfig{})
		want := "unavailable"
		if action == "redact" {
			want = "withheld"
		}
		if got.Outcome != want {
			t.Fatal("cancelled detection bypassed scoped policy")
		}
	}
}

func TestTransformToolOutputCleanSecretScanDoesNotStrengthenAlert(t *testing.T) {
	rules := append(secretRules(), outputRule("R_PII_EMAIL", "btpii", "email", "alert"))
	got, _ := transformToolOutput(context.Background(), "private-fixture", rules, BTPIIConfig{})
	if got.Outcome != "unavailable" {
		t.Fatal("completed clean credential scan strengthened unavailable alert policy")
	}
}

func TestTransformToolOutputSameTagActions(t *testing.T) {
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":0,"end":20,"score":1}]`))
	})
	rules := []Rule{outputRule("A_ALERT", "btpii", "email", "alert"), outputRule("Z_REDACT", "btpii", "email", "redact")}
	got, _ := transformToolOutput(context.Background(), "fake@example.invalid", rules, cfg)
	if got.Outcome != "rewritten" || got.Text == nil || *got.Text != "[EMAIL_ADDRESS]" {
		t.Fatal("equal-strength alert hid an applicable redact rule")
	}
}

func TestTransformToolOutputAuditFailureKeepsReplacement(t *testing.T) {
	e := engine(t)
	r, err := e.Submit(input("audit-failure", "Read", map[string]any{"file_path": "README.md"}))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.SaveRule(testActorContext(), outputRule("U_OUTPUT", "contains", "private-fixture", "redact")); err != nil {
		t.Fatal(err)
	}
	rejectAudit(t, e)
	got, err := e.TransformToolOutput(context.Background(), r.ID, strings.NewReader(`{"operation":"transform_tool_output","text":"private-fixture"}`))
	if err == nil || got.Outcome != "rewritten" || got.Text == nil || *got.Text != "[CUSTOM]" {
		t.Fatal("audit failure discarded a valid replacement")
	}
}

type blockingOutputReader struct {
	io.Reader
	started, release chan struct{}
	blocked          bool
}

func (r *blockingOutputReader) Read(p []byte) (int, error) {
	if !r.blocked {
		r.blocked = true
		close(r.started)
		<-r.release
	}
	return r.Reader.Read(p)
}

func TestTransformToolOutputBlockingBodyDoesNotLockEngine(t *testing.T) {
	e := engine(t)
	first, err := e.Submit(input("blocking-output", "Read", map[string]any{"file_path": "README.md"}))
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.Submit(input("unrelated-output", "Read", map[string]any{"file_path": "README.md"}))
	if err != nil {
		t.Fatal(err)
	}
	body := &blockingOutputReader{Reader: strings.NewReader(`{"operation":"transform_tool_output","text":"benign"}`), started: make(chan struct{}), release: make(chan struct{})}
	transformed := make(chan error, 1)
	go func() { _, err := e.TransformToolOutput(context.Background(), first.ID, body); transformed <- err }()
	<-body.started
	finished := make(chan error, 1)
	go func() { finished <- e.Result(other.ID, "instance", "succeeded", "benign") }()
	blocked := false
	select {
	case err := <-finished:
		if err != nil {
			close(body.release)
			<-transformed
			t.Fatal(err)
		}
	case <-time.After(1500 * time.Millisecond):
		blocked = true // Existing core_test.go concurrent-operation bound.
	}
	close(body.release)
	if err := <-transformed; err != nil {
		t.Fatal(err)
	}
	if blocked {
		<-finished
		t.Fatal("incomplete output body blocked an unrelated engine result")
	}
}

func TestTransformToolOutputPostgresTenantIsolation(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	if _, err := admin.Exec(`INSERT INTO records VALUES ('other','reviews','foreign-output','{"id":"foreign-output","instanceId":"foreign-instance","toolName":"Read"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.TransformToolOutput(context.Background(), "foreign-output", strings.NewReader(`{"operation":"transform_tool_output","text":""}`)); err == nil {
		t.Fatal("foreign tenant review became accessible")
	}
}

func TestTransformToolOutputSecretsBeforeSerialization(t *testing.T) {
	candidate := runtimeSecretCandidate("private-key")
	got, _ := transformToolOutput(context.Background(), candidate, secretRules(), BTPIIConfig{})
	if got.Outcome != "withheld" || got.Text == nil || *got.Text != "[REDACTED]" {
		t.Fatal("original multiline credential bypassed output scan")
	}
	assertSecretAbsent(t, candidate, got)
}

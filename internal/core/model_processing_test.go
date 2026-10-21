package core

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

// Decode the additive wire contract so RED exercises old behavior, not a compile failure.
func processingSettings(t *testing.T, class string, enabled bool) Settings {
	t.Helper()
	var s Settings
	raw, err := json.Marshal(map[string]any{
		"mode": "human", "prompt": DefaultPrompt, "approvalSeconds": 600, "modelSeconds": 5,
		"model":              map[string]any{"protocol": "openai", "baseUrl": "https://selected.invalid/v1", "model": "fixture", "tested": true, "processingClass": class},
		"externalProcessing": map[string]any{"enabled": enabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestModelProcessingConsent(t *testing.T) {
	for _, protocol := range []string{"openai", "anthropic"} {
		for _, purpose := range []string{"judge", "classifier", "format_retry_entry"} {
			for _, tc := range []struct {
				name, class      string
				enabled, allowed bool
			}{
				{"absent_legacy_tested", "", false, false},
				{"unknown", "unknown", true, false},
				{"external_default", "external", false, false},
				{"external_opt_in", "external", true, true},
				{"self_hosted", "self_hosted", false, true},
			} {
				t.Run(protocol+"/"+purpose+"/"+tc.name, func(t *testing.T) {
					s := processingSettings(t, tc.class, tc.enabled)
					s.Model.Protocol = protocol
					calls := 0
					previous := http.DefaultTransport
					t.Cleanup(func() { http.DefaultTransport = previous })
					http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.URL.Host != "selected.invalid" {
							t.Errorf("unselected destination: %s", req.URL.Host)
						}
						reply := unknownApprove
						if purpose == "classifier" {
							reply = `{"tags":[],"confidence":"high"}`
						}
						finish := "stop"
						if protocol == "anthropic" {
							finish = "end_turn"
						}
						return retryResponse(protocol, reply, finish, true), nil
					})
					var err error
					if purpose == "classifier" {
						result := classifyPromptAttack(context.Background(), s, PromptAttackInput{Text: "customer content", Surface: "prompt"}, nil)
						if result.Unavailable != !tc.allowed {
							t.Fatalf("classifier unavailable=%v", result.Unavailable)
						}
						if !tc.allowed && result.Reason != "classifier_processing_not_permitted" {
							t.Errorf("reason=%s", result.Reason)
						}
					} else if purpose == "judge" {
						_, err = callModel(context.Background(), s, map[string]string{"text": "customer content"})
					} else {
						var usage *TokenUsage
						_, err = callModelText(context.Background(), s, []map[string]string{
							{"role": "user", "content": "customer content"},
							{"role": "assistant", "content": "malformed JSON"},
							{"role": "user", "content": "correct only the format"},
						}, &usage)
					}
					if purpose != "classifier" && ((err == nil) != tc.allowed || !tc.allowed && !strings.Contains(err.Error(), "processing not permitted")) {
						t.Errorf("allowed=%v err=%v", tc.allowed, err)
					}
					want := 0
					if tc.allowed {
						want = 1
					}
					if calls != want {
						t.Fatalf("dispatches=%d want=%d", calls, want)
					}
				})
			}
		}
	}
}

func TestModelProcessingClassifierOverride(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := processingSettings(t, "self_hosted", enabled)
		override := processingSettings(t, "external", enabled).Model
		override.BaseURL = "https://classifier.invalid/v1"
		s.PromptAttack.Model = &override
		calls := 0
		previous := http.DefaultTransport
		t.Cleanup(func() { http.DefaultTransport = previous })
		http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Host != "classifier.invalid" {
				t.Errorf("classifier fell back: %s", req.URL.Host)
			}
			return retryResponse("openai", `{"tags":[],"confidence":"high"}`, "stop", true), nil
		})
		r := Rule{ID: "R_PA_STEALING", Enabled: true, Matcher: "prompt-attack", Pattern: "prompt-stealing", Decision: "reject"}
		got, err := (PromptAttackDetector{Settings: s, Rules: []Rule{r}}).Detect(context.Background(), PromptAttackInput{Text: "ordinary customer text", Surface: "prompt", Tenant: "default"})
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if enabled {
			want = 1
		}
		if calls != want || got.Unavailable != !enabled || !enabled && got.Decision != "reject" {
			t.Fatalf("enabled=%v calls=%d result=%+v", enabled, calls, got)
		}
	}
}

func TestModelProcessingFailureNeverFallsBack(t *testing.T) {
	s := processingSettings(t, "self_hosted", true)
	calls := 0
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "selected.invalid" {
			t.Errorf("provider fallback: %s", req.URL.Host)
		}
		return nil, errors.New("synthetic provider unavailable")
	})
	if _, err := callModel(context.Background(), s, nil); err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestModelProcessingSyntheticTestNeedsNoConsent(t *testing.T) {
	e := engine(t)
	e.Settings = processingSettings(t, "external", false)
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		return retryResponse("openai", unknownApprove, "stop", true), nil
	})
	if err := e.TestModel(testActorContext()); err != nil || calls != 1 || !e.Config().Model.Tested {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if _, err := callModel(context.Background(), e.Settings, "customer content"); err == nil || calls != 1 {
		t.Fatalf("connection test granted consent: calls=%d err=%v", calls, err)
	}
}

func TestModelProcessingTransportOwnership(t *testing.T) {
	// Structural backstop: no production caller can bypass the shared gate except
	// the fixed synthetic TestModel probe; no context flag can propagate a bypass.
	packages, err := parser.ParseDir(token.NewFileSet(), ".", func(info os.FileInfo) bool { return !strings.HasSuffix(info.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					target, ok := node.(*ast.Ident)
					if ok && target.Name == "requestModelText" {
						seen = true
						if fn.Name.Name != "callModelText" && fn.Name.Name != "TestModel" {
							t.Errorf("ungated transport caller: %s", fn.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
	if !seen {
		t.Fatal("missing explicitly separated transport")
	}
}

func TestModelProcessingConsentAudited(t *testing.T) {
	e := engine(t)
	actor := Actor{Kind: "human", Issuer: "https://issuer.example", Subject: "admin", Name: "Admin"}
	s := processingSettings(t, "external", true)
	if err := e.SaveSettings(WithActor(context.Background(), actor), s, nil); err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	raw, _ := json.Marshal(e.Config())
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	consent, ok := wire["externalProcessing"].(map[string]any)
	if !ok || consent["enabled"] != true || consent["updatedAt"] == nil {
		t.Fatalf("consent not persisted: %v", consent)
	}
	gotActor, _ := json.Marshal(consent["actor"])
	var savedActor Actor
	if json.Unmarshal(gotActor, &savedActor) != nil || savedActor != actor {
		t.Fatalf("consent actor=%s", gotActor)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audits {
		if a.Action == "settings.update" {
			found = a.Actor == actor
		}
	}
	if !found {
		t.Fatal("opt-in lacks actor audit")
	}
	versions, err := e.ConfigVersions()
	if err != nil || len(versions) == 0 {
		t.Fatalf("missing revision: %v", err)
	}
	// An unrelated save must not replace the consent's actor/time.
	next := e.Config()
	if err := e.SaveSettings(testActorContext(), next, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(e.Config())
	_ = json.Unmarshal(raw, &wire)
	if !reflect.DeepEqual(wire["externalProcessing"], consent) {
		t.Fatal("unrelated save rewrote consent metadata")
	}
	// Revoke through the same audited revision path.
	next = processingSettings(t, "external", false)
	if err := e.SaveSettings(WithActor(context.Background(), actor), next, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(e.Config())
	_ = json.Unmarshal(raw, &wire)
	if wire["externalProcessing"].(map[string]any)["enabled"] != false {
		t.Fatal("revocation not stored")
	}
}

func TestModelProcessingAuditFailureAndLegacy(t *testing.T) {
	e := engine(t)
	before := e.Config()
	rejectAudit(t, e)
	s := processingSettings(t, "external", true)
	if err := e.SaveSettings(testActorContext(), s, nil); err == nil {
		t.Fatal("audit failure granted consent")
	}
	if !reflect.DeepEqual(e.Config(), before) {
		t.Fatal("failed audit changed runtime permission")
	}
	var stored Settings
	if err := e.get("settings", "current", &stored); err != nil || stored.ExternalProcessing.Enabled {
		t.Fatalf("failed audit changed persisted consent: %v", err)
	}
	var legacy Settings
	if err := json.Unmarshal([]byte(`{"model":{"baseUrl":"https://selected.invalid","model":"fixture","tested":true}}`), &legacy); err != nil || legacy.ExternalProcessing.Enabled || legacy.Model.ProcessingClass != "" {
		t.Fatal("legacy config gained permission", err)
	}
}

func TestModelProcessingProductionJudgeDenied(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := engine(t)
		e.Settings = processingSettings(t, "external", false)
		e.Settings.Mode = "model"
		calls := 0
		previous := http.DefaultTransport
		t.Cleanup(func() { http.DefaultTransport = previous })
		http.DefaultTransport = reviewRoundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return retryResponse("openai", unknownApprove, "stop", true), nil
		})
		r, err := e.Submit(input("consent", "fixture", map[string]any{"text": "ordinary customer text"}))
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		r, err = e.Review(r.ID)
		if err != nil || calls != 0 || r.Decision != "reject" || r.RuleID != "E_MODEL" || r.Execution == "awaiting_execution" {
			t.Fatalf("calls=%d decision=%s rule=%s err=%v", calls, r.Decision, r.RuleID, err)
		}
	})
}

func TestModelProcessingRetriesStaySelected(t *testing.T) {
	for _, purpose := range []string{"judge", "classifier"} {
		s := processingSettings(t, "external", true)
		calls := 0
		previous := http.DefaultTransport
		t.Cleanup(func() { http.DefaultTransport = previous })
		http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Host != "selected.invalid" {
				t.Errorf("retry changed destination: %s", req.URL.Host)
			}
			reply := "malformed"
			if calls > 1 {
				reply = unknownApprove
				if purpose == "classifier" {
					reply = `{"tags":[],"confidence":"high"}`
				}
			}
			return retryResponse("openai", reply, "stop", true), nil
		})
		if purpose == "judge" {
			if _, err := callModel(context.Background(), s, nil); err != nil {
				t.Fatal(err)
			}
		} else if got := classifyPromptAttack(context.Background(), s, PromptAttackInput{Text: "customer", Surface: "prompt"}, nil); got.Unavailable {
			t.Fatal(got.Reason)
		}
		if calls != 2 {
			t.Fatalf("format correction dispatches=%d", calls)
		}
	}
}

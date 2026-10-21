package core

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the real Submit/Decide/model pipeline without a listener, live model
// or executing the tool arguments. Fixtures mirror the adapter wire inputs.
func TestRuleFirstAcrossAgentsAndModes(t *testing.T) {
	for _, mode := range []string{"human", "model"} {
		for _, agent := range []string{"pi", "claude", "codex", "opencode", "grok", "openclaw", "hermes"} {
			t.Run(mode+"/"+agent, func(t *testing.T) {
				var requests atomic.Int32
				original := http.DefaultTransport
				t.Cleanup(func() { http.DefaultTransport = original })
				http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
					requests.Add(1)
					verdict := `{"decision":"approve","comment":"实际操作：处理测试调用；成功后的后果：返回测试结果；命中规则：D1"}`
					body, _ := json.Marshal(map[string]any{
						"choices": []any{map[string]any{"message": map[string]string{"content": verdict}}},
						"usage":   map[string]int{"prompt_tokens": 10, "completion_tokens": 5},
					})
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
				})
				e := engine(t)
				cwd := t.TempDir()
				if err := e.Register(Instance{ID: agent, Agent: agent, SessionID: agent, Cwd: cwd, HookVersion: Version}); err != nil {
					t.Fatal(err)
				}
				e.mu.Lock()
				e.Settings.Mode = mode
				e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
				e.mu.Unlock()
				for _, rule := range []Rule{
					{ID: "U_JSON", Name: "完整参数", Enabled: true, Decision: "reject", Matcher: "contains", Target: "arguments", Pattern: `"marker":"fixture"`},
					{ID: "U_NAME", Name: "工具名允许", Enabled: true, Decision: "approve", Matcher: "regex", Target: "toolName", Pattern: `(?i)^fixture_allow$`, Priority: 1000},
					{ID: "U_FIELD", Name: "原始字段", Enabled: true, Decision: "reject", Matcher: "regex", Target: "arguments", Field: "request.token", Pattern: `^fixture-secret$`},
				} {
					if err := e.SaveRule(testActorContext(), rule); err != nil {
						t.Fatal(err)
					}
				}
				submit := func(tool string, args map[string]any) Review {
					t.Helper()
					r, err := e.Submit(ReviewInput{InstanceID: agent, CallID: ID(), ToolName: tool, Arguments: args})
					if err != nil {
						t.Fatal(err)
					}
					return r
				}
				tool, read, field := "Bash", "Read", "file_path"
				if agent == "pi" || agent == "opencode" {
					tool, read, field = "bash", "read", "path"
				} else if agent == "openclaw" {
					tool, read, field = "exec", "read", "path"
				} else if agent == "hermes" {
					tool, read, field = "terminal", "read_file", "path"
				}
				var first Review
				for _, tc := range []struct {
					tool, rule, decision string
					args                 map[string]any
				}{
					{tool, "R_DB_REDIS", "reject", map[string]any{"command": "redis-cli FLUSHALL"}},
					{read, "A7", "approve", map[string]any{field: "README.md"}},
					{"mcp_fixture", "U_JSON", "reject", map[string]any{"marker": "fixture"}},
					{"FIXTURE_ALLOW", "U_NAME", "approve", map[string]any{"command": "echo fixture"}},
					// A high-priority allow still cannot hide a rejecting rule.
					{"fixture_allow", "U_JSON", "reject", map[string]any{"marker": "fixture"}},
					{"mcp_fixture", "U_FIELD", "reject", map[string]any{"request": map[string]any{"token": "fixture-secret"}}},
				} {
					r := submit(tc.tool, tc.args)
					if first.ID == "" {
						first = r
					}
					if r.ReviewPath != "rule" || r.Decision != tc.decision || r.RuleID != tc.rule || r.NeedsHuman || r.ModelVerdict != nil || r.ModelContext != nil || r.DecidedAt == nil {
						t.Fatalf("%s: path=%s decision=%s rule=%s", tc.tool, r.ReviewPath, r.Decision, r.RuleID)
					}
					if tc.rule == "U_FIELD" && valueAt(r.Arguments, "request.token") != "[REDACTED]" {
						t.Fatal("rule must match original input, storage must remain redacted")
					}
					if _, err := e.Decide(testActorContext(), r.ID, r.Digest, "approve", ""); err == nil {
						t.Fatal("rule verdict entered human approval")
					}
				}
				if usage, err := e.Usage(); err != nil || len(usage) != 0 || requests.Load() != 0 {
					t.Fatal("rule hits used the model", err)
				}
				finishFallback := func(r Review) Review {
					t.Helper()
					if r.Decision != "pending" || r.ReviewPath != mode || r.NeedsHuman != (mode == "human") || r.RuleID != "" {
						t.Fatal("unmatched call did not enter the selected reviewer")
					}
					var err error
					if mode == "human" {
						r, err = e.Decide(testActorContext(), r.ID, r.Digest, "approve", "")
					} else {
						for n := 0; n < 400; n++ {
							r, err = e.Review(r.ID)
							if err != nil || r.Decision != "pending" {
								break
							}
							time.Sleep(5 * time.Millisecond)
						}
					}
					if err != nil || r.Decision != "approve" || r.ReviewPath != mode || r.Execution != "awaiting_execution" {
						t.Fatal("fallback did not finish", err)
					}
					return r
				}
				fallback := finishFallback(submit(tool, map[string]any{"command": "echo fixture"}))
				if again, err := e.Submit(fallback.ReviewInput); err != nil || again.ReviewPath != mode || again.Decision != "approve" {
					t.Fatal("retry did not preserve the original verdict", err)
				}
				redis := ruleByID(t, e, "R_DB_REDIS")
				redis.Enabled = false
				if err := e.SaveRule(testActorContext(), redis); err != nil {
					t.Fatal(err)
				}
				finishFallback(submit(tool, map[string]any{"command": "redis-cli FLUSHALL"}))
				if old, err := e.Review(first.ID); err != nil || old.ReviewPath != "rule" || old.Decision != "reject" {
					t.Fatal("rule change rewrote a prior decision", err)
				}
				if err := e.SaveScope(testActorContext(), Scope{Name: "fixture", Project: cwd, Paths: []string{filepath.Join(cwd, "allowed")}}); err != nil {
					t.Fatal(err)
				}
				if r := submit(read, map[string]any{field: filepath.Join(cwd, "outside")}); r.ReviewPath != "scope" || r.RuleID != "SCOPE_PATH" || r.Decision != "reject" || r.NeedsHuman {
					t.Fatal("scope must precede read allow rule and both reviewers")
				}
				want := int32(0)
				if mode == "model" {
					want = 2
				}
				usage, err := e.Usage()
				if err != nil || requests.Load() != want || len(usage) != int(want) {
					t.Fatalf("model requests=%d usage=%d want=%d err=%v", requests.Load(), len(usage), want, err)
				}
			})
		}
	}
}

// AC1 compares enforcement, not the configured mode or timestamps. Detector
// settings are identical and disabled; all three actions must terminate locally.
func TestJudgeDisabledDeterministicModeEquivalence(t *testing.T) {
	for _, action := range []string{"approve", "reject", "alert"} {
		t.Run(action, func(t *testing.T) {
			previous := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = previous })
			var calls atomic.Int32
			http.DefaultTransport = reviewRoundTrip(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				panic("resolved rule dispatched a model request")
			})
			var before Review
			var detectorSettings Settings
			for _, mode := range []string{"human", "model"} {
				e := engine(t)
				e.Settings.Mode = mode
				e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
				if err := e.SaveRule(testActorContext(), Rule{ID: "U_ACTION", Name: "Fixture", Matcher: "contains", Pattern: "fixture", Tool: "fixture", Enabled: true, Decision: action}); err != nil {
					t.Fatal(err)
				}
				r, err := e.Submit(input("mode-equivalence", "fixture", map[string]any{"value": "fixture"}))
				want, execution := "approve", "awaiting_execution"
				if action == "reject" {
					want, execution = "reject", "not_executed"
				}
				if err != nil || r.Decision != want || r.RuleID != "U_ACTION" || r.Execution != execution || r.ReviewPath != "rule" || r.NeedsHuman || r.DecidedAt == nil {
					t.Fatalf("%s: decision=%s rule=%s execution=%s path=%s err=%v", mode, r.Decision, r.RuleID, r.Execution, r.ReviewPath, err)
				}
				if mode == "human" {
					detectorSettings = e.Settings
				} else if r.Decision != before.Decision || r.RuleID != before.RuleID || r.Execution != before.Execution || r.ReviewPath != before.ReviewPath || !reflect.DeepEqual(e.Settings.PromptAttack, detectorSettings.PromptAttack) || e.Settings.NSFA != detectorSettings.NSFA || !reflect.DeepEqual(e.Settings.BTPII, detectorSettings.BTPII) {
					t.Fatal("changing only judge mode changed deterministic enforcement")
				}
				before = r
			}
			if calls.Load() != 0 {
				t.Fatal("resolved fixture used a model", calls.Load())
			}
		})
	}
}

// The BTPII fake is an independent detector, never a generic tool judge.
func TestResolvedBlocksNeverDispatchJudge(t *testing.T) {
	for _, boundary := range []string{"scope", "acl", "rule", "sensitive-info"} {
		for _, mode := range []string{"human", "model"} {
			t.Run(boundary+"/"+mode, func(t *testing.T) {
				e := engine(t)
				e.Settings.Mode = mode
				e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
				enablePA(t, e, "R_PA_STEALING", "reject")
				previous := http.DefaultTransport
				t.Cleanup(func() { http.DefaultTransport = previous })
				var calls atomic.Int32
				http.DefaultTransport = reviewRoundTrip(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					panic("resolved block dispatched judge or classifier")
				})
				in := input("resolved-block", "read", map[string]any{"path": "README.md"})
				wantRule, wantPath := "U_DENY", "rule"
				switch boundary {
				case "scope":
					var instance Instance
					if err := e.get("instances", "instance", &instance); err != nil {
						t.Fatal(err)
					}
					cwd := instance.Cwd
					if err := e.SaveScope(testActorContext(), Scope{Name: "Fixture", Project: cwd, Paths: []string{filepath.Join(cwd, "allowed")}}); err != nil {
						t.Fatal(err)
					}
					in.Arguments = map[string]any{"path": filepath.Join(cwd, "outside")}
					wantRule, wantPath = "SCOPE_PATH", "scope"
				case "acl":
					aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "Fixture deny", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "tools", Tools: []string{"read"}}}})
					state := aclState(t, e)
					wantPath = "acl"
					for _, rule := range state.EffectiveACLRules() {
						if rule.Name == "Fixture deny" {
							wantRule = rule.ID
						}
					}
				case "rule":
					if err := e.SaveRule(testActorContext(), Rule{ID: wantRule, Name: "Fixture deny", Matcher: "contains", Pattern: "README.md", Enabled: true, Decision: "reject"}); err != nil {
						t.Fatal(err)
					}
				case "sensitive-info":
					var detectorCalls atomic.Int32
					e.Settings.BTPII = fakeBTPII(t, func(w http.ResponseWriter, req *http.Request) {
						detectorCalls.Add(1)
						var body struct {
							Text string `json:"text"`
						}
						if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
							t.Error(err)
							return
						}
						start := strings.Index(body.Text, "fake@example.invalid")
						if start < 0 {
							t.Error("missing synthetic detector input")
							return
						}
						json.NewEncoder(w).Encode([]map[string]any{{"entity_type": "EMAIL_ADDRESS", "start": start, "end": start + len("fake@example.invalid"), "score": 1}})
					})
					// Loopback detector traffic uses the real stdlib transport; all model
					// traffic still hits the panic fake above.
					blocked := http.DefaultTransport
					http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
						if strings.HasPrefix(req.URL.String(), e.Settings.BTPII.Endpoint) {
							return previous.RoundTrip(req)
						}
						return blocked.RoundTrip(req)
					})
					if err := e.SaveRule(testActorContext(), Rule{ID: "R_PII_EMAIL", Name: "Fixture email", Matcher: "btpii", Pattern: "email", Enabled: true, Decision: "reject"}); err != nil {
						t.Fatal(err)
					}
					in.Arguments["value"] = "fake@example.invalid"
					wantRule = "R_PII_EMAIL"
					t.Cleanup(func() {
						if detectorCalls.Load() != 1 {
							t.Errorf("detector requests=%d want 1", detectorCalls.Load())
						}
					})
				}
				r, err := e.Submit(in)
				if err != nil || r.Decision != "reject" || r.RuleID != wantRule || r.ReviewPath != wantPath || r.Execution != "not_executed" || r.NeedsHuman || r.ModelVerdict != nil || calls.Load() != 0 {
					t.Fatalf("block lost: decision=%s rule=%s path=%s execution=%s calls=%d err=%v", r.Decision, r.RuleID, r.ReviewPath, r.Execution, calls.Load(), err)
				}
				if usage, err := e.Usage(); err != nil || len(usage) != 0 {
					t.Fatal("resolved block recorded judge usage", usage, err)
				}
			})
		}
	}
}

func TestLegacyReviewPathUsesSavedEvidence(t *testing.T) {
	e := engine(t)
	for _, tc := range []struct {
		name, want string
		r          Review
	}{
		{"rule-in-model-mode", "rule", Review{Mode: "model", Decision: "reject", RuleID: "R1", Rules: BuiltinRules()}},
		{"model-with-builtin-id", "model", Review{Mode: "model", Decision: "reject", RuleID: "R1", Rules: BuiltinRules(), ModelVerdict: &Decision{Decision: "reject", RuleID: "R1"}}},
		{"deleted-custom-rule", "rule", Review{Mode: "human", Decision: "approve", RuleID: "U_OLD", Rules: []Rule{{ID: "U_OLD", Enabled: true, Decision: "approve"}}}},
		{"scope", "scope", Review{Mode: "model", RuleID: "SCOPE_TARGET"}},
		{"human", "human", Review{Mode: "human", RuleID: "HUMAN"}},
		{"pending-model", "model", Review{Mode: "model", Decision: "pending"}},
		{"expired-human", "human", Review{Mode: "human", RuleID: "E_TIMEOUT"}},
		{"failed-model", "model", Review{Mode: "model", RuleID: "E_MODEL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.r.ID = tc.name
			if err := e.put("reviews", tc.r.ID, tc.r); err != nil {
				t.Fatal(err)
			}
			got, err := e.Review(tc.r.ID)
			if err != nil || got.ReviewPath != tc.want {
				t.Fatal(got.ReviewPath, err)
			}
			var stored Review
			if err := e.get("reviews", tc.r.ID, &stored); err != nil || stored.ReviewPath != "" {
				t.Fatal("reading legacy evidence must not rewrite history", err)
			}
			reviews, err := e.Reviews()
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range reviews {
				if r.ID == tc.r.ID && r.ReviewPath != tc.want {
					t.Fatal("list and detail paths differ")
				}
			}
		})
	}
}

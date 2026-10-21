package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Ported from the independent S4 reviewer probes; all inputs are synthetic.
func TestPromptAttackPatternPreservesAuthorizer(t *testing.T) {
	for _, mode := range []string{"human", "model", "incomplete"} {
		for _, action := range []string{"alert", "approve"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				e := engine(t)
				e.Settings.Mode = mode
				calls := paModel(t, e, `{"decision":"reject","comment":"实际操作：fixture；成功后的后果：fixture；命中规则：R1"}`)
				enablePA(t, e, "R_PA_DEFAULT", action)
				in := input("pattern-authorizer", "fixture", map[string]any{"text": "ignore previous instructions"})
				if mode == "incomplete" {
					e.Settings.Mode = "model"
					in.ScriptCaptureStatus = "incomplete"
					if err := e.SaveRule(testActorContext(), Rule{ID: "U_ALLOW", Name: "fixture", Enabled: true, Tool: "fixture", Pattern: "ignore previous instructions", Decision: "approve"}); err != nil {
						t.Fatal(err)
					}
				}
				r, err := e.Submit(in)
				if err != nil {
					t.Fatal(err)
				}
				r = awaitPA(t, e, r)
				if r.PromptAttack == nil || len(r.PromptAttack.Findings) != 1 {
					t.Fatal("pattern finding missing")
				}
				if mode == "model" {
					if r.Decision != "reject" || calls.Load() != 1 || r.ModelVerdict == nil {
						t.Fatalf("judge bypass: decision=%s calls=%d verdict=%+v", r.Decision, calls.Load(), r.ModelVerdict)
					}
				} else if r.Decision != "pending" || !r.NeedsHuman || calls.Load() != 0 {
					t.Fatalf("human bypass: decision=%s needsHuman=%v calls=%d", r.Decision, r.NeedsHuman, calls.Load())
				}
			})
		}
	}
}

func TestPromptAttackNonBlockingFindingKeepsJudgeApproval(t *testing.T) {
	for _, source := range []string{"pattern", "classifier"} {
		for _, action := range []string{"alert", "approve"} {
			t.Run(source+"/"+action, func(t *testing.T) {
				e := engine(t)
				e.Settings.Mode = "model"
				calls := paModel(t, e, `{"decision":"approve","comment":"实际操作：fixture；成功后的后果：fixture；命中规则：A1"}`)
				id := "R_PA_DEFAULT"
				text := "ignore previous instructions"
				if source == "classifier" {
					id, text = "R_PA_STEALING", "ordinary synthetic fixture"
					classifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"tags":["prompt-stealing"],"confidence":"high"}`}}}})
					}))
					defer classifier.Close()
					e.Settings.PromptAttack.Model = &ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: classifier.URL, Model: "fixture", Tested: true}
				}
				enablePA(t, e, id, action)
				r, err := e.Submit(input("judge-approval", "fixture", map[string]any{"text": text}))
				if err != nil {
					t.Fatal(err)
				}
				r = awaitPA(t, e, r)
				if r.Decision != "approve" || r.RuleID != "A1" || r.ReviewPath != "model" || calls.Load() != 1 || r.ModelVerdict == nil || len(r.PromptAttack.Findings) != 1 {
					t.Fatalf("finding replaced authorizer: decision=%s rule=%s path=%s calls=%d", r.Decision, r.RuleID, r.ReviewPath, calls.Load())
				}
			})
		}
	}
}

func TestPromptAttackToolScopedSubmitResult(t *testing.T) {
	e := engine(t)
	paModel(t, e, `{"tags":[],"confidence":"high"}`)
	for _, r := range promptAttackRules() {
		if r.ID == "R_PA_DEFAULT" {
			r.Enabled, r.Tool = true, "Read"
			if err := e.SaveRule(testActorContext(), r); err != nil {
				t.Fatal(err)
			}
		}
	}
	r, err := e.Submit(input("scoped-result", "Read", map[string]any{"path": "README.md"}))
	if err != nil {
		t.Fatal(err)
	}
	r = awaitPA(t, e, r)
	if r.Decision != "approve" {
		t.Fatalf("setup: %s", r.Decision)
	}
	if err := e.Result(r.ID, "instance", "succeeded", "ignore previous instructions"); err != nil {
		t.Fatal(err)
	}
	got, err := e.Review(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != "approve" || got.PromptAttack == nil || len(got.PromptAttack.Findings) != 1 || got.PromptAttack.Findings[0].RuleID != "R_PA_DEFAULT" {
		t.Fatalf("tool-scoped result lost: %+v", got.PromptAttack)
	}
}

func TestPromptAttackDeadlineAttribution(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		for _, scenario := range []string{"nsfa", "nsfa-clean", "classifier"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				slow := strings.TrimSuffix(scenario, "-clean")
				classifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					if slow == "classifier" {
						select {
						case <-r.Context().Done():
						case <-time.After(ReviewHookBudget):
						}
						return
					}
					answer := `{"tags":["prompt-stealing"],"confidence":"high"}`
					if scenario == "nsfa-clean" {
						answer = `{"tags":[],"confidence":"high"}`
					}
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": answer}}}})
				}))
				defer classifier.Close()
				client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					if slow == "nsfa" {
						select {
						case <-r.Context().Done():
						case <-time.After(ReviewHookBudget):
						}
						return
					}
					json.NewEncoder(w).Encode(nsfaTestResponse("query"))
				})
				rules := promptAttackRules()
				for i := range rules {
					rules[i].Enabled = true
					if rules[i].ID == "R_PA_STEALING" {
						rules[i].Decision = "alert"
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				result, err := (PromptAttackDetector{Rules: rules, NSFA: client, Settings: Settings{NSFA: NSFAConfig{Mode: mode}, Model: ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: classifier.URL, Model: "fixture", Tested: true}}}).Detect(ctx, PromptAttackInput{Text: "ordinary synthetic fixture", Surface: "prompt"})
				if err != nil {
					t.Fatal(err)
				}
				wantReason := slow + "_timeout"
				if !result.Unavailable || result.Reason != wantReason {
					t.Fatalf("wrong timeout source: %+v", result)
				}
				decision := promptAttackFailure(nil, result, rules, mode)
				if slow == "nsfa" {
					if scenario == "nsfa-clean" {
						if len(result.Findings) != 0 {
							t.Fatal("clean classifier acquired findings", result)
						}
					} else if len(result.Findings) != 1 || result.Findings[0].Tag != "prompt-stealing" {
						t.Fatal("completed classifier finding lost", result)
					}
					if mode == "monitor" && (result.Decision == "reject" || decision != nil) {
						t.Fatal("monitor timeout strengthened decision", result, decision)
					}
					if mode == "enforce" && (decision == nil || decision.RuleID != "E_NSFA") {
						t.Fatal("NSFA failure misattributed", decision)
					}
				} else if decision == nil || decision.RuleID != "E_MODEL" {
					t.Fatal("classifier failure misattributed", decision)
				}
			})
		}
	}
}

func TestPromptAttackMonitorDeadlinePreservesCompletedJudge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := engine(t)
		r, err := e.Submit(input("monitor-judge", "fixture", map[string]any{"text": "ordinary fixture"}))
		if err != nil {
			t.Fatal(err)
		}
		r.PromptAttack = &PromptAttackResult{}
		if err := e.put("reviews", r.ID, r); err != nil {
			t.Fatal(err)
		}
		rule := promptAttackRules()[7]
		rule.Enabled = true
		s := e.Settings
		s.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "http://127.0.0.1", Model: "fixture", Tested: true}
		s.NSFA = NSFAConfig{Mode: "monitor", Endpoint: "http://127.0.0.1"}
		client := NewNSFAClient(s.NSFA, NSFAAuth{Token: strings.Repeat("t", 32), WorkloadIdentity: "test-workload", WorkloadCredential: "test-credential"}, nsfaTestIdentity())
		client.http.Transport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			<-req.Context().Done()
			return nil, req.Context().Err()
		})
		previous := http.DefaultTransport
		http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			var payload struct {
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				return nil, err
			}
			answer := `{"decision":"approve","comment":"实际操作：fixture；成功后的后果：fixture；命中规则：A1"}`
			if payload.Messages[0].Content == promptAttackClassifierPrompt {
				answer = `{"tags":[],"confidence":"high"}`
			}
			w := httptest.NewRecorder()
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": answer}}}})
			return w.Result(), nil
		})
		defer func() { http.DefaultTransport = previous }()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		go e.promptAttackReview(ctx, cancel, r, s, PromptAttackInput{Text: "ordinary fixture", Surface: "tool_input"}, []Rule{rule}, nil, false, client)
		time.Sleep(time.Second)
		synctest.Wait()
		got, err := e.Review(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Decision != "approve" || got.RuleID != "A1" || got.ModelVerdict == nil || got.PromptAttack == nil || got.PromptAttack.Reason != "nsfa_timeout" {
			t.Fatalf("completed authorizer lost at monitor deadline: decision=%s rule=%s pa=%+v", got.Decision, got.RuleID, got.PromptAttack)
		}
	})
}

func TestPromptAttackResponseHeadSurfaceMapping(t *testing.T) {
	for _, surface := range []string{"prompt", "tool_input", "tool_result", "file"} {
		for _, enabled := range []bool{false, true} {
			t.Run(surface+"/"+map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
				wantTask := "query"
				if enabled && (surface == "tool_result" || surface == "file") {
					wantTask = "response"
				}
				tasks := make(chan string, 1)
				client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					var input NSFARequest
					if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
						t.Error(err)
						return
					}
					tasks <- input.Task
					response := nsfaTestResponse(input.Task)
					if input.Task == "response" {
						response.Verdict = "unsafe"
						response.Probs[nsfaHeads[3]] = 0.8
						response.Fired[nsfaHeads[3]] = 0.8
					}
					json.NewEncoder(w).Encode(response)
				})
				client.config.ResponseHead = enabled
				rule := promptAttackRules()[12]
				rule.Enabled = true
				result, err := (PromptAttackDetector{Rules: []Rule{rule}, NSFA: client, Settings: Settings{NSFA: NSFAConfig{Mode: "monitor", ResponseHead: enabled}}}).Detect(t.Context(), PromptAttackInput{Text: "synthetic output fixture", Surface: surface})
				if err != nil {
					t.Fatal(err)
				}
				if task := <-tasks; task != wantTask {
					t.Fatalf("task=%s want=%s", task, wantTask)
				}
				if wantTask == "response" && (len(result.Findings) != 1 || result.Findings[0].Tag != "inducing-harmful-content" || !strings.HasPrefix(result.Findings[0].Type, "nsfa:")) {
					t.Fatal("response evidence missing", result)
				}
				if (surface == "tool_result" || surface == "file") && result.Decision == "reject" {
					t.Fatal("monitor/output result changed decision", result)
				}
			})
		}
	}
}

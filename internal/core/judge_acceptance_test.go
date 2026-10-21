package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// Reuse the production classifier prompt to distinguish the two independent
// purposes even when they share a provider. Never infer purpose from call order.
func judgeFixtureTransport(t *testing.T, judge func(*http.Request) (*http.Response, error), classifier func(*http.Request) (*http.Response, error)) {
	t.Helper()
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
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
		if len(payload.Messages) == 0 {
			return nil, errors.New("missing fixture system prompt")
		}
		if payload.Messages[0].Content == promptAttackClassifierPrompt {
			return classifier(req)
		}
		return judge(req)
	})
}

func TestJudgeOnlyForUnresolvedTool(t *testing.T) {
	for _, mode := range []string{"human", "model"} {
		for _, surface := range []string{"fixture", "prompt_turn"} {
			t.Run(mode+"/"+surface, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					e := engine(t)
					e.Settings.Mode = mode
					e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
					var judgeCalls, classifierCalls atomic.Int32
					judgeFixtureTransport(t, func(*http.Request) (*http.Response, error) {
						judgeCalls.Add(1)
						return retryResponse("openai", unknownApprove, "stop", true), nil
					}, func(*http.Request) (*http.Response, error) {
						classifierCalls.Add(1)
						return retryResponse("openai", `{"tags":[],"confidence":"high"}`, "stop", true), nil
					})
					// Prompt-only work really exercises the classifier, not a no-op.
					if surface == "prompt_turn" {
						enablePA(t, e, "R_PA_STEALING", "reject")
					}
					r, err := e.Submit(input("unresolved", surface, map[string]any{"text": "ordinary fixture"}))
					if err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					r, err = e.Review(r.ID)
					if err != nil {
						t.Fatal(err)
					}
					wantJudge, wantClassifier := int32(0), int32(0)
					if surface == "prompt_turn" {
						wantClassifier = 1
						if r.Decision != "approve" || r.RuleID != "PA_CLEAN" || r.ModelVerdict != nil {
							t.Fatal("prompt check used a tool authorizer", r.Decision, r.RuleID)
						}
					} else if mode == "model" {
						wantJudge = 1
						if r.Decision != "approve" || r.RuleID != "D1" || r.ReviewPath != "model" || r.Execution != "awaiting_execution" || r.ModelVerdict == nil {
							t.Fatal("unresolved tool did not use judge", r.Decision, r.RuleID)
						}
					} else if r.Decision != "pending" || !r.NeedsHuman || r.ReviewPath != "human" || r.Execution != "not_executed" || r.ModelVerdict != nil {
						t.Fatal("unresolved human tool authorized", r.Decision)
					}
					if judgeCalls.Load() != wantJudge || classifierCalls.Load() != wantClassifier {
						t.Fatalf("judge/classifier calls=%d/%d want=%d/%d", judgeCalls.Load(), classifierCalls.Load(), wantJudge, wantClassifier)
					}
				})
			})
		}
	}
}

// Actual production coordinator, not legacy modelReview. Channel gates and Go's
// synctest (existing TestPromptAttackMonitorDeadlinePreservesCompletedJudge)
// force each completion order without sleeps or timing assumptions.
func TestPromptAttackCoordinatorRejectCannotDowngrade(t *testing.T) {
	for _, outcome := range []string{"approve", "reject", "invalid", "error", "timeout"} {
		for _, order := range []string{"judge-first", "detector-first"} {
			t.Run(outcome+"/"+order, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					e := engine(t)
					// Save unresolved human input, then drive the coordinator explicitly
					// so its full completion can be observed before comparing storage.
					r, err := e.Submit(input("deny-merge", "fixture", map[string]any{"text": "ordinary fixture"}))
					if err != nil {
						t.Fatal(err)
					}
					s := e.Settings
					s.Mode = "model"
					s.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
					rule := promptAttackRules()[7] // Existing classifier-only prompt-stealing rule.
					rule.Enabled, rule.Decision = true, "reject"
					// Match the Submit snapshot: event attribution requires the selected
					// effective detector rule in the saved review, not just the worker.
					for index, saved := range r.Rules {
						if saved.ID == rule.ID {
							r.Rules[index] = rule
						}
					}
					r.Mode, r.ReviewPath, r.NeedsHuman = "model", "model", false
					r.PromptAttack = &PromptAttackResult{}
					if err := e.put("reviews", r.ID, r); err != nil {
						t.Fatal(err)
					}
					judgeRelease, detectorRelease := make(chan struct{}), make(chan struct{})
					var judgeCalls, detectorCalls atomic.Int32
					judgeFixtureTransport(t, func(*http.Request) (*http.Response, error) {
						judgeCalls.Add(1)
						<-judgeRelease
						switch outcome {
						case "error":
							return nil, errors.New("synthetic judge failure")
						case "timeout":
							return nil, context.DeadlineExceeded
						case "invalid":
							return retryResponse("openai", `{"decision":"invalid","comment":"fixture"}`, "stop", true), nil
						case "reject":
							return retryResponse("openai", strings.Replace(strings.Replace(unknownApprove, "approve", "reject", 1), "D1", "R4", 1), "stop", true), nil
						default:
							return retryResponse("openai", unknownApprove, "stop", true), nil
						}
					}, func(*http.Request) (*http.Response, error) {
						detectorCalls.Add(1)
						<-detectorRelease
						return retryResponse("openai", `{"tags":["prompt-stealing"],"confidence":"high"}`, "stop", true), nil
					})
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					done := make(chan struct{})
					go func() {
						e.promptAttackReview(ctx, cancel, r, s, promptAttackOriginal(r.ReviewInput), []Rule{rule}, nil, false, nil)
						close(done)
					}()
					synctest.Wait()
					if judgeCalls.Load() != 1 || detectorCalls.Load() != 1 {
						t.Fatal("both concurrent tasks must start", judgeCalls.Load(), detectorCalls.Load())
					}
					if order == "judge-first" {
						close(judgeRelease)
					} else {
						close(detectorRelease)
					}
					synctest.Wait()
					pending, err := e.Review(r.ID)
					if err != nil || pending.Decision != "pending" || pending.Execution != "not_executed" {
						t.Fatal("partial completion emitted authorization", pending.Decision, err)
					}
					if order == "judge-first" {
						close(detectorRelease)
					} else {
						close(judgeRelease)
					}
					synctest.Wait()
					select {
					case <-done:
					default:
						t.Fatal("coordinator did not finish")
					}
					got, err := e.Review(r.ID)
					if err != nil || got.Decision != "reject" || got.RuleID != rule.ID || got.ReviewPath != "rule" || got.Execution != "not_executed" || got.NeedsHuman {
						t.Fatalf("detector deny downgraded: decision=%s rule=%s path=%s execution=%s err=%v", got.Decision, got.RuleID, got.ReviewPath, got.Execution, err)
					}
					wantVerdict := "reject"
					if outcome == "approve" {
						wantVerdict = "approve"
					}
					if got.ModelVerdict == nil || got.ModelVerdict.Decision != wantVerdict {
						t.Fatal("judge response was not exercised", got.ModelVerdict)
					}
					failed := hasExact(outcome, "invalid", "error", "timeout")
					usage, err := e.Usage()
					if err != nil || len(usage) != 1 || usage[0].Failed != failed || judgeCalls.Load() != 1 {
						t.Fatal("wrong judge outcome", usage, judgeCalls.Load(), err)
					}
					if failed && got.ModelVerdict.RuleID != "E_MODEL" {
						t.Fatal("failure became approval", got.ModelVerdict)
					}
					if err := e.Result(got.ID, "instance", "succeeded", "fixture"); err == nil {
						t.Fatal("denied execution accepted")
					}
				})
			})
		}
	}
}

func TestPromptAttackCoordinatorLateApprovalCannotOverwrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := engine(t)
		r, err := e.Submit(input("late-approval", "fixture", map[string]any{"text": "ordinary fixture"}))
		if err != nil {
			t.Fatal(err)
		}
		s := e.Settings
		s.Mode = "model"
		s.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
		release := make(chan struct{})
		var calls atomic.Int32
		judgeFixtureTransport(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			<-release
			return retryResponse("openai", unknownApprove, "stop", true), nil
		}, func(*http.Request) (*http.Response, error) { panic("unconfigured classifier dispatched") })
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			e.promptAttackReview(ctx, cancel, r, s, promptAttackOriginal(r.ReviewInput), nil, nil, false, nil)
			close(done)
		}()
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("judge did not start")
		}
		terminal, err := e.Decide(testActorContext(), r.ID, r.Digest, "reject", "fixture")
		if err != nil || terminal.Decision != "reject" {
			t.Fatal("terminal fixture failed", err)
		}
		// Compare the actual serialized snapshot (JSON normalizes empty slices),
		// not the in-memory return value from Decide.
		terminal, err = e.Review(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		before, err := e.riskEventOccurrences()
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != 1 {
			t.Fatal("terminal decision must emit one occurrence", len(before))
		}
		close(release)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("late coordinator did not finish")
		}
		got, err := e.Review(r.ID)
		if err != nil || !reflect.DeepEqual(got, terminal) {
			t.Fatal("late approval overwrote terminal saved review", got.Decision, got.RuleID, err)
		}
		after, err := e.riskEventOccurrences()
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatal("late completion duplicated or replaced a decision event", len(after), err)
		}
		usage, err := e.Usage()
		if err != nil || len(usage) != 1 || usage[0].Failed || usage[0].Usage == nil {
			t.Fatal("late valid approval was not consumed", usage, err)
		}
	})
}

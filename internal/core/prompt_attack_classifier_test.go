package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestModelResponseErrorPreservesTimeoutWithoutTransportDetails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantTimeout bool
	}{
		{"deadline", context.DeadlineExceeded, true},
		{"network_timeout", &net.DNSError{Err: "synthetic-canary", Name: "private.invalid", IsTimeout: true}, true},
		{"other", errors.New("synthetic-canary"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := modelResponseError("model request failed", tc.err)
			if errors.Is(err, context.DeadlineExceeded) != tc.wantTimeout || strings.Contains(err.Error(), "synthetic-canary") || strings.Contains(err.Error(), "private.invalid") {
				t.Fatalf("timeout identity or sanitized message invalid: %v", err)
			}
		})
	}
}

func TestParsePromptAttackTags(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		want        []string
	}{
		{"empty", `{"tags":[],"confidence":"high"}`, []string{}},
		{"positive", `{"tags":["role-playing","prompt-stealing"],"confidence":"medium"}`, []string{"role-playing", "prompt-stealing"}},
		{"whitespace", " \n{\"confidence\":\"low\",\"tags\":[]}\t", []string{}},
		{"unknown_slug", `{"tags":["invented"],"confidence":"high"}`, nil},
		{"extra_field", `{"tags":[],"confidence":"high","decision":"approve"}`, nil},
		{"trailing_text", `{"tags":[],"confidence":"high"} explanation`, nil},
		{"second_object", `{"tags":[],"confidence":"high"}{}`, nil},
		{"syntax", `{"tags":`, nil},
		{"empty_reply", "", nil},
		{"markdown", "```json\n{\"tags\":[],\"confidence\":\"high\"}\n```", nil},
		{"null_object", `null`, nil},
		{"array", `[]`, nil},
		{"missing_tags", `{"confidence":"high"}`, nil},
		{"null_tags", `{"tags":null,"confidence":"high"}`, nil},
		{"wrong_tags_type", `{"tags":"role-playing","confidence":"high"}`, nil},
		{"wrong_tag_type", `{"tags":[true],"confidence":"high"}`, nil},
		{"null_tag", `{"tags":[null],"confidence":"high"}`, nil},
		{"missing_confidence", `{"tags":[]}`, nil},
		{"null_confidence", `{"tags":[],"confidence":null}`, nil},
		{"wrong_confidence_type", `{"tags":[],"confidence":1}`, nil},
		{"unknown_confidence", `{"tags":[],"confidence":"certain"}`, nil},
		{"case_variant_field", `{"Tags":[],"confidence":"high"}`, nil},
		{"duplicate_field", `{"tags":["prompt-stealing"],"tags":[],"confidence":"high"}`, nil},
		{"duplicate_tags", `{"tags":["role-playing","role-playing"],"confidence":"high"}`, nil},
		{"duplicate_confidence", `{"tags":[],"confidence":"low","confidence":"high"}`, nil},
		{"missing_close", `{"tags":[],"confidence":"high"`, nil},
		{"extra_comma", `{"tags":[],"confidence":"high",}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePromptAttackTags(tc.reply)
			if tc.want != nil {
				if err != nil || !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("got %v, err=%v; want %v", got, err, tc.want)
				}
				return
			}
			var formatErr *modelJSONError
			if !errors.As(err, &formatErr) || got != nil {
				t.Fatalf("expected retryable JSON error; tags=%v err=%v", got, err)
			}
			if strings.Contains(err.Error()+formatErr.detail, tc.reply) && tc.reply != "" {
				t.Fatal("diagnostic exposes raw model output")
			}
		})
	}
	allTags := make([]string, 0, len(promptAttackTags))
	for _, tag := range promptAttackTags {
		allTags = append(allTags, tag.slug)
	}
	reply, err := json.Marshal(map[string]any{"tags": allTags, "confidence": "low"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsePromptAttackTags(string(reply))
	if err != nil || !reflect.DeepEqual(got, allTags) {
		t.Fatalf("all taxonomy tags: got=%v err=%v", got, err)
	}
}

// This fake uses the real transport but intercepts its context, since an HTTP
// server cannot observe the client's context identity or deadline directly.
func TestClassifyPromptAttackRetries(t *testing.T) {
	for _, protocol := range []string{"openai", "anthropic"} {
		for _, tc := range []struct {
			name      string
			replies   []string
			wantCalls int
			wantTags  []string
		}{
			{"benign", []string{`{"tags":[],"confidence":"high"}`}, 1, []string{}},
			{"hit", []string{`{"tags":["role-playing"],"confidence":"medium"}`}, 1, []string{"role-playing"}},
			{"third_retry_success", []string{"", `{"tags":[],"confidence":"high","extra":true}`, `{"tags":["unknown"],"confidence":"high"}`, `{"tags":["prompt-stealing"],"confidence":"low"}`}, 4, []string{"prompt-stealing"}},
			{"exhausted", []string{"bad"}, 4, nil},
		} {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				// Same existing model_retry_test.go budget, below transport timeout.
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				in := PromptAttackInput{Text: "  原始输入\nBearer synthetic-canary  ", Surface: "tool_result", Language: "zh", Tenant: "private-tenant"}
				indicators := []string{"invisible-text"}
				calls := 0
				var firstInput string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var payload struct {
						System   string
						Messages []map[string]string
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					messages, system, finish := payload.Messages, payload.System, "end_turn"
					if protocol == "openai" {
						system, messages, finish = messages[0]["content"], messages[1:], "stop"
					}
					if system != promptAttackClassifierPrompt || len(messages) != 1+2*calls {
						t.Error("classifier prompt or retry history changed")
					}
					if calls == 0 {
						firstInput = messages[0]["content"]
						var input struct {
							Text, Surface, Language string
							Indicators              []string
						}
						if err := json.Unmarshal([]byte(firstInput), &input); err != nil || input.Text != in.Text || input.Surface != in.Surface || input.Language != in.Language || !reflect.DeepEqual(input.Indicators, indicators) {
							t.Errorf("original input lost: %+v err=%v", input, err)
						}
						if strings.Contains(firstInput, in.Tenant) {
							t.Error("unneeded tenant metadata sent to classifier")
						}
					} else if messages[len(messages)-2]["role"] != "assistant" || messages[len(messages)-1]["role"] != "user" || !strings.Contains(messages[len(messages)-1]["content"], "confidence") {
						t.Error("missing classifier-specific correction")
					}
					if messages[0]["content"] != firstInput {
						t.Error("retry changed original input")
					}
					reply := tc.replies[min(calls, len(tc.replies)-1)]
					calls++
					response := retryResponse(protocol, reply, finish, true)
					defer response.Body.Close()
					_, _ = io.Copy(w, response.Body)
				}))
				defer server.Close()
				transport := http.DefaultTransport
				t.Cleanup(func() { http.DefaultTransport = transport })
				http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
					if req.Context() != ctx {
						t.Error("classifier replaced the shared caller context")
					}
					return transport.RoundTrip(req)
				})
				s := Settings{Prompt: "tool judge policy must not leak", ModelSeconds: 5, Model: ModelConfig{Protocol: protocol, BaseURL: server.URL, Model: "fixture", Tested: true}}
				got := classifyPromptAttack(ctx, s, in, indicators)
				if calls != tc.wantCalls || got.Unavailable != (tc.wantTags == nil) || got.Decision != "" || len(got.Evidence) != 0 {
					t.Fatalf("calls=%d result=%+v", calls, got)
				}
				if len(got.Findings) != len(tc.wantTags) {
					t.Fatalf("findings=%+v want=%v", got.Findings, tc.wantTags)
				}
				for i, finding := range got.Findings {
					want := PromptAttackFinding{Category: "category::prompt-attack", Tag: tc.wantTags[i], Type: "classifier"}
					if finding != want {
						t.Errorf("finding=%+v want=%+v", finding, want)
					}
				}
				wire, _ := json.Marshal(got)
				if strings.Contains(string(wire), "synthetic-canary") || s.Prompt != "tool judge policy must not leak" {
					t.Fatal("classifier retained raw input or mutated settings")
				}
			})
		}
	}
}

func TestClassifyPromptAttackUnavailable(t *testing.T) {
	for _, kind := range []string{"untested", "empty_url", "empty_model", "canceled", "expired", "cancel_in_flight", "deadline_in_flight", "transport_timeout", "transport_body_timeout", "anthropic_transport_body_timeout", "http", "envelope", "incomplete", "invalid_url"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				calls.Add(1)
				switch kind {
				case "cancel_in_flight", "deadline_in_flight", "transport_timeout", "transport_body_timeout", "anthropic_transport_body_timeout":
					if strings.HasSuffix(kind, "body_timeout") {
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
					}
					if kind == "cancel_in_flight" {
						cancel()
					}
					select {
					case <-r.Context().Done():
					case <-release:
					}
				case "http":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "incomplete":
					response := retryResponse("openai", `{"tags":[],"confidence":"high"}`, "length", true)
					defer response.Body.Close()
					_, _ = io.Copy(w, response.Body)
				default:
					_, _ = io.WriteString(w, "invalid envelope synthetic-canary")
				}
			}))
			defer server.Close()
			defer close(release)
			s := Settings{Model: ModelConfig{BaseURL: server.URL, Model: "fixture", Tested: true}}
			if strings.HasPrefix(kind, "anthropic_") {
				s.Model.Protocol = "anthropic"
			}
			wantCalls, wantReason := int32(0), "classifier_unavailable"
			switch kind {
			case "untested":
				s.Model.Tested = false
				wantReason = "classifier_not_configured"
			case "empty_url":
				s.Model.BaseURL = ""
				wantReason = "classifier_not_configured"
			case "empty_model":
				s.Model.Model = ""
				wantReason = "classifier_not_configured"
			case "invalid_url":
				s.Model.BaseURL = "http://fixture.invalid"
			case "canceled":
				cancel()
				wantReason = "classifier_canceled"
			case "expired":
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				wantReason = "classifier_timeout"
			case "deadline_in_flight", "transport_timeout", "transport_body_timeout", "anthropic_transport_body_timeout":
				// Existing model_retry_test.go uses a five-second test budget.
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if strings.Contains(kind, "transport_") {
					// Accepted S2 review regression: transport ceiling < caller budget.
					s.ModelSeconds = 1
				}
				wantCalls, wantReason = 1, "classifier_timeout"
			case "cancel_in_flight":
				wantCalls, wantReason = 1, "classifier_canceled"
			default:
				wantCalls = 1
			}
			got := classifyPromptAttack(ctx, s, PromptAttackInput{Text: "synthetic-canary", Surface: "prompt"}, nil)
			if strings.Contains(kind, "transport_") && ctx.Err() != nil {
				t.Fatal("transport-timeout fixture exhausted the parent context")
			}
			if !got.Unavailable || got.Reason != wantReason || got.Decision != "" || len(got.Findings) != 0 || calls.Load() != wantCalls {
				t.Fatalf("calls=%d result=%+v wantReason=%s", calls.Load(), got, wantReason)
			}
		})
	}
}

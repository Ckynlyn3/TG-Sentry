package core

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func nsfaTestIdentity() NSFAIdentity {
	identity := NSFAIdentity{Model: nsfaModel, ModelRevision: nsfaRevision, ManifestSHA256: strings.Repeat("a", 64), Representation: nsfaRepresentation,
		Heads: map[string]NSFAHead{}, Thresholds: map[string]float64{}}
	for _, head := range nsfaHeads {
		identity.Heads[head] = NSFAHead{Task: nsfaHeadTask(head), SHA256: strings.Repeat("b", 64)}
		identity.Thresholds[head] = 0.5
	}
	return identity
}

// Fixtures follow TG-Java trust-gateway/deploy/nsfa-guard/openapi.yaml:93-209.
func nsfaTestResponse(task string) NSFAResponse {
	response := NSFAResponse{Verdict: "safe", Task: task, Fired: map[string]float64{}, Probs: map[string]float64{}, Thresholds: map[string]float64{}, Identity: nsfaTestIdentity()}
	for _, head := range nsfaTaskHeads(task) {
		response.Probs[head] = 0.1
		response.Thresholds[head] = 0.5
	}
	return response
}

func nsfaTestClient(t *testing.T, handler http.HandlerFunc) *NSFAClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewNSFAClient(NSFAConfig{Endpoint: server.URL, Mode: "monitor", ResponseHead: true},
		NSFAAuth{Token: strings.Repeat("t", 32), WorkloadIdentity: "test-workload", WorkloadCredential: "test-credential"}, nsfaTestIdentity())
}

func TestNSFAValidAndRoundedFired(t *testing.T) {
	for _, task := range []string{"query", "response"} {
		for _, unsafe := range []bool{false, true} {
			t.Run(task+"/"+map[bool]string{false: "safe", true: "M5-rounded"}[unsafe], func(t *testing.T) {
				response := nsfaTestResponse(task)
				if unsafe {
					response.Verdict = "unsafe"
					for head := range response.Probs {
						response.Probs[head] = 0.5
						response.Fired[head] = 0.5 // M5: selected before upstream six-decimal rounding.
					}
				}
				client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/classify" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) || r.Header.Get("X-TG-Workload-Identity") != "test-workload" || r.Header.Get("X-TG-Workload-Credential") != "test-credential" {
						t.Error("request contract mismatch")
					}
					var request NSFARequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Text != "  input <&>\n" || request.Task != task || request.RequestID != "review/pa/rule/nsfa" {
						t.Error("input was not preserved verbatim")
					}
					_ = json.NewEncoder(w).Encode(response)
				})
				result := client.Classify(t.Context(), "  input <&>\n", task, "review/pa/rule/nsfa")
				if result.Unavailable || len(result.Evidence) != len(response.Fired) {
					t.Fatalf("result = %+v", result)
				}
				want := map[string]string{"Prompt_Injection_and_Jailbreak": "default-prompt-injection", "Malicious_Code_and_Cyberattack": "remote-code-execution", "Hazardous_Action_Generation": "inducing-harmful-content"}
				for _, evidence := range result.Evidence {
					if evidence.Tag != want[evidence.Head] || evidence.Score != 0.5 || evidence.Type != "nsfa:"+evidence.Head {
						t.Fatalf("evidence = %+v", evidence)
					}
				}
				wantFindings := len(response.Fired)
				if unsafe && task == "query" {
					wantFindings-- // Dangerous_Operations_Tool_Abuse is evidence only.
				}
				if len(result.Findings) != wantFindings || result.Decision != "" {
					t.Fatalf("findings or authorization = %+v", result)
				}
				for _, finding := range result.Findings {
					if finding.Category != "category::prompt-attack" || finding.PromptAttackSpan != (PromptAttackSpan{}) || finding.RuleID != "" {
						t.Fatalf("unexpected attribution = %+v", finding)
					}
				}
			})
		}
	}
}

func TestNSFAInvalidResponses(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"extra":                   func(m map[string]any) { m["raw_input"] = "private" },
		"missing":                 func(m map[string]any) { delete(m, "latency_ms") },
		"null latency":            func(m map[string]any) { m["latency_ms"] = nil },
		"negative latency":        func(m map[string]any) { m["latency_ms"] = -1 },
		"fraction latency":        func(m map[string]any) { m["latency_ms"] = 0.5 },
		"verdict":                 func(m map[string]any) { m["verdict"] = "approve" },
		"task":                    func(m map[string]any) { m["task"] = "response" },
		"fired array":             func(m map[string]any) { m["fired"] = []string{} },
		"fired null":              func(m map[string]any) { m["fired"] = nil },
		"unknown fired":           func(m map[string]any) { m["fired"] = map[string]float64{"unknown": 0.8}; m["verdict"] = "unsafe" },
		"safe fired":              func(m map[string]any) { m["fired"] = map[string]float64{nsfaHeads[0]: 0.8} },
		"unsafe empty":            func(m map[string]any) { m["verdict"] = "unsafe" },
		"probs keys":              func(m map[string]any) { m["probs"] = map[string]float64{nsfaHeads[0]: 0.1} },
		"probs null":              func(m map[string]any) { m["probs"].(map[string]any)[nsfaHeads[0]] = nil },
		"probs string":            func(m map[string]any) { m["probs"].(map[string]any)[nsfaHeads[0]] = "0.1" },
		"probs negative":          func(m map[string]any) { m["probs"].(map[string]any)[nsfaHeads[0]] = -0.1 },
		"probs over one":          func(m map[string]any) { m["probs"].(map[string]any)[nsfaHeads[0]] = 1.1 },
		"threshold":               func(m map[string]any) { m["thresholds"].(map[string]any)[nsfaHeads[0]] = 0.6 },
		"threshold missing":       func(m map[string]any) { delete(m["thresholds"].(map[string]any), nsfaHeads[0]) },
		"identity model":          func(m map[string]any) { m["identity"].(map[string]any)["model"] = "other" },
		"identity revision":       func(m map[string]any) { m["identity"].(map[string]any)["model_revision"] = "other" },
		"identity representation": func(m map[string]any) { m["identity"].(map[string]any)["representation"] = "other" },
		"identity manifest":       func(m map[string]any) { m["identity"].(map[string]any)["manifest_sha256"] = strings.Repeat("c", 64) },
		"identity extra":          func(m map[string]any) { m["identity"].(map[string]any)["extra"] = true },
		"identity head task": func(m map[string]any) {
			m["identity"].(map[string]any)["heads"].(map[string]any)[nsfaHeads[0]].(map[string]any)["task"] = "response"
		},
		"identity head hash": func(m map[string]any) {
			m["identity"].(map[string]any)["heads"].(map[string]any)[nsfaHeads[0]].(map[string]any)["sha256"] = strings.Repeat("c", 64)
		},
		"identity head extra": func(m map[string]any) {
			m["identity"].(map[string]any)["heads"].(map[string]any)[nsfaHeads[0]].(map[string]any)["extra"] = true
		},
		"identity threshold": func(m map[string]any) {
			m["identity"].(map[string]any)["thresholds"].(map[string]any)[nsfaHeads[0]] = 0.6
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(nsfaTestResponse("query"))
			var object map[string]any
			_ = json.Unmarshal(data, &object)
			mutate(object)
			data, _ = json.Marshal(object)
			client := nsfaTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
			if result := client.Classify(t.Context(), "private", "query", ""); !result.Unavailable || result.Reason != "nsfa_invalid_verdict" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestNSFAInvalidJSONAndBound(t *testing.T) {
	valid, _ := json.Marshal(nsfaTestResponse("query"))
	for name, data := range map[string]string{
		"malformed": "{private", "trailing": string(valid) + "{}", "duplicate": strings.Replace(string(valid), `"verdict":"safe"`, `"verdict":"safe","verdict":"safe"`, 1),
		"nested duplicate": strings.Replace(string(valid), `"model":`, `"model":"private","model":`, 1), "case variant": strings.Replace(string(valid), `"verdict":`, `"Verdict":`, 1),
		"oversized": strings.Repeat(" ", nsfaMaxResponseBytes+1), "nonfinite": strings.Replace(string(valid), `:0.1`, `:1e999`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			client := nsfaTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(data)) })
			if result := client.Classify(t.Context(), "private", "query", ""); !result.Unavailable || result.Reason != "nsfa_invalid_verdict" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
	for _, p := range []float64{math.NaN(), math.Inf(1), -0.1, 1.1} {
		if nsfaProbability(p) {
			t.Errorf("accepted invalid probability")
		}
	}
}

func TestNSFAStatusAndContext(t *testing.T) {
	for _, status := range []int{413, 503, 500, 401, 400} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := nsfaTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("private response"))
			})
			result := client.Classify(t.Context(), "private input", "query", "")
			want := "nsfa_unavailable"
			if status == 413 {
				want = "nsfa_413"
			}
			if !result.Unavailable || result.Reason != want {
				t.Fatalf("result = %+v", result)
			}
			if status == 413 && (client.Stats().InputTooLarge != 1 || client.failures != 0) {
				t.Fatal("413 counted as breaker failure")
			}
		})
	}
	t.Run("deadline reaches request", func(t *testing.T) {
		entered, canceled := make(chan struct{}), make(chan struct{})
		client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body) // Enable server disconnect observation before waiting.
			close(entered)
			<-r.Context().Done()
			close(canceled)
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan PromptAttackResult, 1)
		go func() { done <- client.Classify(ctx, "private", "query", "") }()
		<-entered
		cancel()
		if result := <-done; result.Reason != "nsfa_canceled" {
			t.Fatalf("result = %+v", result)
		}
		<-canceled
	})
	t.Run("inflight timeout", func(t *testing.T) {
		client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
		})
		// Existing shared hook ceiling (prompt_attack.go); no new timeout value.
		ctx, cancel := context.WithTimeout(t.Context(), ReviewHookBudget)
		defer cancel()
		client.http.Transport = nsfaDeadlineTransport{t: t, next: client.http.Transport, ctx: ctx}
		if result := client.Classify(ctx, "private", "query", ""); result.Reason != "nsfa_timeout" {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("expired deadline", func(t *testing.T) {
		client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("expired request reached server") })
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer cancel()
		if result := client.Classify(ctx, "private", "query", ""); result.Reason != "nsfa_timeout" {
			t.Fatalf("result = %+v", result)
		}
	})
}

type nsfaDeadlineTransport struct {
	t    *testing.T
	next http.RoundTripper
	ctx  context.Context
}

func (transport nsfaDeadlineTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	want, _ := transport.ctx.Deadline()
	got, _ := request.Context().Deadline()
	if !got.Equal(want) {
		transport.t.Error("caller deadline changed")
	}
	return transport.next.RoundTrip(request)
}

func TestNSFABreakerSequence(t *testing.T) {
	var status atomic.Int64
	status.Store(503)
	var calls atomic.Int64
	entered, release := make(chan struct{}, 1), make(chan struct{})
	client := nsfaTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if status.Load() == 200 {
			entered <- struct{}{}
			<-release
			_ = json.NewEncoder(w).Encode(nsfaTestResponse("query"))
			return
		}
		w.WriteHeader(int(status.Load()))
	})
	now := time.Unix(0, 0)
	client.now = func() time.Time { return now }
	call := func() PromptAttackResult { return client.Classify(t.Context(), "input", "query", "") }
	call()
	if client.Stats().State != "closed" {
		t.Fatal("opened before two failures")
	}
	call()
	if client.Stats().State != "open" {
		t.Fatal("did not open")
	}
	if result := call(); result.Reason != "nsfa_breaker" || calls.Load() != 2 {
		t.Fatal("open admitted a request")
	}
	now = now.Add(15*time.Second - time.Nanosecond)
	if result := call(); result.Reason != "nsfa_breaker" {
		t.Fatal("cooldown shortened")
	}
	now = now.Add(time.Nanosecond)
	status.Store(413)
	call()
	if client.Stats().State != "half_open" || client.Stats().InputTooLarge != 1 {
		t.Fatal("413 closed probe or counted as failure")
	}
	status.Store(503)
	call()
	if client.Stats().State != "open" {
		t.Fatal("failed probe did not reopen")
	}
	now = now.Add(15 * time.Second)
	status.Store(200)
	done := make(chan PromptAttackResult, 1)
	go func() { done <- call() }()
	<-entered
	if client.Stats().State != "half_open" {
		t.Fatal("probe not half-open")
	}
	if result := call(); result.Reason != "nsfa_breaker" {
		t.Fatal("second probe admitted")
	}
	close(release)
	if result := <-done; result.Unavailable {
		t.Fatalf("probe = %+v", result)
	}
	if client.Stats().State != "closed" || client.failures != 0 {
		t.Fatal("successful probe did not close")
	}
}

func TestNSFAEndpointMatchesJavaAllowedBase(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"http://localhost": true, "HTTP://LOCALHOST/": true, "http://[::1]:8009": true,
		"http://localhost#": false, "http://localhost:": false,
	} {
		if got := nsfaAllowedEndpoint(endpoint); got != want {
			t.Errorf("endpoint %q: got %v, want %v", endpoint, got, want)
		}
	}
}

func TestNSFAConfigurationAndInputs(t *testing.T) {
	client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid input reached server") })
	for _, request := range []NSFARequest{{Text: "", Task: "query"}, {Text: "x", Task: "other"}, {Text: "x", Task: "query", RequestID: strings.Repeat("x", 129)}, {Text: string([]byte{0xff}), Task: "query"}} {
		if result := client.Classify(t.Context(), request.Text, request.Task, request.RequestID); result.Reason != "nsfa_invalid_input" {
			t.Fatalf("result = %+v", result)
		}
	}
	client.config.ResponseHead = false
	if result := client.Classify(t.Context(), "x", "response", ""); result.Reason != "nsfa_response_disabled" {
		t.Fatalf("result = %+v", result)
	}
	for _, endpoint := range []string{"https://127.0.0.1", "http://example.com", "http://127.0.0.1/path", "http://user@127.0.0.1", "http://127.0.0.1?x", "http://127.0.0.1#x", "http://127.0.0.1:0", "http://127.0.0.1:99999"} {
		invalid := NewNSFAClient(NSFAConfig{Endpoint: endpoint, Mode: "monitor"}, client.auth, nsfaTestIdentity())
		if result := invalid.Classify(t.Context(), "x", "query", ""); result.Reason != "nsfa_not_configured" {
			t.Fatalf("endpoint accepted: %s", endpoint)
		}
	}
	identity := nsfaTestIdentity()
	identity.Heads[nsfaHeads[0]] = NSFAHead{Task: "query", SHA256: "bad"}
	invalid := NewNSFAClient(client.config, client.auth, identity)
	if result := invalid.Classify(t.Context(), "x", "query", ""); result.Reason != "nsfa_not_configured" {
		t.Fatalf("identity accepted: %+v", result)
	}
}

func TestNSFARedirectRefusedAndIdentityFrozen(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Store(true) }))
	defer target.Close()
	client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	if result := client.Classify(t.Context(), "private", "query", ""); !result.Unavailable || redirected.Load() {
		t.Fatalf("redirect followed: %+v", result)
	}
	expected := nsfaTestIdentity()
	frozen := NewNSFAClient(client.config, client.auth, expected)
	expected.Heads[nsfaHeads[0]] = NSFAHead{Task: "response", SHA256: "changed"}
	if reflect.DeepEqual(frozen.expected, expected) {
		t.Fatal("identity not frozen")
	}
}

func TestNSFABusyAndStaleCompletion(t *testing.T) {
	entered := make(chan struct{}, nsfaFailureThreshold)
	releaseFailure, releaseSuccess := make(chan struct{}), make(chan struct{})
	client := nsfaTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var input NSFARequest
		_ = json.NewDecoder(r.Body).Decode(&input)
		switch input.RequestID {
		case "old-success":
			entered <- struct{}{}
			<-releaseSuccess
			_ = json.NewEncoder(w).Encode(nsfaTestResponse("query"))
		case "old-failure":
			entered <- struct{}{}
			<-releaseFailure
			w.WriteHeader(503)
		default:
			w.WriteHeader(503)
		}
	})
	// Always release fake handlers if an assertion fails.
	defer func() {
		select {
		case <-releaseSuccess:
		default:
			close(releaseSuccess)
		}
		select {
		case <-releaseFailure:
		default:
			close(releaseFailure)
		}
	}()
	call := func(id string) PromptAttackResult { return client.Classify(t.Context(), "input", "query", id) }
	oldSuccess, oldFailure := make(chan PromptAttackResult, 1), make(chan PromptAttackResult, 1)
	go func() { oldSuccess <- call("old-success") }()
	go func() { oldFailure <- call("old-failure") }()
	<-entered
	<-entered
	if result := call("busy"); result.Reason != "nsfa_busy" {
		t.Fatalf("busy = %+v", result)
	}
	close(releaseFailure)
	<-oldFailure
	call("second-failure")
	if client.Stats().State != "open" {
		t.Fatal("two failures did not open breaker")
	}
	close(releaseSuccess)
	if result := <-oldSuccess; result.Unavailable {
		t.Fatalf("old request failed: %+v", result)
	}
	if client.Stats().State != "open" {
		t.Fatal("stale success closed a newer breaker generation")
	}
}

func TestNSFAConsecutiveFailuresExclude413(t *testing.T) {
	var status atomic.Int64
	client := nsfaTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if status.Load() == 200 {
			_ = json.NewEncoder(w).Encode(nsfaTestResponse("query"))
			return
		}
		w.WriteHeader(int(status.Load()))
	})
	for _, code := range []int64{503, 200, 503, 413} {
		status.Store(code)
		client.Classify(t.Context(), "input", "query", "")
		if client.Stats().State != "closed" {
			t.Fatal("success did not reset consecutive failures, or 413 incremented them")
		}
	}
	status.Store(503)
	client.Classify(t.Context(), "input", "query", "")
	if client.Stats().State != "open" || client.Stats().InputTooLarge != 1 {
		t.Fatal("413 reset failures instead of being counted separately")
	}
}

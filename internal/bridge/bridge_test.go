package bridge

import (
	"aegishook/internal/core"
	"aegishook/internal/secrets"
	"aegishook/internal/server"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf16"
)

func fixture(t *testing.T) (*core.Engine, string, string) {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewServer(server.New(e, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("fixture")}}, "admin-fixture", "hook-fixture", t.TempDir()).Handler())
	t.Cleanup(srv.Close)
	path := filepath.Join(e.Dir, "connection.json")
	if err = os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "hook-fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	return e, path, cwd
}
func invoke(agent, path string, v any) (int, string, string) {
	var out, log bytes.Buffer
	code := Run(agent, path, bytes.NewReader(mustJSON(v)), &out, &log)
	return code, out.String(), log.String()
}
func native(agent, cwd, call, tool, event string, args map[string]any) map[string]any {
	if agent == "grok" {
		return map[string]any{"hookEventName": event, "sessionId": "session", "cwd": cwd, "toolUseId": call, "toolName": tool, "toolInput": args}
	}
	return map[string]any{"hook_event_name": event, "session_id": "session", "cwd": cwd, "tool_use_id": call, "tool_name": tool, "tool_input": args}
}
func TestNativeProtocolsDenyAllowAndResults(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "grok", "opencode"} {
		t.Run(agent, func(t *testing.T) {
			e, path, cwd := fixture(t)
			code, _, log := invoke(agent, path, native(agent, cwd, "deny", "Bash", "PreToolUse", map[string]any{"command": "passwd fixture"}))
			if code != 2 || !strings.Contains(log, "R1") {
				t.Fatal(code, log)
			}
			allowed := native(agent, cwd, "allow", "Read", "PreToolUse", map[string]any{"file_path": "README.md"})
			code, out, log := invoke(agent, path, allowed)
			if code != 0 {
				t.Fatal(code, out, log)
			}
			if (agent == "claude" || agent == "codex") && strings.TrimSpace(out) != "{}" {
				t.Fatal("native permission bypass", out)
			}
			if c, _, l := invoke(agent, path, allowed); c != 0 {
				t.Fatal(l)
			}
			reviews, _ := e.Reviews()
			if len(reviews) != 2 {
				t.Fatal("duplicate review", len(reviews))
			}
			for _, r := range reviews {
				if r.Agent != agent {
					t.Fatal("wrong source", r)
				}
				if r.CallID == "allow" && r.Execution != "awaiting_execution" {
					t.Fatal("false success", r)
				}
			}
			post := native(agent, cwd, "allow", "Read", "PostToolUse", nil)
			post["tool_response"] = map[string]any{"exit_code": float64(0)}
			post["executionState"] = "succeeded"
			if c, _, l := invoke(agent, path, post); c != 0 {
				t.Fatal(l)
			}
			r, _ := e.Review(hash(hash(agent, "session", cwd), "allow"))
			if r.Execution != "succeeded" {
				t.Fatal(r)
			}
			changed := native(agent, cwd, "allow", "Read", "PreToolUse", map[string]any{"file_path": "different"})
			if c, _, _ := invoke(agent, path, changed); c != 2 {
				t.Fatal("changed args allowed")
			}
			if c, _, l := invoke(agent, path, native(agent, cwd, "", "", "SessionEnd", nil)); c != 0 {
				t.Fatal(l)
			}
			instances, _ := e.Instances()
			if len(instances) != 1 || instances[0].State != "disconnected" || instances[0].ConnectionMode != "events" {
				t.Fatal(instances)
			}
		})
	}
}
func TestHumanReviewBlocksAndDisconnectRejects(t *testing.T) {
	for _, end := range []bool{false, true} {
		t.Run(map[bool]string{false: "approve", true: "disconnect"}[end], func(t *testing.T) {
			e, path, cwd := fixture(t)
			prompt := native("codex", cwd, "", "", "UserPromptSubmit", nil)
			prompt["prompt"] = "fixture token=private-value"
			if c, _, l := invoke("codex", path, prompt); c != 0 {
				t.Fatal(l)
			}
			done := make(chan int, 1)
			go func() {
				code, _, _ := invoke("codex", path, native("codex", cwd, "pending", "Bash", "PreToolUse", map[string]any{"command": "echo fixture"}))
				done <- code
			}()
			var r core.Review
			for n := 0; n < 150; n++ {
				rs, _ := e.Reviews()
				promptExists := false
				for _, review := range rs {
					if review.ToolName == "prompt_turn" {
						promptExists = true
					}
					if review.CallID == "pending" {
						r = review
					}
				}
				if r.ID != "" {
					if !promptExists {
						t.Fatal("prompt_turn review missing")
					}
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if r.ID == "" {
				t.Fatal("no pending review")
			}
			if strings.Contains(r.UserMessage, "private-value") || !strings.Contains(r.UserMessage, "REDACTED") {
				t.Fatal("context unredacted", r.UserMessage)
			}
			select {
			case <-done:
				t.Fatal("did not wait")
			default:
			}
			if end {
				if err := e.Disconnect(r.InstanceID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := e.Decide(core.WithActor(context.Background(), core.SystemActor("test")), r.ID, r.Digest, "approve", ""); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case code := <-done:
				if (!end && code != 0) || (end && code != 2) {
					t.Fatal(code)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("bridge stuck")
			}
		})
	}
}
func TestOfflineMalformedAndUnavailableAuditFailClosed(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "grok", "opencode"} {
		t.Run(agent, func(t *testing.T) {
			e, path, cwd := fixture(t)
			e.DB.Close()
			if code, _, _ := invoke(agent, path, native(agent, cwd, "call", "Read", "PreToolUse", map[string]any{"path": "fixture"})); code != 2 {
				t.Fatal("audit unavailable allowed")
			}
			for _, input := range []string{"not json", "null", `{} {}`} {
				var out, log bytes.Buffer
				if code := Run(agent, path, strings.NewReader(input), &out, &log); code != 2 {
					t.Fatal(input, code)
				}
			}
			os.WriteFile(path, mustJSON(Config{Endpoint: "http://127.0.0.1:1", Token: "test"}), 0600)
			if code, _, _ := invoke(agent, path, native(agent, cwd, "call", "Read", "PreToolUse", map[string]any{"path": "fixture"})); code != 2 {
				t.Fatal("offline allowed")
			}
		})
	}
}
func TestInvalidServerVerdict(t *testing.T) {
	for _, decision := range []string{"ask", "", "allow"} {
		t.Run(decision, func(t *testing.T) {
			cwd := t.TempDir()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"id": hash(hash("codex", "session", cwd), "call"), "decision": decision, "deadline": time.Now().Add(time.Minute)})
			}))
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "connection.json")
			os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "test"}), 0600)
			if code, _, _ := invoke("codex", path, native("codex", cwd, "call", "Read", "PreToolUse", map[string]any{"path": "fixture"})); code != 2 {
				t.Fatal("invalid decision allowed")
			}
		})
	}
}
func TestGrokWithoutCallIDAndUnknownCodexResult(t *testing.T) {
	e, path, cwd := fixture(t)
	pre := native("grok", cwd, "", "Read", "PreToolUse", map[string]any{"path": "fixture"})
	if c, _, l := invoke("grok", path, pre); c != 0 {
		t.Fatal(l)
	}
	post := native("grok", cwd, "", "Read", "PostToolUse", nil)
	if c, _, l := invoke("grok", path, post); c != 0 {
		t.Fatal(l)
	}
	reviews, _ := e.Reviews()
	if len(reviews) != 1 || reviews[0].Execution != "awaiting_execution" {
		t.Fatal("fabricated result", reviews)
	}
	state, _ := resultState("codex", "PostToolUse", map[string]any{"tool_response": "looks okay"})
	if state != "" {
		t.Fatal("unknown result claimed success")
	}
	state, _ = resultState("codex", "PostToolUse", map[string]any{"tool_response": "Process exited with code 1\nerror"})
	if state != "failed" {
		t.Fatal(state)
	}
}

// Match the in-memory recipe in internal/secrets/fixture_test.go: seed 22,
// GitHub PAT alphabet and length from the pinned Gitleaks manifest. Never live.
func bridgeSecretFixture() string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rng := mathrand.New(mathrand.NewSource(22))
	candidate := make([]byte, 36)
	for i := range candidate {
		candidate[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return "ghp_" + string(candidate)
}

type bridgeSecretRequest struct {
	path string
	body map[string]any
}

func secretBridgeFixture(t *testing.T) (string, string, func() []bridgeSecretRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []bridgeSecretRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error("decode bridge request", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests = append(requests, bridgeSecretRequest{r.URL.Path, body})
		mu.Unlock()
		if r.URL.Path == "/api/v1/reviews" {
			json.NewEncoder(w).Encode(map[string]any{
				"id":       hash(body["instanceId"].(string), body["callId"].(string)),
				"decision": "approve", "comment": "fixture", "ruleId": "fixture",
				"execution": "awaiting_execution", "deadline": time.Now().Add(core.ReviewHookBudget),
			})
			return
		}
		fmt.Fprintln(w, "{}")
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "hook-fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path, cwd, func() []bridgeSecretRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]bridgeSecretRequest(nil), requests...)
	}
}

func assertSecretLocation(t *testing.T, raw any, surface, kind, path, original, candidate string) {
	t.Helper()
	location, ok := raw.(map[string]any)
	if !ok || location["entity_type"] != "github-pat" || location["surface"] != surface {
		t.Fatal("missing secret location")
	}
	for key := range location {
		if !contains(key, "entity_type", "surface", "kind", "field_digest", "span") {
			t.Fatal("unexpected location field", key)
		}
	}
	if kind != "" && (location["kind"] != kind || location["field_digest"] != hash(path)) {
		t.Fatal("location does not identify the original leaf")
	}
	span, ok := location["span"].(map[string]any)
	start := strings.Index(original, candidate)
	wantStart := len(utf16.Encode([]rune(original[:start])))
	wantEnd := wantStart + len(utf16.Encode([]rune(candidate)))
	if !ok || span["start"] != float64(wantStart) || span["end"] != float64(wantEnd) {
		t.Fatal("span does not identify the original UTF-16 leaf")
	}
}

func TestSecretPromptCacheAndHandoff(t *testing.T) {
	candidate := bridgeSecretFixture()
	for _, agent := range []string{"claude", "cursor", "codex", "opencode"} {
		t.Run(agent, func(t *testing.T) {
			path, cwd, requests := secretBridgeFixture(t)
			prompt := native(agent, cwd, "", "", "UserPromptSubmit", nil)
			pre := native(agent, cwd, "call", "Read", "PreToolUse", map[string]any{"path": "fixture"})
			if agent == "cursor" {
				prompt = cursorPayload(cwd, "beforeSubmitPrompt")
				pre = cursorTool(cwd, "call", "preToolUse", "Read", map[string]any{"path": "fixture"})
			}
			original := "😀 token=" + candidate
			prompt["prompt"] = original
			if c, _, l := invoke(agent, path, prompt); c != 0 {
				t.Fatal("prompt invocation failed", c, l)
			}
			files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "context-*.json"))
			if err != nil || len(files) != 1 {
				t.Fatal("missing prompt cache")
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), candidate) || strings.Contains(string(data), "token=") {
				t.Fatal("prompt cache retained original or partially masked text")
			}
			var saved map[string]any
			if json.Unmarshal(data, &saved) != nil || saved["userMessage"] != "[REDACTED]" {
				t.Fatal("prompt cache must use the #20 whole-input marker")
			}
			scan, ok := saved["prompt_scan"].(map[string]any)
			if !ok || scan["status"] != "Complete" {
				t.Fatal("prompt scan metadata missing")
			}
			findings, ok := scan["findings"].([]any)
			if !ok || len(findings) != 1 {
				t.Fatal("missing prompt finding")
			}
			assertSecretLocation(t, findings[0], "prompt", "", "", original, candidate)
			if c, _, l := invoke(agent, path, pre); c != 0 {
				t.Fatal("pre-tool invocation failed", c, l)
			}
			var reviewRequests int
			for _, request := range requests() {
				if request.path != "/api/v1/reviews" {
					continue
				}
				reviewRequests++
				if strings.Contains(string(mustJSON(request.body)), candidate) || request.body["userMessage"] != "[REDACTED]" || !reflect.DeepEqual(request.body["prompt_scan"], scan) {
					t.Fatal("prompt scan lost or value retained in review handoff")
				}
			}
			if reviewRequests != 2 { // prompt_turn and the following pre-tool call.
				t.Fatal("review handoff was not exercised")
			}
		})
	}
}

func TestSecretOutputBeforeMaskingWithOriginalLeafSpans(t *testing.T) {
	candidate := bridgeSecretFixture()
	path, cwd, requests := secretBridgeFixture(t)
	original := "😀 token=" + candidate + "; done"
	value := map[string]any{"nested": []any{map[string]any{"message": original}}, candidate: "safe", "safe": "visible"}
	post := native("claude", cwd, "call", "Read", "PostToolUse", nil)
	post["tool_response"] = value
	if c, _, l := invoke("claude", path, post); c != 0 {
		t.Fatal(c, l)
	}
	for _, request := range requests() {
		if !strings.HasSuffix(request.path, "/result") {
			continue
		}
		if strings.Contains(string(mustJSON(request.body)), candidate) {
			t.Fatal("secret retained in result report")
		}
		result, _ := request.body["result"].(string)
		if !strings.Contains(result, "[REDACTED]") || !strings.Contains(result, "visible") || strings.Contains(result, "token=") {
			t.Fatal("finding leaves must be omitted, not partially masked")
		}
		findings, ok := request.body["findings"].([]any)
		if !ok || len(findings) != 2 {
			t.Fatal("pre-masking findings missing")
		}
		for _, raw := range findings {
			finding := raw.(map[string]any)
			if finding["kind"] == "key" {
				assertSecretLocation(t, raw, "tool_result", "key", candidate, candidate, candidate)
			} else {
				assertSecretLocation(t, raw, "tool_result", "value", "nested.0.message", original, candidate)
			}
		}
		if value["nested"].([]any)[0].(map[string]any)["message"] != original {
			t.Fatal("original output was mutated")
		}
		return
	}
	t.Fatal("no result report")
}

func TestSecretScanDeadlineExhaustion(t *testing.T) {
	candidate := bridgeSecretFixture()
	// An already-expired deadline is deterministic; no new timer or sleep is
	// needed to prove that exhaustion is Interrupted, never a clean cache.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-core.ReviewHookBudget))
	defer cancel()
	saved := scanPrompt(ctx, candidate)
	if saved.UserMessage != "[REDACTED]" || saved.PromptScan == nil || saved.PromptScan.Status != secrets.Interrupted || len(saved.PromptScan.Findings) != 0 {
		t.Fatal("expired prompt scan was not omitted and Interrupted")
	}
	data := mustJSON(saved)
	if strings.Contains(string(data), candidate) || !strings.Contains(string(data), `"findings":[]`) {
		t.Fatal("interrupted cache retained content or omitted completion status")
	}
}

func TestSecretOutputInterruptedDoesNotSendResult(t *testing.T) {
	path, cwd, requests := secretBridgeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalTransport := http.DefaultTransport
	// Reuse the existing transport seam: finish heartbeat, then expire the
	// shared request context immediately before output scanning.
	http.DefaultTransport = rotationTransport(func(r *http.Request) (*http.Response, error) {
		response, err := originalTransport.RoundTrip(r)
		if err == nil && strings.HasSuffix(r.URL.Path, "/heartbeat") {
			cancel()
		}
		return response, err
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	post := native("claude", cwd, "call", "Read", "PostToolUse", nil)
	post["tool_response"] = bridgeSecretFixture()
	var out, log bytes.Buffer
	code := run(ctx, "claude", path, bytes.NewReader(mustJSON(post)), &out, &log)
	if code != 1 || !strings.Contains(log.String(), "Secret scan interrupted") || strings.Contains(log.String(), bridgeSecretFixture()) {
		t.Fatal("interrupted output did not take the unavailable path")
	}
	for _, request := range requests() {
		if strings.HasSuffix(request.path, "/result") {
			t.Fatal("partial/clean result was sent after interrupted scanning")
		}
	}
}

func TestSecretCleanAndLegacyCacheCompatibility(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			path, cwd, requests := secretBridgeFixture(t)
			message := "ordinary prompt"
			instance := hash("claude", "session", cwd)
			contextPath := filepath.Join(filepath.Dir(path), "context-"+instance+".json")
			if legacy {
				if err := os.WriteFile(contextPath, mustJSON(map[string]string{"userMessage": message}), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				prompt := native("claude", cwd, "", "", "UserPromptSubmit", nil)
				prompt["prompt"] = message
				if c, _, l := invoke("claude", path, prompt); c != 0 {
					t.Fatal(c, l)
				}
			}
			data, err := os.ReadFile(contextPath)
			if err != nil || strings.Contains(string(data), "prompt_scan") {
				t.Fatal("clean/legacy cache acquired scan metadata")
			}
			pre := native("claude", cwd, "call", "Read", "PreToolUse", map[string]any{"path": "fixture"})
			if c, _, l := invoke("claude", path, pre); c != 0 {
				t.Fatal(c, l)
			}
			for _, request := range requests() {
				if request.path == "/api/v1/reviews" {
					if request.body["userMessage"] != message || request.body["prompt_scan"] != nil {
						t.Fatal("clean/legacy prompt handoff changed")
					}
				}
			}
		})
	}
}

func TestSecretResultFailureAndTruncationSurfaces(t *testing.T) {
	candidate := bridgeSecretFixture()
	for _, tc := range []struct {
		name, agent, event, prefix, state string
		failure                           bool
	}{
		{"failure", "claude", "PostToolUseFailure", "😀 token=", "failed", true},
		{"permission", "cursor", "postToolUseFailure", "😀 token=", "not_executed", true},
		// 24,000 bytes is the inherited RedactText ceiling (policy.go), not
		// a scanner limit. Findings must survive beyond that output boundary.
		{"before_truncation", "claude", "PostToolUse", strings.Repeat("x", 24000) + " ", "succeeded", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, cwd, requests := secretBridgeFixture(t)
			post := native(tc.agent, cwd, "call", "Read", tc.event, nil)
			original := tc.prefix + candidate
			if tc.agent == "cursor" {
				post = cursorTool(cwd, "call", tc.event, "Read", map[string]any{})
				post["failure_type"], post["error_message"] = "permission_denied", original
			} else if tc.failure {
				post["error"] = original
			} else {
				post["tool_response"] = original
			}
			if c, _, l := invoke(tc.agent, path, post); c != 0 {
				t.Fatal(c, l)
			}
			for _, request := range requests() {
				if !strings.HasSuffix(request.path, "/result") {
					continue
				}
				findings, ok := request.body["findings"].([]any)
				if !ok || len(findings) != 1 || request.body["state"] != tc.state || strings.Contains(string(mustJSON(request.body)), candidate) {
					t.Fatal("failure or long output escaped pre-masking detection")
				}
				assertSecretLocation(t, findings[0], "tool_result", "value", "", original, candidate)
				want := `"[REDACTED]"`
				if tc.failure {
					want = "[REDACTED]"
				}
				if request.body["result"] != want {
					t.Fatal("original leaf was not wholly omitted")
				}
				return
			}
			t.Fatal("result path not exercised")
		})
	}
}

func TestSecretLeafOmissionCopiesNestedContainers(t *testing.T) {
	candidate := bridgeSecretFixture()
	original := map[string]any{"nested": map[string]any{"array": []any{candidate, true}}, "safe": float64(1)}
	leaves, status := secrets.ScanTree(context.Background(), original, "tool_result")
	if status != secrets.Complete || len(leaves) != 1 {
		t.Fatal("nested fixture was not detected")
	}
	omitted := omitSecretLeaves(original, "", leaves).(map[string]any)
	array := omitted["nested"].(map[string]any)["array"].([]any)
	if array[0] != "[REDACTED]" || array[1] != true || omitted["safe"] != float64(1) || original["nested"].(map[string]any)["array"].([]any)[0] != candidate {
		t.Fatal("omission changed clean siblings or mutated original leaves")
	}
}

package bridge

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// syntheticID mirrors internal/core's test generator: an unassigned all-zero
// region/IIN body with the GB 11643 check character appended.
func syntheticID() string {
	for _, c := range "0123456789X" {
		if value := "00000020000229001" + string(c); core.ValidCNID(value) {
			return value
		}
	}
	panic("synthetic checksum generation failed")
}

// claudeReadFixture wires one synthetic detector that reports the CN ID label
// wherever it appears in the review envelope.
func claudeReadFixture(t *testing.T) (*core.Engine, string, string) {
	t.Helper()
	e, path, cwd := fixture(t)
	pii := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		id := syntheticID()
		i := strings.Index(body.Text, id)
		if i < 0 {
			w.Write([]byte(`[]`))
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{{"entity_type": "CN_ID_CARD", "start": i, "end": i + len(id), "score": 1}})
	}))
	t.Cleanup(pii.Close)
	token := filepath.Join(e.Dir, "fixture.token")
	if err := os.WriteFile(token, []byte("fixture-token"), 0600); err != nil {
		t.Fatal(err)
	}
	e.Settings.BTPII = core.BTPIIConfig{Endpoint: pii.URL, TokenFile: token, Language: "en", Entities: []string{"CN_ID_CARD"}}
	if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("hook")), core.Rule{ID: "R_PII_ID", Name: "fixture", Matcher: "btpii", Pattern: "id-number", Decision: "reject", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return e, path, cwd
}

// The acceptance scenario end-to-end: bridge capture, HTTP review envelope and
// the native deny for both in-scope clients.
func TestOutgoingFileIDNumberDeniedAtBridge(t *testing.T) {
	id := syntheticID()
	for _, agent := range []string{"claude", "cursor"} {
		t.Run(agent, func(t *testing.T) {
			// The synthetic generator lives in internal/core tests; use the same
			// checksum-valid all-zero IIN region here.
			e, path, cwd := claudeReadFixture(t)
			file := filepath.Join(cwd, "record.txt")
			if err := os.WriteFile(file, []byte("customer record "+id+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"file_path": file}
			var code int
			var out, log string
			if agent == "claude" {
				code, out, log = invoke(agent, path, native(agent, cwd, "call", "Read", "PreToolUse", args))
				if code != 2 || !strings.Contains(out, "deny") {
					t.Fatalf("claude read was not denied: %d %s %s", code, out, log)
				}
			} else {
				code, out, log = invoke(agent, path, cursorTool(cwd, "call", "preToolUse", "Read", args))
				assertCursorDecision(t, code, out, true)
			}
			reviews, err := e.Reviews()
			if err != nil || len(reviews) != 1 {
				t.Fatal(reviews, err)
			}
			if reviews[0].RuleID != "R_PII_ID" || reviews[0].Decision != "reject" {
				t.Fatalf("unexpected verdict: %+v", reviews[0])
			}
			// The sensitive hit omits the whole captured surface from the record.
			if len(reviews[0].Scripts) != 0 || core.ReviewListView(reviews[0]).InputState != core.ContentPolicyOmitted {
				t.Fatalf("snapshot survived the hit: %+v", reviews[0])
			}
			if b, _ := json.Marshal(reviews[0]); strings.Contains(string(b), id) {
				t.Fatal("identifier retained in the stored review")
			}
		})
	}
}

// D2 transport bound end-to-end through the real bridge and review server: with
// a captured file plus the call's own arguments the envelope would exceed the
// server's 2 MiB review body (internal/server/server.go read()), so the bridge
// must drop the content rather than have the request rejected. The stored
// review keeps the descriptor size, stays content-free and is never approved.
func TestOutgoingFileOverTransportBoundStillReviewed(t *testing.T) {
	// This test checks size bounds, not latency: ~2 MiB through the real bridge and server
	// takes 0.4 s normally but 6.7-9.6 s under -race on GitHub runners (CI 39567422399),
	// past the 4.5 s budget that both the bridge and the server enforce (CI 39570619178:
	// server HTTP 409). Widen the shared core budget to Run's non-review default (bridge.go).
	old := core.ReviewHookBudget
	core.ReviewHookBudget = 24*time.Hour + time.Minute
	t.Cleanup(func() { core.ReviewHookBudget = old })
	e, path, cwd := fixture(t)
	file := filepath.Join(cwd, "edge.txt")
	const size = 1 << 20
	if err := os.WriteFile(file, bytes.Repeat([]byte("y"), size), 0600); err != nil {
		t.Fatal(err)
	}
	// The file alone fits both limits; the arguments push the envelope over.
	args := map[string]any{"file_path": file, "padding": strings.Repeat("p", size+100000)}
	// The request must still be accepted; a rejected body would surface as the
	// bridge's own JSON error instead of a review verdict.
	code, out, log := invoke("claude", path, native("claude", cwd, "bound", "Read", "PreToolUse", args))
	if strings.Contains(log, "2 MB") {
		t.Fatalf("over-bound envelope reached the server: %s", log)
	}
	var r core.Review
	reviews, err := e.Reviews()
	if err != nil {
		t.Fatal(err)
	}
	for _, review := range reviews {
		if review.CallID == "bound" {
			r = review
		}
	}
	if r.ID == "" {
		t.Fatalf("over-bound review never reached the server: %d %s %s", code, out, log)
	}
	if r.ScriptCaptureStatus != "incomplete" || len(r.Scripts) != 1 {
		t.Fatalf("over-bound capture status=%s files=%+v", r.ScriptCaptureStatus, r.Scripts)
	}
	got := r.Scripts[0]
	// The list view always strips content; the drop is proven by the marker,
	// the retained descriptor size and the forced human path.
	if got.Content != "" || !got.Truncated || got.ReadError != core.OutgoingFileOverEnvelope || got.Bytes != size {
		t.Fatalf("over-bound capture kept content: %+v", got)
	}
	if r.Decision != "pending" || r.ReviewPath != "human" || !r.NeedsHuman {
		t.Fatalf("over-bound capture was decided: %+v", r)
	}
	// A pending human review must never be reported as approval to the agent.
	if code == 0 {
		t.Fatalf("over-bound capture was approved: %d %s", code, out)
	}
}

func TestOutgoingFileCleanReadKeepsExistingBehaviour(t *testing.T) {
	e, path, cwd := claudeReadFixture(t)
	file := filepath.Join(cwd, "clean.txt")
	if err := os.WriteFile(file, []byte("ordinary note\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, log := invoke("claude", path, native("claude", cwd, "call", "Read", "PreToolUse", map[string]any{"file_path": file}))
	if code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("clean read changed behaviour: %d %s %s", code, out, log)
	}
	reviews, err := e.Reviews()
	if err != nil || len(reviews) != 1 || reviews[0].ScriptCaptureStatus != "complete" || len(reviews[0].Scripts) != 1 {
		t.Fatalf("clean snapshot missing: %+v %v", reviews, err)
	}
	if reviews[0].Scripts[0].Content != "ordinary note\n" {
		t.Fatal(reviews[0].Scripts)
	}
}

// D5 scope: a client without the documented scalar path contract keeps its
// pre-existing envelope even when it emits a tool named Read.
func TestOutgoingFileCaptureLimitedToClaudeAndCursor(t *testing.T) {
	for _, agent := range []string{"codex", "grok", "opencode"} {
		t.Run(agent, func(t *testing.T) {
			e, path, cwd := claudeReadFixture(t)
			file := filepath.Join(cwd, "record.txt")
			if err := os.WriteFile(file, []byte("customer record "+syntheticID()+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			_, _, log := invoke(agent, path, native(agent, cwd, "call", "Read", "PreToolUse", map[string]any{"file_path": file}))
			reviews, err := e.Reviews()
			if err != nil || len(reviews) != 1 {
				t.Fatalf("review missing: %+v %v", reviews, err)
			}
			if len(reviews[0].Scripts) != 0 || reviews[0].ScriptCaptureStatus != "not_applicable" {
				t.Fatalf("%s gained an outgoing-file capture: %+v %s", agent, reviews[0].Scripts, log)
			}
			if reviews[0].Decision == "reject" && reviews[0].RuleID == "R_PII_ID" {
				t.Fatalf("%s file content was scanned: %+v", agent, reviews[0])
			}
		})
	}
}

// A non-applicable tool must keep the pre-existing envelope (regression for Bash):
// no outgoing-file entry is added and the script-capture status is unchanged.
func TestOutgoingFileCaptureLeavesBashUnchanged(t *testing.T) {
	e, path, cwd := claudeReadFixture(t)
	if code, _, log := invoke("claude", path, native("claude", cwd, "call", "Bash", "PreToolUse", map[string]any{"command": "echo ordinary"})); code != 2 {
		t.Fatalf("bash fixture changed behaviour: %d %s", code, log)
	}
	reviews, err := e.Reviews()
	if err != nil || len(reviews) != 1 || reviews[0].ScriptCaptureStatus != "not_applicable" || len(reviews[0].Scripts) != 0 {
		t.Fatalf("bash envelope gained a capture: %+v %v", reviews, err)
	}
}

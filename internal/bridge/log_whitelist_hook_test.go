package bridge

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// whitelistHookFixture enrolls a device, registers its node in the log
// whitelist, and returns the hook connection file bound to that node.
func whitelistHookFixture(t *testing.T) (*core.Engine, string, string) {
	t.Helper()
	e, path, cwd := fixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var original Config
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "whitelist hook fixture")
	if err != nil {
		t.Fatal(err)
	}
	// Disposable generated test identity, not a host credential.
	conn, err := e.EnrollClient(key.Code, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	conn.Endpoint = original.Endpoint
	if err := os.WriteFile(path, mustJSON(conn), 0600); err != nil {
		t.Fatal(err)
	}
	entry := core.LogWhitelistEntry{Name: "Device recording", Description: "Fixture device", Enabled: true,
		Subject: core.LogWhitelistSubject{Kind: "agents", AgentIDs: []string{conn.NodeID}}}
	state, err := e.Protection()
	if err != nil {
		t.Fatal(err)
	}
	review, err := e.ReviewProtection(core.ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry}, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConfirmProtection(core.WithActor(context.Background(), core.SystemActor("test")), review.ID, state.Revision, true, "log-whitelist", "", false); err != nil {
		t.Fatal(err)
	}
	return e, path, cwd
}

// Adapters reject a terminal verdict whose comment is empty (bridge.go verdict
// validation; OpenClaw verdict()). Suppression must therefore deliver a fixed,
// content-free explanation instead of the persisted (empty) comment.
func TestLogWhitelistSuppressedVerdictsPassHookValidation(t *testing.T) {
	for _, decision := range []string{"approve", "alert", "reject"} {
		t.Run(decision, func(t *testing.T) {
			e, path, cwd := whitelistHookFixture(t)
			rule := core.Rule{ID: "U_WHITELIST_HOOK", Name: "CANARY_RULE_NAME", Message: "CANARY_RULE_COMMENT",
				Matcher: "contains", Target: "arguments", Field: "file_path", Pattern: "CANARY_HOOK", Enabled: true, Decision: decision}
			if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
				t.Fatal(err)
			}
			code, output, log := invoke("claude", path, claudePayload(cwd, "whitelist", "Read", map[string]any{"file_path": "CANARY_HOOK.txt"}))
			if decision == "reject" {
				if code != 2 {
					t.Fatal("whitelisted reject did not deny", code, output, log)
				}
				assertClaudeDeny(t, code, output)
			} else {
				if code != 0 || strings.TrimSpace(output) != "{}" {
					t.Fatal("whitelisted terminal verdict failed hook validation", code, output, log)
				}
			}
			for _, text := range []string{output, log} {
				if strings.Contains(text, "CANARY_") {
					t.Fatal("hook response leaked suppressed content", text)
				}
			}
			if decision == "reject" && !strings.Contains(output, core.SuppressedComment) {
				t.Fatal("deny reason is not the fixed suppression text", output)
			}
			rs, err := e.Reviews()
			if err != nil || len(rs) == 0 {
				t.Fatal("review missing", err)
			}
			for _, r := range rs {
				if r.LogSuppression == nil || r.Comment != "" {
					t.Fatal("suppressed review retained a comment or lost provenance", r.Comment, r.LogSuppression)
				}
			}
		})
	}
}

// Polling and retry: a suppressed human decision must still reach the waiting
// hook through the same fixed comment path.
func TestLogWhitelistSuppressedHumanApprovalPollsThrough(t *testing.T) {
	e, path, cwd := whitelistHookFixture(t)
	done := make(chan int, 1)
	go func() {
		code, _, _ := invoke("codex", path, codexPayload(cwd, "whitelist-pending", "echo fixture"))
		done <- code
	}()
	var r core.Review
	for n := 0; n < 300; n++ {
		rs, _ := e.Reviews()
		for _, review := range rs {
			if review.CallID == "whitelist-pending" {
				r = review
			}
		}
		if r.ID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.ID == "" || r.LogSuppression == nil || r.Decision != "pending" {
		t.Fatal("no suppressed pending review", r.Decision, r.LogSuppression)
	}
	if _, err := e.Decide(core.WithActor(context.Background(), core.SystemActor("test")), r.ID, r.Digest, "approve", "CANARY_HUMAN_REASON"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal("suppressed human approval did not pass hook validation", code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("bridge stuck")
	}
}

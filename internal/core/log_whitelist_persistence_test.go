package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"aegishook/internal/teststore"
)

// Capture every insertion/update, including the initial pending payload, rather
// than trusting only the final row. Admin is required for FORCE RLS inspection.
func captureWhitelistWrites(t *testing.T, e *Engine) {
	t.Helper()
	query := `CREATE TABLE whitelist_writes (kind TEXT, payload TEXT);
CREATE TRIGGER whitelist_insert AFTER INSERT ON records WHEN NEW.kind IN ('reviews','audit','log_delivery') BEGIN INSERT INTO whitelist_writes VALUES (NEW.kind,NEW.payload); END;
CREATE TRIGGER whitelist_update AFTER UPDATE ON records WHEN NEW.kind IN ('reviews','audit','log_delivery') BEGIN INSERT INTO whitelist_writes VALUES (NEW.kind,NEW.payload); END;`
	if e.postgres {
		query = `CREATE TABLE whitelist_writes (kind TEXT, payload TEXT);
CREATE FUNCTION whitelist_capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN INSERT INTO whitelist_writes VALUES (NEW.kind,NEW.payload); RETURN NEW; END $$;
CREATE TRIGGER whitelist_capture AFTER INSERT OR UPDATE ON records FOR EACH ROW WHEN (NEW.kind IN ('reviews','audit','log_delivery')) EXECUTE FUNCTION whitelist_capture();`
	}
	if _, err := teststore.Admin(t, e.DB).Exec(query); err != nil {
		t.Fatal(err)
	}
}

func assertWhitelistWrites(t *testing.T, e *Engine) {
	t.Helper()
	rows, err := teststore.Admin(t, e.DB).Query("SELECT kind,payload FROM whitelist_writes")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var kind, payload string
		if err := rows.Scan(&kind, &payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, "CANARY_") || strings.Contains(payload, "tg.sentry.audit.v1") {
			t.Fatalf("suppressed payload inserted into %s: %s", kind, payload)
		}
		if kind == "audit" {
			var a Audit
			if err := json.Unmarshal([]byte(payload), &a); err != nil {
				t.Fatal(err)
			}
			if a.Action != "review.human" && len(a.Events) == 0 {
				t.Fatalf("routine suppressed audit inserted: %+v", a)
			}
		}
		seen++
	}
	if err := rows.Err(); err != nil || seen == 0 {
		t.Fatal("write capture empty or unreadable", seen, err)
	}
}

func whitelistPersistenceFixture(t *testing.T, suppressed bool) (*Engine, string) {
	t.Helper()
	e, node, _ := protectionFixture(t)
	if suppressed {
		entry := whitelistEntry(node)
		publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry})
	}
	if err := e.Register(Instance{ID: "private-instance", Agent: "claude", NodeID: node, Platform: "linux", SessionID: "private-session", Cwd: "/workspace", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	// Sink fixture follows log_delivery_test.go; no delivery worker is started.
	e.syslog = &syslogConfig{address: "localhost:6514", transport: "tls", facility: 16}
	return e, node
}

func whitelistCanaryInput(call, tool string) ReviewInput {
	return ReviewInput{InstanceID: "private-instance", CallID: call, ToolName: tool,
		Arguments:   map[string]any{"text": "CANARY_ARGUMENT", "nested": map[string]any{"CANARY_KEY": "CANARY_NESTED"}},
		UserMessage: "CANARY_USER", Context: "CANARY_CONTEXT", ScriptCaptureStatus: "complete",
		Scripts: []ReviewScript{{Path: "/CANARY_SCRIPT_PATH", SHA256: "CANARY_SCRIPT_HASH", Bytes: 1, Content: "CANARY_SCRIPT_CONTENT", Complete: true, ReadError: "CANARY_SCRIPT_ERROR"}}}
}

func TestLogWhitelistPersistenceProtectionAndRiskParity(t *testing.T) {
	schemas := pinnedEventSchemas(t)
	for _, action := range []string{"approve", "reject", "alert"} {
		t.Run(action, func(t *testing.T) {
			var baseline Review
			for _, suppressed := range []bool{false, true} {
				t.Run(map[bool]string{false: "normal", true: "suppressed"}[suppressed], func(t *testing.T) {
					e, _ := whitelistPersistenceFixture(t, suppressed)
					rule := Rule{ID: "U_WHITELIST", Name: "CANARY_RULE_NAME", Message: "CANARY_RULE_COMMENT", Matcher: "contains", Field: "text", Pattern: "CANARY_ARGUMENT", Enabled: true, Decision: action, Severity: "high", Categories: []string{"category::high-risk-ops"}}
					if err := e.SaveRule(testActorContext(), rule); err != nil {
						t.Fatal(err)
					}
					if suppressed {
						captureWhitelistWrites(t, e)
					}
					r, err := e.Submit(whitelistCanaryInput("parity", "fixture"))
					if err != nil {
						t.Fatal(err)
					}
					if !suppressed {
						baseline = r
					} else if r.Decision != baseline.Decision || r.RuleID != baseline.RuleID || r.ReviewPath != baseline.ReviewPath || r.Execution != baseline.Execution {
						t.Fatal("whitelist changed authorization", r, baseline)
					}
					if suppressed {
						assertWhitelistWrites(t, e)
					}
					state := "succeeded"
					if r.Decision == "reject" {
						state = "not_executed"
					}
					if err := e.Result(r.ID, "private-instance", state, "CANARY_RESULT"); err != nil {
						t.Fatal(err)
					}
					if err := e.Result(r.ID, "private-instance", state, "CANARY_RETRY"); err != nil {
						t.Fatal(err)
					}
					page, err := e.RiskEvents(0, "", RiskEventFilter{})
					want := map[string]int{"approve": 0, "reject": 2, "alert": 1}[action]
					if err != nil || len(page.Items) != want {
						t.Fatal("risk findings lost", page, err)
					}
					for _, event := range page.Items {
						if err := validateEventWire(schemas, wireEvent(t, event)); err != nil {
							t.Fatal(err)
						}
					}
					if suppressed {
						assertWhitelistWrites(t, e)
						batch, err := e.pendingLogDeliveries(context.Background(), e.syslog.destination())
						if err != nil || len(batch) != want {
							t.Fatal("suppressed audit reached outbox or risk delivery lost", len(batch), want, err)
						}
					}
				})
			}
		})
	}
}

func TestLogWhitelistPersistenceHumanAndLifecycle(t *testing.T) {
	for _, terminal := range []string{"human", "expiry", "disconnect", "restart"} {
		t.Run(terminal, func(t *testing.T) {
			e, _ := whitelistPersistenceFixture(t, true)
			captureWhitelistWrites(t, e)
			r, err := e.Submit(whitelistCanaryInput("pending", "fixture"))
			if err != nil || r.Decision != "pending" || !r.NeedsHuman {
				t.Fatal(r, err)
			}
			assertWhitelistWrites(t, e)
			stored, err := e.Review(r.ID)
			if err != nil || reviewInputState(stored) != ContentPolicyOmitted {
				t.Fatal("pending content is not explicitly unavailable", stored, err)
			}
			switch terminal {
			case "human":
				r, err = e.Decide(testActorContext(), r.ID, r.Digest, "approve", "CANARY_HUMAN_COMMENT")
				if err != nil || r.Decision != "approve" {
					t.Fatal(r, err)
				}
				assertWhitelistWrites(t, e)
				err = e.Result(r.ID, "private-instance", "succeeded", "CANARY_HUMAN_RESULT")
			case "expiry":
				e.mu.Lock()
				e.clock = func() time.Time { return r.Deadline.Add(time.Second) }
				e.mu.Unlock()
				e.Expire()
			case "disconnect":
				err = e.Disconnect("private-instance")
			case "restart":
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
				e, err = Open(e.Dir)
				if err == nil {
					defer e.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			assertWhitelistWrites(t, e)
			stored, err = e.Review(r.ID)
			if err != nil || stored.Decision == "pending" {
				t.Fatal("lifecycle did not finalize control state", stored, err)
			}
		})
	}
}

func TestLogWhitelistPersistenceModelInitialWriteAndCompletion(t *testing.T) {
	e, _ := whitelistPersistenceFixture(t, true)
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		defer close(finished)
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		b, _ := json.Marshal(body)
		if !strings.Contains(string(b), "CANARY_ARGUMENT") || !strings.Contains(string(b), "CANARY_SCRIPT_CONTENT") {
			t.Error("judge did not receive live input")
		}
		close(started)
		<-release
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"decision":"approve","comment":"实际操作：读取 CANARY_MODEL_COMMENT；成功后的后果：返回文本；命中规则：A7"}`}}}})
	}))
	defer srv.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	e.Settings.Mode = "model"
	e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: srv.URL, Model: "fixture", Tested: true}
	e.Settings.Prompt = "CANARY_MODEL_PROMPT"
	captureWhitelistWrites(t, e)
	r, err := e.Submit(whitelistCanaryInput("model-pending", "fixture"))
	if err != nil || r.Decision != "pending" {
		t.Fatal(r, err)
	}
	select {
	case <-started:
	case <-time.After(ReviewHookBudget):
		t.Fatal("judge did not start")
	}
	assertWhitelistWrites(t, e)
	close(release)
	<-finished
	deadline := time.NewTimer(ReviewHookBudget)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		stored, err := e.Review(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Decision != "pending" {
			if stored.Decision != "approve" || stored.ModelVerdict == nil {
				t.Fatal("model protection changed", stored)
			}
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("model did not complete")
		case <-tick.C:
		}
	}
	assertWhitelistWrites(t, e)
}

func TestLogWhitelistPersistenceFailuresNeverReleaseAllow(t *testing.T) {
	for _, path := range []string{"submit", "human", "confirmed-block"} {
		t.Run(path, func(t *testing.T) {
			e, _ := whitelistPersistenceFixture(t, true)
			tool := "fixture"
			args := map[string]any{"text": "benign"}
			if path == "submit" {
				tool = "Read"
			} else if path == "confirmed-block" {
				tool, args = "Bash", map[string]any{"command": "redis-cli FLUSHALL"}
			}
			var before Review
			if path != "submit" {
				in := input("failure", tool, args)
				in.InstanceID = "private-instance"
				var err error
				before, err = e.Submit(in)
				if err == nil {
					before, err = e.Review(before.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			// Fault the review write itself: routine suppressed audits are absent.
			query := `CREATE TRIGGER reject_whitelist_write BEFORE INSERT ON records WHEN NEW.kind='reviews' BEGIN SELECT RAISE(ABORT,'injected'); END;
CREATE TRIGGER reject_whitelist_update BEFORE UPDATE ON records WHEN NEW.kind='reviews' BEGIN SELECT RAISE(ABORT,'injected'); END;`
			if e.postgres {
				query = `CREATE FUNCTION reject_whitelist_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$;
CREATE TRIGGER reject_whitelist_write BEFORE INSERT OR UPDATE ON records FOR EACH ROW WHEN (NEW.kind='reviews') EXECUTE FUNCTION reject_whitelist_write();`
			}
			if _, err := teststore.Admin(t, e.DB).Exec(query); err != nil {
				t.Fatal(err)
			}
			var got Review
			var err error
			switch path {
			case "submit":
				in := input("failure", tool, args)
				in.InstanceID = "private-instance"
				got, err = e.Submit(in)
			case "human":
				got, err = e.Decide(testActorContext(), before.ID, before.Digest, "approve", "CANARY_FAILED_COMMENT")
			case "confirmed-block":
				err = e.Result(before.ID, "private-instance", "not_executed", "CANARY_FAILED_RESULT")
			}
			if err == nil || got.Decision == "approve" {
				t.Fatal("uncommitted allow released", got, err)
			}
			if path != "submit" {
				stored, err := e.Review(before.ID)
				if err != nil || !reflect.DeepEqual(before, stored) {
					t.Fatal("failed transaction changed control state", stored, err)
				}
			}
		})
	}
}

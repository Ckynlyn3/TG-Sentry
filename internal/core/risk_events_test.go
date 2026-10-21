package core

import (
	"aegishook/internal/teststore"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRiskEventLocalDetectionAndAuditFailure(t *testing.T) {
	e := engine(t)
	r, err := e.Submit(input("risk", "Bash", map[string]any{"command": "redis-cli FLUSHALL", "secret": "raw-canary"}))
	if err != nil || r.Decision != "reject" {
		t.Fatal(r, err)
	}
	page, err := e.RiskEvents(20, "", RiskEventFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	event := page.Items[0]
	if event.Data.Actor.AppUID != "" || event.Data.Unmapped.TGSentry.IdentityState != "unenrolled" {
		t.Fatal("invented enrolled identity", event)
	}
	if event.Data.Metadata.TenantUID != "default" || event.Data.FindingInfo.UID != r.ID || event.Data.ActionID != 0 || event.Data.DispositionID != 0 {
		t.Fatal(event)
	}
	b, _ := json.Marshal(event)
	if strings.Contains(string(b), "raw-canary") || strings.Contains(string(b), "redis-cli") {
		t.Fatal("content leaked into event")
	}
	again, err := e.Submit(input("risk", "Bash", map[string]any{"command": "redis-cli FLUSHALL", "secret": "raw-canary"}))
	if err != nil || again.ID != r.ID {
		t.Fatal(again, err)
	}
	same, _ := e.RiskEvents(20, "", RiskEventFilter{})
	if len(same.Items) != 1 || same.Items[0].ID != event.ID {
		t.Fatal("duplicate occurrence", same)
	}
	got, err := e.RiskEvent(event.ID)
	if err != nil || got.ID != event.ID {
		t.Fatal(got, err)
	}
	rejectAudit(t, e)
	denied, err := e.Submit(input("read-without-audit", "Read", map[string]any{"file_path": "README.md"}))
	if err == nil || denied.Decision != "reject" || denied.Execution != "not_executed" {
		t.Fatal("audit failure returned allow", denied, err)
	}
	if _, err = e.Review(denied.ID); err == nil {
		t.Fatal("failed transaction persisted review")
	}
}

func TestRiskEventEnrolledPaginationAndAlert(t *testing.T) {
	e := engine(t)
	code, err := e.CreateEnrollment(testActorContext(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Register(Instance{ID: "enrolled", NodeID: connection.NodeID, Agent: "claude", Platform: "linux", SessionID: "session", Cwd: "/workspace", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "U_ALERT", Name: "Fixture alert", Decision: "alert", Enabled: true, Tool: "fixture", Pattern: "risk", Severity: "high", Categories: []string{"category::prompt-attack"}}
	if err = e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second", "third"} {
		r, err := e.Submit(ReviewInput{InstanceID: "enrolled", CallID: id, ToolName: "fixture", Arguments: map[string]any{"value": "risk"}})
		if err != nil || r.Decision != "approve" {
			t.Fatal(r, err)
		}
	}
	filter := RiskEventFilter{Severity: "high", Category: "category::prompt-attack", Agent: connection.NodeID + "/claude"}
	page, err := e.RiskEvents(1, "", filter)
	if err != nil || len(page.Items) != 1 || page.NextPageToken == "" {
		t.Fatal(page, err)
	}
	first := page.Items[0]
	if first.Data.Actor.AppUID != filter.Agent || first.Data.SeverityID != 4 || first.Data.ActionID != 3 || first.Data.DispositionID != 19 {
		t.Fatal(first)
	}
	next, err := e.RiskEvents(100, page.NextPageToken, filter)
	if err != nil || len(next.Items) != 2 || next.NextPageToken != "" || next.Items[0].ID == first.ID {
		t.Fatal(next, err)
	}
	if _, err = e.RiskEvents(1, page.NextPageToken, RiskEventFilter{}); !errors.Is(err, ErrRiskEventQuery) {
		t.Fatal("changed filters accepted", err)
	}
	if _, err = e.RiskEvents(-1, "", filter); !errors.Is(err, ErrRiskEventQuery) {
		t.Fatal(err)
	}
	if _, err = e.RiskEvents(1, "invalid", filter); !errors.Is(err, ErrRiskEventQuery) {
		t.Fatal(err)
	}
}

func TestHumanApprovalFailsClosedOnAuditFailure(t *testing.T) {
	e := engine(t)
	r, err := e.Submit(input("human", "Bash", map[string]any{"command": "echo fixture"}))
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(t, e)
	denied, err := e.Decide(testActorContext(), r.ID, r.Digest, "approve", "")
	if err == nil || denied.Decision != "reject" || denied.Execution != "not_executed" {
		t.Fatal(denied, err)
	}
	stored, err := e.Review(r.ID)
	if err != nil || stored.Decision != "pending" {
		t.Fatal("audit rollback failed", stored, err)
	}
}

func TestRiskEventFiltersAndStoreErrors(t *testing.T) {
	e := engine(t)
	for _, rule := range []Rule{
		{ID: "U_SEVERITY", Name: "Fixture", Decision: "alert", Enabled: true, Pattern: "fixture", Severity: "invalid"},
		{ID: "U_CATEGORY", Name: "Fixture", Decision: "alert", Enabled: true, Pattern: "fixture", Categories: []string{"invalid"}},
	} {
		if err := e.SaveRule(testActorContext(), rule); err == nil {
			t.Fatal("invalid risk rule accepted")
		}
	}
	rule := Rule{ID: "U_FILTER", Name: "Fixture", Decision: "alert", Enabled: true, Tool: "fixture", Pattern: "fixture", Severity: "low", Categories: []string{"category::behavior"}}
	if err := e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit(input("fixture", "fixture", map[string]any{"value": "fixture"})); err != nil {
		t.Fatal(err)
	}
	for _, filter := range []RiskEventFilter{{Severity: "high"}, {Category: "category::sensitive-info"}, {Agent: "absent"}} {
		page, err := e.RiskEvents(0, "", filter)
		if err != nil || len(page.Items) != 0 {
			t.Fatal(page, err)
		}
	}
	page, err := e.RiskEvents(1000, "", RiskEventFilter{Category: "category::behavior"})
	if err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	if _, err = e.RiskEvent("absent"); err == nil {
		t.Fatal("missing ID accepted")
	}
	if err = e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = e.RiskEvents(1, "", RiskEventFilter{}); err == nil {
		t.Fatal("store error hidden")
	}
	if _, err = e.RiskEvent(page.Items[0].ID); err == nil {
		t.Fatal("store error hidden")
	}
}

func TestRiskEventContinuationSurvivesInsert(t *testing.T) {
	e := engine(t)
	for _, call := range []string{"one", "two"} {
		if _, err := e.Submit(input(call, "Bash", map[string]any{"command": "redis-cli FLUSHALL"})); err != nil {
			t.Fatal(err)
		}
	}
	first, err := e.RiskEvents(1, "", RiskEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Submit(input("new", "Bash", map[string]any{"command": "redis-cli FLUSHALL"})); err != nil {
		t.Fatal(err)
	}
	next, err := e.RiskEvents(1, first.NextPageToken, RiskEventFilter{})
	if err != nil || len(next.Items) != 1 || next.NextPageToken != "" || !next.Items[0].Time.Before(first.Items[0].Time) {
		t.Fatal(next, err)
	}
}

func TestRiskEventPaginationDuplicateOccurrences(t *testing.T) {
	e := sqliteStatsEngine(t)
	duplicate := statsEvent("duplicate", statsNow.Add(-time.Hour), "agent", 4, 2, 2, "category::behavior")
	rows := [][]Event{
		{statsEvent("newest", statsNow.Add(-time.Minute), "agent", 4, 2, 2), duplicate, duplicate, duplicate},
		{duplicate, statsEvent("oldest", statsNow.Add(-2*time.Hour), "agent", 4, 2, 2)},
	}
	for row, events := range rows {
		for index := range events {
			// Distinguish stored occurrences without changing their CloudEvents identity.
			events[index].Data.Metadata.UID = fmt.Sprintf("%d/%d", row, index)
		}
		id := fmt.Sprint(row)
		if err := e.put("audit", id, Audit{ID: id, Events: events}); err != nil {
			t.Fatal(err)
		}
	}
	for _, filter := range []RiskEventFilter{{}, {Category: "category::behavior"}, {From: &rows[1][1].Data.Time, To: &rows[0][0].Data.Time}} {
		whole, err := e.RiskEvents(100, "", filter)
		if err != nil || whole.NextPageToken != "" {
			t.Fatal(whole, err)
		}
		for _, sizes := range [][]int{{1}, {2}, {1, 2}} {
			t.Run(fmt.Sprint(filter, sizes), func(t *testing.T) {
				items := []Event{}
				seen := map[string]bool{}
				token := ""
				for pageIndex := 0; ; pageIndex++ {
					// A nonempty page must consume at least one remaining occurrence.
					if pageIndex >= len(whole.Items) {
						t.Fatal("pagination did not terminate")
					}
					page, err := e.RiskEvents(sizes[pageIndex%len(sizes)], token, filter)
					if err != nil || len(page.Items) == 0 {
						t.Fatal(page, err)
					}
					items = append(items, page.Items...)
					token = page.NextPageToken
					if token == "" {
						break
					}
					if seen[token] {
						t.Fatal("pagination repeated an occurrence cursor")
					}
					seen[token] = true
				}
				if len(items) != len(whole.Items) || !reflect.DeepEqual(items, whole.Items) {
					t.Fatalf("paged occurrences differ from full filtered set: got %v want %v", items, whole.Items)
				}
			})
		}
	}
}

func TestAlertCannotOverrideRejectOrAuditFailure(t *testing.T) {
	e := engine(t)
	rule := Rule{ID: "U_ALERT", Name: "Fixture", Decision: "alert", Enabled: true, Tool: "Bash", Pattern: ".*"}
	if err := e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	rejected, err := e.Submit(input("deny-wins", "Bash", map[string]any{"command": "redis-cli FLUSHALL"}))
	if err != nil || rejected.Decision != "reject" {
		t.Fatal(rejected, err)
	}
	rejectAudit(t, e)
	rejected, err = e.Submit(input("audit-fail", "Bash", map[string]any{"command": "echo fixture"}))
	if err == nil || rejected.Decision != "reject" || rejected.Execution != "not_executed" {
		t.Fatal(rejected, err)
	}
}

func TestReviewEventIdentityLookupFailures(t *testing.T) {
	e := engine(t)
	test := func(id string, wantError bool, wantNode string) {
		t.Helper()
		tx, err := e.beginTenant()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		node, err := reviewEventNode(tx, id)
		if (err != nil) != wantError || node != wantNode {
			t.Fatal(node, err)
		}
	}
	test("missing", true, "")
	if err := e.put("instances", "malformed", map[string]any{"nodeId": 42}); err != nil {
		t.Fatal(err)
	}
	test("malformed", true, "")
	node := ID()
	if err := e.put("instances", "remote", Instance{ID: "remote", NodeID: node}); err != nil {
		t.Fatal(err)
	}
	if err := e.put("client_nodes", node, map[string]any{"id": 42}); err != nil {
		t.Fatal(err)
	}
	test("remote", true, "")
	if err := e.put("client_nodes", node, ClientNode{ID: node, Revoked: true}); err != nil {
		t.Fatal(err)
	}
	test("remote", false, "")
	if _, err := teststore.Admin(t, e.DB).Exec("DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	test("remote", true, "")
}

package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIndependentRecheckObservationsAndPrivacy(t *testing.T) {
	e := engine(t)
	const secret = "synthetic-private-recheck"
	for _, id := range []string{"U_PRIVATE_A", "U_PRIVATE_B"} {
		if err := e.SaveRule(testActorContext(), Rule{ID: id, Name: secret, Message: secret, Enabled: true, Matcher: "keywords", Pattern: secret, Field: "value", Decision: "approve", Categories: []string{SensitiveInfoCategory}}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := e.Submit(input("independent-recheck", "read", map[string]any{"value": secret, "card": syntheticCard(), "id": syntheticID()}))
	if err != nil {
		t.Fatal(err)
	}
	if r.RuleID != "A7" || r.Decision != "approve" || r.Execution != "awaiting_execution" {
		t.Fatal("A7 winner changed")
	}
	page, err := e.RiskEvents(0, "", RiskEventFilter{})
	if err != nil || len(page.Items) != 2 {
		t.Fatal("expected exactly two custom observations and no A7 risk event", err)
	}
	schemas := pinnedEventSchemas(t)
	for _, ev := range page.Items {
		if ev.Data.ActionID != 3 || ev.Data.DispositionID != 17 {
			t.Fatal("not observed/logged")
		}
		if err := validateEventWire(schemas, wireEvent(t, ev)); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Result(r.ID, "instance", "succeeded", secret+syntheticCard()+syntheticID()); err != nil {
		t.Fatal(err)
	}
	page, err = e.RiskEvents(0, "", RiskEventFilter{})
	if err != nil || len(page.Items) != 2 {
		t.Fatal("result duplicated observations", err)
	}
	tx, err := e.beginTenant()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Configuration deliberately retains detection patterns; runtime records must not.
	rows, err := tx.Query("SELECT kind,id,payload FROM records WHERE tenant_id=$1 AND kind NOT IN ('rules')", eventTenant())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, id, payload string
		if err := rows.Scan(&kind, &id, &payload); err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{secret, syntheticCard(), syntheticID()} {
			if strings.Contains(id+payload, raw) {
				t.Errorf("private content retained in %s", kind)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentRecheckExpirationAndOpaqueIDs(t *testing.T) {
	for _, raw := range []string{"instance-" + syntheticCard(), "instance-" + syntheticID(), "abcdef" + syntheticCard() + "fedcba", "550e8400-e29b-41d4-a716-446655440000"} {
		e := engine(t)
		if err := e.Register(Instance{ID: raw, SessionID: "session-" + syntheticID(), Cwd: t.TempDir(), HookVersion: Version}); err != nil {
			t.Fatal(err)
		}
		if err := e.Heartbeat(raw, "running"); err != nil {
			t.Fatal(err)
		}
		r, err := e.Submit(ReviewInput{InstanceID: raw, CallID: "pending", ToolName: "unknown", Arguments: map[string]any{"value": "safe"}})
		if err != nil || r.Decision != "pending" {
			t.Fatal("pending", err)
		}
		if strings.HasPrefix(raw, "abcdef") || strings.HasPrefix(raw, "550e") {
			if r.InstanceID != raw {
				t.Error("opaque identifier falsely digested")
			}
		}
		now := e.clock()
		e.clock = func() time.Time { return now.Add(31 * time.Second) }
		e.Expire()
		saved, err := e.Review(r.ID)
		if err != nil || saved.RuleID != "E_SESSION" || saved.Decision != "reject" {
			t.Fatal("expired identity not cancelled", err)
		}
		if err := e.Result(r.ID, raw, "not_executed", ""); err != nil {
			t.Fatal(err)
		}
		if err := e.Disconnect(raw); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(saved)
		if strings.Contains(string(b), syntheticID()) {
			t.Fatal("CN-ID leaked")
		}
	}
}

func TestIndependentRecheckSessionFilterReservedPrefix(t *testing.T) {
	e := engine(t)
	// Session IDs accept this opaque shape; unlike instance IDs Register does not reserve it.
	raw := "sha256:" + strings.Repeat("a", 64)
	if err := e.Register(Instance{ID: "session-prefix", SessionID: raw, Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Submit(ReviewInput{InstanceID: "session-prefix", CallID: "call", ToolName: "read", Arguments: map[string]any{"value": "safe"}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := e.ReviewsPage(1, 20, ReviewFilter{SessionID: raw})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatal("accepted raw SessionID no longer resolves through reviews filter")
	}
}

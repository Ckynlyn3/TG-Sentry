package core

import (
	"aegishook/internal/teststore"
	"errors"
	"reflect"
	"testing"
	"time"
)

func summaryEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func summaryTime(t *testing.T, value string) time.Time {
	t.Helper()
	stamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

func TestSessionSummariesProjection(t *testing.T) {
	e := summaryEngine(t)
	start := summaryTime(t, "2026-10-18T10:00:00Z")
	for _, in := range []Instance{
		{ID: "one", SessionID: "shared", Agent: "claude", NodeID: "device-a", StartedAt: start, Heartbeat: start.Add(24 * time.Hour)},
		{ID: "two", SessionID: "shared", Agent: "cursor", NodeID: "device-b", StartedAt: start.Add(time.Hour)},
		{ID: "three", SessionID: "shared", Agent: "claude", NodeID: "device-a", StartedAt: start},
		{ID: "live", SessionID: "live", StartedAt: start.Add(2 * time.Hour)},
	} {
		if err := e.put("instances", in.ID, in); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Review{
		{ID: "r1", SessionID: "shared", Agent: "codex", CreatedAt: start.Add(-time.Hour), Decision: "pending"},
		{ID: "r2", SessionID: "shared", Agent: "claude", CreatedAt: start.Add(time.Hour)},
		{ID: "orphan", SessionID: "orphan", Agent: "grok", CreatedAt: start.Add(3 * time.Hour)},
	} {
		if err := e.put("reviews", r.ID, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.put("client_nodes", "device-a", storedClientNode{ClientNode: ClientNode{ID: "device-a", Name: "Laptop", Revoked: true}, Hash: "must-not-leak"}); err != nil {
		t.Fatal(err)
	}
	page, err := e.SessionSummaries(1, 20, SessionSummaryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Items) != 3 || page.Page != 1 || page.PageSize != 20 {
		t.Fatalf("page: %+v", page)
	}
	if page.Items[0].SessionID != "orphan" || page.Items[1].SessionID != "live" {
		t.Fatalf("order: %+v", page.Items)
	}
	shared := page.Items[2]
	if !reflect.DeepEqual(shared.Agents, []string{"claude", "codex", "cursor"}) || !reflect.DeepEqual(shared.Devices, []SessionDevice{{NodeID: "device-a", Name: "Laptop"}, {NodeID: "device-b"}}) {
		t.Fatalf("distinct metadata: %+v", shared)
	}
	if shared.CallCount != 2 || !shared.SessionTime.Equal(start.Add(-time.Hour)) || shared.LastCallAt == nil || !shared.LastCallAt.Equal(start.Add(time.Hour)) || shared.User != nil || shared.UserState != "unassociated" {
		t.Fatalf("aggregate: %+v", shared)
	}
	if page.Items[1].CallCount != 0 || page.Items[1].LastCallAt != nil || !reflect.DeepEqual(page.Items[1].Agents, []string{"pi"}) || len(page.Items[0].Devices) != 0 {
		t.Fatal("liveness/orphan semantics")
	}
	for _, filter := range []SessionSummaryFilter{{Agent: "cursor"}, {Agent: "codex"}, {NodeID: "device-b"}, {SessionKey: "shared"}} {
		p, err := e.SessionSummaries(1, 1, filter)
		if err != nil || p.Total != 1 || len(p.Items) != 1 || p.Items[0].SessionID != "shared" {
			t.Fatalf("ANY/exact filter %+v: %+v %v", filter, p, err)
		}
	}
	missing, err := e.SessionSummaries(1, 20, SessionSummaryFilter{SessionKey: "sha256:shared"})
	if err != nil || missing.Total != 0 || len(missing.Items) != 0 {
		t.Fatal("sessionKey must be exact", err)
	}
	second, err := e.SessionSummaries(2, 1, SessionSummaryFilter{})
	if err != nil || second.Total != 3 || len(second.Items) != 1 || second.Items[0].SessionID != "live" {
		t.Fatal("paging", err)
	}
	empty, err := e.SessionSummaries(10, 1, SessionSummaryFilter{})
	if err != nil || empty.Total != 3 || empty.Items == nil || len(empty.Items) != 0 {
		t.Fatal("empty page count", err)
	}
}

func TestSessionSummariesTimeBounds(t *testing.T) {
	e := summaryEngine(t)
	for _, fixture := range []struct{ id, stamp string }{
		{"before", "2026-10-17T23:59:59.999999999Z"},
		{"from", "2026-10-18T00:00:00Z"},
		{"fraction", "2026-10-18T02:00:00.123456789+02:00"},
		{"fraction-before", "2026-10-18T00:00:00.123456788Z"},
		{"last", "2026-10-18T23:59:59.999999999Z"},
		{"upper", "2026-10-19T00:00:00Z"},
	} {
		if err := e.put("reviews", fixture.id, Review{ID: fixture.id, SessionID: fixture.id, CreatedAt: summaryTime(t, fixture.stamp)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		from, to string
		total    int
	}{
		{"2026-10-18", "2026-10-18", 4},
		{"2026-10-18T02:00:00+02:00", "2026-10-18T02:00:00.123456789+02:00", 2},
		{"2026-10-18T00:00:00.123456788Z", "2026-10-18T00:00:00.123456789Z", 1},
		{"2026-10-18T00:00:00.123456789Z", "2026-10-18T00:00:00.123456790Z", 1},
		{"2026-10-19T00:00:00Z", "2026-10-19T00:00:00Z", 0},
	} {
		p, err := e.SessionSummaries(1, 20, SessionSummaryFilter{From: tc.from, To: tc.to})
		if err != nil || p.Total != tc.total {
			t.Errorf("bounds %+v: total=%d err=%v", tc, p.Total, err)
		}
	}
	for _, filter := range []SessionSummaryFilter{{From: "bad"}, {To: "bad"}, {From: "2026-10-20", To: "2026-10-18"}, {From: "2026-10-18T00:00:01Z", To: "2026-10-18T02:00:00+02:00"}} {
		if _, err := e.SessionSummaries(1, 20, filter); !errors.Is(err, ErrSessionSummaryQuery) {
			t.Fatalf("invalid filter %+v accepted: %v", filter, err)
		}
	}
}

func TestSessionSummariesNanosecondOrdering(t *testing.T) {
	e := summaryEngine(t)
	for _, fixture := range []struct{ id, stamp string }{
		{"z", "2026-10-18T00:00:00Z"},
		{"nano", "2026-10-17T23:00:00.000000001-01:00"},
	} {
		if err := e.put("instances", fixture.id, Instance{ID: fixture.id, SessionID: fixture.id, StartedAt: summaryTime(t, fixture.stamp)}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := e.SessionSummaries(1, 20, SessionSummaryFilter{})
	if err != nil || len(p.Items) != 2 || p.Items[0].SessionID != "nano" || p.Items[1].SessionID != "z" {
		t.Fatal("Z/fraction ordering", p, err)
	}
	p, err = e.SessionSummaries(1, 20, SessionSummaryFilter{From: "2026-10-18T00:00:00.000000001Z", To: "2026-10-18T00:00:00.000000002Z"})
	if err != nil || p.Total != 1 || p.Items[0].SessionID != "nano" {
		t.Fatal("nanosecond inclusion", p, err)
	}
	p, err = e.SessionSummaries(1, 20, SessionSummaryFilter{From: "2026-10-18T00:00:00Z", To: "2026-10-18T00:00:00.000000001Z"})
	if err != nil || p.Total != 1 || p.Items[0].SessionID != "z" {
		t.Fatal("nanosecond exclusion", p, err)
	}
}

func TestSessionSummariesSortAndFailure(t *testing.T) {
	e := summaryEngine(t)
	stamp := summaryTime(t, "2026-10-18T00:00:00Z")
	for _, id := range []string{"a", "b"} {
		if err := e.put("reviews", id, Review{ID: id, SessionID: id, CreatedAt: stamp}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := e.SessionSummaries(0, 101, SessionSummaryFilter{})
	if err != nil || p.Page != 1 || p.PageSize != 100 || p.Items[0].SessionID != "b" {
		t.Fatal("clamp/order", p, err)
	}
	p, err = e.SessionSummaries(0, 0, SessionSummaryFilter{})
	if err != nil || p.PageSize != 20 {
		t.Fatal("default", err)
	}
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SessionSummaries(1, 20, SessionSummaryFilter{}); err == nil {
		t.Fatal("closed store succeeded")
	}
}

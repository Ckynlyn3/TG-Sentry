package core

import (
	"aegishook/internal/core/discovery"
	"aegishook/internal/teststore"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryFreshness(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		policy *DiscoveryPolicy
		stamp  time.Time
		want   string
	}{
		{"absent", nil, now, "not_scanned"},
		{"disabled", &DiscoveryPolicy{Enabled: false, IntervalSeconds: 60}, now, "not_scanned"},
		{"zero interval", &DiscoveryPolicy{Enabled: true}, now, "not_scanned"},
		{"no successful scan", &DiscoveryPolicy{Enabled: true, IntervalSeconds: 60}, time.Time{}, "not_scanned"},
		{"inside", &DiscoveryPolicy{Enabled: true, IntervalSeconds: 60}, now.Add(-59 * time.Second), "fresh"},
		{"exact boundary", &DiscoveryPolicy{Enabled: true, IntervalSeconds: 60}, now.Add(-60 * time.Second), "fresh"},
		{"outside", &DiscoveryPolicy{Enabled: true, IntervalSeconds: 60}, now.Add(-60*time.Second - time.Nanosecond), "stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoveryFreshness(now, tc.stamp, tc.policy); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestDiscoveryReadRetainedFailureAndEffectiveTime(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	publishProtection(t, e, discoveryChange(t, true, 60))
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	original := report.ScanCompletedAt
	report.ScanCompletedAt = report.ScanCompletedAt.Add(time.Second)
	category := &report.Accounts[0].Agents[0].Categories[0]
	category.ScanState, category.Reason, category.Assets = discovery.ScanError, discovery.ReasonUnreadable, nil
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	e.clock = func() time.Time { return original.Add(61 * time.Second) }
	agents, err := e.DiscoveredAgents(0, "", DiscoveryFilter{})
	if err != nil || len(agents.Items) != 1 {
		t.Fatal(agents, err)
	}
	c := agents.Items[0].Categories[0]
	if c.ScanState != discovery.ScanError || c.Reason != discovery.ReasonUnreadable || c.Freshness != "stale" || !c.LastScanCompletedAt.Equal(original) {
		t.Fatal(c)
	}
	assets, err := e.AgentAssets(0, "", DiscoveryFilter{})
	if err != nil || len(assets.Items) != 1 {
		t.Fatal(assets, err)
	}
	a := assets.Items[0]
	if a.ScanState != discovery.ScanError || a.Reason != discovery.ReasonUnreadable || a.Freshness != "stale" || !a.ScanCompletedAt.Equal(original) {
		t.Fatal(a)
	}
	// Future raw node watermarks must not make inventory fresh beyond receipt.
	report.ScanCompletedAt = original.Add(time.Hour)
	category.ScanState, category.Reason = discovery.ScanScanned, ""
	received := e.clock()
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	e.clock = func() time.Time { return received.Add(60*time.Second + time.Nanosecond) }
	agents, err = e.DiscoveredAgents(0, "", DiscoveryFilter{})
	if err != nil || agents.Items[0].Freshness != "stale" || !agents.Items[0].ScanCompletedAt.Equal(received) {
		t.Fatal(agents, err)
	}
}

func TestDiscoveryPaginationParity(t *testing.T) {
	e, _, report := discoveryStoreFixture(t)
	stamp := report.ScanCompletedAt
	for i := 0; i < 105; i++ {
		id := fmt.Sprintf("%064x", i)
		agent := DiscoveredAgent{ID: id, NodeID: "node", AccountID: "1000", Family: "claude", State: "present", Found: discovery.Found, ScanCompletedAt: stamp, Categories: []DiscoveredCategory{{Category: discovery.Category{Category: "skills", Scope: discovery.ScopeHome, ScanState: discovery.ScanScanned}, LastScanCompletedAt: stamp}}}
		asset := AgentAsset{Asset: discovery.Asset{AssetID: id, Name: id, Category: "skills"}, DiscoveredAgentID: id, NodeID: "node", AccountID: "1000", Family: "claude", Scope: discovery.ScopeHome, ScanCompletedAt: stamp}
		if err := e.put("discovered_agents", id, agent); err != nil {
			t.Fatal(err)
		}
		if err := e.put("agent_assets", id, asset); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{0, 20, 100, 101} {
		want := size
		if want == 0 {
			want = 20
		}
		if want > 100 {
			want = 100
		}
		agents, err := e.DiscoveredAgents(size, "", DiscoveryFilter{})
		if err != nil || len(agents.Items) != want || len(agents.NextPageToken) != 64 {
			t.Fatal(size, agents, err)
		}
		assets, err := e.AgentAssets(size, "", DiscoveryFilter{})
		if err != nil || len(assets.Items) != want || len(assets.NextPageToken) != 64 {
			t.Fatal(size, assets, err)
		}
	}
	agents, err := e.DiscoveredAgents(20, "", DiscoveryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.DiscoveredAgents(100, agents.NextPageToken, DiscoveryFilter{})
	if err != nil || len(next.Items) != 85 || next.NextPageToken != "" || next.Items[0].ID == agents.Items[0].ID {
		t.Fatal(next, err)
	}
	assets, err := e.AgentAssets(20, "", DiscoveryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	more, err := e.AgentAssets(100, assets.NextPageToken, DiscoveryFilter{})
	if err != nil || len(more.Items) != 85 || more.NextPageToken != "" {
		t.Fatal(more, err)
	}
	for _, tc := range []struct {
		size   int
		token  string
		filter DiscoveryFilter
	}{
		{-1, "", DiscoveryFilter{}}, {1, "invalid", DiscoveryFilter{}},
		{1, agents.NextPageToken, DiscoveryFilter{Node: "different"}},
	} {
		if _, err := e.DiscoveredAgents(tc.size, tc.token, tc.filter); !errors.Is(err, ErrDiscoveryQuery) {
			t.Fatal(err)
		}
	}
	if _, err := e.AgentAssets(1, agents.NextPageToken, DiscoveryFilter{}); !errors.Is(err, ErrDiscoveryQuery) {
		t.Fatal("cross-resource token", err)
	}
	if _, err := e.AgentAsset("unknown"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
}

func TestDiscoveryReadFiltersScopesAndPolicy(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	publishProtection(t, e, discoveryChange(t, true, 60))
	agent := &report.Accounts[0].Agents[0]
	agent.Categories = append(agent.Categories,
		discovery.Category{Category: "skills", Scope: discovery.ScopeProject, ScanState: discovery.ScanNotScanned, Reason: discovery.ReasonProjectScopeDeferred},
		discovery.Category{Category: "memory", Scope: discovery.ScopeHome, ScanState: discovery.ScanError, Reason: discovery.ReasonUnreadable},
		discovery.Category{Category: "builtin_tools", Scope: discovery.ScopeHome, ScanState: discovery.ScanNotSupported},
		discovery.Category{Category: "plugins", Scope: discovery.ScopeHome, ScanState: discovery.ScanUnknown})
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	id, err := discovery.DiscoveredAgentID(node, "1000", "claude")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		filter                     DiscoveryFilter
		agents, categories, assets int
	}{
		{DiscoveryFilter{}, 1, 5, 1},
		{DiscoveryFilter{Node: node, Account: "1000", Agent: id, Category: "skills", State: "scanned"}, 1, 1, 1},
		{DiscoveryFilter{Category: "skills"}, 1, 2, 1},
		{DiscoveryFilter{State: "not_scanned"}, 1, 1, 0},
		{DiscoveryFilter{State: "error"}, 1, 1, 0},
		{DiscoveryFilter{State: "not_supported"}, 1, 1, 0},
		{DiscoveryFilter{State: "unknown"}, 1, 1, 0},
		{DiscoveryFilter{Category: "memory", State: "scanned"}, 0, 0, 0},
		{DiscoveryFilter{Node: "other"}, 0, 0, 0},
		{DiscoveryFilter{Account: "other"}, 0, 0, 0},
		{DiscoveryFilter{Agent: "claude"}, 0, 0, 0},
	} {
		page, err := e.DiscoveredAgents(0, "", tc.filter)
		if err != nil || len(page.Items) != tc.agents {
			t.Fatal(tc, page, err)
		}
		if tc.agents > 0 && len(page.Items[0].Categories) != tc.categories {
			t.Fatal(tc, page)
		}
		assets, err := e.AgentAssets(0, "", tc.filter)
		if err != nil || len(assets.Items) != tc.assets {
			t.Fatal(tc, assets, err)
		}
	}
	page, err := e.DiscoveredAgents(0, "", DiscoveryFilter{})
	if err != nil || page.Items[0].Freshness != "fresh" {
		t.Fatal(page, err)
	}
	for _, c := range page.Items[0].Categories {
		want := "not_scanned"
		if c.ScanState == discovery.ScanScanned {
			want = "fresh"
		}
		if c.Freshness != want {
			t.Fatal(c)
		}
	}
	assetID := agent.Categories[0].Assets[0].AssetID
	asset, err := e.AgentAsset(assetID)
	if err != nil || asset.Freshness != "fresh" || asset.DiscoveredAgentID != id || asset.SourceRelPath == nil {
		t.Fatal(asset, err)
	}
	for _, f := range []DiscoveryFilter{{Category: "invalid"}, {State: "stale"}} {
		if _, err := e.DiscoveredAgents(0, "", f); !errors.Is(err, ErrDiscoveryQuery) {
			t.Fatal(err)
		}
		if _, err := e.AgentAssets(0, "", f); !errors.Is(err, ErrDiscoveryQuery) {
			t.Fatal(err)
		}
	}
	// These reads must observe a policy change without rewriting inventory.
	before := discoverySnapshot(t, e)
	for _, policy := range []DiscoveryPolicy{{Enabled: false, IntervalSeconds: 60}, {Enabled: true}} {
		publishProtection(t, e, discoveryChange(t, policy.Enabled, policy.IntervalSeconds))
		assets, err := e.AgentAssets(0, "", DiscoveryFilter{})
		if err != nil || assets.Items[0].Freshness != "not_scanned" {
			t.Fatal(assets, err)
		}
	}
	if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
		t.Fatal("GET mutated inventory")
	}
}

func TestDiscoveryReadTenantIsolation(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	publishProtection(t, e, discoveryChange(t, true, 60))
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	db := teststore.Admin(t, e.DB)
	for key, payload := range discoverySnapshot(t, e) {
		parts := strings.SplitN(key, "/", 2)
		var value map[string]any
		if err := json.Unmarshal([]byte(payload), &value); err != nil {
			t.Fatal(err)
		}
		value["nodeId"] = "FOREIGN_NODE"
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('other',$1,$2,$3)", parts[0], parts[1], string(b)); err != nil {
			t.Fatal(err)
		}
	}
	// A foreign-only asset and cursor cannot bypass tenant membership. The foreign
	// policy and same-ID agent rows must not influence freshness or category state.
	for _, row := range []struct{ kind, id, payload string }{
		{"agent_assets", "foreign-only", `{"assetId":"foreign-only","nodeId":"FOREIGN_NODE"}`},
		{"protection", "current", `{"discovery":{"enabled":false,"intervalSeconds":0}}`},
	} {
		if _, err := db.Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('other',$1,$2,$3)", row.kind, row.id, row.payload); err != nil {
			t.Fatal(err)
		}
	}
	agents, err := e.DiscoveredAgents(0, "", DiscoveryFilter{})
	if err != nil || len(agents.Items) != 1 || agents.Items[0].NodeID != node || agents.Items[0].Freshness != "fresh" {
		t.Fatal(agents, err)
	}
	assets, err := e.AgentAssets(0, "", DiscoveryFilter{})
	if err != nil || len(assets.Items) != 1 || assets.Items[0].NodeID != node || assets.Items[0].Freshness != "fresh" {
		t.Fatal(assets, err)
	}
	if _, err := e.AgentAsset("foreign-only"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	token := discoveryToken("agent_assets", "foreign-only", DiscoveryFilter{})
	if _, err := e.AgentAssets(1, token, DiscoveryFilter{}); !errors.Is(err, ErrDiscoveryQuery) {
		t.Fatal(err)
	}
}

func TestDiscoveryReadStorageFailures(t *testing.T) {
	for _, kind := range []string{"discovered_agents", "agent_assets", "protection"} {
		t.Run(kind, func(t *testing.T) {
			e, _, _ := discoveryStoreFixture(t)
			if err := e.put(kind, "current", []string{"invalid object"}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.DiscoveredAgents(0, "", DiscoveryFilter{}); err == nil {
				t.Fatal("bad record accepted")
			}
			if _, err := e.AgentAssets(0, "", DiscoveryFilter{}); err == nil {
				t.Fatal("bad record accepted")
			}
			if _, err := e.AgentAsset("any"); err == nil {
				t.Fatal("bad record accepted")
			}
		})
	}
	e, _, _ := discoveryStoreFixture(t)
	empty, err := e.DiscoveredAgents(0, "", DiscoveryFilter{})
	if err != nil || empty.Items == nil || len(empty.Items) != 0 {
		t.Fatal(empty, err)
	}
	if err := e.put("agent_assets", "orphan", AgentAsset{Asset: discovery.Asset{AssetID: "orphan"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AgentAssets(0, "", DiscoveryFilter{}); err == nil {
		t.Fatal("orphan category accepted")
	}
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DiscoveredAgents(0, "", DiscoveryFilter{}); err == nil {
		t.Fatal("closed database accepted")
	}
	if _, err := e.AgentAssets(0, "", DiscoveryFilter{}); err == nil {
		t.Fatal("closed database accepted")
	}
}

func TestDiscoveryReadUsesCurrentProtectionSingleton(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	publishProtection(t, e, discoveryChange(t, true, 60))
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	// Protection() reads protection/current, not arbitrary records of that kind.
	if err := e.put("protection", "not-current", ProtectionState{Discovery: &DiscoveryPolicy{}}); err != nil {
		t.Fatal(err)
	}
	page, err := e.DiscoveredAgents(0, "", DiscoveryFilter{})
	if err != nil || page.Items[0].Freshness != "fresh" {
		t.Fatal(page, err)
	}
}

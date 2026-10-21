package core

import (
	"aegishook/internal/core/discovery"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func discoveryStoreFixture(t *testing.T) (*Engine, string, discovery.Report) {
	t.Helper()
	e, err := Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	key, err := e.CreateEnrollment(context.Background(), "discovery")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	asset := discovery.Asset{Name: "example", Category: "skills", SourceRelPath: ".claude/skills/example/SKILL.md", Hash: "digest", HashKind: discovery.FileSHA256}
	asset.AssetID, err = discovery.AssetID(conn.NodeID, "1000", "claude", asset.Category, asset.SourceRelPath, asset.Name)
	if err != nil {
		t.Fatal(err)
	}
	report := discovery.Report{SchemaVersion: discovery.SchemaVersion, NodeID: conn.NodeID, Scope: discovery.AllLocalAccounts, Mode: "full", Final: true, ScanStartedAt: now.Add(-time.Minute), ScanCompletedAt: now.Add(-time.Second), Accounts: []discovery.Account{{AccountID: "1000", ObservedLocalAccount: "user", HomePath: "/home/user", HomeState: discovery.HomeReadable, Agents: []discovery.Agent{{Family: "claude", Found: discovery.Found, Version: "unknown", Evidence: discovery.Evidence{Kind: "config_file", RelPath: ".claude.json"}, Categories: []discovery.Category{{Category: "skills", Scope: discovery.ScopeHome, ScanState: discovery.ScanScanned, Assets: []discovery.Asset{asset}}}}}}}}
	return e, conn.NodeID, report
}

func discoverySnapshot(t *testing.T, e *Engine) map[string]string {
	t.Helper()
	tx, err := e.beginTenant()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT kind,id,payload FROM records WHERE tenant_id=$1 AND kind IN ('discovered_agents','agent_assets','discovery_node_state') ORDER BY kind,id", eventTenant())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var kind, id, payload string
		if err := rows.Scan(&kind, &id, &payload); err != nil {
			t.Fatal(err)
		}
		out[kind+"/"+id] = payload
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func discoveryNext(t *testing.T, report discovery.Report) discovery.Report {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var next discovery.Report
	if err := json.Unmarshal(data, &next); err != nil {
		t.Fatal(err)
	}
	next.ScanCompletedAt = next.ScanCompletedAt.Add(time.Millisecond)
	return next
}

func TestDiscoveryStoreIngestAndReplay(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	assets, err := list[AgentAsset](e, "agent_assets")
	if err != nil || len(assets) != 1 || assets[0].NodeID != node || assets[0].Scope != discovery.ScopeHome {
		t.Fatalf("assets=%+v err=%v", assets, err)
	}
	agents, err := list[DiscoveredAgent](e, "discovered_agents")
	agentID, idErr := discovery.DiscoveredAgentID(node, "1000", "claude")
	if err != nil || idErr != nil || len(agents) != 1 || agents[0].ID != agentID || agents[0].State != "present" {
		t.Fatalf("agents=%+v err=%v", agents, err)
	}
	before := discoverySnapshot(t, e)
	for _, completion := range []time.Time{report.ScanCompletedAt, report.ScanCompletedAt.Add(-time.Second)} {
		stale := discoveryNext(t, report)
		stale.ScanCompletedAt = completion
		stale.Accounts[0].Agents[0].Categories[0].Assets = nil
		if err := e.IngestDiscoveryReport(context.Background(), node, stale); !errors.Is(err, ErrStaleDiscoveryReport) {
			t.Fatalf("stale: %v", err)
		}
		if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
			t.Fatal("stale report changed inventory")
		}
	}
}

func TestDiscoveryStorePreservesIncompleteScopes(t *testing.T) {
	for _, state := range []discovery.ScanState{discovery.ScanNotSupported, discovery.ScanNotScanned, discovery.ScanError, discovery.ScanUnknown} {
		t.Run(string(state), func(t *testing.T) {
			e, node, report := discoveryStoreFixture(t)
			// An existing project-scope asset must not be erased by a home-only scan.
			project := report.Accounts[0].Agents[0].Categories[0]
			project.Scope = discovery.ScopeProject
			project.Assets = append([]discovery.Asset(nil), project.Assets...)
			project.Assets[0].SourceRelPath = "project/SKILL.md"
			var idErr error
			project.Assets[0].AssetID, idErr = discovery.AssetID(node, "1000", "claude", "skills", "project/SKILL.md", "example")
			if idErr != nil {
				t.Fatal(idErr)
			}
			report.Accounts[0].Agents[0].Categories = append(report.Accounts[0].Agents[0].Categories, project)
			if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
				t.Fatal(err)
			}
			next := discoveryNext(t, report)
			next.Accounts[0].Agents[0].Categories[0].ScanState = state
			next.Accounts[0].Agents[0].Categories[0].Reason = discovery.ReasonUnreadable
			next.Accounts[0].Agents[0].Categories[0].Assets = nil
			next.Accounts[0].Agents[0].Categories[1] = discovery.Category{Category: "skills", Scope: discovery.ScopeProject, ScanState: discovery.ScanNotScanned, Reason: discovery.ReasonProjectScopeDeferred}
			if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
				t.Fatal(err)
			}
			assets, err := list[AgentAsset](e, "agent_assets")
			if err != nil || len(assets) != 2 {
				t.Fatalf("incomplete scope erased assets: %+v %v", assets, err)
			}
			// Completing home now deletes home only, never deferred project.
			next = discoveryNext(t, next)
			next.Accounts[0].Agents[0].Categories[0].ScanState = discovery.ScanScanned
			next.Accounts[0].Agents[0].Categories[0].Reason = ""
			if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
				t.Fatal(err)
			}
			assets, err = list[AgentAsset](e, "agent_assets")
			if err != nil || len(assets) != 1 || assets[0].Scope != discovery.ScopeProject {
				t.Fatalf("scope isolation: %+v %v", assets, err)
			}
		})
	}
}

func TestDiscoveryStoreRemovalAndUnreadableHomes(t *testing.T) {
	for _, home := range []discovery.HomeState{discovery.HomeReadable, discovery.HomeDenied, discovery.HomeUnavailable} {
		t.Run(string(home), func(t *testing.T) {
			e, node, report := discoveryStoreFixture(t)
			if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
				t.Fatal(err)
			}
			before := discoverySnapshot(t, e)
			next := discoveryNext(t, report)
			next.Accounts[0].HomeState = home
			agent := &next.Accounts[0].Agents[0]
			agent.Found = discovery.NotFound
			agent.Evidence = discovery.Evidence{}
			agent.Categories[0].Assets = nil
			if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
				t.Fatal(err)
			}
			agents, err := list[DiscoveredAgent](e, "discovered_agents")
			if err != nil {
				t.Fatal(err)
			}
			assets, err := list[AgentAsset](e, "agent_assets")
			if err != nil {
				t.Fatal(err)
			}
			if home == discovery.HomeReadable {
				if len(assets) != 0 || agents[0].State != "absent" {
					t.Fatal("confirmed absence not applied")
				}
			} else {
				after := discoverySnapshot(t, e)
				delete(before, "discovery_node_state/"+node)
				delete(after, "discovery_node_state/"+node)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("unreadable home changed inventory")
				}
			}
		})
	}
}

func TestDiscoveryStoreRejectsInvalidIdentityAndReport(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*discovery.Report)
	}{
		{"wrong node", func(r *discovery.Report) { r.NodeID = "other" }},
		{"unknown schema", func(r *discovery.Report) { r.SchemaVersion = "discovery/v2" }},
		{"not final", func(r *discovery.Report) { r.Final = false }},
		{"zero completion", func(r *discovery.Report) { r.ScanCompletedAt = time.Time{} }},
		{"reversed times", func(r *discovery.Report) { r.ScanStartedAt = r.ScanCompletedAt.Add(time.Second) }},
		{"duplicate account", func(r *discovery.Report) { r.Accounts = append(r.Accounts, r.Accounts[0]); r.Accounts[1].Agents = nil }},
		{"duplicate family", func(r *discovery.Report) {
			r.Accounts[0].Agents = append(r.Accounts[0].Agents, r.Accounts[0].Agents[0])
			r.Accounts[0].Agents[1].Categories = nil
		}},
		{"spoofed asset", func(r *discovery.Report) { r.Accounts[0].Agents[0].Categories[0].Assets[0].AssetID = "other" }},
		{"wrong category", func(r *discovery.Report) { r.Accounts[0].Agents[0].Categories[0].Assets[0].Category = "memory" }},
		{"contradictory absence", func(r *discovery.Report) { r.Accounts[0].Agents[0].Found = discovery.NotFound }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, node, report := discoveryStoreFixture(t)
			if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
				t.Fatal(err)
			}
			before := discoverySnapshot(t, e)
			next := discoveryNext(t, report)
			tc.mutate(&next)
			if err := e.IngestDiscoveryReport(context.Background(), node, next); err == nil {
				t.Fatal("invalid report accepted")
			}
			if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
				t.Fatal("invalid report changed inventory")
			}
		})
	}
}

func TestDiscoveryStoreFutureTimeAndReplay(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	report.ScanCompletedAt = e.clock().Add(time.Hour)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	assets, err := list[AgentAsset](e, "agent_assets")
	if err != nil || len(assets) != 1 || !assets[0].ScanCompletedAt.Equal(e.clock()) {
		t.Fatalf("future timestamp not clamped: %+v %v", assets, err)
	}
	var state DiscoveryNodeState
	if err := e.get("discovery_node_state", node, &state); err != nil || !state.ReceivedAt.Equal(e.clock()) {
		t.Fatalf("receipt time: %+v %v", state, err)
	}
	before := discoverySnapshot(t, e)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); !errors.Is(err, ErrStaleDiscoveryReport) {
		t.Fatalf("future replay accepted: %v", err)
	}
	if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
		t.Fatal("future replay changed inventory")
	}
}

func TestDiscoveryStoreRollback(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	before := discoverySnapshot(t, e)
	// Reject the last write, after asset replacement and agent updates.
	query := `CREATE TRIGGER reject_discovery BEFORE INSERT ON records WHEN NEW.kind='discovery_node_state' BEGIN SELECT RAISE(ABORT,'injected discovery failure'); END;`
	if e.postgres {
		query = `CREATE FUNCTION reject_discovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected discovery failure'; END $$; CREATE TRIGGER reject_discovery BEFORE INSERT ON records FOR EACH ROW WHEN (NEW.kind='discovery_node_state') EXECUTE FUNCTION reject_discovery();`
	}
	if _, err := teststore.Admin(t, e.DB).Exec(query); err != nil {
		t.Fatal(err)
	}
	next := discoveryNext(t, report)
	next.Accounts[0].Agents[0].Categories[0].Assets = nil
	if err := e.IngestDiscoveryReport(context.Background(), node, next); err == nil {
		t.Fatal("injected transaction committed")
	}
	if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
		t.Fatal("rollback lost prior inventory")
	}
}

func TestDiscoveryStoreTenantIsolation(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	// Same logical IDs and matching scope predicates in both tenants: a missing
	// tenant condition must be observable on reads, replacement and watermark writes.
	foreign := discoverySnapshot(t, e)
	foreign["discovery_node_state/"+node] = `{"lastScanCompletedAt":"2099-01-01T00:00:00Z"}`
	for key, payload := range foreign {
		parts := strings.SplitN(key, "/", 2)
		if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('other',$1,$2,$3)", parts[0], parts[1], payload); err != nil {
			t.Fatal(err)
		}
	}
	next := discoveryNext(t, report)
	next.Accounts[0].Agents[0].Categories[0].Assets = nil
	if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
		t.Fatal(err)
	}
	for key, payload := range foreign {
		parts := strings.SplitN(key, "/", 2)
		var actual string
		if err := teststore.Admin(t, e.DB).QueryRow("SELECT payload FROM records WHERE tenant_id='other' AND kind=$1 AND id=$2", parts[0], parts[1]).Scan(&actual); err != nil || actual != payload {
			t.Fatalf("foreign record changed: %s %v", key, err)
		}
	}
	assets, err := list[AgentAsset](e, "agent_assets")
	if err != nil || len(assets) != 0 {
		t.Fatalf("default tenant replacement failed: %+v %v", assets, err)
	}
}

func TestDiscoveryStoreSharedPoolSerializesReplay(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	// Independent Engine mutexes share the production single-connection pool.
	// This checks serialized replay, not FOR UPDATE contention: store_database.go
	// admits one writer and db.SetMaxOpenConns(1) serializes these transactions.
	other := &Engine{DB: e.DB, postgres: e.postgres, clock: e.clock}
	for _, engine := range []*Engine{e, other} {
		wg.Go(func() { results <- engine.IngestDiscoveryReport(context.Background(), node, report) })
	}
	wg.Wait()
	close(results)
	accepted, replayed := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrStaleDiscoveryReport) {
			replayed++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || replayed != 1 {
		t.Fatalf("accepted=%d replayed=%d", accepted, replayed)
	}
}

func TestDiscoveryStoreAbsencePreservesDeferredScope(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	project := discoveryNext(t, report).Accounts[0].Agents[0].Categories[0]
	project.Scope = discovery.ScopeProject
	project.Assets[0].SourceRelPath = "project/SKILL.md"
	var err error
	project.Assets[0].AssetID, err = discovery.AssetID(node, "1000", "claude", "skills", project.Assets[0].SourceRelPath, project.Assets[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	report.Accounts[0].Agents[0].Categories = append(report.Accounts[0].Agents[0].Categories, project)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	next := discoveryNext(t, report)
	agent := &next.Accounts[0].Agents[0]
	agent.Found = discovery.NotFound
	agent.Evidence = discovery.Evidence{}
	agent.Categories[0].Assets = nil
	agent.Categories[1] = discovery.Category{Category: "skills", Scope: discovery.ScopeProject, ScanState: discovery.ScanNotScanned, Reason: discovery.ReasonProjectScopeDeferred}
	if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
		t.Fatal(err)
	}
	assets, err := list[AgentAsset](e, "agent_assets")
	if err != nil || len(assets) != 1 || assets[0].Scope != discovery.ScopeProject {
		t.Fatalf("absence erased deferred scope: %+v %v", assets, err)
	}
	agents, err := list[DiscoveredAgent](e, "discovered_agents")
	if err != nil || len(agents) != 1 || agents[0].State != "absent" || len(agents[0].Categories) != 2 {
		t.Fatalf("agent state: %+v %v", agents, err)
	}
	if !agents[0].Categories[1].LastScanCompletedAt.Equal(report.ScanCompletedAt) {
		t.Fatal("deferred scope lost last successful time")
	}
}

func TestDiscoveryStoreScopeCollisionPreservesInventory(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	before := discoverySnapshot(t, e)
	next := discoveryNext(t, report)
	next.Accounts[0].Agents[0].Categories[0].Scope = discovery.ScopeProject
	if err := e.IngestDiscoveryReport(context.Background(), node, next); !errors.Is(err, discovery.ErrInvalidReport) {
		t.Fatalf("scope collision accepted: %v", err)
	}
	if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
		t.Fatal("cross-scope ID collision replaced inventory")
	}
}

func TestDiscoveryStoreClientAndCancellation(t *testing.T) {
	for _, kind := range []string{"empty client", "missing client", "revoked", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			e, node, report := discoveryStoreFixture(t)
			if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
				t.Fatal(err)
			}
			before := discoverySnapshot(t, e)
			next := discoveryNext(t, report)
			ctx := context.Background()
			switch kind {
			case "empty client":
				node = ""
			case "missing client":
				node = "not-enrolled"
				next.NodeID = node
			case "revoked":
				if err := e.RevokeClient(ctx, node); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := e.IngestDiscoveryReport(ctx, node, next); err == nil {
				t.Fatal("unavailable client/context accepted")
			}
			if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
				t.Fatal("rejected ingest changed inventory")
			}
		})
	}
}

func TestDiscoveryStoreReplacementIsAccountAndFamilyScoped(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	for _, accountID := range []string{"1000", "1001"} {
		account := discoveryNext(t, report).Accounts[0]
		account.AccountID = accountID
		account.Agents = nil
		for _, family := range []string{"claude", "codex"} {
			agent := discoveryNext(t, report).Accounts[0].Agents[0]
			agent.Family = family
			asset := &agent.Categories[0].Assets[0]
			var err error
			asset.AssetID, err = discovery.AssetID(node, accountID, family, "skills", asset.SourceRelPath, asset.Name)
			if err != nil {
				t.Fatal(err)
			}
			account.Agents = append(account.Agents, agent)
		}
		if accountID == "1000" {
			report.Accounts[0] = account
		} else {
			report.Accounts = append(report.Accounts, account)
		}
	}
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	next := discoveryNext(t, report)
	next.Accounts = next.Accounts[:1]
	next.Accounts[0].Agents = next.Accounts[0].Agents[:1]
	next.Accounts[0].Agents[0].Categories[0].Assets = nil
	if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
		t.Fatal(err)
	}
	assets, err := list[AgentAsset](e, "agent_assets")
	if err != nil || len(assets) != 3 {
		t.Fatalf("replacement escaped account/family: %+v %v", assets, err)
	}
	for _, asset := range assets {
		if asset.AccountID == "1000" && asset.Family == "claude" {
			t.Fatal("completed scope retained old asset")
		}
	}
	agents, err := list[DiscoveredAgent](e, "discovered_agents")
	if err != nil || len(agents) != 4 {
		t.Fatalf("omitted account/family not preserved: %+v %v", agents, err)
	}
}

func TestDiscoveryStoreAuditSuccessAndReplay(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	before, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	after, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("audit count %d want %d", len(after), len(before)+1)
	}
	var audit Audit
	for _, a := range after {
		if a.Action == "discovery.ingest" {
			audit = a
		}
	}
	if audit.Subject != node || audit.Actor.Kind != "device" || audit.Actor.Subject != node || !audit.CreatedAt.Equal(e.clock()) {
		t.Fatalf("missing device-attributed audit: %+v", audit)
	}
	if audit.Detail != "accounts=1 agents=1 assets=1" {
		t.Fatalf("metadata counts: %q", audit.Detail)
	}
	data, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{report.Accounts[0].HomePath, report.Accounts[0].ObservedLocalAccount, report.Accounts[0].Agents[0].Evidence.RelPath, report.Accounts[0].Agents[0].Categories[0].Assets[0].SourceRelPath} {
		if strings.Contains(string(data), secret) {
			t.Fatal("audit contains discovery content")
		}
	}
	snapshot := discoverySnapshot(t, e)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); !errors.Is(err, ErrStaleDiscoveryReport) {
		t.Fatal("replay not rejected", err)
	}
	replayAudits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, replayAudits) || !reflect.DeepEqual(snapshot, discoverySnapshot(t, e)) {
		t.Fatal("replay changed audit or inventory")
	}
}

func TestDiscoveryStoreAuditFailureRollsBack(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	before := discoverySnapshot(t, e)
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(t, e)
	next := discoveryNext(t, report)
	next.Accounts[0].Agents[0].Categories[0].Assets = nil
	if err := e.IngestDiscoveryReport(context.Background(), node, next); err == nil {
		t.Fatal("audit-write failure committed ingest")
	}
	if !reflect.DeepEqual(before, discoverySnapshot(t, e)) {
		t.Fatal("audit failure changed watermark or inventory")
	}
	after, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(audits, after) {
		t.Fatal("audit failure changed audit log")
	}
}

func TestDiscoveryStoreNewerBeforeOlder(t *testing.T) {
	e, node, older := discoveryStoreFixture(t)
	newer := discoveryNext(t, older)
	newer.Accounts[0].Agents[0].Categories[0].Assets[0].Hash = "newer-digest"
	if err := e.IngestDiscoveryReport(context.Background(), node, newer); err != nil {
		t.Fatal(err)
	}
	snapshot := discoverySnapshot(t, e)
	if err := e.IngestDiscoveryReport(context.Background(), node, older); !errors.Is(err, ErrStaleDiscoveryReport) {
		t.Fatal("older report not rejected", err)
	}
	if !reflect.DeepEqual(snapshot, discoverySnapshot(t, e)) {
		t.Fatal("older report regressed inventory or effective timestamps")
	}
	var state DiscoveryNodeState
	if err := e.get("discovery_node_state", node, &state); err != nil || !state.LastScanCompletedAt.Equal(newer.ScanCompletedAt) {
		t.Fatalf("watermark regressed: %+v %v", state, err)
	}
}

func TestDiscoveryStoreEmptyFinalReportPreservesInventory(t *testing.T) {
	e, node, report := discoveryStoreFixture(t)
	if err := e.IngestDiscoveryReport(context.Background(), node, report); err != nil {
		t.Fatal(err)
	}
	before := discoverySnapshot(t, e)
	next := discoveryNext(t, report)
	next.Accounts = []discovery.Account{}
	if err := e.IngestDiscoveryReport(context.Background(), node, next); err != nil {
		t.Fatal("valid empty final report rejected", err)
	}
	var state DiscoveryNodeState
	if err := e.get("discovery_node_state", node, &state); err != nil || !state.LastScanCompletedAt.Equal(next.ScanCompletedAt) {
		t.Fatalf("empty report watermark: %+v %v", state, err)
	}
	after := discoverySnapshot(t, e)
	delete(before, "discovery_node_state/"+node)
	delete(after, "discovery_node_state/"+node)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("empty report deleted inventory without scanned scopes")
	}
}

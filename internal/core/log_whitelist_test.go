package core

import (
	"aegishook/internal/teststore"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func whitelistEntry(node string) LogWhitelistEntry {
	return LogWhitelistEntry{Name: "Device recording", Description: "All protected agents on this device", Enabled: true, Subject: LogWhitelistSubject{Kind: "agents", AgentIDs: []string{node}}}
}

func TestLogWhitelistExactDeviceMatching(t *testing.T) {
	for _, tc := range []struct {
		name, kind, node string
		ids              []string
		enabled, want    bool
	}{
		{"exact", "agents", "node", []string{"other", "node"}, true, true},
		{"disabled", "agents", "node", []string{"node"}, false, false},
		{"case differs", "agents", "Node", []string{"node"}, true, false},
		{"whitespace differs", "agents", " node ", []string{"node"}, true, false},
		{"no wildcard", "agents", "node", []string{"*"}, true, false},
		{"no all scope", "all", "node", nil, true, false},
		{"no users yet", "users", "node", []string{"node"}, true, false},
		{"empty node", "agents", "", []string{""}, true, false},
		{"empty collection", "agents", "node", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := LogWhitelistEntry{Enabled: tc.enabled, Subject: LogWhitelistSubject{Kind: tc.kind, AgentIDs: tc.ids}}
			before, _ := json.Marshal(entry)
			if got := entry.MatchesNode(tc.node); got != tc.want {
				t.Fatalf("match=%v want=%v", got, tc.want)
			}
			after, _ := json.Marshal(entry)
			if string(before) != string(after) {
				t.Fatal("matching mutated entry")
			}
		})
	}
}

func TestLogWhitelistAbsentCollectionAndRestart(t *testing.T) {
	for _, payload := range []string{"", `{"revision":0,"templates":[],"policies":[],"tags":{},"definitions":{}}`, `{"logWhitelist":[]}`, `{"logWhitelist":null}`} {
		t.Run(payload, func(t *testing.T) {
			dir := teststore.Dir(t, t.TempDir())
			e := aclOpen(t, dir)
			if payload != "" {
				if err := e.put("protection", "current", json.RawMessage(payload)); err != nil {
					t.Fatal(err)
				}
			}
			before, version := aclState(t, e), e.Config().Version
			aclClose(t, e)
			e = aclOpen(t, dir)
			defer e.Close()
			if got := aclState(t, e); len(got.LogWhitelist) != 0 || !reflect.DeepEqual(got, before) || e.Config().Version != version {
				t.Fatal("absent collection changed on restart", got)
			}
			var raw json.RawMessage
			err := e.get("protection", "current", &raw)
			if payload == "" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("fresh open wrote protection", err)
				}
			} else if err != nil || string(raw) != payload {
				t.Fatal("legacy payload rewritten", err)
			}
		})
	}
}

func TestLogWhitelistValidationAndOwnedInput(t *testing.T) {
	e, node, revoked := protectionFixture(t)
	if err := e.RevokeClient(testActorContext(), revoked); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*LogWhitelistEntry)
		want error
	}{
		{"blank name", func(r *LogWhitelistEntry) { r.Name = " " }, ErrProtectionInvalid},
		{"long name", func(r *LogWhitelistEntry) { r.Name = strings.Repeat("x", 201) }, ErrProtectionInvalid},
		{"all", func(r *LogWhitelistEntry) { r.Subject.Kind = "all" }, ErrProtectionInvalid},
		{"users", func(r *LogWhitelistEntry) { r.Subject.Kind = "users" }, ErrProtectionInvalid},
		{"tags", func(r *LogWhitelistEntry) { r.Subject.Kind = "tags" }, ErrProtectionInvalid},
		{"empty agents", func(r *LogWhitelistEntry) { r.Subject.AgentIDs = nil }, ErrProtectionInvalid},
		{"duplicate agents", func(r *LogWhitelistEntry) { r.Subject.AgentIDs = []string{node, node} }, ErrProtectionInvalid},
		{"unknown node", func(r *LogWhitelistEntry) { r.Subject.AgentIDs = []string{"missing"} }, sql.ErrNoRows},
		{"revoked node", func(r *LogWhitelistEntry) { r.Subject.AgentIDs = []string{revoked} }, ErrProtectionInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := whitelistEntry(node)
			tc.edit(&r)
			before := aclState(t, e)
			if _, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", LogWhitelist: &r}, before.Revision); !errors.Is(err, tc.want) {
				t.Fatalf("validation=%v want=%v", err, tc.want)
			}
			if !reflect.DeepEqual(aclState(t, e), before) {
				t.Fatal("invalid review changed state")
			}
		})
	}
	for _, c := range []ProtectionChange{{Kind: "log-whitelist"}, {Kind: "log-whitelist", Delete: true}, {Kind: "log-whitelist", ID: "missing", Delete: true}} {
		if _, err := e.ReviewProtection(c, aclState(t, e).Revision); err == nil {
			t.Fatal("invalid change accepted", c)
		}
	}
	input := whitelistEntry(node)
	input.ID, input.UpdatedAt = "forged", time.Unix(1, 0)
	state := aclState(t, e)
	if err := e.applyProtection(&state, ProtectionChange{Kind: "log-whitelist", LogWhitelist: &input}); err != nil {
		t.Fatal(err)
	}
	got := state.LogWhitelist[0]
	if got.ID == "" || got.ID == input.ID || got.UpdatedAt.Equal(input.UpdatedAt) || got.UpdatedAt.IsZero() {
		t.Fatal("server identity/timestamp lost", got)
	}
	input.Subject.AgentIDs[0] = "changed"
	if got.Subject.AgentIDs[0] != node {
		t.Fatal("draft aliases input")
	}
}

func TestLogWhitelistReviewImpactAndAcknowledgement(t *testing.T) {
	e, a, b := protectionFixture(t)
	entry := whitelistEntry(a)
	before := aclState(t, e)
	r, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resource != "log-whitelist" || r.ResourceID == "" || len(r.Downgrades) == 0 || !strings.Contains(r.Warning, "recording") || strings.Contains(r.Warning, "weakened") || !reflect.DeepEqual(r.AffectedAgentIDs, []string{a}) || len(r.Bindings) != 1 || r.Bindings[0].AgentID != a || len(r.AffectedPolicyIDs) != 0 {
		t.Fatal("wrong recording impact", r)
	}
	for _, field := range []string{"/name", "/description", "/enabled", "/subject"} {
		if !slices.ContainsFunc(r.Diff, func(d ProtectionDiff) bool { return d.Field == field }) {
			t.Fatal("missing diff", field)
		}
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, before.Revision, false, "log-whitelist", "", false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatal("unacknowledged recording reduction accepted", err)
	}
	s, err := e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "log-whitelist", "", false)
	if err != nil {
		t.Fatal(err)
	}
	entry = s.LogWhitelist[0]
	if _, err = e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", ID: entry.ID, LogWhitelist: &entry}, s.Revision); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("unchanged entry reviewed", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*LogWhitelistEntry)
		ack  bool
	}{
		{"metadata", func(r *LogWhitelistEntry) { r.Name = "renamed" }, false},
		{"disable", func(r *LogWhitelistEntry) { r.Enabled = false }, false},
		{"subject change", func(r *LogWhitelistEntry) { r.Subject.AgentIDs = []string{b} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := entry
			tc.edit(&next)
			r, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", ID: entry.ID, LogWhitelist: &next}, s.Revision)
			if err != nil || (len(r.Downgrades) > 0) != tc.ack {
				t.Fatal("wrong acknowledgement", r, err)
			}
			expected := []string{a, b}
			slices.Sort(expected)
			if tc.ack && !reflect.DeepEqual(r.AffectedAgentIDs, expected) {
				t.Fatal("impact must include before and after subjects", r)
			}
		})
	}
	deleted, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", ID: entry.ID, Delete: true}, s.Revision)
	if err != nil || len(deleted.Downgrades) != 0 {
		t.Fatal("delete incorrectly reduces recording", deleted, err)
	}
}

func TestLogWhitelistConfirmationBindingStaleAndRevocation(t *testing.T) {
	e, node, _ := protectionFixture(t)
	entry := whitelistEntry(node)
	before := aclState(t, e)
	r, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, id string
		deleted  bool
	}{
		{"acl", "", false}, {"log-whitelist", r.ResourceID, false}, {"log-whitelist", "", true},
	} {
		if _, err := e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, tc.kind, tc.id, tc.deleted); !errors.Is(err, ErrProtectionConflict) {
			t.Fatal("mismatched review published", err)
		}
	}
	publishProtection(t, e, ProtectionChange{Kind: "tags", ID: node, Tags: []string{"team"}})
	for _, base := range []int{before.Revision, aclState(t, e).Revision} {
		if _, err := e.ConfirmProtection(testActorContext(), r.ID, base, true, "log-whitelist", "", false); !errors.Is(err, ErrProtectionPrecondition) {
			t.Fatal("stale review published", err)
		}
	}
	r, err = e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry}, aclState(t, e).Revision)
	if err != nil {
		t.Fatal(err)
	}
	before = aclState(t, e)
	if err := e.RevokeClient(testActorContext(), node); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "log-whitelist", "", false); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("revoked node published", err)
	}
	if !reflect.DeepEqual(aclState(t, e), before) {
		t.Fatal("revocation failure changed state")
	}
}

func TestLogWhitelistAuditRollbackAndPersistence(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[failed], func(t *testing.T) {
			dir := teststore.Dir(t, t.TempDir())
			e := aclOpen(t, dir)
			code, err := e.CreateEnrollment(testActorContext(), "device", EnrollmentOptions{Type: "reusable"})
			if err != nil {
				t.Fatal(err)
			}
			node, err := e.EnrollClient(code.Code, "linux")
			if err != nil {
				t.Fatal(err)
			}
			entry := whitelistEntry(node.NodeID)
			before, version := aclState(t, e), e.Config().Version
			versions, err := e.ConfigVersions()
			if err != nil {
				t.Fatal(err)
			}
			r, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry}, before.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if failed {
				rejectAudit(t, e)
			}
			_, err = e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "log-whitelist", "", false)
			if (err != nil) != failed {
				t.Fatal("wrong commit outcome", err)
			}
			state := aclState(t, e)
			if failed {
				gotVersions, err := e.ConfigVersions()
				if err != nil || !reflect.DeepEqual(state, before) || e.Config().Version != version || !reflect.DeepEqual(gotVersions, versions) || len(aclAudits(t, e, "protection.log-whitelist.publish")) != 0 {
					t.Fatal("audit failure did not roll back resource/revisions/snapshots", err)
				}
			} else if state.Revision != before.Revision+1 || e.Config().Version != version+1 || len(state.LogWhitelist) != 1 || len(aclAudits(t, e, "protection.log-whitelist.publish")) != 1 {
				t.Fatal("publication not atomic/versioned", state)
			}
			aclClose(t, e)
			e = aclOpen(t, dir)
			defer e.Close()
			if !reflect.DeepEqual(aclState(t, e), state) {
				t.Fatal("state lost on restart")
			}
			if !failed {
				publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", ID: r.ResourceID, Delete: true})
				if len(aclState(t, e).LogWhitelist) != 0 {
					t.Fatal("delete retained entry")
				}
			}
		})
	}
}

func TestLogWhitelistDisabledEnableAndRevokedDelete(t *testing.T) {
	e, node, _ := protectionFixture(t)
	entry := whitelistEntry(node)
	entry.Enabled = false
	r, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry}, aclState(t, e).Revision)
	if err != nil || len(r.Downgrades) != 0 || len(r.AffectedAgentIDs) != 0 {
		t.Fatal("disabled creation affects recording", r, err)
	}
	s, err := e.ConfirmProtection(testActorContext(), r.ID, r.BaseRevision, false, "log-whitelist", "", false)
	if err != nil {
		t.Fatal(err)
	}
	entry = s.LogWhitelist[0]
	entry.Enabled = true
	r, err = e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", ID: entry.ID, LogWhitelist: &entry}, s.Revision)
	if err != nil || len(r.Downgrades) == 0 || !reflect.DeepEqual(r.AffectedAgentIDs, []string{node}) {
		t.Fatal("enabling needs acknowledgement", r, err)
	}
	if _, err := e.ConfirmProtection(testActorContext(), r.ID, r.BaseRevision, false, "log-whitelist", entry.ID, false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatal("enabled without acknowledgement", err)
	}
	publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", ID: entry.ID, LogWhitelist: &entry})
	if err := e.RevokeClient(testActorContext(), node); err != nil {
		t.Fatal(err)
	}
	// Deleting a stale entry must remain possible after its device is revoked.
	s = publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", ID: entry.ID, Delete: true})
	if len(s.LogWhitelist) != 0 {
		t.Fatal("revoked entry could not be removed")
	}
}

func TestLogWhitelistMutationAuditFailureRollback(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "delete"}[deleted], func(t *testing.T) {
			e, node, _ := protectionFixture(t)
			entry := whitelistEntry(node)
			publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry})
			before, version := aclState(t, e), e.Config().Version
			entry = before.LogWhitelist[0]
			entry.Name = "updated"
			r, err := e.ReviewProtection(ProtectionChange{Kind: "log-whitelist", ID: entry.ID, Delete: deleted, LogWhitelist: &entry}, before.Revision)
			if err != nil {
				t.Fatal(err)
			}
			rejectAudit(t, e)
			if _, err := e.ConfirmProtection(testActorContext(), r.ID, r.BaseRevision, true, "log-whitelist", entry.ID, deleted); err == nil {
				t.Fatal("audit failure accepted")
			}
			if !reflect.DeepEqual(aclState(t, e), before) || e.Config().Version != version || len(aclAudits(t, e, "protection.log-whitelist.publish")) != 1 {
				t.Fatal("failed mutation changed state/version/audit")
			}
		})
	}
}

func TestLogWhitelistSuppressesRecordingWithoutChangingProtection(t *testing.T) {
	e, node, _ := protectionFixture(t)
	if err := e.Register(Instance{ID: node, NodeID: node, Agent: "claude", Platform: "linux", SessionID: node, Cwd: "/project", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	bundleBefore, err := e.ClientPolicyBundle(node)
	if err != nil {
		t.Fatal(err)
	}
	entry := whitelistEntry(node)
	before := aclState(t, e)
	after := publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry})
	if !reflect.DeepEqual(before.ACL, after.ACL) || !reflect.DeepEqual(before.Templates, after.Templates) || !reflect.DeepEqual(before.Policies, after.Policies) || !reflect.DeepEqual(before.Tags, after.Tags) || !reflect.DeepEqual(before.Definitions, after.Definitions) {
		t.Fatal("whitelist altered protection configuration")
	}
	bundleAfter, err := e.ClientPolicyBundle(node)
	if err != nil {
		t.Fatal(err)
	}
	var oldPolicy, newPolicy PolicyBundle
	if err := json.Unmarshal(bundleBefore.Payload, &oldPolicy); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bundleAfter.Payload, &newPolicy); err != nil || !reflect.DeepEqual(oldPolicy.Rules, newPolicy.Rules) || bytes.Contains(bundleAfter.Payload, []byte("logWhitelist")) || bytes.Contains(bundleAfter.Payload, []byte(entry.Name)) {
		t.Fatal("whitelist altered distributed protection or leaked entries", err)
	}
	for _, tc := range []struct {
		tool, command, want string
	}{
		{"Read", "fixture", "approve"},
		{"Bash", "passwd fixture", "reject"},
	} {
		in := ReviewInput{InstanceID: node, CallID: ID(), ToolName: tc.tool, Arguments: map[string]any{"command": tc.command}}
		r, err := e.Submit(in)
		if err != nil || r.Decision != tc.want {
			t.Fatal("whitelist changed authorization", r, err)
		}
		stored, err := e.Review(r.ID)
		if err != nil || stored.Decision != tc.want || stored.Arguments != nil || stored.InputState != ContentPolicyOmitted || stored.LogSuppression == nil {
			t.Fatal("whitelist did not persist content-free decision state", stored, err)
		}
		if stored.LogSuppression.Revision != after.Revision || !reflect.DeepEqual(stored.LogSuppression.EntryIDs, []string{after.LogWhitelist[0].ID}) {
			t.Fatal("whitelist suppression provenance changed", stored.LogSuppression)
		}
		audits := aclAudits(t, e, "review.submit")
		wantCarriers := 0
		if tc.want == "reject" {
			wantCarriers = 1
		}
		if len(audits) != wantCarriers {
			t.Fatal("whitelist lost risk carrier or retained routine audit", len(audits), wantCarriers)
		}
		for _, audit := range audits {
			if audit.Subject != r.ID || audit.Detail != "" || len(audit.Events) != 1 || audit.Events[0].Type != "tg.sentry.risk.v1" {
				t.Fatal("whitelist retained conversational audit or lost risk finding", audit)
			}
		}
	}
}

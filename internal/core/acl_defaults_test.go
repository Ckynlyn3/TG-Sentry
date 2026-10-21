package core

import (
	"aegishook/internal/teststore"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func aclState(t *testing.T, e *Engine) ProtectionState {
	t.Helper()
	s, err := e.Protection()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func aclAudits(t *testing.T, e *Engine, action string) []Audit {
	t.Helper()
	all, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	out := []Audit{}
	for _, a := range all {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}
func aclOpen(t *testing.T, dir string) *Engine {
	t.Helper()
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func aclClose(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// S2b owns ACL review diff/impact. Exercise S2a aggregate writes with the
// existing audited transaction rather than duplicating review production.
func aclPublish(t *testing.T, e *Engine, c ProtectionChange) ProtectionState {
	t.Helper()
	s := aclState(t, e)
	if err := e.applyProtection(&s, c); err != nil {
		t.Fatal(err)
	}
	s.Revision++
	if err := e.change(testActorContext(), "protection", "current", s, "protection.acl.publish", "ACL fixture publication"); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestACLDefaultVirtualFreshAndLegacy(t *testing.T) {
	for _, payload := range []string{"", `{"revision":0,"templates":[],"policies":[],"tags":{},"definitions":{}}`, `{"acl":{"initialized":false,"rules":[]}}`} {
		t.Run(payload, func(t *testing.T) {
			dir := teststore.Dir(t, t.TempDir())
			e := aclOpen(t, dir)
			if payload != "" {
				if err := e.put("protection", "current", json.RawMessage(payload)); err != nil {
					t.Fatal(err)
				}
			}
			before := aclState(t, e)
			config := e.Config()
			versions, err := e.ConfigVersions()
			if err != nil {
				t.Fatal(err)
			}
			audits, err := e.Audits()
			if err != nil {
				t.Fatal(err)
			}
			aclClose(t, e)
			e = aclOpen(t, dir)
			defer e.Close()
			s := aclState(t, e)
			if s.ACL.Initialized || len(s.ACL.Rules) != 0 {
				t.Fatal("Open persisted virtual ACL", s.ACL)
			}
			rules := s.EffectiveACLRules()
			if len(rules) != 1 || rules[0].ID != "acl-default-all-pass" || !rules[0].Enabled || rules[0].Subject.Kind != "all" || rules[0].Effect != "allow" || rules[0].Target.Kind != "all" {
				t.Fatal("missing virtual default", rules)
			}
			if got := EvaluateACL(rules, "future-agent", nil, "future-tool"); got != (ACLDecision{Effect: "allow", RuleID: "acl-default-all-pass"}) {
				t.Fatal("virtual default denied", got)
			}
			// Each call owns its returned virtual rule, not a mutable global default.
			rules[0].Effect = "deny"
			if s.EffectiveACLRules()[0].Effect != "allow" {
				t.Fatal("virtual default aliases caller")
			}
			gotVersions, err := e.ConfigVersions()
			if err != nil {
				t.Fatal(err)
			}
			gotAudits, err := e.Audits()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s, before) || !reflect.DeepEqual(e.Config(), config) || !reflect.DeepEqual(gotVersions, versions) || !reflect.DeepEqual(gotAudits, audits) {
				t.Fatal("Open changed protection/settings/snapshots/audits")
			}
			var raw json.RawMessage
			err = e.get("protection", "current", &raw)
			if payload == "" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("fresh Open wrote protection", err)
				}
			} else if err != nil || string(raw) != payload {
				t.Fatal("Open rewrote legacy aggregate", string(raw), err)
			}
		})
	}
}
func TestACLDefaultFirstEditPersistsAndPreservesProtection(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e := aclOpen(t, dir)
	before := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "preserved", Rules: []TemplateRule{}}})
	before = publishProtection(t, e, ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "preserved", TemplateIDs: []string{before.Templates[0].ID}, Scope: PolicyScope{Type: "all"}}})
	if before.ACL.Initialized || len(before.ACL.Rules) != 0 {
		t.Fatal("unrelated publish materialized virtual rule")
	}
	version := e.Config().Version
	c := ProtectionChange{Kind: "acl", ID: "acl-default-all-pass", ACL: &ACLRule{Name: "edited default", Enabled: true, Subject: ACLSubject{Kind: "all"}, Effect: "allow", Target: ACLTarget{Kind: "tools", Tools: []string{"Read"}}}}
	s := aclPublish(t, e, c)
	if !s.ACL.Initialized || len(s.ACL.Rules) != 1 || s.ACL.Rules[0].ID != c.ID || s.ACL.Rules[0].Name != "edited default" || s.ACL.Rules[0].UpdatedAt.IsZero() || s.Revision != before.Revision+1 || e.Config().Version != version+1 {
		t.Fatal("first edit not materialized/versioned", s)
	}
	if !reflect.DeepEqual(s.Templates, before.Templates) || !reflect.DeepEqual(s.Policies, before.Policies) || !reflect.DeepEqual(s.Tags, before.Tags) || !reflect.DeepEqual(s.Definitions, before.Definitions) {
		t.Fatal("ACL publication changed existing protection")
	}
	if len(aclAudits(t, e, "protection.acl.publish")) != 1 || len(aclAudits(t, e, "protection.acl.initialize")) != 0 {
		t.Fatal("wrong ACL audit actions")
	}
	// Compare persisted values: time.Time JSON omits the monotonic clock reading.
	s = aclState(t, e)
	aclClose(t, e)
	e = aclOpen(t, dir)
	defer e.Close()
	if !reflect.DeepEqual(aclState(t, e), s) || e.Config().Version != version+1 {
		t.Fatal("first publication lost on restart")
	}
	if EvaluateACL(s.EffectiveACLRules(), "node", nil, "Read").Effect != "allow" || EvaluateACL(s.EffectiveACLRules(), "node", nil, "Write").Effect != "deny" {
		t.Fatal("persisted ACL did not replace virtual all-pass")
	}
}
func TestACLDefaultDeleteLastPersistsEmptyAcrossRestart(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e := aclOpen(t, dir)
	version := e.Config().Version
	s := aclPublish(t, e, ProtectionChange{Kind: "acl", ID: "acl-default-all-pass", Delete: true})
	if !s.ACL.Initialized || s.ACL.Rules == nil || len(s.ACL.Rules) != 0 || s.Revision != 1 || e.Config().Version != version+1 {
		t.Fatal("virtual default deletion did not materialize empty", s)
	}
	aclClose(t, e)
	e = aclOpen(t, dir)
	defer e.Close()
	got := aclState(t, e)
	if !reflect.DeepEqual(got, s) || e.Config().Version != version+1 || len(aclAudits(t, e, "protection.acl.publish")) != 1 || EvaluateACL(got.EffectiveACLRules(), "node", nil, "Read") != (ACLDecision{Effect: "deny"}) {
		t.Fatal("empty ACL lost or reseeded after restart")
	}
}
func TestACLDefaultInitializedEmptyNeverFallsBack(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e := aclOpen(t, dir)
	if err := e.put("protection", "current", map[string]any{"revision": 0, "acl": ACLState{Initialized: true, Rules: []ACLRule{}}}); err != nil {
		t.Fatal(err)
	}
	before := aclState(t, e)
	version := e.Config().Version
	rejectAudit(t, e)
	aclClose(t, e)
	e = aclOpen(t, dir)
	defer e.Close()
	s := aclState(t, e)
	if !reflect.DeepEqual(s, before) || e.Config().Version != version || EvaluateACL(s.EffectiveACLRules(), "node", nil, "Read") != (ACLDecision{Effect: "deny"}) {
		t.Fatal("initialized-empty did not remain deny-all")
	}
}
func TestACLDefaultFailedFirstPublishRollsBack(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e := aclOpen(t, dir)
	before := aclState(t, e)
	version := e.Config().Version
	snapshots, err := e.ConfigVersions()
	if err != nil {
		t.Fatal(err)
	}
	draft := aclState(t, e)
	if err := e.applyProtection(&draft, ProtectionChange{Kind: "acl", ID: "acl-default-all-pass", Delete: true}); err != nil {
		t.Fatal(err)
	}
	draft.Revision++
	rejectAudit(t, e)
	if err := e.change(testActorContext(), "protection", "current", draft, "protection.acl.publish", "first ACL publication"); err == nil {
		t.Fatal("audit failure accepted")
	}
	gotSnapshots, err := e.ConfigVersions()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(aclState(t, e), before) || e.Config().Version != version || !reflect.DeepEqual(gotSnapshots, snapshots) || len(aclAudits(t, e, "protection.acl.publish")) != 0 {
		t.Fatal("failed first publication changed flag/rules/revision/version/audit")
	}
	aclClose(t, e)
	e = aclOpen(t, dir)
	defer e.Close()
	s := aclState(t, e)
	if s.ACL.Initialized || !reflect.DeepEqual(s, before) || e.Config().Version != version || EvaluateACL(s.EffectiveACLRules(), "node", nil, "Read").Effect != "allow" {
		t.Fatal("failed first publication materialized on restart")
	}
}

func TestACLAggregateValidation(t *testing.T) {
	e, node, revoked := protectionFixture(t)
	if err := e.RevokeClient(testActorContext(), revoked); err != nil {
		t.Fatal(err)
	}
	valid := ACLRule{Name: "fixture", Enabled: true, Subject: ACLSubject{Kind: "all"}, Effect: "allow", Target: ACLTarget{Kind: "all"}}
	for _, tc := range []struct {
		name string
		edit func(*ACLRule)
	}{
		{"empty name", func(r *ACLRule) { r.Name = " " }},
		{"invalid effect", func(r *ACLRule) { r.Effect = "approve" }},
		{"invalid subject", func(r *ACLRule) { r.Subject.Kind = "users" }},
		{"all with agents", func(r *ACLRule) { r.Subject.AgentIDs = []string{node} }},
		{"all with tags", func(r *ACLRule) { r.Subject.Tags = []string{"team"} }},
		{"empty tags", func(r *ACLRule) { r.Subject = ACLSubject{Kind: "tags"} }},
		{"mixed tags", func(r *ACLRule) {
			r.Subject = ACLSubject{Kind: "tags", Tags: []string{"team"}, AgentIDs: []string{node}}
		}},
		{"duplicate tags", func(r *ACLRule) { r.Subject = ACLSubject{Kind: "tags", Tags: []string{"team", "team"}} }},
		{"empty agents", func(r *ACLRule) { r.Subject = ACLSubject{Kind: "agents"} }},
		{"mixed agents", func(r *ACLRule) {
			r.Subject = ACLSubject{Kind: "agents", AgentIDs: []string{node}, Tags: []string{"team"}}
		}},
		{"duplicate agents", func(r *ACLRule) { r.Subject = ACLSubject{Kind: "agents", AgentIDs: []string{node, node}} }},
		{"unknown agent", func(r *ACLRule) { r.Subject = ACLSubject{Kind: "agents", AgentIDs: []string{"missing"}} }},
		{"revoked agent", func(r *ACLRule) { r.Subject = ACLSubject{Kind: "agents", AgentIDs: []string{revoked}} }},
		{"unknown target", func(r *ACLRule) { r.Target.Kind = "unknown" }},
		{"all with tools", func(r *ACLRule) { r.Target.Tools = []string{"Read"} }},
		{"empty tools", func(r *ACLRule) { r.Target = ACLTarget{Kind: "tools"} }},
		{"blank tool", func(r *ACLRule) { r.Target = ACLTarget{Kind: "tools", Tools: []string{" "}} }},
		{"duplicate tools", func(r *ACLRule) { r.Target = ACLTarget{Kind: "tools", Tools: []string{"Read", "Read"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.edit(&r)
			s := aclState(t, e)
			if err := e.applyProtection(&s, ProtectionChange{Kind: "acl", ACL: &r}); err == nil {
				t.Fatalf("invalid ACL accepted: %+v", r)
			}
		})
	}
	for _, subject := range []ACLSubject{{Kind: "all"}, {Kind: "tags", Tags: []string{"team"}}, {Kind: "agents", AgentIDs: []string{node}}} {
		r := valid
		r.ID = "spoofed"
		r.Subject = subject
		r.Target = ACLTarget{Kind: "tools", Tools: []string{" Read ", "read", "*"}}
		s := aclState(t, e)
		if err := e.applyProtection(&s, ProtectionChange{Kind: "acl", ACL: &r}); err != nil {
			t.Fatal(err)
		}
		got := s.ACL.Rules[len(s.ACL.Rules)-1]
		if got.ID == "" || got.ID == r.ID || got.UpdatedAt.IsZero() || !reflect.DeepEqual(got.Target.Tools, r.Target.Tools) {
			t.Fatalf("lost server ownership or exact tool names: %+v", got)
		}
		r.Target.Tools[0] = "changed"
		if got.Target.Tools[0] != " Read " {
			t.Fatal("draft aliases input tools")
		}
		if len(r.Subject.AgentIDs) > 0 {
			r.Subject.AgentIDs[0] = "changed"
			if got.Subject.AgentIDs[0] != node {
				t.Fatal("draft aliases input agents")
			}
		}
		if len(r.Subject.Tags) > 0 {
			r.Subject.Tags[0] = "changed"
			if got.Subject.Tags[0] != "team" {
				t.Fatal("draft aliases input tags")
			}
		}
	}
	for _, c := range []ProtectionChange{{Kind: "acl"}, {Kind: "acl", ID: "missing", Delete: true}, {Kind: "acl", Delete: true}} {
		s := aclState(t, e)
		if err := e.applyProtection(&s, c); err == nil {
			t.Fatalf("invalid ACL change accepted: %+v", c)
		}
	}
}

func TestACLConfirmationRechecksNodesRevisionAndRollback(t *testing.T) {
	e, node, _ := protectionFixture(t)
	before := aclState(t, e)
	// S2b owns draft review/diff production. Bind a server-side draft directly
	// to exercise S2a's existing confirmation, audit, and CAS boundary.
	stage := func(c ProtectionChange) ProtectionReview {
		t.Helper()
		s := aclState(t, e)
		if err := e.applyProtection(&s, c); err != nil {
			t.Fatal(err)
		}
		r := ProtectionReview{ID: ID(), BaseRevision: s.Revision, Resource: "acl", ResourceID: c.ID, Delete: c.Delete}
		if c.ID == "" {
			r.ResourceID = s.ACL.Rules[len(s.ACL.Rules)-1].ID
		}
		s.Revision++
		if err := e.put("protection_reviews", r.ID, protectionDraft{Review: r, State: s}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	c := ProtectionChange{Kind: "acl", ID: "acl-default-all-pass", ACL: &ACLRule{Name: "agent allow", Enabled: true, Subject: ACLSubject{Kind: "agents", AgentIDs: []string{node}}, Effect: "allow", Target: ACLTarget{Kind: "all"}}}
	r := stage(c)
	if _, err := e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "acl", "", false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("create accepted an update draft: %v", err)
	}
	if err := e.RevokeClient(testActorContext(), node); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "acl", c.ID, false); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatalf("confirmation accepted revoked node: %v", err)
	}
	if !reflect.DeepEqual(aclState(t, e), before) {
		t.Fatal("revoked-node publish mutated aggregate")
	}
	c.ACL.Subject = ACLSubject{Kind: "all"}
	r = stage(c)
	version := e.Config().Version
	s, err := e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "acl", c.ID, false)
	if err != nil || s.Revision != before.Revision+1 || e.Config().Version != version+1 || len(aclAudits(t, e, "protection.acl.publish")) != 1 {
		t.Fatal("ACL confirmation not audited/versioned", err)
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, before.Revision, true, "acl", c.ID, false); !errors.Is(err, ErrProtectionPrecondition) {
		t.Fatalf("stale ACL confirmation accepted: %v", err)
	}
	if _, err = e.ReviewProtection(ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "stale", Rules: []TemplateRule{}}}, before.Revision); !errors.Is(err, ErrProtectionPrecondition) {
		t.Fatalf("ACL publication failed to invalidate aggregate revision: %v", err)
	}
	r = stage(ProtectionChange{Kind: "acl", ACL: c.ACL})
	s, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "acl", "", false)
	if err != nil || len(s.ACL.Rules) != 2 {
		t.Fatal("ACL create confirmation failed", err)
	}
	r = stage(ProtectionChange{Kind: "acl", ID: r.ResourceID, Delete: true})
	s, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "acl", r.ResourceID, true)
	if err != nil || len(s.ACL.Rules) != 1 {
		t.Fatal("ACL delete confirmation failed", err)
	}
	r = stage(ProtectionChange{Kind: "acl", ID: c.ID, Delete: true})
	version = e.Config().Version
	rejectAudit(t, e)
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "acl", c.ID, true); err == nil {
		t.Fatal("ACL audit failure accepted")
	}
	if !reflect.DeepEqual(aclState(t, e), s) || e.Config().Version != version {
		t.Fatal("failed ACL publication changed aggregate/version")
	}
}

package core

import (
	"errors"
	"slices"
	"testing"
)

func TestACLReviewImpactExpansionsRequireAcknowledgement(t *testing.T) {
	deny := ACLRule{ID: "acl-fixture", Name: "Fixture", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "all"}}
	allow := deny
	allow.Effect = "allow"
	disabledDeny, disabledAllow := deny, allow
	disabledDeny.Enabled, disabledAllow.Enabled = false, false
	narrowDeny, narrowAllow := deny, allow
	narrowDeny.Subject, narrowAllow.Subject = ACLSubject{Kind: "tags", Tags: []string{"engineering"}}, ACLSubject{Kind: "tags", Tags: []string{"engineering"}}
	toolDeny, toolAllow := deny, allow
	toolDeny.Target, toolAllow.Target = ACLTarget{Kind: "tools", Tools: []string{"read"}}, ACLTarget{Kind: "tools", Tools: []string{"read"}}
	renamed := deny
	renamed.Name, renamed.Description = "Renamed", "Updated description"
	for _, tc := range []struct {
		name          string
		before, after *ACLRule
		ack           bool
	}{
		{"deny-to-allow", &deny, &allow, true},
		{"disable-deny", &deny, &disabledDeny, true},
		{"delete-deny", &deny, nil, true},
		{"add-allow", nil, &allow, true},
		{"enable-allow", &disabledAllow, &allow, true},
		{"widen-allow-subject", &narrowAllow, &allow, true},
		{"widen-allow-target", &toolAllow, &allow, true},
		{"narrow-deny-subject", &deny, &narrowDeny, true},
		{"narrow-deny-target", &deny, &toolDeny, true},
		{"add-deny", nil, &deny, false},
		{"enable-deny", &disabledDeny, &deny, false},
		{"allow-to-deny", &allow, &deny, false},
		{"disable-allow", &allow, &disabledAllow, false},
		{"delete-allow", &allow, nil, false},
		{"delete-disabled-deny", &disabledDeny, nil, false},
		{"metadata-only", &deny, &renamed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := engine(t)
			s := aclState(t, e)
			s.ACL = ACLState{Initialized: true, Rules: []ACLRule{}}
			if tc.before != nil {
				s.ACL.Rules = append(s.ACL.Rules, *tc.before)
			}
			if err := e.put("protection", "current", s); err != nil {
				t.Fatal(err)
			}
			c := ProtectionChange{Kind: "acl", ACL: tc.after, Delete: tc.after == nil}
			if tc.before != nil {
				c.ID = tc.before.ID
			}
			r, err := e.ReviewProtection(c, s.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Diff) == 0 || (len(r.Downgrades) > 0) != tc.ack || (r.Warning != "") != tc.ack {
				t.Fatalf("incorrect impact surface: %+v", r)
			}
			_, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, false, c.Kind, c.ID, c.Delete)
			if tc.ack {
				if !errors.Is(err, ErrProtectionConflict) {
					t.Fatalf("unacknowledged expansion published: %v", err)
				}
				_, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, c.Kind, c.ID, c.Delete)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestACLReviewDiffAndAffectedAgents(t *testing.T) {
	e, a, b := protectionFixture(t)
	publishProtection(t, e, ProtectionChange{Kind: "tags", ID: a, Tags: []string{"engineering"}})
	s := aclState(t, e)
	r, err := e.ReviewProtection(ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "Team", Description: "Exact tools", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "tags", Tags: []string{"engineering"}}, Target: ACLTarget{Kind: "tools", Tools: []string{"Read"}}}}, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"/name", "/description", "/enabled", "/effect", "/subject", "/target"} {
		if !slices.ContainsFunc(r.Diff, func(d ProtectionDiff) bool { return d.Field == field }) {
			t.Errorf("missing ACL diff %s: %+v", field, r.Diff)
		}
	}
	if len(r.AffectedAgentIDs) != 1 || r.AffectedAgentIDs[0] != a || slices.Contains(r.AffectedAgentIDs, b) || len(r.Bindings) != 1 || r.Bindings[0].AgentID != a {
		t.Fatalf("incorrect ACL affected-agent scope: %+v", r)
	}
	if _, err := e.ConfirmProtection(testActorContext(), r.ID, s.Revision, false, "acl", "", false); err != nil {
		t.Fatal(err)
	}
	s = aclState(t, e)
	id := r.ResourceID
	old := s.ACL.Rules[aclIndex(s, id)]
	old.Target.Tools = []string{"Read", "Write"}
	r, err = e.ReviewProtection(ProtectionChange{Kind: "acl", ID: id, ACL: &old}, s.Revision)
	if err != nil || !slices.ContainsFunc(r.Diff, func(d ProtectionDiff) bool { return d.Field == "/target/tools" }) {
		t.Fatal("nested ACL target diff missing", r, err)
	}
	if _, err := e.ReviewProtection(ProtectionChange{Kind: "acl", ID: id, ACL: &s.ACL.Rules[aclIndex(s, id)]}, s.Revision); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("unchanged ACL accepted", err)
	}
}

func TestACLReviewTagGrantsAndStalePublications(t *testing.T) {
	for _, effect := range []string{"allow", "deny"} {
		t.Run(effect, func(t *testing.T) {
			e, a, _ := protectionFixture(t)
			aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "Tag", Enabled: true, Effect: effect, Subject: ACLSubject{Kind: "tags", Tags: []string{"engineering"}}, Target: ACLTarget{Kind: "all"}}})
			tags := []string{"engineering"}
			if effect == "deny" {
				publishProtection(t, e, ProtectionChange{Kind: "tags", ID: a, Tags: tags})
				tags = []string{}
			}
			s := aclState(t, e)
			r, err := e.ReviewProtection(ProtectionChange{Kind: "tags", ID: a, Tags: tags}, s.Revision)
			if err != nil || len(r.Downgrades) == 0 {
				t.Fatal("ACL tag expansion not acknowledged", r, err)
			}
			if _, err := e.ConfirmProtection(testActorContext(), r.ID, s.Revision, false, "tags", a, false); !errors.Is(err, ErrProtectionConflict) {
				t.Fatal("tag expansion bypassed acknowledgement", err)
			}
			if _, err := e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "tags", a, false); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, intervening := range []string{"acl", "tags"} {
		t.Run("stale-after-"+intervening, func(t *testing.T) {
			e, a, _ := protectionFixture(t)
			s := aclState(t, e)
			r, err := e.ReviewProtection(ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "Draft", Enabled: true, Effect: "allow", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "all"}}}, s.Revision)
			if err != nil {
				t.Fatal(err)
			}
			c := ProtectionChange{Kind: "tags", ID: a, Tags: []string{"changed"}}
			if intervening == "acl" {
				c = ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "Intervening", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "all"}}}
			}
			publishProtection(t, e, c)
			if _, err := e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "acl", "", false); !errors.Is(err, ErrProtectionPrecondition) {
				t.Fatal("intervening publication failed to invalidate draft", err)
			}
		})
	}
}

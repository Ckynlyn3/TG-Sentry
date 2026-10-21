package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestACLAuthorizationVerdictIsAuditOnly(t *testing.T) {
	now := time.Now()
	for _, id := range []string{"", "acl-deny"} {
		r := Review{ReviewPath: "acl", RuleID: id, Decision: "reject", DecidedAt: &now}
		if _, ok := riskReviewEvent(r, "", "review.submit"); ok {
			t.Errorf("ACL authorization verdict %q projected as a risk finding", id)
		}
	}
	e := engine(t)
	aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "deny", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "all"}}})
	r, err := e.Submit(input("acl-audit-only", "read", map[string]any{"path": "README.md"}))
	if err != nil || r.ReviewPath != "acl" {
		t.Fatal("ACL deny missing", r, err)
	}
	audits := aclAudits(t, e, "review.submit")
	if len(audits) != 1 || len(audits[0].Events) != 1 || audits[0].Events[0].Type != "tg.sentry.audit.v1" {
		t.Fatal("expected only the unchanged audit projection", audits)
	}
}

func TestACLDenyRetainsIndependentSensitiveFinding(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			e := engine(t)
			const private = "synthetic-acl-private"
			if err := e.SaveRule(testActorContext(), Rule{ID: "U_ACL_PRIVATE", Name: "Private", Matcher: "keywords", Pattern: private, Field: "value", Enabled: true, Decision: "alert", Categories: []string{SensitiveInfoCategory}}); err != nil {
				t.Fatal(err)
			}
			s := aclState(t, e)
			s.ACL = ACLState{Initialized: true, Rules: []ACLRule{}}
			if !implicit {
				s.ACL.Rules = []ACLRule{{ID: "acl-deny", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "all"}}}
			}
			if err := e.put("protection", "current", s); err != nil {
				t.Fatal(err)
			}
			r, err := e.Submit(input("acl-sensitive", "read", map[string]any{"value": private}))
			if err != nil || r.Decision != "reject" || r.ReviewPath != "acl" || r.SensitiveInfo == nil || len(r.SensitiveInfo.Findings) != 1 {
				t.Fatalf("ACL deny hid finding or lost precedence: %+v err=%v", r, err)
			}
			raw, err := json.Marshal(r)
			if err != nil || strings.Contains(string(raw), private) {
				t.Fatal("sensitive snapshot retained", err)
			}
			page, err := e.RiskEvents(0, "", RiskEventFilter{})
			if err != nil || len(page.Items) != 1 {
				t.Fatal("expected independent finding only", page, err)
			}
			event := page.Items[0]
			if event.Data.FindingInfo.Analytic == nil || event.Data.FindingInfo.Analytic.UID != "U_ACL_PRIVATE" || event.Data.ActionID != 3 || event.Data.DispositionID != 19 {
				t.Fatal("independent finding changed attribution/action", event)
			}
			if err := validateEventWire(pinnedEventSchemas(t), wireEvent(t, event)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

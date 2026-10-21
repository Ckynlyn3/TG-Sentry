package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIndependentRecheckDenySnapshotOverlap(t *testing.T) {
	e := engine(t)
	const secret = "synthetic-private-recheck"
	for _, rule := range []Rule{
		{ID: "U_PRIVATE", Name: "Private", Enabled: true, Matcher: "keywords", Pattern: secret, Field: "value", Decision: "approve", Categories: []string{SensitiveInfoCategory}},
		{ID: "U_DENY", Name: "Deny", Enabled: true, Matcher: "contains", Pattern: secret, Decision: "reject"},
	} {
		if err := e.SaveRule(testActorContext(), rule); err != nil {
			t.Fatal(err)
		}
	}
	r, err := e.Submit(input("overlap-deny", "read", map[string]any{"value": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if r.RuleID != "U_DENY" || r.Decision != "reject" || r.SensitiveInfo == nil || len(r.SensitiveInfo.Findings) != 1 {
		t.Fatal("deny/findings regression")
	}
	saved, err := e.Review(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("matched custom secret retained in persisted denying review rule snapshot")
	}
}

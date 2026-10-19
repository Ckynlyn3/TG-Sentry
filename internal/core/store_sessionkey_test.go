package core

import (
	"strings"
	"testing"
)

func TestReviewsPageSessionKeyExactMatch(t *testing.T) {
	e := engine(t)
	raw := "sha256:" + strings.Repeat("a", 64)
	stored := eventIdentifier(raw)
	for _, fixture := range []struct{ instance, session string }{
		{"first", raw}, {"second", stored},
	} {
		if err := e.Register(Instance{ID: fixture.instance, SessionID: fixture.session, Cwd: t.TempDir(), HookVersion: Version}); err != nil {
			t.Fatal(err)
		}
		for _, call := range []string{"a", "b"} {
			if _, err := e.Submit(ReviewInput{InstanceID: fixture.instance, CallID: call, ToolName: "read", Arguments: map[string]any{}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name   string
		filter ReviewFilter
		want   string
	}{
		{"stored key", ReviewFilter{SessionKey: stored}, stored},
		{"raw id", ReviewFilter{SessionID: raw}, stored},
		{"raw id equal to stored key", ReviewFilter{SessionID: stored}, eventIdentifier(stored)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := e.ReviewsPage(1, 1, tc.filter)
			if err != nil || first.Total != 2 || len(first.Items) != 1 {
				t.Fatalf("first page total/items incorrect: %+v, %v", first, err)
			}
			second, err := e.ReviewsPage(2, 1, tc.filter)
			if err != nil || second.Total != 2 || len(second.Items) != 1 {
				t.Fatalf("second page total/items incorrect: %+v, %v", second, err)
			}
			if first.Items[0].SessionID != tc.want || second.Items[0].SessionID != tc.want || first.Items[0].ID == second.Items[0].ID {
				t.Fatal("session filtering must precede counting and pagination, without merging raw/stored interpretations")
			}
		})
	}
	missing, err := e.ReviewsPage(1, 20, ReviewFilter{SessionKey: raw})
	if err != nil || missing.Total != 0 || len(missing.Items) != 0 {
		t.Fatal("sessionKey must not hash the supplied key", err)
	}
}

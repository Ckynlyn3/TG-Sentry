package core

import (
	"reflect"
	"sort"
	"testing"
)

// Uses the existing store fixture so scripts/test-store.sh runs the same
// regression against real Postgres, while ordinary go test uses SQLite.
func TestReviewsPageInstantBounds(t *testing.T) {
	e := summaryEngine(t)
	for _, fixture := range []struct{ id, stamp string }{
		{"previous", "2026-10-17T23:59:59.999999999Z"},
		{"whole", "2026-10-18T00:00:00Z"},
		{"offset", "2026-10-18T01:00:00+01:00"},
		{"nano", "2026-10-18T00:00:00.000000001Z"},
		{"fraction", "2026-10-18T00:00:00.1Z"},
		{"last", "2026-10-18T23:59:59.999999999Z"},
		{"next", "2026-10-19T00:00:00Z"},
	} {
		if err := e.put("reviews", fixture.id, Review{ID: fixture.id, CreatedAt: summaryTime(t, fixture.stamp)}); err != nil {
			t.Fatal(err)
		}
	}
	// Plan #16 A3: from is inclusive, an instant to is exclusive, and a
	// date-only to includes that UTC day but excludes the following midnight.
	for _, tc := range []struct {
		name   string
		filter ReviewFilter
		want   []string
	}{
		{"whole to nano", ReviewFilter{From: "2026-10-18T00:00:00Z", To: "2026-10-18T00:00:00.000000001Z"}, []string{"offset", "whole"}},
		{"nano to fraction", ReviewFilter{From: "2026-10-18T00:00:00.000000001Z", To: "2026-10-18T00:00:00.1Z"}, []string{"nano"}},
		{"offset bounds", ReviewFilter{From: "2026-10-18T01:00:00+01:00", To: "2026-10-18T01:00:00.000000001+01:00"}, []string{"offset", "whole"}},
		{"equal bounds", ReviewFilter{From: "2026-10-18T00:00:00Z", To: "2026-10-18T01:00:00+01:00"}, []string{}},
		{"UTC date", ReviewFilter{From: "2026-10-18", To: "2026-10-18"}, []string{"fraction", "last", "nano", "offset", "whole"}},
		{"from only", ReviewFilter{From: "2026-10-18T23:59:59.999999999Z"}, []string{"last", "next"}},
		{"to only", ReviewFilter{To: "2026-10-18T00:00:00Z"}, []string{"previous"}},
		{"invalid internal from", ReviewFilter{From: "invalid"}, []string{}},
		{"invalid internal to", ReviewFilter{To: "invalid"}, []string{"fraction", "last", "nano", "next", "offset", "previous", "whole"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := e.ReviewsPage(1, 20, tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, review := range page.Items {
				got = append(got, review.ID)
			}
			sort.Strings(got)
			if page.Total != len(tc.want) || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("total=%d IDs=%v; want total=%d IDs=%v", page.Total, got, len(tc.want), tc.want)
			}
		})
	}
}

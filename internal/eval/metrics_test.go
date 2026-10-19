package eval

import (
	"math"
	"testing"
)

func TestProportionsAndWilson(t *testing.T) {
	if Proportion(0, 0).Value != nil {
		t.Fatal("zero denominator must be N/A")
	}
	// Published worked example: 20/50, Wilson 95% [0.276,0.538].
	// https://influentialpoints.com/Training/confidence_intervals_of_proportions.htm#wils
	p := Proportion(20, 50)
	if p.Value == nil || *p.Value != .4 || math.Abs(*p.Lower-.2760839) > 1e-6 || math.Abs(*p.Upper-.5381856) > 1e-6 {
		t.Fatalf("Wilson: %+v", p)
	}
	if Proportion(0, 10).Lower == nil || *Proportion(0, 10).Lower != 0 {
		t.Fatal("boundary")
	}
	c := Counts{TP: 3, FP: 1, FN: 2, TN: 4}
	if *c.Precision().Value != .75 || *c.Recall().Value != .6 {
		t.Fatal("P/R")
	}
}
func TestNearestRank(t *testing.T) {
	values := []float64{4, 1, 3, 2}
	for _, tc := range []struct{ p, w float64 }{{.5, 2}, {.95, 4}, {.99, 4}} {
		if got := NearestRank(values, tc.p); got == nil || *got != tc.w {
			t.Fatal(tc, got)
		}
	}
	if values[0] != 4 || NearestRank(nil, .5) != nil || NearestRank(values, 0) != nil {
		t.Fatal("mutation/empty/invalid")
	}
}
func TestUTF16Entities(t *testing.T) {
	// Emoji occupies two UTF-16 units. Partial overlaps are FP+FN.
	text := "😀fake@example.invalid"
	gold := []Entity{{Type: "Email", Span: Span{2, 22}}}
	pred := []Entity{{Type: "EMAIL_ADDRESS", Span: Span{2, 22}}}
	mapping := map[string]string{"EMAIL_ADDRESS": "Email"}
	c := ExactEntities(gold, pred, mapping)
	if c.TP != 1 || c.FP != 0 || c.FN != 0 {
		t.Fatal(c)
	}
	if err := ValidateEntities(text, gold); err != nil {
		t.Fatal(err)
	}
	pred[0].EndUTF16--
	c = ExactEntities(gold, pred, mapping)
	if c.TP != 0 || c.FP != 1 || c.FN != 1 {
		t.Fatal(c)
	}
	chars := CharacterCounts(gold, pred, mapping, "Email")
	if chars.TP != 19 || chars.FN != 1 || chars.FP != 0 || math.Abs(*chars.F1()-38.0/39) > 1e-10 {
		t.Fatal(chars)
	}
	if ExactEntities(gold, append(gold, gold...), nil).FP != 1 {
		t.Fatal("duplicates must not reuse gold")
	}
	if ValidateEntities(text, []Entity{{Type: "Email", Span: Span{1, 2}}}) == nil {
		t.Fatal("split surrogate accepted")
	}
}
func TestBenignEnforcement(t *testing.T) {
	for _, d := range []string{"alert", "monitor", "log-only", "approve"} {
		if WouldBlock(d) {
			t.Fatal(d)
		}
	}
	if !WouldBlock("block") || !WouldBlock("reject") {
		t.Fatal("blocking actions")
	}
}

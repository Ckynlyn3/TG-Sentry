package eval

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestPIIValidators(t *testing.T) {
	// Luhn patent worked vector US2950048A; GB 11643 checksum example.
	for _, tc := range []struct {
		kind, value string
		valid       bool
	}{
		{"Card", "79927398713", true}, {"Card", "79927398714", false}, {"Card", "x", false},
		{"ID", "11010519491231002X", true}, {"ID", "110105194912310021", false}, {"ID", "11010519490230002X", false},
		{"Email", "synthetic@example.invalid", true}, {"Email", "not an address", false},
		{"Phone", "13800000000", true}, {"Phone", "12800000000", false}, {"Phone", "1380000000x", false},
	} {
		if ValidatePII(tc.kind, tc.value) != tc.valid {
			t.Fatal(tc)
		}
	}
}
func TestDevGeneratorDeterministicAndFixtures(t *testing.T) {
	a, b := GenerateDev(), GenerateDev()
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if !bytes.Equal(x, y) || len(a) < 20 {
		t.Fatal("dev reproducibility/warmup")
	}
	for _, r := range a {
		if r.Seed != "dev" || ValidateEntities(r.Text, r.Entities) != nil {
			t.Fatal("seed/spans")
		}
		for _, e := range r.Entities {
			v := UTF16Slice(r.Text, e.Span)
			if !ValidatePII(e.Type, v) {
				t.Fatal("invalid generated entity", e.Type)
			}
		}
	}
	fixture, e := os.ReadFile("testdata/pii-dev/records.json")
	if e != nil {
		t.Fatal(e)
	}
	var saved []PIIRecord
	if json.Unmarshal(fixture, &saved) != nil {
		t.Fatal("fixture JSON")
	}
	z, _ := json.Marshal(saved)
	if !bytes.Equal(x, z) {
		t.Fatal("committed dev fixture drift")
	}
}

package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDocumentsAndConfiguration(t *testing.T) {
	var manifest Manifest
	if err := Load("../../eval/manifest.json", &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"version", "duplicate", "split", "mode", "language", "seed"} {
		m := manifest
		m.Sets = append([]Dataset(nil), manifest.Sets...)
		switch mode {
		case "version":
			m.Version = 0
		case "duplicate":
			m.Sets = append(m.Sets, m.Sets[0])
		case "split":
			m.Sets[0].SplitUse = "test"
		case "mode":
			m.Sets[0].Mode = "unknown"
		case "language":
			m.Sets[0].LanguageMetadataLevel = "auto"
		case "seed":
			m.Sets[0].SplitUse = "dev"
		}
		if m.Validate() == nil {
			t.Fatal(mode)
		}
	}
	c := testConfig()
	if e := c.Validate(nil); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"version", "rules", "digest", "hardware", "env", "lambda", "threshold"} {
		bad := c
		switch mode {
		case "version":
			bad.Version = 0
		case "rules":
			bad.RulesSHA256 = "bad"
		case "digest":
			bad.Digests = map[string]string{"x": "invalid"}
		case "hardware":
			bad.CPUCount = 0
		case "env":
			bad.Environment = map[string]string{"SECRET": "not allowed"}
		case "lambda":
			bad.NSFAEnforce = true
		case "threshold":
			bad.Thresholds = []Threshold{{ID: "fake"}}
		}
		if bad.Validate(bad.Digests) == nil {
			t.Fatal(mode)
		}
	}
	if Load(filepath.Join(t.TempDir(), "missing"), &manifest) == nil {
		t.Fatal("missing doc")
	}
}
func TestRejectUnhashedExtraSealedFile(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "fake"), []byte("synthetic"), 0600)
	h, n, _ := HashFile(filepath.Join(root, "fake"))
	os.WriteFile(filepath.Join(root, "extra"), []byte("synthetic extra"), 0600)
	if _, e := VerifyFiles(root, []LockedFile{{Path: "fake", SHA256: h, Bytes: n}}); e == nil {
		t.Fatal("unhashed file ignored by sealed tree")
	}
}
func TestRejectUnsafeEntityAndUnmappedCharacterCounts(t *testing.T) {
	if ValidateEntities(string([]byte{0xff}), nil) == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	gold := []Entity{{Type: "Email", Span: Span{0, 2}}}
	pred := []Entity{{Type: "UNKNOWN", Span: Span{0, 2}}}
	c := CharacterCounts(gold, pred, map[string]string{}, "unmapped")
	if c.FP != 2 {
		t.Fatal("unmapped type lost", c)
	}
}
func TestFrozenDocumentsMustBeTrackedAtHEAD(t *testing.T) {
	o, _ := syntheticRun(t)
	external := filepath.Join(t.TempDir(), "manifest.json")
	b, _ := os.ReadFile(o.Manifest)
	os.WriteFile(external, b, 0600)
	o.Manifest = external
	if e := checkDocument(o.Root, o.Manifest, "eval/manifest.json"); e == nil || !strings.Contains(e.Error(), "document") {
		t.Fatal("external manifest accepted", e)
	}
}

func TestT8CannotReusePrimaryInjectionMetric(t *testing.T) {
	g := Group{Dataset: "AgentDojo", Category: "category::prompt-attack", Language: "mixed/unknown", Precision: Proportion(1, 1)}
	bound := 1.0
	result := EvaluateThresholds([]Threshold{{ID: "T8", Dataset: g.Dataset, Category: g.Category, Metric: "precision", Operator: ">=", Bound: &bound}}, []Group{g})
	if result[0].Status != "NOT_MEASURED" {
		t.Fatal("T8 lacks scoped ground truth", result)
	}
}

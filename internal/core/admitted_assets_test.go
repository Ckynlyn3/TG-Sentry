package core

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestAdmittedAssetMatch(t *testing.T) {
	base := mustSubject(t, map[string]string{"SKILL.md": digestBytes([]byte("skill")), "scripts/run.py": digestBytes([]byte("script"))})
	changed := mustSubject(t, map[string]string{"SKILL.md": base.Files["SKILL.md"], "scripts/run.py": digestBytes([]byte("changed script"))})
	added := mustSubject(t, map[string]string{"SKILL.md": base.Files["SKILL.md"], "scripts/run.py": base.Files["scripts/run.py"], "extra.py": digestBytes([]byte("extra"))})
	removed := mustSubject(t, map[string]string{"SKILL.md": base.Files["SKILL.md"]})
	renamed := mustSubject(t, map[string]string{"SKILL.md": base.Files["SKILL.md"], "scripts/renamed.py": base.Files["scripts/run.py"]})
	entry := AdmittedAsset{ID: "admission", Name: "inventory-asset", Enabled: true, Family: SupplyChainFamilySkill, SubjectDigest: base.Digest, SourceSnapshotID: "snapshot"}
	disabled := entry
	disabled.Enabled = false
	uppercase := entry
	uppercase.SubjectDigest = strings.ToUpper(base.Digest)
	for _, tc := range []struct {
		name    string
		list    []AdmittedAsset
		family  SupplyChainFamily
		subject SupplyChainSubject
		want    bool
	}{
		{"exact digest", []AdmittedAsset{entry}, entry.Family, base, true},
		{"changed sibling bytes", []AdmittedAsset{entry}, entry.Family, changed, false},
		{"added membership", []AdmittedAsset{entry}, entry.Family, added, false},
		{"removed membership", []AdmittedAsset{entry}, entry.Family, removed, false},
		{"renamed membership", []AdmittedAsset{entry}, entry.Family, renamed, false},
		{"wrong family", []AdmittedAsset{entry}, SupplyChainFamilyMCP, base, false},
		{"unknown family", []AdmittedAsset{{Enabled: true, Family: "*", SubjectDigest: base.Digest}}, "*", base, false},
		{"disabled entry", []AdmittedAsset{disabled}, entry.Family, base, false},
		{"skip disabled entry", []AdmittedAsset{disabled, entry}, entry.Family, base, true},
		{"absent list", nil, entry.Family, base, false},
		{"empty subject", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{}, false},
		{"digest without membership", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{Digest: base.Digest}, false},
		{"membership without digest", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{Files: base.Files}, false},
		{"partial membership with old digest", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{Digest: base.Digest, Files: removed.Files}, false},
		{"changed bytes with old digest", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{Digest: base.Digest, Files: changed.Files}, false},
		{"malformed member", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{Digest: base.Digest, Files: map[string]string{"../escape": base.Files["SKILL.md"]}}, false},
		{"malformed member hash", []AdmittedAsset{entry}, entry.Family, SupplyChainSubject{Digest: base.Digest, Files: map[string]string{"SKILL.md": "partial"}}, false},
		{"noncanonical entry digest", []AdmittedAsset{uppercase}, entry.Family, base, false},
		{"name cannot authorize digest", []AdmittedAsset{{Name: changed.Digest, Enabled: true, Family: entry.Family, SubjectDigest: base.Digest}}, entry.Family, changed, false},
		{"inventory id cannot authorize digest", []AdmittedAsset{{ID: changed.Digest, SourceSnapshotID: changed.Digest, Enabled: true, Family: entry.Family, SubjectDigest: base.Digest}}, entry.Family, changed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := json.Marshal(tc.list)
			got, ok := MatchAdmission(tc.list, tc.family, tc.subject)
			if ok != tc.want || (got != nil) != tc.want {
				t.Fatalf("MatchAdmission = (%v, %v), want match %v", got, ok, tc.want)
			}
			if got != nil {
				if *got != entry {
					t.Fatalf("matched metadata = %+v, want %+v", *got, entry)
				}
				got.Enabled = false // The result must not mutate the caller's policy.
			}
			after, _ := json.Marshal(tc.list)
			if string(before) != string(after) {
				t.Fatal("matcher mutated admission list")
			}
		})
	}
}

func TestAdmittedAssetValidation(t *testing.T) {
	hash := strings.Repeat("a", 64)
	entry := AdmittedAsset{ID: "admission", Name: "label", Family: SupplyChainFamilySkill, SubjectDigest: hash, SourceSnapshotID: "snapshot"}
	for _, tc := range []struct {
		name, id, label, digest, source string
		family                          SupplyChainFamily
		valid                           bool
	}{
		{"valid", entry.ID, entry.Name, hash, entry.SourceSnapshotID, entry.Family, true},
		{"blank id", " ", entry.Name, hash, entry.SourceSnapshotID, entry.Family, false},
		{"blank label", entry.ID, " \t", hash, entry.SourceSnapshotID, entry.Family, false},
		{"existing name boundary", entry.ID, strings.Repeat("n", 200), hash, entry.SourceSnapshotID, entry.Family, true},
		{"oversized label", entry.ID, strings.Repeat("n", 201), hash, entry.SourceSnapshotID, entry.Family, false},
		{"byte name boundary", entry.ID, strings.Repeat("界", 67), hash, entry.SourceSnapshotID, entry.Family, false},
		{"blank source", entry.ID, entry.Name, hash, " ", entry.Family, false},
		{"partial digest", entry.ID, entry.Name, hash[:63], entry.SourceSnapshotID, entry.Family, false},
		{"uppercase digest", entry.ID, entry.Name, strings.ToUpper(hash), entry.SourceSnapshotID, entry.Family, false},
		{"nonhex digest", entry.ID, entry.Name, strings.Repeat("z", 64), entry.SourceSnapshotID, entry.Family, false},
		{"wildcard digest", entry.ID, entry.Name, "*", entry.SourceSnapshotID, entry.Family, false},
		{"unknown family", entry.ID, entry.Name, hash, entry.SourceSnapshotID, "*", false},
		{"mcp", entry.ID, entry.Name, hash, entry.SourceSnapshotID, SupplyChainFamilyMCP, true},
		{"plugin", entry.ID, entry.Name, hash, entry.SourceSnapshotID, SupplyChainFamilyPlugin, true},
		{"builtin tool", entry.ID, entry.Name, hash, entry.SourceSnapshotID, SupplyChainFamilyBuiltinTool, true},
		{"memory file", entry.ID, entry.Name, hash, entry.SourceSnapshotID, SupplyChainFamilyMemoryFile, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := AdmittedAsset{ID: tc.id, Name: tc.label, Family: tc.family, SubjectDigest: tc.digest, SourceSnapshotID: tc.source}
			if err := value.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate = %v, want valid %v", err, tc.valid)
			}
		})
	}
	for _, tc := range []struct {
		name, label, digest, source string
		valid                       bool
	}{
		{"valid create", "label", hash, "snapshot", true},
		{"blank name", " ", hash, "snapshot", false},
		{"blank snapshot", "label", hash, " ", false},
		{"invalid digest", "label", "*", "snapshot", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := AdmittedAssetCreateInput{Name: tc.label, SourceSnapshotID: tc.source, ExpectedSubjectDigest: tc.digest}
			if err := input.Validate(); (err == nil) != tc.valid {
				t.Fatalf("create Validate = %v, want valid %v", err, tc.valid)
			}
		})
	}
	for _, name := range []string{"label", " ", strings.Repeat("n", 201)} {
		if err := (AdmittedAssetUpdateInput{Name: name}).Validate(); (err == nil) != validProtectionName(name) {
			t.Errorf("update Validate(%q) = %v", name, err)
		}
	}
}

func TestAdmittedAssetOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/protection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties           map[string]json.RawMessage
				AdditionalProperties bool
			}
		}
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"AdmittedAsset": AdmittedAsset{}, "AdmittedAssetCreateInput": AdmittedAssetCreateInput{}, "AdmittedAssetUpdateInput": AdmittedAssetUpdateInput{}, "Actor": Actor{}} {
		schema, found := spec.Components.Schemas[name]
		if !found || schema.AdditionalProperties {
			t.Fatalf("missing or open schema %s", name)
		}
		typ := reflect.TypeOf(value)
		if len(schema.Properties) != typ.NumField() {
			t.Fatalf("%s schema properties do not match core type", name)
		}
		for i := 0; i < typ.NumField(); i++ {
			key := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if _, found := schema.Properties[key]; !found {
				t.Errorf("%s schema missing %s", name, key)
			}
		}
	}
}

func TestAdmittedAssetNoNewHashing(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "admitted_assets.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(path, "crypto/") || strings.Contains(path, "hash") {
			t.Fatalf("admissions must reuse #42, not import hashing: %s", path)
		}
	}
	reused := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := call.Fun.(*ast.Ident); ok {
			switch fn.Name {
			case "NewSupplyChainSubject":
				reused = true
			case "digestBytes", "supplyChainSubjectDigest":
				t.Errorf("admission bypasses #42 subject validation via %s", fn.Name)
			}
		}
		return true
	})
	if !reused {
		t.Fatal("admission must reuse NewSupplyChainSubject for membership validation")
	}
}

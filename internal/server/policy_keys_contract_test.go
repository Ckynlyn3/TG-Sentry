package server

import (
	"aegishook/internal/core"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Plan §3.6/§4/§9.3: the OpenAPI boundary uses the same shared wire types.
func TestPolicyKeysOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/protection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	type operation struct {
		Security   []map[string][]string `json:"security"`
		Parameters []struct {
			Name     string `json:"name"`
			In       string `json:"in"`
			Required bool   `json:"required"`
			Schema   struct {
				Type    string `json:"type"`
				Minimum int    `json:"minimum"`
			} `json:"schema"`
		} `json:"parameters"`
		Responses map[string]struct {
			Headers map[string]json.RawMessage `json:"headers"`
			Content map[string]struct {
				Schema struct {
					Ref string `json:"$ref"`
				} `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	var bundle operation
	if err := json.Unmarshal(spec.Paths["/api/v1/client/bundle"]["get"], &bundle); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"200", "304"} {
		if _, ok := bundle.Responses[code].Headers["TG-Trust-Version"]; !ok {
			t.Fatal("trust-version header contract missing", code)
		}
	}
	var keys operation
	if err := json.Unmarshal(spec.Paths["/api/v1/client/keys/{version}"]["get"], &keys); err != nil {
		t.Fatal("trust-record operation missing or invalid", err)
	}
	if len(keys.Security) != 1 {
		t.Fatal("trust-record device authentication contract missing")
	}
	if _, ok := keys.Security[0]["deviceCredential"]; !ok {
		t.Fatal("wrong trust-record authentication contract")
	}
	if len(keys.Parameters) != 1 || keys.Parameters[0].Name != "version" || keys.Parameters[0].In != "path" || !keys.Parameters[0].Required || keys.Parameters[0].Schema.Type != "integer" || keys.Parameters[0].Schema.Minimum != 1 {
		t.Fatal("positive trust version path contract missing")
	}
	for _, code := range []string{"200", "400", "401", "403", "404", "503"} {
		if _, ok := keys.Responses[code]; !ok {
			t.Fatal("trust-record response contract missing", code)
		}
	}
	if keys.Responses["200"].Content["application/json"].Schema.Ref != "#/components/schemas/SignedTrustRecord" {
		t.Fatal("trust-record wire schema missing")
	}
	for name, value := range map[string]any{"SignedTrustRecord": core.SignedTrustRecord{}, "TrustRecord": core.TrustRecord{}, "TrustKey": core.TrustKey{}, "TrustSignature": core.TrustSignature{}} {
		fields := spec.Components.Schemas[name].Properties
		typ := reflect.TypeOf(value)
		if len(fields) != typ.NumField() {
			t.Fatal("schema field count differs from shared type", name)
		}
		for n := range typ.NumField() {
			field := strings.Split(typ.Field(n).Tag.Get("json"), ",")[0]
			if _, ok := fields[field]; !ok {
				t.Fatal("shared field absent from OpenAPI", name, field)
			}
		}
	}
}

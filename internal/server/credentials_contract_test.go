package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCredentialsOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/credentials.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for route := range routeRoles {
		if !strings.Contains(route, "credentials") {
			continue
		}
		method, path, _ := strings.Cut(route, " ")
		if _, ok := doc.Paths[path][strings.ToLower(method)]; !ok {
			t.Errorf("undocumented route %s", route)
		}
	}
	for _, schema := range []string{"Credential", "CredentialBinding", "ResolvedCredential"} {
		if len(doc.Components.Schemas[schema].Properties) == 0 {
			t.Errorf("missing %s", schema)
		}
	}
	for _, forbidden := range []string{"value", "sealed", "dekWrapped", "ciphertext"} {
		if _, ok := doc.Components.Schemas["Credential"].Properties[forbidden]; ok {
			t.Errorf("metadata contains %s", forbidden)
		}
	}
	if _, ok := doc.Components.Schemas["ResolvedCredential"].Properties["value"]; !ok {
		t.Fatal("device value missing")
	}
}

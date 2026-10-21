package server

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func discoveryReadFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s, conn, report := discoveryHTTPFixture(t)
	asset := &report.Accounts[0].Agents[0].Categories[0].Assets[0]
	asset.Descriptor = &discovery.MCPDescriptor{Name: "fixture", Transport: "stdio", EnvKeys: []string{"KEY"}, HeaderKeys: []string{}}
	if err := s.Engine.IngestDiscoveryReport(context.Background(), conn.NodeID, report); err != nil {
		t.Fatal(err)
	}
	return s, asset.AssetID
}

func TestDiscoveryReadRoleMatrixAndProjection(t *testing.T) {
	s, id := discoveryReadFixture(t)
	h := s.Handler()
	paths := []string{"/discovered-agents", "/agent-assets", "/agent-assets/" + id}
	for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin, "unknown", ""} {
		for _, path := range paths {
			t.Run(string(role)+path, func(t *testing.T) {
				w := rbacRequest(h, rbacCookie(s, "human", role), "GET", "http://localhost/api/v1"+path+"?content=true&tenant=other", "", "127.0.0.1:12345")
				if role == "unknown" || role == "" {
					if w.Code != 403 {
						t.Fatalf("got %d", w.Code)
					}
					return
				}
				if w.Code != 200 {
					t.Fatalf("got %d %s", w.Code, w.Body)
				}
				var wire map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &wire); err != nil {
					t.Fatal(err)
				}
				if path == "/discovered-agents" || path == "/agent-assets" {
					if len(wire) != 2 || wire["next_page_token"] != "" {
						t.Fatal(wire)
					}
					wire = wire["items"].([]any)[0].(map[string]any)
				}
				var pathsPresent bool
				if path == "/discovered-agents" {
					evidence := wire["evidence"].(map[string]any)
					_, account := wire["observedLocalAccount"]
					_, home := wire["homePath"]
					_, rel := evidence["relPath"]
					pathsPresent = account && home && rel
					if role == core.RoleReadOnly && (account || home || rel) {
						t.Fatal("restricted agent fields present")
					}
					c := wire["categories"].([]any)[0].(map[string]any)
					if c["scanState"] != "scanned" || c["freshness"] != "not_scanned" {
						t.Fatal(c)
					}
					if _, ok := c["assets"]; ok {
						t.Fatal("nested stored assets leaked")
					}
				} else {
					_, pathsPresent = wire["sourceRelPath"]
					d := wire["descriptor"].(map[string]any)
					if len(d) != 4 || !reflect.DeepEqual(d["envKeys"], []any{"KEY"}) || !reflect.DeepEqual(d["headerKeys"], []any{}) {
						t.Fatal(d)
					}
				}
				if pathsPresent != (role != core.RoleReadOnly) {
					t.Fatalf("role %s path fields=%v", role, pathsPresent)
				}
				if wire["freshness"] != "not_scanned" || wire["nodeId"] == "" || wire["accountId"] != "1000" {
					t.Fatal(wire)
				}
				assertDiscoveryNoContent(t, wire)
			})
		}
	}
	for _, path := range paths {
		for _, tc := range []struct {
			kind   string
			cookie *http.Cookie
			want   int
		}{{"anonymous", nil, 401}, {"cli", rbacCookie(s, "cli", core.RoleAdmin), 403}} {
			w := rbacRequest(h, tc.cookie, "GET", "http://localhost/api/v1"+path, "", "127.0.0.1:12345")
			if w.Code != tc.want {
				t.Fatalf("%s %s: got %d", tc.kind, path, w.Code)
			}
		}
	}
	for _, pattern := range []string{"GET /api/v1/discovered-agents", "GET /api/v1/agent-assets", "GET /api/v1/agent-assets/{id}"} {
		if routeRoles[pattern] != core.RoleReadOnly {
			t.Fatalf("missing matrix row %s", pattern)
		}
	}
}

func assertDiscoveryNoContent(t *testing.T, value any) {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			switch key {
			case "content", "body", "command", "args", "url", "env", "headers", "userMessage", "context", "result":
				t.Fatalf("content key %s", key)
			}
			assertDiscoveryNoContent(t, item)
		}
	case []any:
		for _, item := range v {
			assertDiscoveryNoContent(t, item)
		}
	}
}

func TestDiscoveryReadHTTPPaginationAndErrors(t *testing.T) {
	s, conn, report := discoveryHTTPFixture(t)
	category := &report.Accounts[0].Agents[0].Categories[0]
	template := category.Assets[0]
	category.Assets = nil
	for i := 0; i < 105; i++ {
		asset := template
		asset.Name = fmt.Sprintf("asset-%03d", i)
		var err error
		asset.AssetID, err = discovery.AssetID(conn.NodeID, "1000", "claude", "skills", asset.SourceRelPath, asset.Name)
		if err != nil {
			t.Fatal(err)
		}
		category.Assets = append(category.Assets, asset)
	}
	if err := s.Engine.IngestDiscoveryReport(context.Background(), conn.NodeID, report); err != nil {
		t.Fatal(err)
	}
	h, cookie := s.Handler(), rbacCookie(s, "human", core.RoleAdmin)
	for _, tc := range []struct {
		size string
		want int
	}{{"", 20}, {"0", 20}, {"20", 20}, {"100", 100}, {"101", 100}} {
		w := rbacRequest(h, cookie, "GET", "http://localhost/api/v1/agent-assets?page_size="+tc.size, "", "127.0.0.1:12345")
		var page core.DiscoveryPage[core.AgentAssetView]
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != tc.want || len(page.NextPageToken) != 64 {
			t.Fatalf("size %s: %d %s", tc.size, w.Code, w.Body)
		}
		next := rbacRequest(h, cookie, "GET", "http://localhost/api/v1/agent-assets?page_size=100&page_token="+url.QueryEscape(page.NextPageToken), "", "127.0.0.1:12345")
		var tail core.DiscoveryPage[core.AgentAssetView]
		if next.Code != 200 || json.Unmarshal(next.Body.Bytes(), &tail) != nil || len(tail.Items) != 105-tc.want || tail.NextPageToken != "" {
			t.Fatalf("tail: %d %s", next.Code, next.Body)
		}
	}
	for _, path := range []string{"/discovered-agents", "/agent-assets"} {
		for _, query := range []string{"page_size=-1", "page_size=bad", "page_size=2147483648", "page_token=invalid", "state=stale", "category=invalid"} {
			w := rbacRequest(h, cookie, "GET", "http://localhost/api/v1"+path+"?"+query, "", "127.0.0.1:12345")
			if w.Code != 400 || !strings.Contains(w.Body.String(), core.ErrDiscoveryQuery.Error()) {
				t.Fatalf("%s?%s: %d %s", path, query, w.Code, w.Body)
			}
		}
		w := rbacRequest(h, cookie, "GET", "http://localhost/api/v1"+path+"?node=missing", "", "127.0.0.1:12345")
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"items":[],"next_page_token":""}` {
			t.Fatalf("empty: %d %s", w.Code, w.Body)
		}
	}
	w := rbacRequest(h, cookie, "GET", "http://localhost/api/v1/agent-assets/missing", "", "127.0.0.1:12345")
	if w.Code != 404 {
		t.Fatalf("missing: %d %s", w.Code, w.Body)
	}
	if err := s.Engine.DB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/discovered-agents", "/agent-assets", "/agent-assets/missing"} {
		w := rbacRequest(h, cookie, "GET", "http://localhost/api/v1"+path, "", "127.0.0.1:12345")
		if w.Code != 500 || strings.Contains(w.Body.String(), "database") {
			t.Fatalf("store failure: %d %s", w.Code, w.Body)
		}
	}
}

func TestDiscoveryReadWireAllowlist(t *testing.T) {
	s, id := discoveryReadFixture(t)
	// Simulate a future storage field. Reads must not expose unknown fields even
	// to admins, and must not use arbitrary payload maps for role projection.
	for _, kind := range []string{"discovered_agents", "agent_assets"} {
		var recordID, payload string
		db := teststore.Admin(t, s.Engine.DB)
		if err := db.QueryRow("SELECT id,payload FROM records WHERE tenant_id='default' AND kind=$1", kind).Scan(&recordID, &payload); err != nil {
			t.Fatal(err)
		}
		var stored map[string]any
		if err := json.Unmarshal([]byte(payload), &stored); err != nil {
			t.Fatal(err)
		}
		stored["content"] = "SENTINEL_CONTENT"
		stored["command"] = "SENTINEL_COMMAND"
		b, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("UPDATE records SET payload=$1 WHERE tenant_id='default' AND kind=$2 AND id=$3", string(b), kind, recordID); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/discovered-agents", "/agent-assets", "/agent-assets/" + id} {
		w := rbacRequest(s.Handler(), rbacCookie(s, "human", core.RoleAdmin), "GET", "http://localhost/api/v1"+path, "", "127.0.0.1:12345")
		if w.Code != 200 || strings.Contains(w.Body.String(), "SENTINEL") {
			t.Fatalf("wire allowlist: %d %s", w.Code, w.Body)
		}
	}
}

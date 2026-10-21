package server

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func discoveryHTTPFixture(t *testing.T) (*Server, core.ClientConnection, discovery.Report) {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	key, err := e.CreateEnrollment(context.Background(), "discovery HTTP")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	asset := discovery.Asset{Name: "example", Category: "skills", SourceRelPath: ".claude/skills/example/SKILL.md", Hash: "digest", HashKind: discovery.FileSHA256}
	asset.AssetID, err = discovery.AssetID(conn.NodeID, "1000", "claude", "skills", asset.SourceRelPath, asset.Name)
	if err != nil {
		t.Fatal(err)
	}
	report := discovery.Report{SchemaVersion: discovery.SchemaVersion, NodeID: conn.NodeID, Scope: discovery.OwnHome, Mode: "full", Final: true, ScanStartedAt: now.Add(-time.Second), ScanCompletedAt: now, Accounts: []discovery.Account{{AccountID: "1000", ObservedLocalAccount: "user", HomePath: "/home/user", HomeState: discovery.HomeReadable, Agents: []discovery.Agent{{Family: "claude", Found: discovery.Found, Version: "unknown", Evidence: discovery.Evidence{Kind: "config_file", RelPath: ".claude.json"}, Categories: []discovery.Category{{Category: "skills", Scope: discovery.ScopeHome, ScanState: discovery.ScanScanned, Assets: []discovery.Asset{asset}}}}}}}}
	return New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir()), conn, report
}

func postDiscovery(t *testing.T, h http.Handler, token string, body []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "http://localhost/api/v1/client/discovery-reports", bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func discoveryJSON(t *testing.T, report discovery.Report) []byte {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func discoveryHTTPInventory(t *testing.T, s *Server) map[string]string {
	t.Helper()
	rows, err := teststore.Admin(t, s.Engine.DB).Query("SELECT tenant_id,kind,id,payload FROM records WHERE kind IN ('discovered_agents','agent_assets','discovery_node_state') ORDER BY tenant_id,kind,id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tenant, kind, id, payload string
		if err := rows.Scan(&tenant, &kind, &id, &payload); err != nil {
			t.Fatal(err)
		}
		out[tenant+"/"+kind+"/"+id] = payload
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDiscoveryHTTPRequiresEnrolledClient(t *testing.T) {
	s, conn, report := discoveryHTTPFixture(t)
	h := s.Handler()
	body := discoveryJSON(t, report)
	session := s.createSession(session{Kind: "human", Role: core.RoleAdmin, Tenant: "default", Principal: core.Principal{Issuer: "test", Subject: "admin"}})
	for _, tc := range []struct {
		name, token string
		cookie      *http.Cookie
		status      int
	}{
		{name: "no auth", status: http.StatusUnauthorized},
		{name: "cookie only", cookie: &http.Cookie{Name: sessionCookieName, Value: session.ID}, status: http.StatusForbidden},
		{name: "shared hook", token: "legacy", status: http.StatusForbidden},
		{name: "invalid device", token: "invalid", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postDiscovery(t, h, tc.token, body, tc.cookie)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if len(discoveryHTTPInventory(t, s)) != 0 {
				t.Fatal("unauthorized inventory write")
			}
		})
	}
	// Exercise the handler's own boundary, not only middleware authentication.
	for _, ctx := range []context.Context{
		context.Background(),
		context.WithValue(context.Background(), clientContextKey{}, core.ClientNode{}),
		context.WithValue(context.Background(), clientContextKey{}, core.ClientNode{ID: conn.NodeID, Revoked: true}),
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "http://localhost/api/v1/client/discovery-reports", bytes.NewReader(body)).WithContext(ctx)
		s.ingestDiscoveryReport(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("missing/empty/revoked requestClient context: %d", w.Code)
		}
	}
	report.NodeID = "other"
	if w := postDiscovery(t, h, conn.Token, discoveryJSON(t, report), nil); w.Code != http.StatusForbidden {
		t.Fatalf("wrong node accepted: %d %s", w.Code, w.Body)
	}
	if err := s.Engine.RevokeClient(context.Background(), conn.NodeID); err != nil {
		t.Fatal(err)
	}
	report.NodeID = conn.NodeID
	if w := postDiscovery(t, h, conn.Token, discoveryJSON(t, report), nil); w.Code != http.StatusForbidden {
		t.Fatalf("revoked node accepted: %d", w.Code)
	}
	if len(discoveryHTTPInventory(t, s)) != 0 {
		t.Fatal("rejected client changed inventory")
	}
}

func TestDiscoveryHTTPStrictDecodeAndReplay(t *testing.T) {
	s, conn, report := discoveryHTTPFixture(t)
	h := s.Handler()
	body := discoveryJSON(t, report)
	auditsBefore, err := s.Engine.Audits()
	if err != nil {
		t.Fatal(err)
	}
	if w := postDiscovery(t, h, conn.Token, body, nil); w.Code != http.StatusOK {
		t.Fatalf("valid report: %d %s", w.Code, w.Body)
	}
	audits, err := s.Engine.Audits()
	if err != nil || len(audits) != len(auditsBefore)+1 {
		t.Fatalf("success audit count: %d %v", len(audits), err)
	}
	before := discoveryHTTPInventory(t, s)
	unknownTop := append([]byte(`{"content":"SENTINEL_SECRET",`), body[1:]...)
	nested := bytes.Replace(body, []byte(`"name":"example"`), []byte(`"name":"example","content":"SENTINEL_SECRET"`), 1)
	unknownSchema := bytes.Replace(body, []byte(discovery.SchemaVersion), []byte("discovery/v2"), 1)
	var duplicate discovery.Report
	// Round-trip makes the duplicate fixture independent of the valid snapshot.
	if err := json.Unmarshal(body, &duplicate); err != nil {
		t.Fatal(err)
	}
	category := &duplicate.Accounts[0].Agents[0].Categories[0]
	category.Assets = append(category.Assets, category.Assets[0])
	for _, tc := range []struct {
		name      string
		body      []byte
		errorCode string
	}{
		{"unknown top", unknownTop, ""}, {"unknown content", nested, ""}, {"unknown schema", unknownSchema, ""},
		{"trailing object", append(append([]byte(nil), body...), []byte(` {}`)...), ""},
		{"trailing garbage", append(append([]byte(nil), body...), []byte(` x`)...), ""},
		{"duplicate asset", discoveryJSON(t, duplicate), "duplicate_asset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postDiscovery(t, h, conn.Token, tc.body, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if tc.errorCode != "" && !strings.Contains(w.Body.String(), tc.errorCode) {
				t.Fatalf("missing %s: %s", tc.errorCode, w.Body)
			}
			if strings.Contains(w.Body.String(), "SENTINEL_SECRET") {
				t.Fatal("parser echoed source content")
			}
			if !reflect.DeepEqual(before, discoveryHTTPInventory(t, s)) {
				t.Fatal("invalid report changed inventory")
			}
		})
	}
	for _, at := range []time.Time{report.ScanCompletedAt, report.ScanStartedAt} {
		report.ScanCompletedAt = at
		w := postDiscovery(t, h, conn.Token, discoveryJSON(t, report), nil)
		if w.Code != http.StatusConflict {
			t.Fatalf("replay/stale status=%d body=%s", w.Code, w.Body)
		}
		if !reflect.DeepEqual(before, discoveryHTTPInventory(t, s)) {
			t.Fatal("replay changed inventory")
		}
		after, err := s.Engine.Audits()
		if err != nil || !reflect.DeepEqual(audits, after) {
			t.Fatalf("409 replay changed audit log: %v", err)
		}
	}
}

func TestDiscoveryHTTPBodyLimit(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(map[int]string{0: "exact limit", 1: "over limit"}[extra], func(t *testing.T) {
			s, conn, report := discoveryHTTPFixture(t)
			h := s.Handler()
			if w := postDiscovery(t, h, conn.Token, discoveryJSON(t, report), nil); w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body)
			}
			before := discoveryHTTPInventory(t, s)
			report.ScanCompletedAt = report.ScanCompletedAt.Add(time.Millisecond)
			body := discoveryJSON(t, report)
			// Existing transport boundary is 2<<20 (server.go read), not the parser budget.
			body = append(body, bytes.Repeat([]byte(" "), (2<<20)+extra-len(body))...)
			w := postDiscovery(t, h, conn.Token, body, nil)
			expected := http.StatusOK
			if extra != 0 {
				expected = http.StatusRequestEntityTooLarge
			}
			if w.Code != expected {
				t.Fatalf("status=%d want=%d body=%s", w.Code, expected, w.Body)
			}
			if extra != 0 && !reflect.DeepEqual(before, discoveryHTTPInventory(t, s)) {
				t.Fatal("oversize report changed inventory")
			}
		})
	}
}

func TestDiscoveryHTTPTransactionFailure(t *testing.T) {
	s, conn, report := discoveryHTTPFixture(t)
	h := s.Handler()
	if w := postDiscovery(t, h, conn.Token, discoveryJSON(t, report), nil); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	before := discoveryHTTPInventory(t, s)
	query := `CREATE TRIGGER reject_discovery BEFORE INSERT ON records WHEN NEW.kind='discovery_node_state' BEGIN SELECT RAISE(ABORT,'SENTINEL_DB_FAILURE'); END;`
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") != "" {
		query = `CREATE FUNCTION reject_discovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SENTINEL_DB_FAILURE'; END $$; CREATE TRIGGER reject_discovery BEFORE INSERT ON records FOR EACH ROW WHEN (NEW.kind='discovery_node_state') EXECUTE FUNCTION reject_discovery();`
	}
	if _, err := teststore.Admin(t, s.Engine.DB).Exec(query); err != nil {
		t.Fatal(err)
	}
	report.ScanCompletedAt = report.ScanCompletedAt.Add(time.Millisecond)
	report.Accounts[0].Agents[0].Categories[0].Assets = nil
	w := postDiscovery(t, h, conn.Token, discoveryJSON(t, report), nil)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "SENTINEL_DB_FAILURE") {
		t.Fatalf("transaction failure response=%d %s", w.Code, w.Body)
	}
	if !reflect.DeepEqual(before, discoveryHTTPInventory(t, s)) {
		t.Fatal("failed transaction changed inventory")
	}
}

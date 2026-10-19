package server

import (
	"aegishook/internal/core"
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
)

func TestClientPolicyBundleHTTP(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "bundle HTTP")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	h := New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir()).Handler()
	fetch := func(token, etag string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "http://localhost/api/v1/client/bundle", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if etag != "" {
			r.Header.Set("If-None-Match", etag)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := fetch(conn.Token, "")
	var signed core.SignedPolicyBundle
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &signed) != nil {
		t.Fatalf("bundle HTTP %d", w.Code)
	}
	if w.Header().Get("TG-Trust-Version") != "1" {
		t.Fatal("trust version missing on 200")
	}
	bundle, err := core.VerifyPolicyBundle(signed, conn.BundlePublicKey, conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	etag := w.Header().Get("ETag")
	if etag != core.PolicyBundleETag(signed) || len(etag) < 2 || etag[0] != '"' {
		t.Fatal("missing strong ETag")
	}
	for _, match := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		w = fetch(conn.Token, match)
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != etag {
			t.Fatal("conditional bundle not 304", w.Code)
		}
		if w.Header().Get("TG-Trust-Version") != "1" {
			t.Fatal("trust version missing on 304")
		}
	}
	if w = fetch(conn.Token, `"other"`); w.Code != http.StatusOK {
		t.Fatal("nonmatching validator suppressed bundle")
	}
	if err = e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), core.Rule{ID: "U_HTTP", Name: "HTTP fixture", Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "fixture"}); err != nil {
		t.Fatal(err)
	}
	w = fetch(conn.Token, etag)
	var changed core.SignedPolicyBundle
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &changed) != nil || bytes.Equal(signed.Payload, changed.Payload) || w.Header().Get("ETag") == etag {
		t.Fatal("changed policy not published")
	}
	next, err := core.VerifyPolicyBundle(changed, conn.BundlePublicKey, conn.NodeID)
	if err != nil || next.Revision <= bundle.Revision {
		t.Fatal("revision did not advance")
	}
	for _, token := range []string{"", "invalid", "legacy"} {
		if w = fetch(token, etag); w.Code != 401 && w.Code != 403 {
			t.Fatal("bundle accepted without device authentication", w.Code)
		}
	}
	if err = e.RevokeClient(core.WithActor(context.Background(), core.SystemActor("test")), conn.NodeID); err != nil {
		t.Fatal(err)
	}
	if w = fetch(conn.Token, core.PolicyBundleETag(changed)); w.Code != http.StatusForbidden {
		t.Fatal("revoked device received cached 304")
	}
	r := httptest.NewRequest("POST", "http://localhost/api/v1/reviews", bytes.NewBufferString(`{}`))
	r.Header.Set("Authorization", "Bearer "+conn.Token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("revoked device decision accepted")
	}
}

func TestPolicyBundleOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/protection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err = json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	operation, ok := spec.Paths["/api/v1/client/bundle"]["get"]
	var get struct {
		Security  []map[string][]string      `json:"security"`
		Responses map[string]json.RawMessage `json:"responses"`
	}
	if !ok || json.Unmarshal(operation, &get) != nil || len(get.Security) != 1 {
		t.Fatal("bundle device-auth contract missing")
	}
	if _, ok = get.Security[0]["deviceCredential"]; !ok {
		t.Fatal("wrong bundle authentication contract")
	}
	for _, code := range []string{"200", "304", "401", "403", "503"} {
		if _, ok = get.Responses[code]; !ok {
			t.Fatal("bundle response contract missing", code)
		}
	}
	// Derive field names from the shared Go provider/consumer types. This is a
	// contract drift check, not a claim to run a full OpenAPI schema validator.
	for name, value := range map[string]any{"PolicyBundle": core.PolicyBundle{}, "SignedPolicyBundle": core.SignedPolicyBundle{}, "BundleRule": core.Rule{}, "ClientConnection": core.ClientConnection{}} {
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

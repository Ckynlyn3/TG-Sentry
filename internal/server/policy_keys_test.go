package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func policyKeysFixture(t *testing.T) (*Server, core.ClientConnection) {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "trust HTTP")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	return New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir()), conn
}

func policyKeysRequest(h http.Handler, method, target, authorization string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "192.0.2.1:12345"
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Plan §3.6/§6: deliver one exact public record at a time, including history.
func TestClientPolicyKeysHTTP(t *testing.T) {
	s, conn := policyKeysFixture(t)
	h := s.Handler()
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })
	log.Print("trust HTTP log capture active")
	oldID := core.BundleKeyID(conn.BundlePublicKey)
	if err := s.Engine.RotateBundleKey(); err != nil {
		t.Fatal(err)
	}
	if err := s.Engine.RetireBundleKey(oldID); err != nil {
		t.Fatal(err)
	}
	previous, err := core.VerifyTrustBootstrap(*conn.BundleTrust, conn.BundlePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= s.Engine.BundleTrustVersion(); version++ {
		w := policyKeysRequest(h, "GET", "http://localhost/api/v1/client/keys/"+strconv.Itoa(version), "Bearer "+conn.Token, nil)
		var signed core.SignedTrustRecord
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &signed) != nil {
			t.Fatalf("trust version %d HTTP %d", version, w.Code)
		}
		want, err := s.Engine.BundleTrustRecord(version)
		if err != nil {
			t.Fatal(err)
		}
		publicJSON, err := json.Marshal(want)
		if err != nil || !bytes.Equal(bytes.TrimSpace(w.Body.Bytes()), publicJSON) {
			t.Fatal("response differs from committed public record or contains extra fields")
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || w.Body.Len() > core.PolicyBundleMaxBytes {
			t.Fatal("invalid record response type or size")
		}
		if version > 1 {
			previous, err = core.VerifyTrustRecord(signed, previous)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if !strings.Contains(logs.String(), "trust HTTP log capture active") {
		t.Fatal("log capture inactive")
	}
	if strings.Contains(logs.String(), conn.Token) || strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("secret leaked to logs")
	}
}

func TestClientPolicyKeysValidationAndAuthentication(t *testing.T) {
	s, conn := policyKeysFixture(t)
	s.PublicURL = "https://review.example"
	h := s.Handler()
	// Existing admin-session boundary still cannot substitute for a device.
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	for _, target := range []string{"http://localhost", s.PublicURL} {
		for _, version := range []string{"1", "2", "bad"} {
			url := target + "/api/v1/client/keys/" + version
			for _, auth := range []string{"", "Bearer invalid", "Bearer legacy", "Basic " + conn.Token} {
				w := policyKeysRequest(h, "GET", url, auth, nil)
				if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
					t.Fatalf("auth before lookup: %s HTTP %d", version, w.Code)
				}
			}
			if w := policyKeysRequest(h, "GET", url, "", cookie); w.Code != http.StatusForbidden {
				t.Fatalf("admin cookie served trust: HTTP %d", w.Code)
			}
		}
		if w := policyKeysRequest(h, "GET", target+"/api/v1/client/keys/1", "Bearer "+conn.Token, nil); w.Code != http.StatusOK {
			t.Fatalf("enrolled device denied: HTTP %d", w.Code)
		}
	}
	for _, tc := range []struct {
		version string
		status  int
	}{{"2", http.StatusNotFound}, {"0", http.StatusBadRequest}, {"-1", http.StatusBadRequest}, {"bad", http.StatusBadRequest}, {"1.5", http.StatusBadRequest}, {"999999999999999999999999999999999999", http.StatusBadRequest}} {
		w := policyKeysRequest(h, "GET", "http://localhost/api/v1/client/keys/"+tc.version, "Bearer "+conn.Token, nil)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), `"error"`) {
			t.Fatalf("version %s HTTP %d, want %d", tc.version, w.Code, tc.status)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if w := policyKeysRequest(h, method, "http://localhost/api/v1/client/keys/1", "Bearer "+conn.Token, nil); w.Code != http.StatusForbidden {
			t.Fatalf("non-GET allowed: %s HTTP %d", method, w.Code)
		}
	}
	if err := s.Engine.RevokeClient(core.WithActor(context.Background(), core.SystemActor("test")), conn.NodeID); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1", "2", "bad"} {
		if w := policyKeysRequest(h, "GET", "http://localhost/api/v1/client/keys/"+version, "Bearer "+conn.Token, nil); w.Code != http.StatusForbidden {
			t.Fatalf("revoked device received trust: HTTP %d", w.Code)
		}
	}
}

func TestClientPolicyKeysBlockedSource(t *testing.T) {
	s, conn := policyKeysFixture(t)
	ctx := core.WithActor(context.Background(), core.SystemActor("test"))
	ticket, err := s.Engine.CreateClientRequest("blocked source", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Engine.DecideClientRequest(ctx, ticket.ID, "block_ip"); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	for _, version := range []string{"1", "2", "bad"} {
		if w := policyKeysRequest(h, "GET", "http://localhost/api/v1/client/keys/"+version, "Bearer "+conn.Token, nil); w.Code != http.StatusForbidden {
			t.Fatalf("blocked source received trust: HTTP %d", w.Code)
		}
	}
}

// Plan §3.6/§6: key-only transitions do not alter the payload ETag.
func TestClientPolicyBundleTrustTransitions(t *testing.T) {
	s, conn := policyKeysFixture(t)
	h := s.Handler()
	etag := ""
	oldID := core.BundleKeyID(conn.BundlePublicKey)
	for version := 1; version <= 3; version++ {
		w := policyKeysRequest(h, "GET", "http://localhost/api/v1/client/bundle", "Bearer "+conn.Token, nil)
		var signed core.SignedPolicyBundle
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &signed) != nil || w.Header().Get("TG-Trust-Version") != strconv.Itoa(version) {
			t.Fatalf("bundle trust version %d missing on 200", version)
		}
		if etag != "" && w.Header().Get("ETag") != etag {
			t.Fatal("key-only transition changed ETag")
		}
		etag = w.Header().Get("ETag")
		record, err := s.Engine.BundleTrustRecord(version)
		if err != nil {
			t.Fatal(err)
		}
		var trust core.TrustRecord
		if err := json.Unmarshal(record.Payload, &trust); err != nil {
			t.Fatal(err)
		}
		if _, _, err := core.VerifyPolicyBundleWithTrust(signed, signed.KeyID, trust, conn.NodeID); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "http://localhost/api/v1/client/bundle", nil)
		r.Header.Set("Authorization", "Bearer "+conn.Token)
		r.Header.Set("If-None-Match", etag)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != etag || w.Header().Get("TG-Trust-Version") != strconv.Itoa(version) {
			t.Fatalf("bundle trust version %d missing on 304", version)
		}
		if version == 1 {
			err = s.Engine.RotateBundleKey()
		} else if version == 2 {
			err = s.Engine.RetireBundleKey(oldID)
			if signed.KeyID == oldID {
				t.Fatal("rotation did not switch bundle signer")
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

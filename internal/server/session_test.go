package server

import (
	"aegishook/internal/core"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"
)

func sessionServer(t *testing.T) (*Server, *time.Time) {
	t.Helper()
	now := time.Now()
	s := New(&core.Engine{Dir: t.TempDir()}, fstest.MapFS{}, "legacy-test-admin", "test-hook", t.TempDir())
	s.clock = func() time.Time { return now }
	return s, &now
}

func testHumanSession(s *Server) session {
	return s.createSession(session{Kind: "human", Principal: core.Principal{Issuer: "https://issuer.example", Subject: "subject"}, Name: "Fixture", Role: core.RoleAuditor, Tenant: "default"})
}

func TestIdle30mExpires(t *testing.T) {
	s, now := sessionServer(t)
	v := testHumanSession(s)
	*now = now.Add(30*time.Minute + time.Nanosecond)
	if _, ok := s.useSession(v.ID); ok {
		t.Fatal("idle session accepted")
	}
	if _, exists := s.sessions[v.ID]; exists {
		t.Fatal("expired session retained")
	}
}

func TestActivityExtendsIdleNotAbsolute(t *testing.T) {
	s, now := sessionServer(t)
	v := testHumanSession(s)
	for now.Before(v.AbsoluteDeadline) {
		*now = now.Add(30 * time.Minute)
		got, ok := s.useSession(v.ID)
		if !ok || got.AbsoluteDeadline != v.AbsoluteDeadline || got.LastSeen != *now {
			t.Fatal("activity did not extend idle only")
		}
	}
	*now = now.Add(time.Nanosecond)
	if _, ok := s.useSession(v.ID); ok {
		t.Fatal("activity extended absolute lifetime")
	}
}

func TestAbsolute8hExpires(t *testing.T) {
	s, now := sessionServer(t)
	v := testHumanSession(s)
	if v.AbsoluteDeadline.Sub(*now) != 8*time.Hour {
		t.Fatal("wrong absolute lifetime")
	}
	// Keep idle fresh to exercise absolute expiry independently.
	v.LastSeen = v.AbsoluteDeadline
	s.sessions[v.ID] = v
	*now = v.AbsoluteDeadline.Add(time.Nanosecond)
	if _, ok := s.useSession(v.ID); ok {
		t.Fatal("absolute-expired session accepted")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	s, _ := sessionServer(t)
	v := testHumanSession(s)
	for _, public := range []bool{false, true} {
		origin := "http://127.0.0.1:18790"
		if public {
			origin = "https://console.example"
			s.PublicURL = origin
		}
		w := httptest.NewRecorder()
		s.setSessionCookie(w, httptest.NewRequest("GET", origin+"/", nil), v.ID)
		c := w.Result().Cookies()[0]
		if c.Name != "aegis_session" || c.Value != v.ID || c.SameSite != http.SameSiteStrictMode {
			t.Fatal("wrong session cookie")
		}
		if !c.HttpOnly || c.Secure != public || c.MaxAge != 28800 || c.Path != "/" || c.Domain != "" {
			t.Fatal("weak or incorrectly scoped cookie")
		}
	}
}

package server

import (
	"aegishook/internal/core"
	"net/http"
	"time"
)

// OWASP Session Management: low-risk idle upper bound and office-day absolute
// upper bound, selected explicitly by the approved #12 plan §3.4.
const (
	sessionIdle       = 30 * time.Minute
	sessionAbsolute   = 8 * time.Hour
	sessionCookieName = "aegis_session"
)

type session struct {
	ID               string
	Kind             string
	Principal        core.Principal
	Name             string
	Role             core.Role
	Tenant           string
	LastSeen         time.Time
	AbsoluteDeadline time.Time
}

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *Server) createSession(v session) session {
	now := s.now()
	v.ID = core.ID() + core.ID()
	v.LastSeen = now
	v.AbsoluteDeadline = now.Add(sessionAbsolute)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[v.ID] = v
	return v
}

func (s *Server) useSession(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[id]
	now := s.now()
	if !ok || now.After(v.AbsoluteDeadline) || now.Sub(v.LastSeen) > sessionIdle {
		delete(s.sessions, id)
		return session{}, false
	}
	v.LastSeen = now
	s.sessions[id] = v
	return v, true
}

func (s *Server) deleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, id string) {
	age := int(sessionAbsolute.Seconds())
	if id == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: id, Path: "/", HttpOnly: true, Secure: s.publicRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: age})
}

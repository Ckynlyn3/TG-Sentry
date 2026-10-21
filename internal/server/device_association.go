package server

import (
	"aegishook/internal/core"
	"errors"
	"mime"
	"net/http"
	"strings"
)

const deviceAssociationNext = "/device/associate?continuation=confirm"

func deviceAssociationBootstrap(r *http.Request) bool {
	return r.Method == "POST" && r.URL.EscapedPath() == "/api/v1/device-grants/association/begin"
}

func deviceAssociationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrDeviceUserCode), errors.Is(err, core.ErrDeviceGrantNotFound):
		fail(w, 404, err)
	case errors.Is(err, core.ErrDeviceUserCodeThrottled):
		fail(w, 400, err)
	case errors.Is(err, core.ErrDeviceGrantDecided):
		fail(w, 409, err)
	default:
		fail(w, 500, errors.New("device grant store unavailable"))
	}
}

func (s *Server) beginDeviceAssociation(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		fail(w, 503, errors.New("sso_not_configured"))
		return
	}
	var in struct {
		UserCode string `json:"userCode"`
	}
	// Native HTML form navigation follows begin → login → OIDC without fetch redirects.
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/x-www-form-urlencoded" {
		form, ok := readDeviceForm(w, r)
		if !ok {
			return
		}
		if len(form) != 2 {
			fail(w, 400, errors.New("userCode and client_id required"))
			return
		}
		in.UserCode = form.Get("userCode")
	} else if !readDeviceJSON(w, r, &in) {
		return
	}
	if in.UserCode == "" {
		fail(w, 400, errors.New("userCode required"))
		return
	}
	grant, err := s.Engine.PublicDeviceGrantLookup(in.UserCode, s.clientIP(r))
	if err != nil {
		deviceAssociationError(w, err)
		return
	}
	if _, err = s.Engine.DeviceGrantAssociation(grant.GrantID); err != nil {
		deviceAssociationError(w, err)
		return
	}
	// Reuse transaction lifetime/state storage; only the cookie's scoped bootstrap
	// path differs until login rotates it to the existing callback cookie.
	state := core.ID() + core.ID()
	tx := oidcTransaction{AssociationGrant: grant.GrantID, AssociationDeadline: s.now().Add(oidcTransactionLifetime), Deadline: s.now().Add(oidcTransactionLifetime)}
	s.mu.Lock()
	for key, v := range s.oidcTransactions {
		if !s.now().Before(v.Deadline) {
			delete(s.oidcTransactions, key)
		}
	}
	s.oidcTransactions[state] = tx
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: oidcTransactionCookie, Value: state, Path: "/api/v1/auth/login", HttpOnly: true, Secure: s.publicRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: int(oidcTransactionLifetime.Seconds())})
	http.Redirect(w, r, "/api/v1/auth/login", http.StatusFound)
}

func (s *Server) consumeAssociationLogin(w http.ResponseWriter, r *http.Request) (oidcTransaction, bool) {
	cookie, err := r.Cookie(oidcTransactionCookie)
	if err != nil {
		return oidcTransaction{}, false
	}
	http.SetCookie(w, &http.Cookie{Name: oidcTransactionCookie, Value: "", Path: "/api/v1/auth/login", HttpOnly: true, Secure: s.publicRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.oidcTransactions[cookie.Value]
	delete(s.oidcTransactions, cookie.Value)
	return tx, ok && tx.AssociationGrant != "" && s.now().Before(tx.AssociationDeadline)
}

func (s *Server) associationSession(w http.ResponseWriter, r *http.Request) (session, bool) {
	v := requestSession(r)
	if v.Kind != "human" || v.AssociationGrant == "" || !s.now().Before(v.AssociationDeadline) {
		fail(w, 403, errors.New("grant-bound association continuation required"))
		return session{}, false
	}
	return v, true
}
func (s *Server) previewDeviceAssociation(w http.ResponseWriter, r *http.Request) {
	v, ok := s.associationSession(w, r)
	if !ok {
		return
	}
	grant, err := s.Engine.DeviceGrantAssociation(v.AssociationGrant)
	if err != nil {
		deviceAssociationError(w, err)
		return
	}
	// OWASP Transaction Authorization §2.6: bind one confirmation to this session/preview.
	// https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html#26-transaction-data-should-be-protected-against-modification
	confirmation := core.ID() + core.ID() // Existing session/OIDC random-value precedent.
	s.mu.Lock()
	current, exists := s.sessions[v.ID]
	if exists && current.AssociationGrant == v.AssociationGrant {
		current.AssociationConfirmation = confirmation
		s.sessions[v.ID] = current
	}
	s.mu.Unlock()
	if !exists {
		fail(w, 403, errors.New("grant-bound association continuation required"))
		return
	}
	write(w, struct {
		Grant        core.DeviceGrantLookup `json:"grant"`
		User         core.AssociatedUser    `json:"user"`
		Confirmation string                 `json:"confirmation"`
	}{grant, core.AssociatedUser{Principal: v.Principal, Name: v.Name}, confirmation})
}
func (s *Server) confirmDeviceAssociation(w http.ResponseWriter, r *http.Request) {
	v, ok := s.associationSession(w, r)
	if !ok {
		return
	}
	var in struct {
		Confirm      bool   `json:"confirm"`
		Confirmation string `json:"confirmation"`
	}
	if !readDeviceJSON(w, r, &in) {
		return
	}
	if !in.Confirm || in.Confirmation == "" {
		fail(w, 400, errors.New("explicit confirmation required"))
		return
	}
	// Consume under the session lock before the write: replay cannot race confirmation.
	s.mu.Lock()
	current, exists := s.sessions[v.ID]
	valid := exists && current.AssociationGrant == v.AssociationGrant && current.AssociationConfirmation != "" && eq(current.AssociationConfirmation, in.Confirmation)
	if valid {
		current.AssociationConfirmation = ""
		s.sessions[v.ID] = current
	}
	s.mu.Unlock()
	if !valid {
		fail(w, 409, errors.New("association preview changed; review again"))
		return
	}
	grant, err := s.Engine.ConfirmDeviceGrantAssociation(r.Context(), v.AssociationGrant, core.AssociatedUser{Principal: v.Principal, Name: v.Name})
	if err != nil {
		deviceAssociationError(w, err)
		return
	}
	s.mu.Lock()
	current, exists = s.sessions[v.ID]
	if exists {
		current.AssociationGrant = ""
		current.AssociationDeadline = v.AssociationDeadline
		s.sessions[v.ID] = current
	}
	s.mu.Unlock()
	w.Header().Set("ETag", core.DeviceGrantETag(grant))
	write(w, grant)
}

// Reuse protection's RFC 9110 entity-tag parser/list convention, but defer
// comparison to the grant writer lock; never read a global protection revision.
func deviceGrantIfMatch(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	value := strings.Trim(strings.Join(r.Header.Values("If-Match"), ","), " \t")
	if value == "" {
		fail(w, 428, errors.New("If-Match reviewed grant required"))
		return nil, false
	}
	tags := []string{}
	for value != "" {
		value = strings.TrimLeft(value, " \t,")
		if value == "" {
			break
		}
		tag, rest := protectionEntityTag(value)
		if tag == "" {
			fail(w, 400, errors.New("an explicit entity-tag list is required; wildcard is unsupported"))
			return nil, false
		}
		tags = append(tags, tag)
		value = strings.TrimLeft(rest, " \t")
		if value != "" && value[0] != ',' {
			fail(w, 400, errors.New("invalid entity-tag list separator"))
			return nil, false
		}
	}
	return tags, true
}

package server

import (
	"aegishook/internal/core"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Approved #12 plan D2: exact method + ServeMux pattern, never path prefixes.
// Empty entries are non-session routes with their existing credential checks;
// they do not grant a cookie permission. Missing entries require admin.
var routeRoles = map[string]core.Role{
	"POST /api/v1/credentials":            core.RoleAdmin,
	"PUT /api/v1/credentials/{id}":        core.RoleAdmin,
	"DELETE /api/v1/credentials/{id}":     core.RoleAdmin,
	"GET /api/v1/credentials":             core.RoleAuditor,
	"GET /api/v1/credentials/{id}":        core.RoleAuditor,
	"GET /api/v1/client/credentials/{id}": "",
	"GET /livez":                          "", "GET /readyz": "", // Public probes; inventory only, outside session middleware.
	"GET /api/v1/auth/login": "", "GET /api/v1/auth/callback": "",
	"POST /api/v1/login":         "", // Removed in #12 (plan §4): kept pre-auth only so the removed endpoint returns 404, not 401.
	"POST /api/v1/cli/session":   "",
	"POST /api/v1/client/enroll": "", "POST /api/v1/client/requests": "",
	"POST /api/v1/client/device-authorization": "", "POST /api/v1/client/device-token": "",
	"POST /api/v1/device-grants/lookup": core.RoleAdmin, "POST /api/v1/device-grants/decision": core.RoleAdmin,
	"POST /api/v1/device-grants/association/begin": "",
	// #72 S1/U3: never granted by role; the grant-bound continuation is the only
	// admission (see deviceAssociationRoutes). Admin is the deny-by-default floor.
	"GET /api/v1/device-grants/association/confirm":  core.RoleAdmin,
	"POST /api/v1/device-grants/association/confirm": core.RoleAdmin,
	"GET /api/v1/client/requests/{id}":               "",
	"GET /api/v1/client/keys/{version}":              "", // #65: existing enrolled-device authentication, not a console role.
	"GET /install/{id}/{script}":                     "", "GET /install/{id}/{kind}/{os}/{arch}": "",
	"/api/": core.RoleAdmin, "/": core.RoleAdmin,
	"GET /api/v1/me": core.RoleReadOnly, "POST /api/v1/logout": core.RoleReadOnly,
	"GET /api/v1/overview":                       core.RoleReadOnly,
	"GET /api/v1/calls":                          core.RoleReadOnly,
	"GET /api/v1/usage":                          core.RoleReadOnly,
	"GET /api/v1/sessions":                       core.RoleReadOnly,
	"GET /api/v1/session-summaries":              core.RoleReadOnly, // #16 S3 contract.
	"GET /api/v1/discovered-agents":              core.RoleReadOnly,
	"GET /api/v1/agent-assets":                   core.RoleReadOnly,
	"GET /api/v1/agent-assets/{id}":              core.RoleReadOnly,
	"GET /api/v1/instances":                      core.RoleReadOnly,
	"GET /api/v1/agents":                         core.RoleReadOnly,
	"GET /api/v1/installations":                  core.RoleReadOnly,
	"GET /api/v1/client-nodes":                   core.RoleReadOnly,
	"GET /api/v1/client-nodes/{id}/tags":         core.RoleReadOnly,
	"GET /api/v1/client-requests":                core.RoleReadOnly,
	"GET /api/v1/client-ip-blocks":               core.RoleReadOnly,
	"GET /api/v1/rules":                          core.RoleReadOnly,
	"GET /api/v1/rules/defaults":                 core.RoleReadOnly,
	"GET /api/v1/scopes":                         core.RoleReadOnly,
	"GET /api/v1/templates":                      core.RoleReadOnly,
	"GET /api/v1/templates/{id}":                 core.RoleReadOnly,
	"GET /api/v1/policies":                       core.RoleReadOnly,
	"GET /api/v1/policies/{id}":                  core.RoleReadOnly,
	"GET /api/v1/acl":                            core.RoleReadOnly,
	"GET /api/v1/acl/{id}":                       core.RoleReadOnly,
	"GET /api/v1/reviews/{id}":                   core.RoleAuditor,
	"GET /api/v1/calls/export":                   core.RoleAuditor,
	"GET /api/v1/audit":                          core.RoleAuditor,
	"GET /api/v1/audit/export":                   core.RoleAuditor,
	"GET /api/v1/risk-events":                    core.RoleAuditor,
	"GET /api/v1/risk-events/stats":              core.RoleAuditor,
	"GET /api/v1/risk-events/{id}":               core.RoleAuditor,
	"GET /api/v1/risk-events/export":             core.RoleAuditor,
	"GET /api/v1/events":                         core.RoleAuditor,
	"GET /api/v1/settings":                       core.RoleAuditor,
	"GET /api/v1/settings/versions":              core.RoleAuditor,
	"GET /api/v1/settings/default-prompt":        core.RoleAuditor,
	"GET /api/v1/pi":                             core.RoleAuditor,
	"POST /api/v1/rules/test":                    core.RoleAuditor,
	"POST /api/v1/templates/review":              core.RoleAuditor,
	"POST /api/v1/templates/{id}/review":         core.RoleAuditor,
	"POST /api/v1/policies/review":               core.RoleAuditor,
	"POST /api/v1/policies/{id}/review":          core.RoleAuditor,
	"POST /api/v1/acl/review":                    core.RoleAuditor,
	"POST /api/v1/acl/{id}/review":               core.RoleAuditor,
	"POST /api/v1/client-nodes/{id}/tags/review": core.RoleAuditor,
	"PUT /api/v1/settings":                       core.RoleAdmin,
	"POST /api/v1/model/test":                    core.RoleAdmin,
	"POST /api/v1/installations":                 core.RoleAdmin,
	"DELETE /api/v1/installations/{id}":          core.RoleAdmin,
	"POST /api/v1/rules":                         core.RoleAdmin, "DELETE /api/v1/rules/{id}": core.RoleAdmin,
	"POST /api/v1/scopes": core.RoleAdmin, "DELETE /api/v1/scopes/{id}": core.RoleAdmin,
	"POST /api/v1/client-enrollments":            core.RoleAdmin,
	"DELETE /api/v1/client-enrollments/{id}":     core.RoleAdmin,
	"GET /api/v1/client-enrollments":             core.RoleAdmin,
	"GET /api/v1/client-installer":               core.RoleAdmin,
	"DELETE /api/v1/client-nodes/{id}":           core.RoleAdmin,
	"DELETE /api/v1/client-ip-blocks/{id}":       core.RoleAdmin,
	"POST /api/v1/client-requests/{id}/decision": core.RoleAdmin,
	"POST /api/v1/approvals/{id}/decision":       core.RoleAdmin,
	"POST /api/v1/templates":                     core.RoleAdmin,
	"PUT /api/v1/templates/{id}":                 core.RoleAdmin, "DELETE /api/v1/templates/{id}": core.RoleAdmin,
	"POST /api/v1/policies":     core.RoleAdmin,
	"PUT /api/v1/policies/{id}": core.RoleAdmin, "DELETE /api/v1/policies/{id}": core.RoleAdmin,
	"PUT /api/v1/client-nodes/{id}/tags":     core.RoleAdmin,
	"POST /api/v1/discovery-policy/review":   core.RoleAdmin,
	"PUT /api/v1/discovery-policy":           core.RoleAdmin,
	"POST /api/v1/acl":                       core.RoleAdmin,
	"PUT /api/v1/acl/{id}":                   core.RoleAdmin,
	"DELETE /api/v1/acl/{id}":                core.RoleAdmin,
	"GET /api/v1/log-whitelist":              core.RoleReadOnly,
	"GET /api/v1/log-whitelist/{id}":         core.RoleReadOnly,
	"POST /api/v1/log-whitelist/review":      core.RoleAdmin,
	"POST /api/v1/log-whitelist/{id}/review": core.RoleAdmin,
	"POST /api/v1/log-whitelist":             core.RoleAdmin,
	"PUT /api/v1/log-whitelist/{id}":         core.RoleAdmin,
	"DELETE /api/v1/log-whitelist/{id}":      core.RoleAdmin,
	// Cookie callers of hook/device-only routes remain admin-default (D2).
	"POST /api/v1/instances":                          core.RoleAdmin,
	"POST /api/v1/instances/{id}/heartbeat":           core.RoleAdmin,
	"POST /api/v1/instances/{id}/shutdown":            core.RoleAdmin,
	"POST /api/v1/reviews":                            core.RoleAdmin,
	"POST /api/v1/reviews/{id}/result":                core.RoleAdmin,
	"POST /api/v1/reviews/{id}/transform-tool-output": core.RoleAdmin,
	"GET /api/v1/client/bundle":                       core.RoleAdmin,
	"POST /api/v1/client/discovery-reports":           core.RoleAdmin,
}

var cliRoutes = map[string]bool{
	"GET /api/v1/agents": true, "GET /api/v1/instances": true,
	"GET /api/v1/installations": true, "POST /api/v1/installations": true,
	"DELETE /api/v1/installations/{id}": true,
	"GET /api/v1/me":                    true, "POST /api/v1/logout": true,
}

// #72 S1/U3: the association preview/confirm routes are admitted by the
// server-owned grant continuation, never by a console role. They stay in
// routeRoles for the exact-route inventory, but generic role matrices skip this
// class; dedicated tests cover bound success and unbound denial.
var deviceAssociationRoutes = map[string]bool{
	"GET /api/v1/device-grants/association/confirm":  true,
	"POST /api/v1/device-grants/association/confirm": true,
}

func knownRole(role core.Role) bool {
	return role == core.RoleAdmin || role == core.RoleAuditor || role == core.RoleReadOnly
}

func sessionAllows(v session, pattern string) bool {
	if deviceAssociationRoutes[pattern] {
		return v.Kind == "human" && v.AssociationGrant != ""
	}
	if !knownRole(v.Role) || (v.Kind != "human" && v.Kind != "cli") || (v.Kind == "cli" && !cliRoutes[pattern]) {
		return false
	}
	required := routeRoles[pattern]
	if required == "" {
		required = core.RoleAdmin
	}
	return v.Role == core.RoleAdmin || (v.Role == core.RoleAuditor && required != core.RoleAdmin) || required == core.RoleReadOnly
}

type sessionContextKey struct{}

func requestSession(r *http.Request) session {
	v, _ := r.Context().Value(sessionContextKey{}).(session)
	return v
}

// Plan §3.6a: only the TCP peer is authoritative, never Host/X-Real-IP/XFF.
func (s *Server) localCLIPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || s.publicRequest(r) {
		return false
	}
	peer, err := netip.ParseAddr(host)
	return err == nil && peer.Unmap().IsLoopback()
}

func (s *Server) cliSession(w http.ResponseWriter, r *http.Request) {
	if !s.localCLIPeer(r) {
		fail(w, http.StatusForbidden, errors.New("local CLI peer required"))
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if !read(w, r, &in) {
		return
	}
	if !eq(in.Token, s.AdminToken) {
		fail(w, http.StatusUnauthorized, errors.New("invalid CLI token"))
		return
	}
	v := s.createSession(session{Kind: "cli", Principal: core.Principal{Issuer: "local", Subject: "cli"}, Name: "cli", Role: core.RoleAdmin, Tenant: "default"})
	s.setSessionCookie(w, r, v.ID)
	write(w, map[string]bool{"ok": true})
}

func (s *Server) authorizeSession(w http.ResponseWriter, r *http.Request, mux *http.ServeMux) (*http.Request, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		fail(w, http.StatusUnauthorized, errors.New("session required"))
		return r, false
	}
	v, ok := s.useSession(cookie.Value)
	if !ok {
		fail(w, http.StatusUnauthorized, errors.New("session required"))
		return r, false
	}
	if v.Kind == "cli" && !s.localCLIPeer(r) {
		s.deleteSession(v.ID)
		fail(w, http.StatusForbidden, errors.New("local CLI peer required"))
		return r, false
	}
	_, pattern := mux.Handler(r)
	if !strings.HasPrefix(pattern, r.Method+" ") {
		pattern = ""
	}
	if !sessionAllows(v, pattern) {
		fail(w, http.StatusForbidden, errors.New("forbidden"))
		return r, false
	}
	ctx := context.WithValue(r.Context(), sessionContextKey{}, v)
	ctx = core.WithActor(ctx, core.Actor{Issuer: v.Principal.Issuer, Subject: v.Principal.Subject, Name: v.Name, Kind: v.Kind})
	return r.WithContext(ctx), true
}

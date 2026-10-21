package server

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Named local exception in plan §9: five-minute transactions, evicted on login.
const oidcTransactionLifetime = 5 * time.Minute
const oidcCallbackPath = "/api/v1/auth/callback"
const oidcTransactionCookie = "aegis_oidc_tx"

type oidcTransaction struct {
	Nonce               string
	Verifier            string
	Next                string
	Deadline            time.Time
	AssociationGrant    string
	AssociationDeadline time.Time
}

type oidcSettings struct {
	issuer           string
	oauth            oauth2.Config
	roleClaim        string
	roleMap          map[core.Role]string
	trustedAudiences []string
	origin           string
}

// Configuration is captured when Handler is built, after the listener is bound.
// Redirect identity never comes from a request Host or forwarded header.
func readOIDCSettings(publicURL, listenAddr string) *oidcSettings {
	env := func(key string) string { return os.Getenv("TG_SENTRY_OIDC_" + key) }
	c := &oidcSettings{issuer: env("ISSUER"), roleClaim: env("ROLE_CLAIM"), roleMap: map[core.Role]string{}, oauth: oauth2.Config{ClientID: env("CLIENT_ID"), ClientSecret: env("CLIENT_SECRET"), RedirectURL: env("REDIRECT_URL"), Scopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}}}
	if c.issuer == "" || c.oauth.ClientID == "" || c.oauth.ClientSecret == "" || c.oauth.RedirectURL == "" || env("ROLE_MAP") == "" {
		return nil
	}
	issuer, err := url.Parse(c.issuer)
	if err != nil || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || (issuer.Scheme != "https" && !(issuer.Scheme == "http" && hasHost(issuer.Hostname()))) {
		return nil
	}
	c.origin = oidcRedirectOrigin(c.oauth.RedirectURL, publicURL, listenAddr)
	if c.origin == "" {
		return nil
	}
	if c.roleClaim == "" {
		c.roleClaim = "roles"
	}
	for _, entry := range strings.Split(env("ROLE_MAP"), ",") {
		key, value, ok := strings.Cut(entry, "=")
		role := core.Role(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || value == "" || (role != core.RoleAdmin && role != core.RoleAuditor && role != core.RoleReadOnly) || c.roleMap[role] != "" {
			return nil
		}
		c.roleMap[role] = value
	}
	if len(c.roleMap) != 3 {
		return nil
	}
	if audiences := env("TRUSTED_AUDIENCES"); audiences != "" {
		for _, aud := range strings.Split(audiences, ",") {
			aud = strings.TrimSpace(aud)
			if aud == "" {
				return nil
			}
			c.trustedAudiences = append(c.trustedAudiences, aud)
		}
	}
	return c
}

func oidcRedirectOrigin(redirectURL, publicURL, listenAddr string) string {
	redirect, err := url.Parse(redirectURL)
	if err != nil || redirect.User != nil || redirect.RawQuery != "" || redirect.Fragment != "" || redirect.Path != oidcCallbackPath {
		return ""
	}
	if publicURL != "" {
		origin, err := url.Parse(publicURL)
		if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || redirectURL != publicURL+oidcCallbackPath {
			return ""
		}
		return publicURL
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" || port == "0" || redirect.Scheme != "http" || (redirect.Hostname() != "127.0.0.1" && redirect.Hostname() != "::1") || redirect.Port() != port {
		return ""
	}
	// RFC 8252 §§7.3, 8.3: an IP-literal loopback redirect, not localhost.
	origin := "http://" + redirect.Host
	if redirectURL != origin+oidcCallbackPath {
		return ""
	}
	return origin
}

func (c *oidcSettings) provider(ctx context.Context) (*oidc.Provider, oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, c.issuer)
	config := c.oauth
	if err == nil {
		config.Endpoint = provider.Endpoint()
	}
	return provider, config, err
}

func oidcPreAuth(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/api/v1/auth/login" || r.URL.Path == oidcCallbackPath)
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		fail(w, 503, errors.New("sso_not_configured"))
		return
	}
	if prior, err := r.Cookie(sessionCookieName); err == nil {
		if _, ok := s.useSession(prior.Value); ok {
			s.deleteSession(prior.Value)
			s.setSessionCookie(w, r, "")
		}
	}
	_, config, err := s.oidc.provider(r.Context())
	if err != nil {
		fail(w, 401, errors.New("sso_auth_failed"))
		return
	}
	state := core.ID() + core.ID()
	tx := oidcTransaction{Nonce: core.ID() + core.ID(), Verifier: oauth2.GenerateVerifier(), Next: safeNext(r.URL.Query().Get("next"), s.oidc.origin), Deadline: s.now().Add(oidcTransactionLifetime)}
	// Only begin's server-owned, browser-bound transaction selects association.
	// A next/query parameter or existing console identity supplies no authority.
	if prior, ok := s.consumeAssociationLogin(w, r); ok {
		tx.AssociationGrant = prior.AssociationGrant
		tx.AssociationDeadline = prior.AssociationDeadline
		tx.Next = deviceAssociationNext
	}
	s.mu.Lock()
	// ponytail: linear eviction under the existing mutex; no sweeper goroutine.
	for key, v := range s.oidcTransactions {
		if s.now().After(v.Deadline) {
			delete(s.oidcTransactions, key)
		}
	}
	s.oidcTransactions[state] = tx
	s.mu.Unlock()
	s.setTransactionCookie(w, r, state)
	http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(tx.Nonce), oauth2.S256ChallengeOption(tx.Verifier)), http.StatusFound)
}

func (s *Server) setTransactionCookie(w http.ResponseWriter, r *http.Request, state string) {
	age := int(oidcTransactionLifetime.Seconds())
	if state == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: oidcTransactionCookie, Value: state, Path: oidcCallbackPath, HttpOnly: true, Secure: s.publicRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: age})
}

func (s *Server) consumeTransaction(r *http.Request) (oidcTransaction, bool) {
	cookie, err := r.Cookie(oidcTransactionCookie)
	state := r.URL.Query().Get("state")
	if err != nil || !eq(cookie.Value, state) {
		return oidcTransaction{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.oidcTransactions[state]
	delete(s.oidcTransactions, state)
	return tx, ok && !s.now().After(tx.Deadline)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		fail(w, 503, errors.New("sso_not_configured"))
		return
	}
	tx, ok := s.consumeTransaction(r)
	s.setTransactionCookie(w, r, "")
	if !ok || r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		fail(w, 401, errors.New("sso_auth_failed"))
		return
	}
	identity, err := s.exchangeIdentity(r.Context(), tx, r.URL.Query().Get("code"))
	if err != nil {
		fail(w, 401, errors.New("sso_auth_failed"))
		return
	}
	recovery, err := s.Engine.IsRecoveryAdmin(identity.Principal)
	if err != nil {
		fail(w, 401, errors.New("sso_auth_failed"))
		return
	}
	if recovery {
		identity.Role = core.RoleAdmin
	}
	if tx.AssociationGrant != "" {
		if !s.now().Before(tx.AssociationDeadline) {
			fail(w, 401, errors.New("sso_auth_failed"))
			return
		}
		if _, err := s.Engine.DeviceGrantAssociation(tx.AssociationGrant); err != nil {
			deviceAssociationError(w, err)
			return
		}
		identity.AssociationGrant = tx.AssociationGrant
		identity.AssociationDeadline = tx.AssociationDeadline
	}
	// #72 S1: a roleless human is admitted only for its own continuation;
	// knownRole continues to deny every other console route.
	if !knownRole(identity.Role) && identity.AssociationGrant == "" {
		fail(w, 403, errors.New("no_role"))
		return
	}
	v := s.createSession(identity)
	s.setSessionCookie(w, r, v.ID)
	http.Redirect(w, r, safeNext(tx.Next, s.oidc.origin), http.StatusFound)
}

// go-oidc's verifier checks signature, issuer, expiry and audience membership.
// OIDC Core §3.1.3.7 additionally requires our nonce, sub, extra-aud and azp checks.
func (s *Server) exchangeIdentity(ctx context.Context, tx oidcTransaction, code string) (session, error) {
	provider, config, err := s.oidc.provider(ctx)
	if err != nil {
		return session{}, err
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		return session{}, err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return session{}, errors.New("missing id token")
	}
	id, err := provider.Verifier(&oidc.Config{ClientID: config.ClientID}).Verify(ctx, raw)
	if err != nil {
		return session{}, err
	}
	if id.Nonce != tx.Nonce || id.Subject == "" {
		return session{}, errors.New("invalid identity")
	}
	for _, aud := range id.Audience {
		if aud != config.ClientID && !slices.Contains(s.oidc.trustedAudiences, aud) {
			return session{}, errors.New("untrusted audience")
		}
	}
	var claims map[string]json.RawMessage
	if err := id.Claims(&claims); err != nil {
		return session{}, err
	}
	if raw, exists := claims["azp"]; exists {
		var azp string
		if json.Unmarshal(raw, &azp) != nil || azp != config.ClientID {
			return session{}, errors.New("invalid authorized party")
		}
	}
	name := claimString(claims["name"])
	if name == "" {
		name = claimString(claims["preferred_username"])
	}
	return session{Kind: "human", Principal: core.Principal{Issuer: id.Issuer, Subject: id.Subject}, Name: name, Role: s.oidc.role(claims[s.oidc.roleClaim]), Tenant: "default"}, nil
}

func claimString(raw json.RawMessage) string {
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v
}

func (c *oidcSettings) role(raw json.RawMessage) core.Role {
	var values []string
	if value := claimString(raw); value != "" {
		values = []string{value}
	} else if json.Unmarshal(raw, &values) != nil {
		return ""
	}
	for _, role := range []core.Role{core.RoleAdmin, core.RoleAuditor, core.RoleReadOnly} {
		if slices.Contains(values, c.roleMap[role]) {
			return role
		}
	}
	return ""
}

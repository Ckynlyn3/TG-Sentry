// Package testoidc is a test fixture — not shipped. It auto-approves a synthetic
// identity; never use it as an identity provider outside isolated tests.
package testoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const ClientID = "client"

// Provider promotes internal/server/oidc_test.go's fakeOIDC. Claims and fault
// controls are for sequential tests: change them only between completed requests.
// ponytail: one outstanding authorization per provider, as in the original fake;
// use separate providers if tests need concurrent login transactions.
// PKCE follows RFC 7636 §4.6; RSA-2048 is RFC 7518 §3.3's RS256 minimum.
type Provider struct {
	URL            string
	Claims         map[string]any
	Challenge      string
	TokenCalls     int
	InvalidGrant   bool
	TokenFailure   bool
	MissingIDToken bool
	BadSignature   bool
	key            *rsa.PrivateKey
	server         *http.Server
	mu             sync.Mutex
}

// Start listens only on an IP-literal loopback address. Port zero asks the OS
// for an available port, matching httptest.NewServer's original behavior.
func Start(addr string) (*Provider, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("test OIDC requires a loopback listen address")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("test OIDC signing key: %w", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("test OIDC listen: %w", err)
	}
	p := &Provider{key: key, URL: "http://" + listener.Addr().String()}
	p.Claims = map[string]any{"iss": p.URL, "sub": "subject", "aud": ClientID, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "roles": []string{"readers", "admins", "auditors"}, "name": "Display Name", "preferred_username": "username"}
	p.server = &http.Server{Handler: p}
	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			panic(err) // Unexpected fixture failure must fail the test, not hang it.
		}
	}()
	return p, nil
}

func (p *Provider) Close() { p.server.Close() }

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		json.NewEncoder(w).Encode(map[string]any{"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token", "jwks_uri": p.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/keys":
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())}}})
	case "/authorize":
		p.Challenge = r.URL.Query().Get("code_challenge")
		p.Claims["nonce"] = r.URL.Query().Get("nonce")
		// Auto-approve only loopback callbacks; this fixture never redirects to
		// an external origin. Preserve the caller's state verbatim (OIDC Core §3.1.2.5).
		redirect, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil || redirect.Scheme != "http" || !net.ParseIP(redirect.Hostname()).IsLoopback() || redirect.User != nil {
			http.Error(w, "loopback redirect required", http.StatusBadRequest)
			return
		}
		q := redirect.Query()
		q.Set("code", "fixture-code")
		q.Set("state", r.URL.Query().Get("state"))
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	case "/token":
		p.TokenCalls++
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}
		digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if p.TokenFailure || p.Challenge == "" || base64.RawURLEncoding.EncodeToString(digest[:]) != p.Challenge {
			p.InvalidGrant = true
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		token := map[string]any{"access_token": "fixture-access", "token_type": "Bearer"}
		if !p.MissingIDToken {
			token["id_token"] = p.sign()
		}
		json.NewEncoder(w).Encode(token)
	default:
		w.WriteHeader(404)
	}
}

func (p *Provider) sign() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture"}`))
	claims, _ := json.Marshal(p.Claims)
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	if p.BadSignature {
		sig[0] ^= 1
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

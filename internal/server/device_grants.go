package server

import (
	"aegishook/internal/core"
	"errors"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Named local exception (#40 S3 lead disposition): the public CLI client ID is
// the existing binary/module name. RFC 8628 §3.1 requires identification but
// does not prescribe its value; this is not the console OIDC client ID.
const deviceClientID = "aegishook"
const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

type deviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type deviceTokenResponse struct {
	AccessToken     string                  `json:"access_token"`
	TokenType       string                  `json:"token_type"`
	NodeID          string                  `json:"nodeId"`
	BundlePublicKey []byte                  `json:"bundlePublicKey,omitempty"`
	BundleTrust     *core.SignedTrustRecord `json:"bundleTrust,omitempty"`
}

func deviceProtocol(r *http.Request) bool {
	return r.Method == "POST" && (r.URL.EscapedPath() == "/api/v1/client/device-authorization" || r.URL.EscapedPath() == "/api/v1/client/device-token")
}

func (s *Server) deviceGrantRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/client/device-authorization", s.deviceAuthorization)
	mux.HandleFunc("POST /api/v1/client/device-token", s.deviceToken)
	mux.HandleFunc("POST /api/v1/device-grants/lookup", s.lookupDeviceGrant)
	mux.HandleFunc("POST /api/v1/device-grants/decision", s.decideDeviceGrant)
	mux.HandleFunc("POST /api/v1/device-grants/association/begin", s.beginDeviceAssociation)
	mux.HandleFunc("GET /api/v1/device-grants/association/confirm", s.previewDeviceAssociation)
	mux.HandleFunc("POST /api/v1/device-grants/association/confirm", s.confirmDeviceAssociation)
}

// RFC 6749 §5.2 JSON errors, including RFC 8628 §3.5 polling extensions.
// Operational failures are generic server_error/500, never invalid_grant.
func deviceOAuthError(w http.ResponseWriter, status int, code string, interval int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	write(w, struct {
		Error    string `json:"error"`
		Interval int    `json:"interval,omitempty"`
	}{code, interval})
}

// RFC 8628 §§3.1/3.4 and RFC 6749 §3.2: body-only UTF-8 forms, no duplicate
// parameters, empty values treated as omitted, unknown parameters ignored.
func readDeviceForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	mediaType, params, err := mime.ParseMediaType(strings.Join(r.Header.Values("Content-Type"), ","))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "UTF-8")) {
		deviceOAuthError(w, 400, "invalid_request", 0)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // Existing server request ceiling.
	if err := r.ParseForm(); err != nil {
		deviceOAuthError(w, 400, "invalid_request", 0)
		return nil, false
	}
	for key, values := range r.Form {
		if len(values) != 1 || !utf8.ValidString(key) || !utf8.ValidString(values[0]) {
			deviceOAuthError(w, 400, "invalid_request", 0)
			return nil, false
		}
	}
	if r.PostForm.Get("client_id") != deviceClientID {
		deviceOAuthError(w, 400, "invalid_client", 0) // RFC 6749 §5.2: unknown client; no authentication header.
		return nil, false
	}
	return r.PostForm, true
}

// Mirror oidcRedirectOrigin's configured-identity boundary. PublicURL must be a
// pure HTTPS origin; without it, the actual configured loopback listener is the
// existing development/test HTTP exception. Request headers never supply it.
func (s *Server) deviceVerificationURI() string {
	if s.PublicURL != "" {
		u, err := url.Parse(s.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return ""
		}
		return s.PublicURL + "/device"
	}
	host, port, err := net.SplitHostPort(s.ListenAddr)
	if err != nil || !hasHost(host) || port == "" || port == "0" {
		return ""
	}
	return "http://" + net.JoinHostPort(host, port) + "/device"
}

func (s *Server) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	form, ok := readDeviceForm(w, r)
	if !ok {
		return
	}
	if form.Get("scope") != "" {
		deviceOAuthError(w, 400, "invalid_scope", 0)
		return
	}
	name, platform, source := form.Get("name"), form.Get("platform"), s.clientIP(r)
	if len(name) == 0 || len(name) > 120 || !validReviewChoice(platform, "linux", "darwin", "windows") {
		deviceOAuthError(w, 400, "invalid_request", 0)
		return
	}
	if _, err := netip.ParseAddr(source); err != nil {
		deviceOAuthError(w, 400, "invalid_request", 0)
		return
	}
	uri := s.deviceVerificationURI()
	if uri == "" {
		deviceOAuthError(w, 500, "server_error", 0)
		return
	}
	ticket, err := s.Engine.CreateDeviceGrant(name, platform, source)
	if err != nil {
		deviceOAuthError(w, 500, "server_error", 0)
		return
	}
	// RFC 8628 §3.2: seconds until expiry, rounded up to preserve the final
	// partial second rather than shortening the newly created 900-second grant.
	write(w, deviceAuthorizationResponse{ticket.DeviceCode, ticket.UserCode, uri, int(math.Ceil(time.Until(ticket.ExpiresAt).Seconds())), ticket.Interval})
}

func (s *Server) deviceToken(w http.ResponseWriter, r *http.Request) {
	form, ok := readDeviceForm(w, r)
	if !ok {
		return
	}
	if form.Get("grant_type") == "" || form.Get("device_code") == "" {
		deviceOAuthError(w, 400, "invalid_request", 0)
		return
	}
	if form.Get("grant_type") != deviceGrantType {
		deviceOAuthError(w, 400, "unsupported_grant_type", 0)
		return
	}
	result, err := s.Engine.PollDeviceGrant(form.Get("device_code"))
	if err != nil {
		deviceOAuthError(w, 500, "server_error", 0)
		return
	}
	if result.Status != core.DeviceGrantIssued {
		deviceOAuthError(w, 400, result.Status, result.Interval)
		return
	}
	connection := result.Connection
	write(w, deviceTokenResponse{connection.Token, "Bearer", connection.NodeID, connection.BundlePublicKey, connection.BundleTrust})
}

func readDeviceJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	mediaType, _, err := mime.ParseMediaType(strings.Join(r.Header.Values("Content-Type"), ","))
	if err != nil || mediaType != "application/json" {
		fail(w, 400, errors.New("application/json required"))
		return false
	}
	return readProtection(w, r, out) // Reuse strict unknown-field, trailing-object and body-budget checks.
}

func (s *Server) lookupDeviceGrant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserCode string `json:"userCode"`
	}
	if !readDeviceJSON(w, r, &in) {
		return
	}
	if in.UserCode == "" {
		fail(w, 400, errors.New("userCode required"))
		return
	}
	grant, err := s.Engine.LookupDeviceGrant(in.UserCode)
	switch {
	case errors.Is(err, core.ErrDeviceUserCode):
		fail(w, 404, err)
	case errors.Is(err, core.ErrDeviceUserCodeThrottled):
		fail(w, 400, err)
	case err != nil:
		fail(w, 500, errors.New("device grant store unavailable"))
	default:
		w.Header().Set("ETag", core.DeviceGrantETag(grant))
		write(w, grant)
	}
}

func (s *Server) decideDeviceGrant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		GrantID  string `json:"grantId"`
		Decision string `json:"decision"`
	}
	if !readDeviceJSON(w, r, &in) {
		return
	}
	if in.GrantID == "" || !validReviewChoice(in.Decision, "approve", "deny") {
		fail(w, 400, errors.New("grantId and approve/deny decision required"))
		return
	}
	tags, ok := deviceGrantIfMatch(w, r)
	if !ok {
		return
	}
	status, err := s.Engine.DecideDeviceGrant(r.Context(), in.GrantID, in.Decision, tags)
	switch {
	case errors.Is(err, core.ErrDeviceGrantPrecondition):
		fail(w, 412, err)
	case errors.Is(err, core.ErrDeviceGrantNotFound):
		fail(w, 404, err)
	case errors.Is(err, core.ErrDeviceGrantDecided):
		fail(w, 409, err)
	case err != nil:
		fail(w, 500, errors.New("device grant store unavailable"))
	default:
		write(w, struct {
			GrantID string `json:"grantId"`
			Status  string `json:"status"`
		}{in.GrantID, status})
	}
}

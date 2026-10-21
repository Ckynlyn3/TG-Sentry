package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// RFC 8628 device-code enrollment (#40 S2): the bounded grant lifecycle. The
// wire contract is frozen by #40 S1 (docs/DECISIONS.md "Device-code enrollment
// (#40 S1)"; docs/ARCHITECTURE.md, same heading; docs/design/protection.openapi.json
// device-authorization / device-token / device-grants). No route is served here.
//
// Every number below is the S1 D5 profile with its cited source; none is chosen
// locally:
//   - grant lifetime 900 s ..... GitHub device flow, Step 1 (documented device/user-code lifetime).
//   - interval 5 s ............. RFC 8628 §3.2 default/example.
//   - slow_down +5 s ........... RFC 8628 §3.5 ("increase the polling interval by 5 seconds").
//   - 8-character user code .... RFC 8628 §6.1 alphabet BCDFGHJKLMNPQRSTVWXZ and example.
//   - 50 submissions/hour ...... GitHub device flow, "Rate limits for the device flow".
//   - 5/256 admission caps ..... reused from client_requests.go:77–90 (D5).
const (
	deviceGrantLifetime    = 900 * time.Second
	deviceGrantInterval    = 5 * time.Second
	deviceGrantSlowDown    = 5 * time.Second
	deviceUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	deviceUserCodeLength   = 8
	// deviceUserCodeLimit is the hourly application-wide ceiling on user-code
	// submissions; unsuccessful guesses are counted (D5, GitHub device flow).
	deviceUserCodeLimit  = 50
	deviceUserCodeWindow = time.Hour
)

// Persisted grant states, also the DeviceGrantLookup.status wire enum.
const (
	deviceStatusPending  = "pending"
	deviceStatusApproved = "approved"
	deviceStatusDenied   = "denied"
	deviceStatusConsumed = "consumed"
)

// Poll outcomes. The RFC 8628 §3.5 / RFC 6749 §5.2 names are returned to S3
// unchanged; only pending and slow_down are nonterminal.
const (
	DeviceGrantPending  = "authorization_pending"
	DeviceGrantSlowDown = "slow_down"
	DeviceGrantDenied   = "access_denied"
	DeviceGrantExpired  = "expired_token"
	DeviceGrantInvalid  = "invalid_grant"
	DeviceGrantIssued   = "approved"
)

var (
	ErrDeviceUserCode          = errors.New("user code is unknown or expired")
	ErrDeviceUserCodeThrottled = errors.New("user code submissions are rate limited")
	ErrDeviceGrantNotFound     = errors.New("device grant not found")
	ErrDeviceGrantDecided      = errors.New("device grant already decided")
	// errDeviceGrantCodeUnknown is the only device-code outcome that is a
	// protocol result (a terminal invalid_grant). Every other lookup failure is
	// operational and propagates, so the transport can answer with the frozen
	// store-unavailable response rather than inventing a protocol error
	// (RFC 6749 §5.2; docs/design/protection.openapi.json).
	errDeviceGrantCodeUnknown = errors.New("device code is not bound to a grant")
)

// DeviceGrantTicket is the RFC 8628 §3.2 authorization response. verification_uri
// is composed by the transport from configured server identity (S3).
type DeviceGrantTicket struct {
	DeviceCode string    `json:"deviceCode"`
	UserCode   string    `json:"userCode"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Interval   int       `json:"interval"`
}

// DeviceGrantLookup is the human-admin view of a submitted user code
// (DeviceGrantLookupResponse). GrantID is opaque and never an authorization token.
type DeviceGrantLookup struct {
	AssociatedUser *AssociatedUser `json:"associatedUser"`
	GrantID        string          `json:"grantId"`
	UserCode       string          `json:"userCode"`
	Name           string          `json:"name"`
	Platform       string          `json:"platform"`
	Source         string          `json:"source"`
	Status         string          `json:"status"`
}

// DeviceGrantPoll is one RFC 8628 §3.5 polling outcome.
type DeviceGrantPoll struct {
	Status     string            `json:"status"`
	Interval   int               `json:"interval,omitempty"`
	Connection *ClientConnection `json:"connection,omitempty"`
}

// DeviceGrant is the management projection. Approval metadata is stored on the
// record so the poll can reuse the approving actor without the caller supplying it.
type DeviceGrant struct {
	AssociatedUser *AssociatedUser `json:"associatedUser"`
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Platform       string          `json:"platform"`
	Source         string          `json:"source"`
	Status         string          `json:"status"`
	CreatedAt      time.Time       `json:"createdAt"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	ApprovedBy     *Actor          `json:"approvedBy,omitempty"`
}

// The stored form keeps the device-code digest and the current polling state out
// of every management response. Only the digest of the device code persists.
type storedDeviceGrant struct {
	DeviceGrant
	DeviceCodeHash string    `json:"deviceCodeHash"`
	UserCode       string    `json:"userCode"`
	Interval       int       `json:"interval"`
	LastPoll       time.Time `json:"lastPoll,omitempty"`
}

// deviceUserCodeThrottle is the rolling application-wide submission counter
// (D5: 50 per hour per application, counting unsuccessful guesses).
type deviceUserCodeThrottle struct {
	WindowStart time.Time `json:"windowStart"`
	Count       int       `json:"count"`
}

func newDeviceUserCode() string {
	for {
		code := make([]byte, deviceUserCodeLength)
		// crypto/rand.Int rejects biased samples, so selection is unbiased
		// (RFC 8628 §6.1). A failure here is as unrecoverable as ID()'s.
		for i := range code {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(deviceUserCodeAlphabet))))
			if err != nil {
				panic(err)
			}
			code[i] = deviceUserCodeAlphabet[n.Int64()]
		}
		return string(code)
	}
}

// displayUserCode is the RFC 8628 §6.1 XXXX-XXXX presentation.
func displayUserCode(code string) string { return code[:4] + "-" + code[4:] }

// normalizeUserCode ignores case and the display hyphen for lookup.
func normalizeUserCode(in string) string {
	return strings.ReplaceAll(strings.ToUpper(in), "-", "")
}

func (e *Engine) deviceGrants() ([]storedDeviceGrant, error) {
	return list[storedDeviceGrant](e, "device_grants")
}

// liveDeviceGrant finds the unexpired grant a user code currently resolves to. A
// consumed grant still resolves so the approving human sees the terminal status
// (DeviceGrantLookupResponse.status includes "consumed"). A store failure is
// returned, never reported as an unknown code.
func (e *Engine) liveDeviceGrant(userCode string) (storedDeviceGrant, bool, error) {
	grants, err := e.deviceGrants()
	if err != nil {
		return storedDeviceGrant{}, false, err
	}
	for _, g := range grants {
		if g.UserCode == userCode && e.clock().Before(g.ExpiresAt) {
			return g, true, nil
		}
	}
	return storedDeviceGrant{}, false, nil
}

// CreateDeviceGrant starts a grant. name/platform are descriptive TG-Sentry
// extensions bound to the grant; source is the trusted-proxy-resolved request
// source, validated and checked against the existing IP blocks exactly as the
// legacy admission path does (client_requests.go:61–98).
func (e *Engine) CreateDeviceGrant(name, platform, ip string) (DeviceGrantTicket, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(name) == 0 || len(name) > 120 || !hasExact(platform, "linux", "darwin", "windows") {
		return DeviceGrantTicket{}, errors.New("设备名称或平台无效")
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return DeviceGrantTicket{}, errors.New("无法识别请求来源")
	}
	if e.ClientIPBlocked(ip) {
		return DeviceGrantTicket{}, errors.New("此来源已被禁止接入")
	}
	count, total, err := e.activeAdmissions(ip)
	if err != nil {
		return DeviceGrantTicket{}, err
	}
	if count >= clientAdmissionPerSource || total >= clientAdmissionGlobal {
		return DeviceGrantTicket{}, errors.New("接入申请过多，请稍后再试")
	}
	// Retry only on a live-code collision; 8 RFC §6.1 characters against a
	// bounded live set make this practically unreachable.
	var userCode string
	for {
		userCode = newDeviceUserCode()
		_, taken, err := e.liveDeviceGrant(userCode)
		if err != nil {
			return DeviceGrantTicket{}, err
		}
		if !taken {
			break
		}
	}
	deviceCode := ID() + ID() // Same 256-bit ID()+ID() convention as client_requests.go:89.
	g := storedDeviceGrant{
		DeviceGrant:    DeviceGrant{ID: ID(), Name: name, Platform: platform, Source: ip, Status: deviceStatusPending, CreatedAt: e.clock(), ExpiresAt: e.clock().Add(deviceGrantLifetime)},
		DeviceCodeHash: credentialHash(deviceCode),
		UserCode:       userCode,
		Interval:       int(deviceGrantInterval / time.Second),
	}
	if err = e.change(WithActor(context.Background(), SystemActor("device")), "device_grants", g.ID, g, "client.device", "收到设备码接入请求"); err != nil {
		return DeviceGrantTicket{}, err
	}
	return DeviceGrantTicket{DeviceCode: deviceCode, UserCode: displayUserCode(userCode), ExpiresAt: g.ExpiresAt, Interval: g.Interval}, nil
}

// LookupDeviceGrant resolves a submitted user code for human review. Every
// submission counts against the application-wide hourly throttle, including
// unsuccessful guesses (D5).
func (e *Engine) LookupDeviceGrant(userCode string) (DeviceGrantLookup, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lookupDeviceGrant(userCode, "current")
}

// PublicDeviceGrantLookup isolates anonymous guesses from administrator review.
// OWASP DoS Cheat Sheet, Rate Limiting:
// https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html#rate-limiting
// Both public ceilings reuse D5's GitHub 50/hour precedent, with trusted source IPs.
func (e *Engine) PublicDeviceGrantLookup(userCode, source string) (DeviceGrantLookup, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := netip.ParseAddr(source); err != nil {
		return DeviceGrantLookup{}, err
	}
	if e.ClientIPBlocked(source) {
		return DeviceGrantLookup{}, ErrDeviceUserCodeThrottled
	}
	// Check the aggregate first: exhausted public traffic cannot create source rows.
	if err := e.consumeDeviceLookupBudget("public"); err != nil {
		return DeviceGrantLookup{}, err
	}
	return e.lookupDeviceGrant(userCode, "public:"+source)
}

func (e *Engine) consumeDeviceLookupBudget(key string) error {
	var throttle deviceUserCodeThrottle
	if err := e.get("device_user_code_throttle", key, &throttle); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if !e.clock().Before(throttle.WindowStart.Add(deviceUserCodeWindow)) {
		throttle = deviceUserCodeThrottle{WindowStart: e.clock()}
	}
	if throttle.Count >= deviceUserCodeLimit {
		return ErrDeviceUserCodeThrottled
	}
	throttle.Count++
	return e.put("device_user_code_throttle", key, throttle)
}

func (e *Engine) lookupDeviceGrant(userCode, budget string) (DeviceGrantLookup, error) {
	if err := e.consumeDeviceLookupBudget(budget); err != nil {
		return DeviceGrantLookup{}, err
	}

	g, ok, err := e.liveDeviceGrant(normalizeUserCode(userCode))
	if err != nil {
		return DeviceGrantLookup{}, err
	}
	if !ok {
		return DeviceGrantLookup{}, ErrDeviceUserCode
	}
	return deviceGrantLookup(g), nil
}

// DecideDeviceGrant records ONLY the human admin's approve/deny decision and the
// authenticated actor from ctx. It consumes nothing and issues nothing; the
// successful poll does that (D2, RFC 8628 §3.5; mirrors the approve/redeem split
// at client_requests.go:97–147). Re-deciding is refused, so a later caller
// cannot restamp the approver.
func (e *Engine) DecideDeviceGrant(ctx context.Context, grantID, decision string, tags []string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var g storedDeviceGrant
	if err := e.get("device_grants", grantID, &g); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrDeviceGrantNotFound
		}
		return "", err
	}
	if !hasExact(decision, "approve", "deny") {
		return "", errors.New("仅支持 approve、deny")
	}
	if !e.clock().Before(g.ExpiresAt) {
		return "", ErrDeviceGrantNotFound
	}
	if g.Status != deviceStatusPending {
		return "", ErrDeviceGrantDecided
	}
	// Recheck the reviewed account under the same writer lock as confirmation.
	// RFC 9110 §13.1.1: weak tags never equal our strong validator.
	if !slices.Contains(tags, DeviceGrantETag(deviceGrantLookup(g))) {
		return "", ErrDeviceGrantPrecondition
	}
	switch decision {
	case "approve":
		g.Status = deviceStatusApproved
		actor := ActorFromContext(ctx)
		g.ApprovedBy = &actor
	case "deny":
		g.Status = deviceStatusDenied
	}
	detail := "拒绝设备接入"
	if decision == "approve" {
		detail = "批准设备接入"
	}
	if err := e.change(ctx, "device_grants", g.ID, g, "client.device."+decision, detail); err != nil {
		return "", err
	}
	return g.Status, nil
}

// PollDeviceGrant answers one RFC 8628 §3.4 token request. The interval is
// enforced while the grant is still pending, which is the waiting loop §3.5's
// slow_down governs; a decided grant is answered immediately so a cadence
// violation cannot delay a token the device is already entitled to.
func (e *Engine) PollDeviceGrant(deviceCode string) (DeviceGrantPoll, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var g storedDeviceGrant
	if len(deviceCode) != 64 {
		return DeviceGrantPoll{Status: DeviceGrantInvalid}, nil
	}
	if err := e.deviceGrantByCode(deviceCode, &g); err != nil {
		if errors.Is(err, errDeviceGrantCodeUnknown) {
			return DeviceGrantPoll{Status: DeviceGrantInvalid}, nil
		}
		return DeviceGrantPoll{}, err
	}
	if !e.clock().Before(g.ExpiresAt) {
		return DeviceGrantPoll{Status: DeviceGrantExpired}, nil
	}
	switch g.Status {
	case deviceStatusConsumed:
		return DeviceGrantPoll{Status: DeviceGrantInvalid}, nil
	case deviceStatusDenied:
		return DeviceGrantPoll{Status: DeviceGrantDenied}, nil
	case deviceStatusPending:
		// The required interval is measured from the preceding poll on both
		// outcomes (RFC 8628 §3.5), so a client that keeps polling early keeps
		// escalating and the next accepted poll must clear the increased
		// interval rather than the one that was current when it last succeeded.
		elapsed := e.clock().Sub(g.LastPoll)
		g.LastPoll = e.clock()
		if elapsed < time.Duration(g.Interval)*time.Second {
			g.Interval += int(deviceGrantSlowDown / time.Second)
			if err := e.put("device_grants", g.ID, g); err != nil {
				return DeviceGrantPoll{}, err
			}
			return DeviceGrantPoll{Status: DeviceGrantSlowDown, Interval: g.Interval}, nil
		}
		if err := e.put("device_grants", g.ID, g); err != nil {
			return DeviceGrantPoll{}, err
		}
		return DeviceGrantPoll{Status: DeviceGrantPending, Interval: g.Interval}, nil
	}
	// Approved: consume and issue atomically under the engine mutex, so
	// concurrent polls issue exactly one credential (RFC 8628 §3.5).
	actor := SystemActor("device")
	if g.ApprovedBy != nil {
		actor = *g.ApprovedBy
	}
	g.Status = deviceStatusConsumed
	connection, err := e.issueClientCredential(actor, "client.device.enroll", "device_grants", g.ID, g, g.Name, g.Platform)
	if err != nil {
		return DeviceGrantPoll{}, err
	}
	return DeviceGrantPoll{Status: DeviceGrantIssued, Connection: &connection}, nil
}

// deviceGrantByCode resolves the digest-indexed device code, mirroring
// AuthenticateClient's token-hash lookup and constant-time re-check. Only an
// unknown code is errDeviceGrantCodeUnknown (a terminal invalid_grant); a
// storage, query, decode or integrity failure is returned as-is.
func (e *Engine) deviceGrantByCode(deviceCode string, out *storedDeviceGrant) error {
	hash := credentialHash(deviceCode)
	tx, err := e.beginTenant()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var payload []byte
	if err := tx.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='device_grants' AND "+e.jsonField("", "deviceCodeHash")+"=$2", eventTenant(), hash).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errDeviceGrantCodeUnknown
		}
		return err
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(out.DeviceCodeHash)) != 1 {
		return errors.New("device code digest mismatch")
	}
	return nil
}

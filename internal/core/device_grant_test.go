package core

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"aegishook/internal/teststore"
)

// grantFixture is the existing engine clock seam (#40 S2 uses injected time,
// not wall-clock sleeps). Every duration asserted here is the #40 S1 D5 profile.
func grantFixture(t *testing.T) (*Engine, func(time.Duration)) {
	t.Helper()
	e := engine(t)
	now := time.Now().UTC()
	e.clock = func() time.Time { return now }
	return e, func(d time.Duration) { now = now.Add(d) }
}

const grantSource = "203.0.113.7"

var userCodeShape = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

func newGrant(t *testing.T, e *Engine) DeviceGrantTicket {
	t.Helper()
	ticket, err := e.CreateDeviceGrant("workstation", "linux", grantSource)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func grantLookup(t *testing.T, e *Engine, userCode string) DeviceGrantLookup {
	t.Helper()
	lookup, err := e.LookupDeviceGrant(userCode)
	if err != nil {
		t.Fatal(err)
	}
	return lookup
}

func grantPoll(t *testing.T, e *Engine, deviceCode string) DeviceGrantPoll {
	t.Helper()
	poll, err := e.PollDeviceGrant(deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	return poll
}

func approveGrant(t *testing.T, e *Engine, ctx context.Context, userCode string) DeviceGrantLookup {
	t.Helper()
	lookup := grantLookup(t, e, userCode)
	if status, err := e.DecideDeviceGrant(ctx, lookup.GrantID, "approve", []string{DeviceGrantETag(lookup)}); err != nil || status != deviceStatusApproved {
		t.Fatalf("approve: status %q err %v", status, err)
	}
	return lookup
}

// rawRecords reads the tenant's stored payloads for one record kind through the
// disposable owner pool. The runtime role is subject to FORCE ROW LEVEL SECURITY
// (internal/core/migrations/00004_records_rls.sql), so an untransacted
// runtime-pool read returns no rows; inspection uses teststore.Admin, as the
// existing raw-payload tests do.
func rawRecords(t *testing.T, e *Engine, kind string) []string {
	t.Helper()
	rows, err := teststore.Admin(t, e.DB).Query("SELECT payload FROM records WHERE tenant_id=$1 AND kind=$2", eventTenant(), kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var payload string
		if err = rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, payload)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The authorization response is frozen in docs/design/protection.openapi.json
// (DeviceAuthorizationResponse) and #40 S1 D5.
func TestDeviceGrantTicketProfile(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	if len(ticket.DeviceCode) != 64 {
		t.Fatalf("device code is %d characters, want the 256-bit ID()+ID() form", len(ticket.DeviceCode))
	}
	if !userCodeShape.MatchString(ticket.UserCode) {
		t.Fatalf("user code %q does not match the RFC 8628 §6.1 display form", ticket.UserCode)
	}
	if ticket.Interval != int(deviceGrantInterval/time.Second) {
		t.Fatalf("interval %d, want %d", ticket.Interval, deviceGrantInterval/time.Second)
	}
	if got := ticket.ExpiresAt.Sub(e.clock()); got != deviceGrantLifetime {
		t.Fatalf("grant lifetime %s, want %s", got, deviceGrantLifetime)
	}
}

// Only the digest of the device code and of the issued bearer may persist
// (docs/ARCHITECTURE.md "Device-code enrollment (#40 S1)").
func TestDeviceGrantStoresOnlyDigests(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := grantLookup(t, e, ticket.UserCode)
	grants := rawRecords(t, e, "device_grants")
	if len(grants) != 1 || strings.Contains(grants[0], ticket.DeviceCode) {
		t.Fatal("device grant record is not a single hash-only record")
	}
	if lookup.GrantID == ticket.DeviceCode || len(lookup.GrantID) != 32 {
		t.Fatalf("grant id %q is not an independent opaque identifier", lookup.GrantID)
	}
	approveGrant(t, e, testActorContext(), ticket.UserCode)
	poll := grantPoll(t, e, ticket.DeviceCode)
	if poll.Status != DeviceGrantIssued || poll.Connection == nil {
		t.Fatalf("poll: %+v", poll)
	}
	for _, payload := range append(rawRecords(t, e, "device_grants"), rawRecords(t, e, "client_nodes")...) {
		if strings.Contains(payload, poll.Connection.Token) {
			t.Fatal("control-plane record persisted the raw bearer")
		}
	}
	if _, ok := e.AuthenticateClient(poll.Connection.Token); !ok {
		t.Fatal("issued bearer did not authenticate")
	}
}

func TestDeviceGrantLifecycle(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := grantLookup(t, e, strings.ToLower(strings.ReplaceAll(ticket.UserCode, "-", "")))
	if lookup.Status != deviceStatusPending || lookup.Name != "workstation" || lookup.Platform != "linux" || lookup.Source != grantSource {
		t.Fatalf("lookup %+v", lookup)
	}
	if poll := grantPoll(t, e, ticket.DeviceCode); poll.Status != DeviceGrantPending {
		t.Fatalf("poll while pending: %+v", poll)
	}
	advance(deviceGrantInterval)
	approveGrant(t, e, testActorContext(), ticket.UserCode)
	poll := grantPoll(t, e, ticket.DeviceCode)
	if poll.Status != DeviceGrantIssued || poll.Connection == nil {
		t.Fatalf("poll after approval: %+v", poll)
	}
	if node, ok := e.AuthenticateClient(poll.Connection.Token); !ok || node.ID != poll.Connection.NodeID {
		t.Fatal("issued bearer did not authenticate as the issued node")
	}
	if again := grantPoll(t, e, ticket.DeviceCode); again.Status != DeviceGrantInvalid || again.Connection != nil {
		t.Fatalf("consumed grant issued again: %+v", again)
	}
	if lookup = grantLookup(t, e, ticket.UserCode); lookup.Status != deviceStatusConsumed {
		t.Fatalf("consumed grant lookup status %q", lookup.Status)
	}
}

func TestDeviceGrantDeny(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := grantLookup(t, e, ticket.UserCode)
	if status, err := e.DecideDeviceGrant(testActorContext(), lookup.GrantID, "deny", []string{DeviceGrantETag(lookup)}); err != nil || status != deviceStatusDenied {
		t.Fatalf("deny: status %q err %v", status, err)
	}
	poll := grantPoll(t, e, ticket.DeviceCode)
	if poll.Status != DeviceGrantDenied || poll.Connection != nil {
		t.Fatalf("denied poll: %+v", poll)
	}
	if got := grantLookup(t, e, ticket.UserCode).Status; got != deviceStatusDenied {
		t.Fatalf("denied lookup status %q", got)
	}
}

func TestDeviceGrantExpiry(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := grantLookup(t, e, ticket.UserCode)
	advance(deviceGrantLifetime)
	if poll := grantPoll(t, e, ticket.DeviceCode); poll.Status != DeviceGrantExpired {
		t.Fatalf("expired poll: %+v", poll)
	}
	if _, err := e.LookupDeviceGrant(ticket.UserCode); !errors.Is(err, ErrDeviceUserCode) {
		t.Fatalf("expired user code lookup error %v", err)
	}
	if _, err := e.DecideDeviceGrant(testActorContext(), lookup.GrantID, "approve", []string{DeviceGrantETag(lookup)}); !errors.Is(err, ErrDeviceGrantNotFound) {
		t.Fatalf("expired grant decision error %v", err)
	}
}

// RFC 8628 §3.5: an early poll returns slow_down and adds five seconds to the
// required interval. The interval is measured from the *preceding poll*, so a
// poll before the increased interval has elapsed is still rejected.
func TestDeviceGrantSlowDownCumulative(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	steps := []struct {
		elapsed  time.Duration
		status   string
		interval int
	}{
		{0, DeviceGrantPending, 5},
		{time.Second, DeviceGrantSlowDown, 10},
		{time.Second, DeviceGrantSlowDown, 15},
		{15 * time.Second, DeviceGrantPending, 15},
		{time.Second, DeviceGrantSlowDown, 20},
		// 19 s after the preceding poll is still early for the increased
		// 20 s interval; the previous behaviour accepted it.
		{19 * time.Second, DeviceGrantSlowDown, 25},
		{25 * time.Second, DeviceGrantPending, 25},
	}
	for i, step := range steps {
		advance(step.elapsed)
		poll := grantPoll(t, e, ticket.DeviceCode)
		if poll.Status != step.status {
			t.Fatalf("step %d: status %q, want %q", i, poll.Status, step.status)
		}
		if poll.Interval != step.interval {
			t.Fatalf("step %d: interval %d, want %d", i, poll.Interval, step.interval)
		}
	}
}

func TestDeviceGrantUnknownAndMalformedCodes(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	grants := make([]string, 0, 3)
	for i := 0; i < 2; i++ {
		grants = append(grants, newGrant(t, e).DeviceCode)
	}
	tests := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"short", "abc"},
		{"unknown 64-character code", strings.Repeat("a", 64)},
		{"another grant's code is still pending", grants[0]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			poll := grantPoll(t, e, tc.code)
			want := DeviceGrantInvalid
			if tc.code == grants[0] {
				want = DeviceGrantPending
			}
			if poll.Status != want || poll.Connection != nil {
				t.Fatalf("poll %+v, want status %q", poll, want)
			}
		})
	}
	if poll := grantPoll(t, e, ticket.DeviceCode); poll.Status != DeviceGrantPending {
		t.Fatalf("unrelated polls disturbed the first grant: %+v", poll)
	}
}

func TestDeviceGrantDecisionRules(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := grantLookup(t, e, ticket.UserCode)
	tests := []struct {
		name     string
		grantID  string
		decision string
		wantErr  error
	}{
		{"unknown grant", "0123456789abcdef0123456789abcdef", "approve", ErrDeviceGrantNotFound},
		{"unsupported decision", lookup.GrantID, "block_ip", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.DecideDeviceGrant(testActorContext(), tc.grantID, tc.decision, []string{DeviceGrantETag(lookup)}); err == nil {
				t.Fatalf("accepted %q for %s", tc.decision, tc.grantID)
			} else if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
	approveGrant(t, e, testActorContext(), ticket.UserCode)
	if _, err := e.DecideDeviceGrant(testActorContext(), lookup.GrantID, "deny", []string{DeviceGrantETag(lookup)}); !errors.Is(err, ErrDeviceGrantDecided) {
		t.Fatalf("re-decision error %v", err)
	}
	if poll := grantPoll(t, e, ticket.DeviceCode); poll.Status != DeviceGrantIssued {
		t.Fatalf("re-decision changed the outcome: %+v", poll)
	}
}

// The decision records the authenticated human actor and nothing the caller
// supplies (D2). A later decision cannot restamp it.
func TestDeviceGrantRecordsAuthenticatedActor(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := grantLookup(t, e, ticket.UserCode)
	admin := Actor{Issuer: "https://issuer.example", Subject: "alice", Name: "Alice", Kind: "human"}
	if status, err := e.DecideDeviceGrant(WithActor(context.Background(), admin), lookup.GrantID, "approve", []string{DeviceGrantETag(lookup)}); err != nil || status != deviceStatusApproved {
		t.Fatalf("approve: %q %v", status, err)
	}
	attacker := Actor{Issuer: "https://issuer.example", Subject: "mallory", Name: "Mallory", Kind: "human"}
	if _, err := e.DecideDeviceGrant(WithActor(context.Background(), attacker), lookup.GrantID, "deny", []string{DeviceGrantETag(lookup)}); !errors.Is(err, ErrDeviceGrantDecided) {
		t.Fatalf("attacker restamped the decision: %v", err)
	}
	poll := grantPoll(t, e, ticket.DeviceCode)
	if poll.Status != DeviceGrantIssued || poll.Connection == nil {
		t.Fatalf("poll: %+v", poll)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	var decided, issued bool
	for _, audit := range audits {
		switch {
		case audit.Action == "client.device.approve" && audit.Subject == lookup.GrantID:
			if audit.Actor != admin {
				t.Fatalf("decision audit actor %+v", audit.Actor)
			}
			decided = true
		case audit.Subject == poll.Connection.NodeID && audit.Action == "client.device.enroll":
			if audit.Actor != admin {
				t.Fatalf("issuance audit actor %+v", audit.Actor)
			}
			issued = true
		}
	}
	if !decided || !issued {
		t.Fatalf("decision audit %v, issuance audit %v", decided, issued)
	}
}

// 50 user-code submissions per hour per application, counting unsuccessful
// guesses (#40 S1 D5, GitHub device flow rate limits).
func TestDeviceGrantUserCodeThrottle(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	if _, err := e.LookupDeviceGrant(ticket.UserCode); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < deviceUserCodeLimit; i++ {
		if _, err := e.LookupDeviceGrant("BBCD-FGHJ"); !errors.Is(err, ErrDeviceUserCode) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if _, err := e.LookupDeviceGrant(ticket.UserCode); !errors.Is(err, ErrDeviceUserCodeThrottled) {
		t.Fatalf("throttle error %v", err)
	}
	advance(deviceUserCodeWindow)
	// The window elapsed, so a fresh grant is submittable again (the first
	// grant has also expired by now, so it no longer counts against admission).
	second := newGrant(t, e)
	if _, err := e.LookupDeviceGrant(second.UserCode); err != nil {
		t.Fatalf("window did not reset: %v", err)
	}
}

func TestDeviceGrantCreateValidation(t *testing.T) {
	e, _ := grantFixture(t)
	blocked := "198.51.100.9"
	if err := e.put("client_ip_blocks", credentialHash(blocked), ClientIPBlock{ID: credentialHash(blocked), IP: blocked, CreatedAt: e.clock()}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		device   string
		platform string
		source   string
	}{
		{"empty name", "", "linux", grantSource},
		{"121 byte name", strings.Repeat("a", 121), "linux", grantSource},
		{"unsupported platform", "endpoint", "plan9", grantSource},
		{"unparseable source", "endpoint", "linux", "not-an-address"},
		{"blocked source", "endpoint", "linux", blocked},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.CreateDeviceGrant(tc.device, tc.platform, tc.source); err == nil {
				t.Fatal("invalid request admitted")
			}
		})
	}
	if _, err := e.CreateDeviceGrant(strings.Repeat("a", 120), "windows", grantSource); err != nil {
		t.Fatalf("120 byte name refused: %v", err)
	}
}

// The 5/256 admission caps are shared with the legacy request flow so the two
// paths cannot double the allowance (D5; client_requests.go:77–90).
func TestDeviceGrantAdmissionSharedWithLegacyFlow(t *testing.T) {
	first, _ := grantFixture(t)
	for i := 0; i < 5; i++ {
		if _, err := first.CreateClientRequest("legacy", "linux", grantSource); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.CreateDeviceGrant("endpoint", "linux", grantSource); err == nil {
		t.Fatal("device grant bypassed the shared per-source cap")
	}
	second, _ := grantFixture(t)
	for i := 0; i < 5; i++ {
		newGrant(t, second)
	}
	if _, err := second.CreateClientRequest("legacy", "linux", grantSource); err == nil {
		t.Fatal("legacy request bypassed the shared per-source cap")
	}
}

// A storage/query/decode failure must not be reported as a terminal protocol
// outcome: RFC 6749 §5.2 reserves those for protocol results, and the frozen
// contract answers an outage with the store-unavailable response
// (docs/design/protection.openapi.json device-token 500).
func TestDeviceGrantStoreFailureIsNotInvalidGrant(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	lookup := approveGrant(t, e, testActorContext(), ticket.UserCode)
	// The existing store failure-injection precedent.
	if _, err := teststore.Admin(t, e.DB).Exec("DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	if poll, err := e.PollDeviceGrant(ticket.DeviceCode); err == nil {
		t.Fatalf("poll answered %q instead of a store failure", poll.Status)
	}
	if _, err := e.LookupDeviceGrant("BBCD-FGHJ"); err == nil {
		t.Fatal("lookup answered a user-code outcome instead of a store failure")
	}
	if _, err := e.DecideDeviceGrant(testActorContext(), lookup.GrantID, "deny", []string{DeviceGrantETag(lookup)}); err == nil {
		t.Fatal("decision answered a grant outcome instead of a store failure")
	}
}

func TestDeviceGrantConcurrentRedemption(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	approveGrant(t, e, testActorContext(), ticket.UserCode)
	const pollers = 8
	results := make([]DeviceGrantPoll, pollers)
	errs := make([]error, pollers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = e.PollDeviceGrant(ticket.DeviceCode)
		}(i)
	}
	wg.Wait()
	tokens := map[string]bool{}
	for i := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		switch results[i].Status {
		case DeviceGrantIssued:
			if results[i].Connection == nil {
				t.Fatal("issued without a connection")
			}
			tokens[results[i].Connection.Token] = true
		case DeviceGrantInvalid:
		default:
			t.Fatalf("unexpected status %q", results[i].Status)
		}
	}
	if len(tokens) != 1 {
		t.Fatalf("issued %d credentials across %d polls", len(tokens), pollers)
	}
}

func TestDeviceGrantSurvivesRestart(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e.clock = func() time.Time { return now }
	ticket := newGrant(t, e)
	approveGrant(t, e, testActorContext(), ticket.UserCode)
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := grantLookup(t, e, ticket.UserCode).Status; got != deviceStatusApproved {
		t.Fatalf("status after restart %q", got)
	}
	poll := grantPoll(t, e, ticket.DeviceCode)
	if poll.Status != DeviceGrantIssued || poll.Connection == nil {
		t.Fatalf("poll after restart: %+v", poll)
	}
	if again := grantPoll(t, e, ticket.DeviceCode); again.Status != DeviceGrantInvalid {
		t.Fatalf("consumption did not persist: %+v", again)
	}
}

func TestDeviceGrantLegacyFlowUnaffected(t *testing.T) {
	e, _ := grantFixture(t)
	key, err := e.CreateEnrollment(testActorContext(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.AuthenticateClient(connection.Token); !ok {
		t.Fatal("setup-key enrollment stopped working")
	}
	request, err := e.CreateClientRequest("legacy request", "linux", grantSource)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.DecideClientRequest(testActorContext(), request.ID, "approve"); err != nil {
		t.Fatal(err)
	}
	result, err := e.PollClientRequest(request.ID, request.Secret, grantSource)
	if err != nil || result.State != "approved" || result.Connection == nil {
		t.Fatalf("legacy request redemption: %+v %v", result, err)
	}
	ticket := newGrant(t, e)
	lookup := approveGrant(t, e, testActorContext(), ticket.UserCode)
	if poll := grantPoll(t, e, ticket.DeviceCode); poll.Status != DeviceGrantIssued {
		t.Fatalf("device grant poll: %+v", poll)
	}
	// The device grant is a distinct record kind: it never appears as a legacy
	// request and its codes never redeem through the legacy poll.
	requests, err := e.ClientRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0].ID != request.ID {
		t.Fatalf("device grants leaked into client_requests: %+v", requests)
	}
	if _, err := e.PollClientRequest(lookup.GrantID, ticket.DeviceCode, grantSource); err == nil {
		t.Fatal("device code redeemed through the legacy poll")
	}
}

func TestDeviceGrantPublicLookupBudgetIsolation(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	for i := 0; i < deviceUserCodeLimit; i++ {
		if _, err := e.PublicDeviceGrantLookup("invalid", grantSource); !errors.Is(err, ErrDeviceUserCode) {
			t.Fatalf("public guess %d: %v", i, err)
		}
	}
	if _, err := e.PublicDeviceGrantLookup(ticket.UserCode, grantSource); !errors.Is(err, ErrDeviceUserCodeThrottled) {
		t.Fatalf("source throttle: %v", err)
	}
	if _, err := e.PublicDeviceGrantLookup(ticket.UserCode, "192.0.2.2"); !errors.Is(err, ErrDeviceUserCodeThrottled) {
		t.Fatalf("public aggregate throttle: %v", err)
	}
	if _, err := e.LookupDeviceGrant(ticket.UserCode); err != nil {
		t.Fatalf("admin budget shared: %v", err)
	}
	advance(deviceUserCodeWindow)
	fresh := newGrant(t, e)
	if _, err := e.PublicDeviceGrantLookup(fresh.UserCode, grantSource); err != nil {
		t.Fatalf("public window did not reset: %v", err)
	}
}

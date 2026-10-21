package core

import (
	"aegishook/internal/core/discovery"
	"aegishook/internal/localaddr"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DiscoveryScan preserves the CLI's existing scanner recorder seam. A nil scan
// in RunDiscovery uses discovery.Scan; production callers never replace it.
type DiscoveryScan func(context.Context, discovery.Policy, func(context.Context) ([]discovery.AccountHome, error), discovery.ScanEnvironment) discovery.Report

// ReadDiscoveryBundle reads only the verified enrolled cache, including rotated
// trust. dir is the caller's already-validated machine/private or client root.
func ReadDiscoveryBundle(dir string) (PolicyBundle, error) {
	conn, err := discoveryConnection(filepath.Join(dir, "adapter", "connection.json"))
	if err != nil {
		return PolicyBundle{}, err
	}
	return discoveryCachedBundle(filepath.Join(dir, "adapter", "bundle.json"), conn)
}

// RunDiscovery is the S7 scan-and-report path shared by ctl and the service.
// The caller validates the machine context (or supplies its own-home account).
// A nil accounts provider enumerates local accounts only in all-account scope.
// Non-final reports (including held locks) are returned without posting.
func RunDiscovery(ctx context.Context, dir string, scope discovery.ReportScope, accounts func(context.Context) ([]discovery.AccountHome, error), scan DiscoveryScan) (discovery.Report, error) {
	connection := filepath.Join(dir, "adapter", "connection.json")
	conn, err := discoveryConnection(connection)
	if err != nil {
		return discovery.Report{}, err
	}
	bundle, err := discoveryCachedBundle(filepath.Join(filepath.Dir(connection), "bundle.json"), conn)
	if err != nil {
		return discovery.Report{}, err
	}
	var policy discovery.Policy
	if bundle.Discovery != nil {
		policy = discovery.Policy{Enabled: bundle.Discovery.Enabled, IntervalSeconds: bundle.Discovery.IntervalSeconds}
	}
	// Gate at the caller as well as in Scan: disabled means no enumeration,
	// account lookup, environment reads, lock acquisition or network requests.
	if !policy.Enabled || policy.IntervalSeconds <= 0 {
		return discovery.Report{}, nil
	}
	env := discovery.ScanEnvironment{NodeID: conn.NodeID, Scope: scope, CredentialsPresent: true, LockPath: filepath.Join(dir, "discovery.lock")}
	if scope == discovery.OwnHome {
		env.Variables = map[string]string{}
		for _, name := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME", "PI_CODING_AGENT_DIR"} {
			env.Variables[name] = os.Getenv(name)
		}
	}
	if scan == nil {
		scan = discovery.Scan
	}
	report := scan(ctx, policy, accounts, env)
	if !report.Final {
		return report, nil
	}
	return report, postDiscoveryReport(ctx, conn, report)
}

func discoveryConnection(path string) (ClientConnection, error) {
	// Same regular-file/handle checks as bridge.readConnection; bound reads by
	// the existing policy JSON budget rather than adding a new resource limit.
	var conn ClientConnection
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return conn, errors.New("discovery credential unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return conn, errors.New("discovery credential unavailable")
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return conn, errors.New("discovery credential unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(f, PolicyBundleMaxBytes+1))
	if err != nil || len(data) > PolicyBundleMaxBytes || json.Unmarshal(data, &conn) != nil || len(conn.Token) != 64 || len(conn.NodeID) != 32 || len(conn.BundlePublicKey) != ed25519.PublicKeySize {
		return ClientConnection{}, errors.New("discovery credential unavailable")
	}
	endpoint, err := localaddr.Endpoint(conn.Endpoint)
	if err != nil {
		return ClientConnection{}, errors.New("invalid discovery endpoint")
	}
	conn.Endpoint = endpoint
	return conn, nil
}

func discoveryCachedBundle(path string, conn ClientConnection) (PolicyBundle, error) {
	// Follow bridge.policyBundle's cached branch, including #65 rotated trust.
	bootstrap, err := BootstrapPolicyTrust(conn.BundlePublicKey, conn.BundleTrust)
	if err != nil {
		return PolicyBundle{}, errors.New("discovery policy unavailable")
	}
	state, err := ReadPolicyTrust(path, bootstrap)
	if err != nil {
		return PolicyBundle{}, errors.New("discovery policy unavailable")
	}
	signed, signer, err := ReadPolicyBundleWithTrust(path, state, conn.NodeID)
	if err != nil {
		return PolicyBundle{}, errors.New("discovery policy unavailable")
	}
	bundle, _, err := VerifyCachedPolicyBundle(signed, signer, state, conn.NodeID)
	if err != nil {
		return PolicyBundle{}, errors.New("discovery policy unavailable")
	}
	return bundle, nil
}

func postDiscoveryReport(ctx context.Context, conn ClientConnection, report discovery.Report) error {
	if !report.Final || report.NodeID != conn.NodeID || report.Validate() != nil {
		return errors.New("invalid discovery report")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return errors.New("invalid discovery report")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, conn.Endpoint+"/api/v1/client/discovery-reports", bytes.NewReader(data))
	if err != nil {
		return errors.New("discovery report unavailable")
	}
	// Match MachineEnrolledContext/bridge.policyGet: device bearer only,
	// HTTPS-or-loopback origin validation, and never forward it on a redirect.
	req.Header.Set("Authorization", "Bearer "+conn.Token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("bundle redirect refused") }}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("discovery report service unavailable")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK, http.StatusConflict:
		return nil // Plan §9.3: stale/replayed report is benign, never retried.
	case http.StatusRequestEntityTooLarge:
		return errors.New("discovery report exceeds body limit")
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("discovery report credential rejected")
	default:
		return errors.New("discovery report rejected")
	}
}

package main

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"aegishook/internal/service"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryDispatchHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runClient([]string{"discover", "--help"}, nil, &out); err != nil {
		t.Fatalf("client discover dispatch: %v", err)
	}
	if code := runCtl([]string{"discover", "--help"}, io.Discard); code != service.ExitOK {
		t.Fatalf("ctl discover dispatch: %d", code)
	}
}

// Credentials and signing keys in these fixtures are generated in temporary
// directories; tests never read an installed connection or a real account home.
func discoveryFixture(t *testing.T, dir, endpoint string, policy *core.DiscoveryPolicy) core.ClientConnection {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn := core.ClientConnection{Endpoint: endpoint, Token: strings.Repeat("a", 64), NodeID: strings.Repeat("b", 32), BundlePublicKey: public}
	adapter := filepath.Join(dir, "adapter")
	if err := os.MkdirAll(adapter, 0700); err != nil {
		t.Fatal(err)
	}
	discoveryWriteJSON(t, filepath.Join(adapter, "connection.json"), conn)
	payload, err := json.Marshal(core.PolicyBundle{Revision: 1, NodeID: conn.NodeID, Rules: []core.Rule{}, Discovery: policy})
	if err != nil {
		t.Fatal(err)
	}
	signed := core.SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
	if _, err := core.CachePolicyBundle(filepath.Join(adapter, "bundle.json"), signed, public, conn.NodeID); err != nil {
		t.Fatal(err)
	}
	return conn
}

func discoveryWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func discoveryEnabled() *core.DiscoveryPolicy {
	// One second is the existing nonzero policy fixture in core tests.
	return &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 1}
}

func stubDiscoveryScan(t *testing.T, scan func(context.Context, discovery.Policy, func(context.Context) ([]discovery.AccountHome, error), discovery.ScanEnvironment) discovery.Report) {
	t.Helper()
	previous := scanDiscovery
	scanDiscovery = scan
	t.Cleanup(func() { scanDiscovery = previous })
}

func finalDiscoveryReport(env discovery.ScanEnvironment) discovery.Report {
	now := time.Now().UTC()
	return discovery.Report{SchemaVersion: discovery.SchemaVersion, NodeID: env.NodeID, Scope: env.Scope, Mode: "full", Final: true, ScanStartedAt: now, ScanCompletedAt: now, Accounts: []discovery.Account{}}
}

func TestDiscoveryPolicyDisabledDoesNotScan(t *testing.T) {
	stubDiscoveryScan(t, func(context.Context, discovery.Policy, func(context.Context) ([]discovery.AccountHome, error), discovery.ScanEnvironment) discovery.Report {
		t.Fatal("disabled policy called scanner")
		return discovery.Report{}
	})
	for _, policy := range []*core.DiscoveryPolicy{nil, {}, {Enabled: false, IntervalSeconds: 1}, {Enabled: true}} {
		dir := t.TempDir()
		discoveryFixture(t, dir, "http://127.0.0.1", policy)
		if err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard); err != nil {
			t.Fatalf("disabled policy: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "discovery.lock")); !os.IsNotExist(err) {
			t.Fatal("disabled policy acquired lock")
		}
	}
}

func TestDiscoveryDoesNotPostNonFinalReport(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	defer server.Close()
	dir := t.TempDir()
	discoveryFixture(t, dir, server.URL, discoveryEnabled())
	for _, empty := range []bool{true, false} {
		t.Run(strconv.FormatBool(empty), func(t *testing.T) {
			stubDiscoveryScan(t, func(_ context.Context, _ discovery.Policy, _ func(context.Context) ([]discovery.AccountHome, error), env discovery.ScanEnvironment) discovery.Report {
				if empty {
					return discovery.Report{}
				}
				report := finalDiscoveryReport(env)
				report.Final = false
				return report
			})
			if err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
	if requests != 0 {
		t.Fatal("posted a non-final report")
	}
}

func TestDiscoveryPostHTTPStatuses(t *testing.T) {
	stubDiscoveryScan(t, func(_ context.Context, _ discovery.Policy, _ func(context.Context) ([]discovery.AccountHome, error), env discovery.ScanEnvironment) discovery.Report {
		return finalDiscoveryReport(env)
	})
	for _, status := range []int{http.StatusOK, http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/client/discovery-reports" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || r.Header.Get("Content-Type") != "application/json" {
					t.Error("incorrect discovery transport")
				}
				report, err := discovery.DecodeReport(r.Body)
				if err != nil || report.Scope != discovery.OwnHome || report.NodeID != strings.Repeat("b", 32) {
					t.Error("invalid posted report")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "SENTINEL_private_path_and_account")
			}))
			defer server.Close()
			dir := t.TempDir()
			discoveryFixture(t, dir, server.URL, discoveryEnabled())
			err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard)
			wantOK := status == http.StatusOK || status == http.StatusConflict
			if (err == nil) != wantOK || requests != 1 {
				t.Fatalf("status %d: error %v, requests %d", status, err, requests)
			}
			if err != nil && strings.Contains(err.Error(), "SENTINEL") {
				t.Fatal("response body leaked")
			}
		})
	}
}

func TestDiscoveryOwnHomeAndLockContention(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	memory := filepath.Join(home, ".claude", "CLAUDE.md")
	if err := os.WriteFile(memory, []byte("SENTINEL_memory_body"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := currentDiscoveryUser
	currentDiscoveryUser = func() (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Geteuid()), Username: "fixture", HomeDir: home}, nil
	}
	t.Cleanup(func() { currentDiscoveryUser = previous })
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	for _, name := range []string{"CODEX_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME", "PI_CODING_AGENT_DIR"} {
		t.Setenv(name, "")
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		data, _ := io.ReadAll(r.Body)
		if bytes.Contains(data, []byte("SENTINEL_memory_body")) {
			t.Error("uploaded memory body")
		}
		report, err := discovery.DecodeReport(bytes.NewReader(data))
		if err != nil || len(report.Accounts) != 1 || report.Accounts[0].HomePath != home || report.Accounts[0].AccountID != strconv.Itoa(os.Geteuid()) {
			t.Error("own-home scope incorrect")
		}
	}))
	defer server.Close()
	discoveryFixture(t, dir, server.URL, discoveryEnabled())
	before := discoveryHomeSnapshot(t, home)
	lock, err := discovery.TryScanLock(filepath.Join(dir, "discovery.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard); err != nil || requests != 0 {
		t.Fatalf("contention not skipped: %v, %d", err, requests)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard); err != nil || requests != 1 {
		t.Fatalf("own-home scan: %v, %d", err, requests)
	}
	if !reflect.DeepEqual(before, discoveryHomeSnapshot(t, home)) {
		t.Fatal("scanner wrote into account home")
	}
}

func discoveryHomeSnapshot(t *testing.T, home string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		result[path] = info.Mode().String() + info.ModTime().String() + strconv.FormatInt(info.Size(), 10)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDiscoveryMachinePrivilegedRejectsUnprivilegedProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		account, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		if account.Uid == "S-1-5-18" {
			t.Skip("test process genuinely runs as Windows SYSTEM")
		}
	} else if os.Geteuid() == 0 {
		t.Skip("test process genuinely runs as root")
	}
	if discoveryMachinePrivileged() {
		t.Fatal("real machine-context predicate accepted an unprivileged process")
	}
}

func TestCtlDiscoveryRequiresMachineContext(t *testing.T) {
	previous := discoveryMachinePrivileged
	discoveryMachinePrivileged = func() bool { return false }
	t.Cleanup(func() { discoveryMachinePrivileged = previous })
	var out bytes.Buffer
	if got := runCtl([]string{"discover", "--machine-dir", t.TempDir()}, &out); got != service.ExitUsage || out.String() != "discovery requires machine context\n" {
		t.Fatalf("unprivileged ctl: %d %q", got, out.String())
	}
	discoveryMachinePrivileged = func() bool { return true }
	for _, root := range []string{"relative", string(filepath.Separator), t.TempDir()} {
		if got := runCtl([]string{"discover", "--machine-dir", root}, io.Discard); got != service.ExitUsage {
			t.Fatalf("non-machine context accepted: %d", got)
		}
	}
}

func TestCtlDiscoveryUsesMachineCredentialAndScope(t *testing.T) {
	previousAdmin, previousValidate := discoveryMachinePrivileged, core.ValidateMachinePath
	discoveryMachinePrivileged = func() bool { return true }
	core.ValidateMachinePath = func(string, bool) error { return nil } // Temporary fixture tree only.
	t.Cleanup(func() { discoveryMachinePrivileged, core.ValidateMachinePath = previousAdmin, previousValidate })
	root := t.TempDir()
	private := core.MachinePaths(root).Private
	posted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted = true
		report, err := discovery.DecodeReport(r.Body)
		if err != nil || report.Scope != discovery.AllLocalAccounts || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			t.Error("machine report not node-authenticated/all-accounts")
		}
	}))
	defer server.Close()
	discoveryFixture(t, private, server.URL, discoveryEnabled())
	stubDiscoveryScan(t, func(_ context.Context, _ discovery.Policy, accounts func(context.Context) ([]discovery.AccountHome, error), env discovery.ScanEnvironment) discovery.Report {
		if accounts != nil || env.Scope != discovery.AllLocalAccounts || env.LockPath != filepath.Join(private, "discovery.lock") || len(env.Variables) != 0 {
			t.Fatal("machine scanner used user context")
		}
		return finalDiscoveryReport(env)
	})
	if code := runCtl([]string{"discover", "--machine-dir", root}, io.Discard); code != service.ExitOK || !posted {
		t.Fatalf("machine discover: %d, posted %v", code, posted)
	}
}

func TestDiscoveryRejectsInvalidCacheAndCredentialsBeforeScan(t *testing.T) {
	stubDiscoveryScan(t, func(context.Context, discovery.Policy, func(context.Context) ([]discovery.AccountHome, error), discovery.ScanEnvironment) discovery.Report {
		t.Fatal("invalid state called scanner")
		return discovery.Report{}
	})
	for _, kind := range []string{"missing-connection", "invalid-connection", "invalid-token", "bad-endpoint", "missing-cache", "tampered-cache", "wrong-node"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			conn := discoveryFixture(t, dir, "http://127.0.0.1", discoveryEnabled())
			connection, bundle := filepath.Join(dir, "adapter", "connection.json"), filepath.Join(dir, "adapter", "bundle.json")
			switch kind {
			case "missing-connection":
				if err := os.Remove(connection); err != nil {
					t.Fatal(err)
				}
			case "invalid-connection":
				if err := os.WriteFile(connection, []byte("SENTINEL_invalid_json"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-token":
				conn.Token = ""
				discoveryWriteJSON(t, connection, conn)
			case "bad-endpoint":
				conn.Endpoint = "http://remote.invalid/SENTINEL"
				discoveryWriteJSON(t, connection, conn)
			case "missing-cache":
				if err := os.Remove(bundle); err != nil {
					t.Fatal(err)
				}
			case "tampered-cache":
				discoveryWriteJSON(t, bundle, core.SignedPolicyBundle{Payload: []byte("SENTINEL_tampered")})
			case "wrong-node":
				conn.NodeID = strings.Repeat("c", 32)
				discoveryWriteJSON(t, connection, conn)
			}
			err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard)
			if err == nil || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), dir) {
				t.Fatalf("invalid state not safely rejected: %v", err)
			}
		})
	}
}

func TestDiscoveryRedirectRefusedAndStaticErrors(t *testing.T) {
	stubDiscoveryScan(t, func(_ context.Context, _ discovery.Policy, _ func(context.Context) ([]discovery.AccountHome, error), env discovery.ScanEnvironment) discovery.Report {
		return finalDiscoveryReport(env)
	})
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++ }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	dir := t.TempDir()
	discoveryFixture(t, dir, server.URL, discoveryEnabled())
	if err := runClient([]string{"discover", "--client-dir", dir}, nil, io.Discard); err == nil || redirected != 0 {
		t.Fatalf("redirect followed: %v, %d", err, redirected)
	}
	for _, args := range [][]string{{"discover", "--bogus", "SENTINEL"}, {"discover", "extra"}} {
		var out bytes.Buffer
		if err := runClient(args, nil, &out); err == nil || strings.Contains(out.String(), "SENTINEL") {
			t.Fatal("usage error not static")
		}
	}
	previous := currentDiscoveryUser
	currentDiscoveryUser = func() (*user.User, error) { return nil, errors.New("SENTINEL_account_path") }
	t.Cleanup(func() { currentDiscoveryUser = previous })
	if _, err := discoveryOwnAccount(context.Background()); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatal("account lookup error leaked")
	}
}

package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func scanFixture(t *testing.T) (AccountHome, ScanEnvironment) {
	t.Helper()
	home := t.TempDir()
	account := AccountHome{"fixture", strconv.Itoa(os.Getuid()), home}
	env := ScanEnvironment{NodeID: "node", Scope: OwnHome, CredentialsPresent: true,
		LockPath: filepath.Join(t.TempDir(), "discovery.lock")}
	return account, env
}

func scanAccounts(accounts ...AccountHome) func(context.Context) ([]AccountHome, error) {
	return func(context.Context) ([]AccountHome, error) { return accounts, nil }
}

func scanAgent(t *testing.T, report Report, family string) Agent {
	t.Helper()
	for _, agent := range report.Accounts[0].Agents {
		if agent.Family == family {
			return agent
		}
	}
	t.Fatal("missing family", family)
	return Agent{}
}

func TestScanGateBeforeAllIO(t *testing.T) {
	for _, tc := range []struct {
		name        string
		policy      Policy
		credentials bool
	}{
		{"absent", Policy{}, true}, {"disabled", Policy{false, 1}, true},
		{"zero", Policy{true, 0}, true}, {"negative", Policy{true, -1}, true},
		{"no credentials", Policy{true, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, env := scanFixture(t)
			env.CredentialsPresent = tc.credentials
			calls := 0
			io := scanIO{
				lock:     func(string) (*ScanLock, error) { calls++; return nil, errors.New("unexpected lock") },
				openHome: func(string, string) (*HomeRoot, HomeState, Reason) { calls++; return nil, HomeDenied, ReasonHomeDenied },
			}
			source := func(context.Context) ([]AccountHome, error) { calls++; return nil, nil }
			got := scan(context.Background(), tc.policy, source, env, io)
			if calls != 0 || got.Final || got.SchemaVersion != "" {
				t.Fatalf("disabled scan performed IO or emitted a report: calls=%d report=%+v", calls, got)
			}
			if _, err := os.Stat(env.LockPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("gate created a lock file")
			}
		})
	}
}

func TestScanHeldLockSkipsEnumerationAndHomes(t *testing.T) {
	_, env := scanFixture(t)
	lock, err := TryScanLock(env.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	calls := 0
	source := func(context.Context) ([]AccountHome, error) { calls++; return nil, nil }
	io := scanIO{lock: TryScanLock, openHome: func(string, string) (*HomeRoot, HomeState, Reason) {
		calls++
		return nil, HomeUnavailable, ReasonHomeUnavailable
	}}
	if got := scan(context.Background(), Policy{true, 1}, source, env, io); got.Final || calls != 0 {
		t.Fatalf("overlap performed scan: final=%v calls=%d", got.Final, calls)
	}
}

func TestScanComposesAllFamiliesAndScopedAssets(t *testing.T) {
	account, env := scanFixture(t)
	for rel, data := range map[string]string{
		".claude.json": collectorJSON, ".claude/skills/example/SKILL.md": "skill body",
		".claude/CLAUDE.md": "memory body", ".codex/config.toml": collectorTOML,
		".codex/AGENTS.md": "instructions", ".codex/AGENTS.override.md": "overrides",
		".cursor/mcpServers.json": collectorJSON, ".config/opencode/opencode.json": `{"mcp":{}}`,
		".config/opencode/plugins/example.js": "plugin", ".pi/agent/extensions/example.ts": "plugin",
		".grok/hooks/example.json": "plugin",
	} {
		fixtureFile(t, account.HomePath, rel, []byte(data))
	}
	got := Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.NodeID != env.NodeID || got.Scope != OwnHome || got.ScanStartedAt.IsZero() || got.ScanCompletedAt.Before(got.ScanStartedAt) || len(got.Accounts) != 1 {
		t.Fatalf("invalid report envelope: %+v", got)
	}
	if got.Accounts[0].HomeState != HomeReadable || len(got.Accounts[0].Agents) != 10 {
		t.Fatal("incomplete account")
	}
	for _, agent := range got.Accounts[0].Agents {
		if len(agent.Categories) != 15 {
			t.Fatal("missing category/scope keys", agent.Family)
		}
		paths, _ := PathsForFamily(agent.Family)
		if paths.Supported && agent.Found != Found {
			t.Fatal("fixture not found", agent.Family)
		}
		if !paths.Supported && agent.Found != FoundUnknown {
			t.Fatal("unsupported must remain unknown")
		}
		for _, c := range agent.Categories {
			if c.Scope != ScopeHome {
				requireCategory(t, c, ScanNotScanned, ReasonProjectScopeDeferred, 0)
			}
			if c.Category == "builtin_tools" && c.Scope == ScopeHome {
				requireCategory(t, c, ScanNotSupported, "", 0)
			}
		}
	}
	requireCategory(t, homeCategory(t, scanAgent(t, got, "claude").Categories, "skills"), ScanScanned, "", 1)
	requireCategory(t, homeCategory(t, scanAgent(t, got, "claude").Categories, "memory"), ScanScanned, "", 1)
	requireCategory(t, homeCategory(t, scanAgent(t, got, "codex").Categories, "memory"), ScanScanned, "", 2)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("SENTINEL_")) || bytes.Contains(encoded, []byte("memory body")) {
		t.Fatal("body leaked")
	}
	if _, err := DecodeReport(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	if lock, err := TryScanLock(env.LockPath); err != nil {
		t.Fatal("scan did not release lock", err)
	} else {
		lock.Close()
	}
}

func TestScanHomeFailuresAndProbeErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  HomeState
		reason Reason
	}{
		{"denied", HomeDenied, ReasonHomeDenied}, {"unavailable", HomeUnavailable, ReasonHomeUnavailable},
		{"owner mismatch", HomeDenied, ReasonOwnerMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account, env := scanFixture(t)
			io := scanIO{lock: TryScanLock, openHome: func(home, id string) (*HomeRoot, HomeState, Reason) {
				if home != account.HomePath || id != account.AccountID {
					t.Fatal("lost enumerated identity")
				}
				return nil, tc.state, tc.reason
			}}
			got := scan(context.Background(), Policy{true, 1}, scanAccounts(account), env, io)
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
			if got.Accounts[0].HomeState != tc.state {
				t.Fatal("lost home state")
			}
			agent := scanAgent(t, got, "claude")
			if agent.Found != FoundUnknown {
				t.Fatal("home failure claimed absence")
			}
			requireCategory(t, homeCategory(t, agent.Categories, "memory"), ScanError, tc.reason, 0)
		})
	}
	account, env := scanFixture(t)
	fixtureFile(t, account.HomePath, ".claude/settings.json", []byte(`{}`))
	got := Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	claude := scanAgent(t, got, "claude")
	if claude.Found != FoundUnknown || claude.Evidence.Kind != "tg_target_only" {
		t.Fatal("TG target claimed discovery")
	}
	requireCategory(t, homeCategory(t, claude.Categories, "mcp"), ScanUnknown, ReasonTGTargetOnly, 0)
	if err := os.Mkdir(filepath.Join(account.HomePath, ".claude.json"), 0700); err != nil {
		t.Fatal(err)
	}
	got = Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	requireCategory(t, homeCategory(t, scanAgent(t, got, "claude").Categories, "mcp"), ScanError, ReasonNotRegularFile, 0)
}

func TestScanCancellationNeverFinalizesPartialResults(t *testing.T) {
	account, env := scanFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	io := scanIO{lock: TryScanLock, openHome: func(home, id string) (*HomeRoot, HomeState, Reason) {
		root, state, reason := OpenHome(home, id)
		cancel()
		return root, state, reason
	}}
	got := scan(ctx, Policy{true, 1}, scanAccounts(account), env, io)
	if got.Final {
		t.Fatal("canceled scan finalized")
	}
	requireCategory(t, homeCategory(t, scanAgent(t, got, "claude").Categories, "memory"), ScanError, ReasonCanceled, 0)
	calls := 0
	got = scan(ctx, Policy{true, 1}, func(context.Context) ([]AccountHome, error) { calls++; return nil, nil }, env, io)
	if calls != 0 || got.Final {
		t.Fatal("pre-canceled scan performed IO")
	}
}

func TestScanOverridesOnlyOwnHomeAndNeverEscape(t *testing.T) {
	account, env := scanFixture(t)
	fixtureFile(t, account.HomePath, "custom/codex/config.toml", []byte(collectorTOML))
	fixtureFile(t, account.HomePath, "custom/codex/AGENTS.md", []byte("memory"))
	env.Variables = map[string]string{"CODEX_HOME": filepath.Join(account.HomePath, "custom", "codex")}
	got := Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	codex := scanAgent(t, got, "codex")
	if codex.Found != Found || codex.Evidence.RelPath != "custom/codex/config.toml" {
		t.Fatal("override ignored")
	}
	requireCategory(t, homeCategory(t, codex.Categories, "memory"), ScanScanned, "", 1)
	env.Scope = AllLocalAccounts
	got = Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	if scanAgent(t, got, "codex").Found != NotFound {
		t.Fatal("cross-account scan used process override")
	}
	env.Scope = OwnHome
	env.Variables["CODEX_HOME"] = t.TempDir()
	got = Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	if scanAgent(t, got, "codex").Found != FoundUnknown {
		t.Fatal("escaping override claimed absence")
	}
	requireCategory(t, homeCategory(t, scanAgent(t, got, "codex").Categories, "mcp"), ScanError, ReasonEscapedRoot, 0)
}

func TestScanEnumerationFailureDoesNotFinalize(t *testing.T) {
	_, env := scanFixture(t)
	got := Scan(context.Background(), Policy{true, 1}, func(context.Context) ([]AccountHome, error) {
		return []AccountHome{{"partial", "123", "/partial"}}, errors.New("SENTINEL_enumerator")
	}, env)
	if got.Final || len(got.Accounts) != 0 {
		t.Fatal("partial enumeration finalized")
	}
}

// Structural exec allowlist complements the OS enumerators' existing executable
// recorders: no scanner/probe/collector may introduce a new process launch path.
func TestScanZeroExecAllowlist(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			if imp.Path.Value != `"os/exec"` {
				continue
			}
			if name != "accounts_linux.go" && name != "accounts_darwin.go" {
				t.Fatal("new process launch surface", name)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun, ok := call.Fun.(*ast.Ident)
			if !ok || (fun.Name != "runGetent" && fun.Name != "runDscl") {
				return true
			}
			want := `"/usr/bin/getent"`
			if fun.Name == "runDscl" {
				want = `"/usr/bin/dscl"`
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok || literal.Value != want {
				t.Fatal("non-allowlisted executable", name)
			}
			seen[fun.Name] = true
			return true
		})
	}
	if !reflect.DeepEqual(seen, map[string]bool{"runGetent": true, "runDscl": true}) {
		t.Fatal("allowlist check lost its enumerator coverage", seen)
	}
}

func TestScanAccountSourceValidationAndOrdering(t *testing.T) {
	account, env := scanFixture(t)
	for _, homes := range [][]AccountHome{nil, {account, {"other", account.AccountID + "1", t.TempDir()}}, {{"invalid", "id", "relative"}}} {
		if got := Scan(context.Background(), Policy{true, 1}, scanAccounts(homes...), env); got.Final {
			t.Fatal("invalid own-home provider finalized")
		}
	}
	if got := Scan(context.Background(), Policy{true, 1}, nil, env); got.Final {
		t.Fatal("own-home scan must not default to all-account enumeration")
	}
	env.Scope = AllLocalAccounts
	first, second := account, account
	first.AccountID, second.AccountID = "10", "20"
	opened := []string{}
	io := scanIO{lock: TryScanLock, openHome: func(_ string, id string) (*HomeRoot, HomeState, Reason) {
		opened = append(opened, id)
		return nil, HomeUnavailable, ReasonHomeUnavailable
	}}
	got := scan(context.Background(), Policy{true, 1}, scanAccounts(second, first, second), env, io)
	if !got.Final || !reflect.DeepEqual(opened, []string{"10", "20"}) || len(got.Accounts) != 2 {
		t.Fatal("did not reuse sorted, deduplicated account normalization", opened)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestScanInvalidScopeAndLockPathNeverEnumerate(t *testing.T) {
	_, env := scanFixture(t)
	calls := 0
	source := func(context.Context) ([]AccountHome, error) { calls++; return nil, nil }
	env.Scope = "invalid"
	if got := Scan(context.Background(), Policy{true, 1}, source, env); got.Final || calls != 0 {
		t.Fatal("invalid scope enumerated")
	}
	env.Scope, env.LockPath = OwnHome, ""
	if got := Scan(context.Background(), Policy{true, 1}, source, env); got.Final || calls != 0 {
		t.Fatal("lock failure enumerated")
	}
}

func TestScanHoldsLockThroughoutEnumeration(t *testing.T) {
	account, env := scanFixture(t)
	source := func(context.Context) ([]AccountHome, error) {
		if lock, err := TryScanLock(env.LockPath); lock != nil || !errors.Is(err, ErrScanLocked) {
			t.Fatal("enumerated without lock", err)
		}
		return []AccountHome{account}, nil
	}
	if got := Scan(context.Background(), Policy{true, 1}, source, env); !got.Final {
		t.Fatal("scan not completed")
	}
}

func TestScanRealMissingAndReplacedHomes(t *testing.T) {
	account, env := scanFixture(t)
	account.HomePath = filepath.Join(account.HomePath, "missing")
	got := Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	if got.Accounts[0].HomeState != HomeUnavailable {
		t.Fatal("missing home not represented")
	}
	requireCategory(t, homeCategory(t, scanAgent(t, got, "codex").Categories, "memory"), ScanError, ReasonHomeUnavailable, 0)
	if runtime.GOOS == "windows" {
		return
	} // Windows ownership is SID/ACL, not a Unix UID.
	account.HomePath = filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(account.HomePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(account.HomePath, account.HomePath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), account.HomePath); err != nil {
		t.Fatal(err)
	}
	account.AccountID = strconv.Itoa(os.Getuid() + 1) // R1's replacement fixture, no chown privilege needed.
	got = Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
	if got.Accounts[0].HomeState != HomeDenied {
		t.Fatal("replacement home accepted")
	}
	requireCategory(t, homeCategory(t, scanAgent(t, got, "codex").Categories, "memory"), ScanError, ReasonOwnerMismatch, 0)
}

func TestScanAllDocumentedOverrides(t *testing.T) {
	for _, tc := range []struct{ family, key, base, rel, category string }{
		{"claude", "CLAUDE_CONFIG_DIR", "custom/claude", "custom/claude/CLAUDE.md", "memory"},
		{"opencode", "OPENCODE_CONFIG_DIR", "custom/opencode", "custom/opencode/plugins/plugin.js", "plugins"},
		{"opencode", "XDG_CONFIG_HOME", "custom", "custom/opencode/plugins/plugin.js", "plugins"},
		{"pi", "PI_CODING_AGENT_DIR", "custom/pi", "custom/pi/extensions/plugin.ts", "plugins"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			account, env := scanFixture(t)
			fixtureFile(t, account.HomePath, tc.rel, []byte("body"))
			if tc.family == "opencode" {
				fixtureFile(t, account.HomePath, "custom/opencode/opencode.json", []byte(`{"mcp":{}}`))
			}
			env.Variables = map[string]string{tc.key: filepath.Join(account.HomePath, filepath.FromSlash(tc.base))}
			got := Scan(context.Background(), Policy{true, 1}, scanAccounts(account), env)
			agent := scanAgent(t, got, tc.family)
			if agent.Found != Found {
				t.Fatal("override evidence not found", agent)
			}
			c := homeCategory(t, agent.Categories, tc.category)
			requireCategory(t, c, ScanScanned, "", 1)
			if c.Assets[0].SourceRelPath != tc.rel {
				t.Fatal("override asset not home-relative", c.Assets)
			}
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScanOverridePrecedenceAndConfinement(t *testing.T) {
	home := t.TempDir()
	p, _ := PathsForFamily("opencode")
	got, reason := ownHomePaths(p, home, map[string]string{
		"OPENCODE_CONFIG_DIR": filepath.Join(home, "specific"), "XDG_CONFIG_HOME": filepath.Join(home, "xdg"),
	})
	if reason != "" || got.ConfigFiles[0] != "specific/opencode.json" {
		t.Fatal("specific override must win")
	}
	if !reflect.DeepEqual(p.ConfigFiles, []string{".config/opencode/opencode.json", ".config/opencode/opencode.jsonc", ".config/opencode/config.json"}) {
		t.Fatal("table mutated")
	}
	p, _ = PathsForFamily("pi")
	for _, override := range []string{"relative", filepath.Join(home, "..", "sibling"), string([]byte{0})} {
		if _, reason := ownHomePaths(p, home, map[string]string{"PI_CODING_AGENT_DIR": override}); reason != ReasonEscapedRoot {
			t.Fatal("invalid override accepted", reason)
		}
	}
	got, reason = ownHomePaths(p, home, map[string]string{"PI_CODING_AGENT_DIR": home})
	if reason != "" || got.VendorDir != "." || got.PluginsDir != "extensions" {
		t.Fatal("home itself must be a valid confined root", got, reason)
	}
}

func TestScanCancellationAfterEnumerationDoesNotOpenHome(t *testing.T) {
	account, env := scanFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	source := func(context.Context) ([]AccountHome, error) { cancel(); return []AccountHome{account}, nil }
	opened := false
	io := scanIO{lock: TryScanLock, openHome: func(string, string) (*HomeRoot, HomeState, Reason) {
		opened = true
		return nil, HomeUnavailable, ReasonHomeUnavailable
	}}
	got := scan(ctx, Policy{true, 1}, source, env, io)
	if got.Final || opened {
		t.Fatal("cancellation performed a home open")
	}
	requireCategory(t, homeCategory(t, scanAgent(t, got, "claude").Categories, "memory"), ScanError, ReasonCanceled, 0)
}

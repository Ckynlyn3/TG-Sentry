package main

import (
	"aegishook/internal/core"
	"aegishook/internal/service"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestCtlStatusN1(t *testing.T) {
	cases := []struct {
		state service.Status
		code  int
	}{
		{service.Status{}, 10},
		{service.Status{Installed: true}, 20},
		{service.Status{Installed: true, Service: true}, 30},
		{service.Status{Installed: true, Service: true, Enrolled: true, Hooks: "missing"}, 40},
		{service.Status{Installed: true, Service: true, Enrolled: true, Hooks: "unknown"}, 50},
		{service.Status{Installed: true, Service: true, Enrolled: true, Hooks: "configured"}, 0},
	}
	for _, c := range cases {
		var out bytes.Buffer
		code := writeCtlStatus(&out, c.state, "hooks")
		if code != c.code {
			t.Fatalf("%+v: %d want %d", c.state, code, c.code)
		}
		if bytes.Contains(out.Bytes(), []byte(`"loaded":"true"`)) {
			t.Fatal("claimed loaded hooks")
		}
	}
	var out bytes.Buffer
	if got := runCtl([]string{"status", "--require", "bogus"}, &out); got != 2 {
		t.Fatalf("usage=%d", got)
	}
}

func TestCtlStatusTargetUserAndUsage(t *testing.T) {
	oldCall, oldCurrent, oldLookup := service.Call, currentCtlUser, lookupCtlUser
	defer func() { service.Call, currentCtlUser, lookupCtlUser = oldCall, oldCurrent, oldLookup }()
	service.Call = func(string, service.Request) (service.Status, error) {
		return service.Status{Installed: true, Service: true, Enrolled: true}, nil
	}
	currentCtlUser = func() (*user.User, error) { return &user.User{Uid: "0"}, nil }
	lookupCtlUser = func(name string) (*user.User, error) { return nil, errors.New("not found") }
	var out bytes.Buffer
	if got := runCtl([]string{"status"}, &out); got != 50 {
		t.Fatalf("root status=%d: %s", got, out.String())
	}
	if got := runCtl([]string{"status", "--require", "installed"}, &out); got != 0 {
		t.Fatal(got)
	}
	if got := runCtl([]string{"status", "--user", "missing"}, &out); got != 2 {
		t.Fatal(got)
	}
	currentCtlUser = func() (*user.User, error) { return &user.User{Uid: "S-1-5-18"}, nil }
	if got := runCtl([]string{"status"}, &out); got != 50 {
		t.Fatal(got)
	}
	lookupCtlUser = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Geteuid()), HomeDir: t.TempDir()}, nil
	}
	if got := runCtl([]string{"status", "--user", "fixture"}, &out); got != 40 {
		t.Fatal(got)
	}
	service.Call = func(string, service.Request) (service.Status, error) {
		return service.Status{}, errors.New("unavailable")
	}
	if got := runCtl([]string{"status", "--machine-dir", t.TempDir()}, &out); got != 10 {
		t.Fatal(got)
	}
	for _, args := range [][]string{nil, {"bogus"}, {"status", "extra"}, {"status", "--bogus"}, {"repair"}, {"commit", "--machine-dir", "relative"}, {"rollback", "--machine-dir", "relative"}, {"system-uninstall", "--machine-dir", "relative"}, {"system-install", "--machine-dir", "relative"}} {
		if got := runCtl(args, &out); got != 2 {
			t.Fatalf("%v = %d", args, got)
		}
	}
	if got := runCtl([]string{"status", "--help"}, &out); got != 0 {
		t.Fatal(got)
	}
	service.Call = func(string, service.Request) (service.Status, error) {
		return service.Status{Installed: true, Service: true, Enrolled: true}, nil
	}
	if got := runCtl([]string{"repair"}, &out); got != 0 {
		t.Fatal(got)
	}
}

func TestCtlNeverLogsTokensAndPackageClientGuard(t *testing.T) {
	var out bytes.Buffer
	token := strings.Repeat("a", 64)
	ctlError(&out, fmt.Errorf("fixture %s", token))
	if regexp.MustCompile(`[0-9a-fA-F]{64}`).Match(out.Bytes()) {
		t.Fatal("token in ctl output")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "aegishook")
	if err := os.WriteFile(binary, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := refusePackageClient(binary, root); err == nil {
		t.Fatal("package binary accepted")
	}
	if err := refusePackageClient(binary, root+"-sibling"); err != nil {
		t.Fatal("prefix sibling rejected", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(binary, link); err == nil {
		if refusePackageClient(link, root) == nil {
			t.Fatal("package symlink accepted")
		}
	}
	if refusePackageClient(filepath.Join(root, "missing"), root) == nil {
		t.Fatal("unresolvable binary accepted")
	}
	for _, platform := range []string{"windows", "darwin", "linux"} {
		if len(managedDestinations(platform)) != 3 {
			t.Fatal("missing managed destination")
		}
	}
}

func TestCtlStatusConfiguredAndOutputFailure(t *testing.T) {
	oldCall, oldCurrent := service.Call, currentCtlUser
	defer func() { service.Call, currentCtlUser = oldCall, oldCurrent }()
	home := t.TempDir()
	currentCtlUser = func() (*user.User, error) { return &user.User{Uid: "1000", HomeDir: home}, nil }
	service.Call = func(string, service.Request) (service.Status, error) {
		return service.Status{Installed: true, Service: true, Enrolled: true}, nil
	}
	project := t.TempDir()
	o := core.ClientOptions{Dir: filepath.Join(home, ".aegishook-client"), Binary: filepath.Join(home, "private-binary"), Agent: "claude", Scope: "project", Project: project, Endpoint: "https://review.example", Token: strings.Repeat("a", 64), Resources: map[string][]byte{"index.ts": []byte("fixture"), "opencode.mjs": []byte("fixture")}}
	if _, err := core.ClientOperation("install", o); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if got := runCtl([]string{"status"}, &out); got != 0 {
		t.Fatalf("configured=%d %s", got, out.String())
	}
	currentCtlUser = func() (*user.User, error) { return nil, errors.New("lookup unavailable") }
	if got := runCtl([]string{"status"}, &out); got != 2 {
		t.Fatal(got)
	}
	if got := writeCtlStatus(failingCtlWriter{}, service.Status{}, "hooks"); got != 2 {
		t.Fatal(got)
	}
}

type failingCtlWriter struct{}

func (failingCtlWriter) Write([]byte) (int, error) { return 0, errors.New("fixture write failure") }

func TestServiceDispatch(t *testing.T) {
	oldArgs, oldRun := os.Args, service.Run
	defer func() { os.Args, service.Run = oldArgs, oldRun }()
	os.Args = []string{"aegishook", "service"}
	called := false
	service.Run = func(root string) error { called = root == core.DefaultRoot(); return nil }
	main()
	if !called {
		t.Fatal("service dispatch missing")
	}
}

// #39 §6 bullet 4: status uses the installer's real snapshot, not service hook data.
func TestCtlStatusDrift(t *testing.T) {
	cases := []struct {
		name, hooks string
		owner       core.OwnerState
		code        int
	}{
		{"exact", "configured", core.OwnedExact, 0},
		{"removed", "missing", core.OwnerMissing, 40},
		{"file-missing", "missing", core.OwnerFileMissing, 40},
		{"modified", "missing", core.OwnedModified, 40},
		{"unreadable", "unknown", core.OwnerUnreadable, 50},
		{"enterprise-only", "missing", core.OwnerNotEvaluated, 40},
		{"absent-manifest", "missing", "", 40},
		{"invalid-manifest", "unknown", "", 50},
		{"unreadable-manifest", "unknown", "", 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			stubCtlStatusUser(t, home)
			agent, scope := "claude", "project"
			if tc.name == "enterprise-only" {
				agent, scope = "cursor", "enterprise"
			}
			entry := ""
			if tc.name != "absent-manifest" {
				entry = installCtlStatusHook(t, home, agent, scope)
				changeCtlStatusFixture(t, home, entry, tc.name)
			}
			var out bytes.Buffer
			if got := runCtl([]string{"status", "--user", "fixture"}, &out); got != tc.code {
				t.Fatalf("status=%d want=%d: %s", got, tc.code, out.String())
			}
			var status struct {
				service.Status
				Hooks []map[string]any `json:"hooks"`
			}
			if err := json.Unmarshal(out.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if status.Status.Hooks != tc.hooks || status.Loaded != "unknown" || status.Hooks == nil {
				t.Fatalf("wrong hook summary/detail: %s", out.String())
			}
			if tc.owner == "" {
				if len(status.Hooks) != 0 {
					t.Fatal("manifest failure reported hook entries")
				}
				return
			}
			if len(status.Hooks) != 1 {
				t.Fatalf("hook count=%d", len(status.Hooks))
			}
			want := map[string]any{"agent": agent, "scope": scope, "entry": entry, "ownerState": string(tc.owner)}
			gotJSON, _ := json.Marshal(status.Hooks[0])
			wantJSON, _ := json.Marshal(want)
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("hook detail=%s want=%s", gotJSON, wantJSON)
			}
		})
	}
}

func stubCtlStatusUser(t *testing.T, home string) {
	t.Helper()
	oldCall, oldCurrent, oldLookup := service.Call, currentCtlUser, lookupCtlUser
	t.Cleanup(func() { service.Call, currentCtlUser, lookupCtlUser = oldCall, oldCurrent, oldLookup })
	service.Call = func(string, service.Request) (service.Status, error) {
		return service.Status{Installed: true, Service: true, Enrolled: true, Hooks: "configured"}, nil
	}
	account := &user.User{Uid: strconv.Itoa(os.Geteuid()), HomeDir: home}
	lookupCtlUser = func(string) (*user.User, error) { return account, nil }
	currentCtlUser = func() (*user.User, error) { return account, nil }
}

func installCtlStatusHook(t *testing.T, home, agent, scope string) string {
	t.Helper()
	o := core.ClientOptions{Dir: filepath.Join(home, ".aegishook-client"), Binary: filepath.Join(home, "private-binary"), Agent: agent, Scope: scope, Endpoint: "https://review.example", Token: strings.Repeat("a", 64), Resources: map[string][]byte{"index.ts": []byte("fixture"), "opencode.mjs": []byte("fixture")}}
	if scope == "project" {
		o.Project = home
	}
	result, err := core.ClientOperation("install", o)
	if err != nil {
		t.Fatal(err)
	}
	return result.Entry
}

func changeCtlStatusFixture(t *testing.T, home, entry, change string) {
	t.Helper()
	manifest := filepath.Join(home, ".aegishook-client", "client.json")
	switch change {
	case "removed":
		if err := os.WriteFile(entry, []byte(`{"hooks":{}}`), 0600); err != nil {
			t.Fatal(err)
		}
	case "modified":
		data, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["matcher"] = "Read"
		data, err = json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry, data, 0600); err != nil {
			t.Fatal(err)
		}
	case "unreadable", "file-missing", "unreadable-manifest":
		path := entry
		if change == "unreadable-manifest" {
			path = manifest
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if change != "file-missing" {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
	case "invalid-manifest":
		if err := os.WriteFile(manifest, []byte("not-json"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCtlStatusDriftPreservesRequiredLayers(t *testing.T) {
	home := t.TempDir()
	stubCtlStatusUser(t, home)
	entry := installCtlStatusHook(t, home, "claude", "project")
	changeCtlStatusFixture(t, home, entry, "unreadable")
	for _, require := range []string{"installed", "service", "enrolled"} {
		var out bytes.Buffer
		if got := runCtl([]string{"status", "--user", "fixture", "--require", require}, &out); got != 0 {
			t.Fatalf("require %s=%d: %s", require, got, out.String())
		}
	}
	for _, state := range []service.Status{{}, {Installed: true}, {Installed: true, Service: true}} {
		service.Call = func(string, service.Request) (service.Status, error) { return state, nil }
		var out bytes.Buffer
		if got, want := runCtl([]string{"status", "--user", "fixture"}, &out), state.ExitCode("hooks"); got != want {
			t.Fatalf("lower-layer status=%d want=%d: %s", got, want, out.String())
		}
	}
}

func TestCtlStatusTargetHomeOwner(t *testing.T) {
	home := t.TempDir()
	stubCtlStatusUser(t, home)
	lookupCtlUser = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Geteuid() + 1), HomeDir: home}, nil
	}
	// Existing Windows owner validation is explicitly not evaluated.
	want := service.ExitHooksUnknown
	if runtime.GOOS == "windows" {
		want = service.ExitHooksMissing
	}
	var out bytes.Buffer
	if got := runCtl([]string{"status", "--user", "fixture"}, &out); got != want {
		t.Fatalf("owner mismatch=%d want=%d: %s", got, want, out.String())
	}
	if got := runCtl([]string{"status", "--user", "fixture", "--require", "enrolled"}, &out); got != 0 {
		t.Fatalf("owner mismatch changed enrolled requirement: %d", got)
	}
}

func TestCtlStatusMixedDrift(t *testing.T) {
	for _, tc := range []struct {
		states []core.OwnerState
		want   string
	}{
		{nil, "missing"},
		{[]core.OwnerState{core.OwnerNotEvaluated, core.OwnedExact}, "configured"},
		{[]core.OwnerState{core.OwnedExact, core.OwnedModified}, "missing"},
		{[]core.OwnerState{core.OwnerMissing, core.OwnerUnreadable}, "unknown"},
		{[]core.OwnerState{core.OwnerUnreadable, core.OwnerMissing}, "unknown"},
	} {
		report := core.DriftReport{Manifest: core.ManifestOK}
		for _, state := range tc.states {
			report.Entries = append(report.Entries, core.DriftEntry{OwnerState: state})
		}
		if got := ctlDriftState(report); got != tc.want {
			t.Fatalf("%v=%s want=%s", tc.states, got, tc.want)
		}
	}
}

func TestCtlStatusDriftOutputFailure(t *testing.T) {
	stubCtlStatusUser(t, t.TempDir())
	if got := runCtl([]string{"status", "--user", "fixture"}, failingCtlWriter{}); got != service.ExitUsage {
		t.Fatalf("output failure=%d", got)
	}
}

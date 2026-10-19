package main

import (
	"aegishook/internal/core"
	"aegishook/internal/service"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
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
	lookupCtlUser = func(string) (*user.User, error) { return &user.User{Uid: "1000", HomeDir: t.TempDir()}, nil }
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

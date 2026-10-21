package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"aegishook/internal/core"
)

func TestClientRepairDispatcher(t *testing.T) {
	old := currentCtlUser
	defer func() { currentCtlUser = old }()
	home := t.TempDir()
	currentCtlUser = func() (*user.User, error) { return &user.User{Uid: "1000", HomeDir: home}, nil }
	o := core.ClientOptions{Dir: filepath.Join(home, ".aegishook-client"), Binary: filepath.Join(home, "private-binary"), Agent: "claude", Scope: "project", Project: home, Endpoint: "https://review.example", Token: strings.Repeat("a", 64), Resources: map[string][]byte{"index.ts": []byte("fixture"), "opencode.mjs": []byte("fixture")}}
	installed, err := core.ClientOperation("install", o)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(installed.Entry); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runClient([]string{"repair"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var result core.ClientResult
	if err := json.NewDecoder(&out).Decode(&result); err != nil || result.Action != "repair" || result.Remaining != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !core.ClientHooksConfigured(home) {
		t.Fatal("dispatcher did not repair")
	}
	if err := runClient([]string{"repair"}, strings.NewReader(""), failingCtlWriter{}); err == nil {
		t.Fatal("output failure swallowed")
	}
}

func TestClientRepairRefusesPrivilegeAndFlags(t *testing.T) {
	old := currentCtlUser
	defer func() { currentCtlUser = old }()
	var out bytes.Buffer
	currentCtlUser = func() (*user.User, error) { return &user.User{Uid: "1000", HomeDir: t.TempDir()}, nil }
	t.Setenv("SUDO_UID", "0")
	if err := runClient([]string{"repair"}, nil, &out); err == nil {
		t.Fatal("sudo repair accepted")
	}
	t.Setenv("SUDO_UID", "")
	for _, uid := range []string{"0", "S-1-5-18"} {
		currentCtlUser = func() (*user.User, error) { return &user.User{Uid: uid, HomeDir: t.TempDir()}, nil }
		if err := runClient([]string{"repair"}, nil, &out); err == nil {
			t.Fatal("privileged repair accepted")
		}
	}
	currentCtlUser = func() (*user.User, error) { return nil, errors.New("no account") }
	if err := runClient([]string{"repair"}, nil, &out); err == nil {
		t.Fatal("lookup error ignored")
	}
	currentCtlUser = func() (*user.User, error) { return &user.User{Uid: "1000", HomeDir: t.TempDir()}, nil }
	for _, args := range [][]string{{"repair"}, {"repair", "--switch"}, {"repair", "--scope", "global"}, {"repair", "--client-dir", t.TempDir()}, {"repair", "--endpoint", "https://review.example"}, {"repair", "extra"}} {
		if err := runClient(args, nil, &out); err == nil {
			t.Fatalf("accepted invalid/un-enrolled repair %v", args)
		}
	}
	// The same package-binary guard used by install must be applied by repair.
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := refusePackageClient(binary, filepath.Dir(binary)); err == nil {
		t.Fatal("package binary accepted")
	}
}

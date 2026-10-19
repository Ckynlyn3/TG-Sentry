//go:build darwin && native

package service

import (
	"aegishook/internal/core"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func nativeMachineRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("NOT RUN: Gate B requires root on the macOS release runner; no privilege escalation in developer tests")
	}
	root := os.Getenv("TG_SENTRY_NATIVE_MACHINE_ROOT")
	if root == "" {
		t.Skip("NOT RUN: Gate B must provide TG_SENTRY_NATIVE_MACHINE_ROOT for the installed hash-verified signed artifact")
	}
	return root
}

func nativeCredential(t *testing.T, name string) *syscall.Credential {
	t.Helper()
	account, err := user.Lookup(name)
	if err != nil {
		t.Fatal("Gate B account unavailable", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatal("Gate B fixture must be non-root", err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
}

func TestNativePrivateDirUnixT2OrdinaryUserDenied(t *testing.T) {
	root := nativeMachineRoot(t)
	// Gate B provisioning keeps these canary fixture files until this test;
	// permissions are tested without reading or printing any secret content.
	p := core.MachinePaths(root)
	credential := nativeCredential(t, os.Getenv("TG_SENTRY_NATIVE_OTHER"))
	for _, path := range []string{p.Code, p.Enrolled, p.Connection, p.Rollback, filepath.Join(p.Private, ".native-temp")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("Gate B protected fixture missing", path, err)
		}
		for _, permission := range []string{"-r", "-w"} {
			cmd := exec.Command("/bin/test", permission, path)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
			err := cmd.Run()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatalf("ordinary-user access not denied: %s %s: %v", permission, path, err)
			}
		}
	}
}

func TestNativeEndpointUnixT3OwnerAdminOther(t *testing.T) {
	root := nativeMachineRoot(t)
	binary := filepath.Join(core.PackageRoot(), "aegishook")
	for _, role := range []string{"OWNER", "ADMIN", "OTHER"} {
		t.Run(role, func(t *testing.T) {
			name := os.Getenv("TG_SENTRY_NATIVE_" + role)
			if name == "" {
				t.Fatal("Gate B role fixture missing", role)
			}
			cmd := exec.Command(binary, "ctl", "status", "--machine-dir", root, "--require", "service")
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: nativeCredential(t, name)}
			err := cmd.Run()
			if role == "OTHER" {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != ExitNotInstalled {
					t.Fatalf("non-owner was not denied: %v", err)
				}
			} else if err != nil {
				t.Fatal("authorized control request failed", err)
			}
		})
	}
}

func TestNativeLaunchdUnixT4Registered(t *testing.T) {
	root := nativeMachineRoot(t)
	if err := checkLaunchd(); err != nil {
		t.Fatal(err)
	}
	state, err := Call(root, Request{Verb: "status"})
	if err != nil || state.ExitCode("service") != ExitOK {
		t.Fatalf("daemon unavailable: %+v %v", state, err)
	}
	// Restart-after-kill and reboot require the release runner's lifecycle
	// controller; this read-only check does not claim either occurred.
}

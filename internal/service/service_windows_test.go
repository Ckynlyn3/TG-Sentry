//go:build windows && native

package service

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestWindowsSCMHandlerT4StopShutdown(t *testing.T) {
	for _, command := range []svc.Cmd{svc.Stop, svc.Shutdown} {
		t.Run(commandName(command), func(t *testing.T) {
			handler := &windowsHandler{serve: func(ctx context.Context, ready chan<- error) error { ready <- nil; <-ctx.Done(); return nil }}
			requests, changes := make(chan svc.ChangeRequest), make(chan svc.Status)
			done := make(chan uint32, 1)
			go func() { _, code := handler.Execute(nil, requests, changes); done <- code }()
			expectSCMState(t, changes, svc.StartPending)
			expectSCMState(t, changes, svc.Running)
			requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
			expectSCMState(t, changes, svc.Running)
			requests <- svc.ChangeRequest{Cmd: command}
			expectSCMState(t, changes, svc.StopPending)
			select {
			case code := <-done:
				if code != 0 {
					t.Fatal(code)
				}
			case <-time.After(controlTimeout):
				t.Fatal("Execute did not exit on stop")
			}
		})
	}
}

func commandName(command svc.Cmd) string {
	if command == svc.Stop {
		return "stop"
	}
	return "shutdown"
}

func expectSCMState(t *testing.T, changes <-chan svc.Status, want svc.State) {
	t.Helper()
	select {
	case state := <-changes:
		if state.State != want {
			t.Fatalf("state=%v want=%v", state.State, want)
		}
		if want == svc.Running && state.Accepts != svc.AcceptStop|svc.AcceptShutdown {
			t.Fatal("missing stop/shutdown acceptance")
		}
	case <-time.After(controlTimeout):
		t.Fatal("SCM state update stalled")
	}
}

func TestWindowsSCMHandlerT4FailureEndsService(t *testing.T) {
	failure := errors.New("injected service failure")
	handler := &windowsHandler{serve: func(context.Context, chan<- error) error { return failure }}
	changes := make(chan svc.Status)
	done := make(chan uint32, 1)
	go func() { _, code := handler.Execute(nil, make(chan svc.ChangeRequest), changes); done <- code }()
	expectSCMState(t, changes, svc.StartPending)
	select {
	case code := <-done:
		if code != ExitService || !errors.Is(handler.err, failure) {
			t.Fatal("service failure not reported", code, handler.err)
		}
	case <-time.After(controlTimeout):
		t.Fatal("Execute did not end after serving failed")
	}
}

func TestWindowsSCMRegistrationRejectsForeignConfig(t *testing.T) {
	for _, config := range []mgr.Config{
		{BinaryPathName: `C:\Users\Public\aegishook.exe service`, StartType: mgr.StartAutomatic, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ServiceStartName: "LocalSystem"},
		{BinaryPathName: windows.ComposeCommandLine([]string{filepath.Join(core.PackageRoot(), "aegishook.exe"), "service", "unexpected"}), StartType: mgr.StartAutomatic, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ServiceStartName: "LocalSystem"},
	} {
		if verifySCMConfig(config) == nil {
			t.Fatal("foreign service configuration accepted")
		}
	}
}

func TestWindowsMachineRootIgnoresProgramDataOverride(t *testing.T) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(programData, "TG-Sentry")
	t.Setenv("ProgramData", filepath.Join(programData, "untrusted-override"))
	if !validWindowsMachineRoot(canonical) {
		t.Fatal("known-folder machine root rejected")
	}
	if validWindowsMachineRoot(core.DefaultRoot()) {
		t.Fatal("environment-redirected machine root accepted")
	}
	if _, err := callWindows(core.DefaultRoot(), Request{Verb: "status"}); err == nil || !strings.Contains(err.Error(), "invalid machine root") {
		t.Fatal("control client did not reject redirected root before pipe access", err)
	}
	if err := runWindows(core.DefaultRoot()); err == nil || !strings.Contains(err.Error(), "invalid machine root") {
		t.Fatal("service did not reject redirected root before SCM access", err)
	}
}

func nativeMachineRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("TG_SENTRY_NATIVE_MACHINE_ROOT")
	if root == "" {
		t.Skip("NOT RUN: Gate B must provide TG_SENTRY_NATIVE_MACHINE_ROOT for the installed hash-verified artifact")
	}
	if !validWindowsRoot(root) {
		t.Fatal("invalid native machine root fixture")
	}
	return root
}

func TestNativeWindowsSCMRegisteredT4(t *testing.T) {
	requireNativeSystem(t)
	root := nativeMachineRoot(t)
	if err := checkSCM(); err != nil {
		t.Fatal(err)
	}
	state, err := Call(root, Request{Verb: "status"})
	if err != nil || state.ExitCode("service") != ExitOK {
		t.Fatalf("service unavailable: %+v %v", state, err)
	}
	// This checks SCM auto-start/recovery CONFIGURATION. Reboot and three measured
	// restarts must be driven externally by the mirror runner, not claimed here.
}

func TestNativeWindowsEndpointT3T9Role(t *testing.T) {
	root := nativeMachineRoot(t)
	// Gate B invokes this test under actual OWNER / elevated ADMIN / OTHER /
	// SYSTEM processes; no passwords or synthetic authorization claims in tests.
	role := os.Getenv("TG_SENTRY_NATIVE_ROLE")
	switch role {
	case "OWNER", "ADMIN", "OTHER", "SYSTEM":
	default:
		t.Skip("NOT RUN: native runner must invoke each actual Windows role")
	}
	binary := filepath.Join(core.PackageRoot(), "aegishook.exe")
	cmd := exec.Command(binary, "ctl", "status", "--machine-dir", root, "--require", "service")
	data, err := cmd.Output()
	denied := role == "OTHER" || (role == "OWNER" && os.Getenv("TG_SENTRY_NATIVE_OWNER_ABSENT") == "1")
	if denied {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != ExitNotInstalled {
			t.Fatalf("untrusted/missing-owner access not denied: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal("authorized native request failed", err)
	}
	var state Status
	if json.Unmarshal(data, &state) != nil || state.ExitCode("service") != ExitOK || state.Loaded != "unknown" {
		t.Fatal("invalid integrated status")
	}
	if role == "SYSTEM" {
		cmd = exec.Command(binary, "ctl", "status", "--machine-dir", root, "--require", "hooks")
		_, err = cmd.Output()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != ExitHooksUnknown {
			t.Fatalf("SYSTEM without target user must report hooks unknown (fixture must be enrolled): %v", err)
		}
	}
}

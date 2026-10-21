package service

import (
	"aegishook/internal/core"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLinuxRegistrationDeterministic(t *testing.T) {
	originalPath, originalCommand, originalValidate := systemdPath, systemdCommand, core.ValidateMachinePath
	t.Cleanup(func() {
		systemdPath, systemdCommand, core.ValidateMachinePath = originalPath, originalCommand, originalValidate
	})
	systemdPath = filepath.Join(t.TempDir(), systemdUnit)
	if err := os.WriteFile(systemdPath, []byte("isolated unit path fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("injected native refusal")
	valid := "{ path=/opt/tg-sentry/aegishook ; argv[]=/opt/tg-sentry/aegishook service ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
	for _, tc := range []struct {
		name, rejectPath, failCommand, output string
		wantError                             bool
		wantCalls                             []string
	}{
		{"parent-path-rejected", filepath.Dir(systemdPath), "", valid, true, nil},
		{"unit-path-rejected", systemdPath, "", valid, true, nil},
		{"is-enabled-fails", "", "is-enabled", valid, true, []string{"is-enabled"}},
		{"show-fails", "", "show", valid, true, []string{"is-enabled", "show"}},
		{"foreign-command-refused", "", "", "{ path=/usr/bin/false }", true, []string{"is-enabled", "show"}},
		{"expected-registration", "", "", valid, false, []string{"is-enabled", "show"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			core.ValidateMachinePath = func(path string, private bool) error {
				if private {
					t.Fatal("registration unexpectedly uses private-path validation")
				}
				if path == tc.rejectPath {
					return refused
				}
				return nil
			}
			systemdCommand = func(path string, args ...string) ([]byte, error) {
				if path != "/usr/bin/systemctl" {
					t.Fatalf("unexpected native command: %q", path)
				}
				verb := args[0]
				want := []string{"is-enabled", systemdUnit}
				if verb == "show" {
					want = []string{"show", "--property=ExecStart", "--value", systemdUnit}
				}
				if !reflect.DeepEqual(args, want) {
					t.Fatalf("unexpected argv: %q, want %q", args, want)
				}
				calls = append(calls, verb)
				if verb == tc.failCommand {
					return nil, refused
				}
				return []byte(tc.output), nil
			}
			err := checkRegistration()
			if (err != nil) != tc.wantError {
				t.Fatalf("registration error = %v, want error %v", err, tc.wantError)
			}
			if (tc.rejectPath != "" || tc.failCommand != "") && !errors.Is(err, refused) {
				t.Fatalf("native refusal lost: %v", err)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("commands = %q, want %q", calls, tc.wantCalls)
			}
		})
	}
}

package service

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedLinuxUnit(t *testing.T) {
	data, err := os.ReadFile("../../packaging/linux/tg-sentry.service")
	if err != nil {
		t.Fatal(err)
	}
	section := ""
	values := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = append(values[key], value)
		}
	}
	for key, want := range map[string]string{"Type": "simple", "Restart": "always", "RestartSec": "5", "User": "root", "Group": "root"} {
		if got := values[key]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want one %q", key, got, want)
		}
	}
	commands := values["ExecStart"]
	if len(commands) != 1 {
		t.Fatalf("ExecStart = %v, want exactly one command", commands)
	}
	argv := strings.Fields(commands[0])
	if len(argv) != 2 {
		t.Fatalf("ExecStart argv = %v, want binary + service", argv)
	}
	// Feed the packaged path/argv through the production systemctl-show verifier.
	// Metadata mirrors TestSystemdExecStart; no second runtime command contract.
	record := "{ path=" + argv[0] + " ; argv[]=" + strings.Join(argv, " ") + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
	if err := verifySystemdExecStart([]byte(record)); err != nil {
		t.Fatalf("packaged ExecStart does not match runtime registration: %v", err)
	}
}

// Isolated copies/stubs follow packaging/macos/test-pkg.sh:script_behavior.
// These assert shell ordering/retention, not native systemd or core behavior.
func TestLinuxPackageFingerprints(t *testing.T) {
	for _, tc := range []struct {
		name, script, modified string
		wantOK                 bool
	}{
		{"foreign-install-unit", "install.sh", "unit", false},
		{"foreign-install-binary", "install.sh", "binary", false},
		{"same-package-reinstall", "install.sh", "", true},
		{"modified-uninstall-unit", "uninstall.sh", "unit", false},
		{"modified-uninstall-binary", "uninstall.sh", "binary", false},
		{"same-package-uninstall", "uninstall.sh", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newLinuxPackageFixture(t, tc.script)
			if tc.modified == "unit" {
				fixture.write(fixture.unit, "foreign unit\n")
			} else if tc.modified == "binary" {
				fixture.write(fixture.app+"/aegishook", "foreign binary\n")
			}
			beforeBinary := fixture.read(fixture.app + "/aegishook")
			beforeUnit := fixture.read(fixture.unit)
			output, err := exec.Command("/bin/sh", fixture.script).CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%v, want %v: %s", err == nil, tc.wantOK, output)
			}
			calls := fixture.read(fixture.log)
			if tc.wantOK {
				if !strings.Contains(string(calls), "ctl system-") {
					t.Fatalf("successful lifecycle did not invoke core: %s", calls)
				}
				return
			}
			if !strings.Contains(string(output), "retained") && !strings.Contains(string(output), "not from this package") {
				t.Fatalf("missing actionable refusal: %s", output)
			}
			afterBinary := fixture.read(fixture.app + "/aegishook")
			afterUnit := fixture.read(fixture.unit)
			if len(calls) != 0 || string(afterBinary) != string(beforeBinary) || string(afterUnit) != string(beforeUnit) {
				t.Fatalf("refusal mutated payload or invoked systemctl/core: %s", calls)
			}
		})
	}
}

type linuxPackageFixture struct {
	t                      *testing.T
	app, unit, log, script string
}

func (f linuxPackageFixture) read(path string) []byte {
	f.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

func (f linuxPackageFixture) write(path, value string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0755); err != nil {
		f.t.Fatal(err)
	}
}

func newLinuxPackageFixture(t *testing.T, script string) linuxPackageFixture {
	t.Helper()
	base := t.TempDir()
	f := linuxPackageFixture{t: t, app: base + "/opt/tg-sentry", unit: base + "/etc/systemd/system/tg-sentry.service", log: base + "/calls", script: base + "/payload/" + script}
	binary := "#!/bin/sh\nprintf '%s\\n' \"ctl $*\" >> '" + f.log + "'\n"
	unit := "fixture unit\n"
	f.write(f.log, "")
	f.write(f.app+"/aegishook", binary)
	f.write(f.unit, unit)
	f.write(base+"/systemctl", "#!/bin/sh\nprintf '%s\\n' \"systemctl $*\" >> '"+f.log+"'\n")
	f.write(base+"/payload/opt/tg-sentry/aegishook", binary)
	f.write(base+"/payload/opt/tg-sentry/uninstall.sh", "fixture uninstall\n")
	f.write(base+"/payload/etc/systemd/system/tg-sentry.service", unit)
	data, err := os.ReadFile("../../packaging/linux/" + script)
	if err != nil {
		t.Fatal(err)
	}
	// Production has no path/root test override; rewrite only this fixture copy.
	rewrite := strings.NewReplacer("/opt/tg-sentry", f.app, "/var/opt/tg-sentry", base+"/state", "/etc/systemd/system", filepath.Dir(f.unit), "$(id -u)", "0", "systemctl ", base+"/systemctl ", "-o root -g root ", "", "@BINARY_SHA256@", fmt.Sprintf("%x", sha256.Sum256([]byte(binary))), "@UNIT_SHA256@", fmt.Sprintf("%x", sha256.Sum256([]byte(unit))))
	// Payload-relative source paths must stay relative to the copied installer.
	text := rewrite.Replace(string(data))
	text = strings.ReplaceAll(text, "$here"+f.app, "$here/opt/tg-sentry")
	text = strings.ReplaceAll(text, "$here"+filepath.Dir(f.unit), "$here/etc/systemd/system")
	f.write(f.script, text)
	return f
}

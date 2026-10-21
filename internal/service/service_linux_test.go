package service

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestLinuxKernelPeerCredentials(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "peer")
		conn, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		uid, err := peerUID(conn.(*net.UnixConn))
		conn.Close()
		if err != nil || uid != uint32(os.Geteuid()) {
			t.Fatalf("kernel uid = %d, want %d: %v", uid, os.Geteuid(), err)
		}
	}
}

func TestLinuxPeerAuthorizationAcrossUIDs(t *testing.T) {
	if root := os.Getenv("TG_SENTRY_LINUX_PEER_ROOT"); root != "" {
		state, err := callUnix(root, Request{Verb: "status"}, 0)
		want := os.Getenv("TG_SENTRY_LINUX_PEER_OWNER") == "true"
		if (err == nil) != want || (want && (!state.Installed || !state.Service)) {
			t.Fatalf("owner=%v: %+v %v", want, state, err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("cross-UID subprocess requires root; same-UID kernel test runs unprivileged")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatalf("non-root fixture uid unavailable: %v", err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []bool{false, true} {
		d, root := testDaemon(t)
		// Go's build directory is private; copy only this fixture executable.
		child := filepath.Join(root, "peer.test")
		if err := os.WriteFile(child, binary, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0755); err != nil {
			t.Fatal(err)
		}
		if owner {
			d.owner = account.Uid
		}
		d.admin = isAdmin
		startTestDaemon(t, d)
		cmd := exec.Command(child, "-test.run=^TestLinuxPeerAuthorizationAcrossUIDs$")
		cmd.Env = append(os.Environ(), "TG_SENTRY_LINUX_PEER_ROOT="+root, "TG_SENTRY_LINUX_PEER_OWNER="+strconv.FormatBool(owner))
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cross-UID owner=%v: %v\n%s", owner, err, output)
		}
	}
}

func TestLinuxAuthorizationRootOrRecordedOwnerOnly(t *testing.T) {
	for _, tc := range []struct {
		name, owner string
		uid         uint32
		want        bool
	}{
		{"root", "", 0, true},
		{"owner", "501", 501, true},
		{"other", "502", 501, false},
		{"missing-owner", "", 501, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if admin, err := isAdmin(tc.uid); err != nil || admin {
				t.Fatalf("Linux must not authorize an admin group: %v %v", admin, err)
			}
			d := unixDaemon{owner: tc.owner, admin: isAdmin}
			if got := d.authorized(tc.uid); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSystemdExecStart(t *testing.T) {
	valid := "{ path=/opt/tg-sentry/aegishook ; argv[]=/opt/tg-sentry/aegishook service ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"expected", valid, true},
		{"delimiter-bearing-argument", strings.Replace(valid, " service ;", " service ; injected ;", 1), false},
		{"truncated-record", "{ path=/opt/tg-sentry/aegishook ; argv[]=/opt/tg-sentry/aegishook service }", false},
		{"duplicate-metadata-field", strings.Replace(valid, "ignore_errors=no", "ignore_errors=no ; ignore_errors=no", 1), false},
		{"unknown-field", strings.Replace(valid, "ignore_errors=no", "unknown=no", 1), false},
		{"missing-metadata-field", strings.Replace(valid, "ignore_errors=no ; ", "", 1), false},
		{"reordered-metadata", strings.Replace(valid, "ignore_errors=no ; start_time=[n/a]", "start_time=[n/a] ; ignore_errors=no", 1), false},
		{"empty-metadata-value", strings.Replace(valid, "pid=0", "pid=", 1), false},
		{"empty", "", false},
		{"foreign-path", strings.Replace(valid, "path=/opt/tg-sentry/aegishook", "path=/usr/bin/false", 1), false},
		{"foreign-argv", strings.Replace(valid, "argv[]=/opt/tg-sentry/aegishook", "argv[]=/usr/bin/false", 1), false},
		{"extra-argument", strings.Replace(valid, " service ;", " service extra ;", 1), false},
		{"wrong-verb", strings.Replace(valid, " service ;", " repair ;", 1), false},
		{"multiple-records", valid + valid, false},
		{"missing-braces", strings.Trim(valid, "{}\n "), false},
		{"duplicate-path", strings.Replace(valid, "ignore_errors=no", "path=/usr/bin/false", 1), false},
		{"duplicate-argv", strings.Replace(valid, "ignore_errors=no", "argv[]=/usr/bin/false", 1), false},
		{"missing-argv", strings.Replace(valid, "argv[]=", "other=", 1), false},
		{"missing-path", strings.Replace(valid, "path=", "other=", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifySystemdExecStart([]byte(tc.output)); (err == nil) != tc.want {
				t.Fatalf("verification = %v, want acceptance %v", err, tc.want)
			}
		})
	}
}

func TestLinuxProductionEntryPointsFailClosed(t *testing.T) {
	if _, err := Call("relative", Request{Verb: "status"}); err == nil || errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("Linux Call not bound to native validation: %v", err)
	}
	if err := Run("relative"); err == nil || errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("Linux Run not bound to native validation: %v", err)
	}
}

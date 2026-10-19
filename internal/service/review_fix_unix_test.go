//go:build darwin

package service

import (
	"aegishook/internal/core"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReviewPublicDirectoryLockMustNotBlockDaemon(t *testing.T) {
	d, root := testDaemon(t)
	public, err := os.Open(core.MachinePaths(root).Run)
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	if err := unix.Flock(int(public.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := d.listen(); err != nil {
		t.Fatalf("public read-only directory lock blocked daemon: %v", err)
	}
	defer d.close()
	other, _ := testDaemon(t)
	other.options = d.options
	if err := other.listen(); err == nil {
		other.close()
		t.Fatal("second daemon was not excluded")
	}
}

func TestReviewPlistRejectsConflictingProgram(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("..", "..", "packaging", "macos", "launchd", launchdLabel+".plist"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"<string>/usr/bin/false</string>", "<string></string>", "<false/>"} {
		modified := strings.Replace(string(original), "<dict>", "<dict><key>Program</key>"+value, 1)
		path := filepath.Join(t.TempDir(), "override.plist")
		if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyLaunchdPlist(path); err == nil {
			t.Fatal("present Program key accepted", value)
		}
	}
}

func TestReviewDeadlineLegacyAndClamp(t *testing.T) {
	for _, kind := range []string{"legacy", "earlier", "later"} {
		t.Run(kind, func(t *testing.T) {
			d, root := testDaemon(t)
			d.owner = strconv.Itoa(os.Geteuid())
			startTestDaemon(t, d)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
			defer server.Close()
			data, _ := json.Marshal(core.ClientConnection{Endpoint: server.URL, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: make([]byte, ed25519.PublicKeySize)})
			if err := os.WriteFile(core.MachinePaths(root).Connection, data, 0600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			deadline := start.Add(controlTimeout)
			var state Status
			var err error
			if kind == "earlier" {
				deadline = start.Add(controlReplyMargin)
				state, err = callUnix(root, Request{Verb: "status", Deadline: deadline}, d.uid)
			} else {
				conn, dialErr := net.DialTimeout("unix", core.MachinePaths(root).Socket, controlTimeout)
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				defer conn.Close()
				if err := conn.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				request := []byte(`{"verb":"status"}`)
				if kind == "later" {
					request, _ = json.Marshal(Request{Verb: "status", Deadline: deadline.Add(controlTimeout)})
				}
				if err := writeFrame(conn, request); err != nil {
					t.Fatal(err)
				}
				response, readErr := readFrame(conn)
				err = readErr
				if err == nil {
					err = json.Unmarshal(response, &state)
				}
			}
			elapsed := time.Since(start)
			t.Logf("%s deadline response in %s", kind, elapsed)
			if err != nil || !state.Installed || !state.Service || state.Enrollment != "unknown" || state.EnrollmentReason != "timeout" || time.Now().After(deadline) {
				t.Fatalf("deadline clamp/legacy failed: %+v %v", state, err)
			}
		})
	}
}

func TestReviewStalledBackendStatusBeforeClientDeadline(t *testing.T) {
	for _, verb := range []string{"status", "repair"} {
		t.Run(verb, func(t *testing.T) {
			d, root := testDaemon(t)
			d.owner = strconv.Itoa(os.Geteuid())
			startTestDaemon(t, d)
			cancelled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); close(cancelled) }))
			defer server.Close()
			conn := core.ClientConnection{Endpoint: server.URL, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: make([]byte, ed25519.PublicKeySize)}
			data, err := json.Marshal(conn)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(core.MachinePaths(root).Connection, data, 0600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			state, err := callUnix(root, Request{Verb: verb}, d.uid)
			elapsed := time.Since(start)
			t.Logf("stalled backend %s returned in %s; client budget %s", verb, elapsed, controlTimeout)
			if err != nil || !state.Installed || !state.Service || state.Enrolled || elapsed >= controlTimeout {
				t.Fatalf("live local status lost on timeout: %+v %v (%s)", state, err, elapsed)
			}
			encoded, _ := json.Marshal(state)
			var status map[string]any
			json.Unmarshal(encoded, &status)
			if status["enrollment"] != "unknown" || status["enrollmentReason"] != "timeout" || state.ExitCode("enrolled") != ExitNotEnrolled {
				t.Fatalf("timeout not explicit/fail-closed: %s", encoded)
			}
			select {
			case <-cancelled:
			case <-time.After(time.Until(start.Add(controlTimeout))):
				t.Fatal("backend HTTP request was not cancelled before the client deadline")
			}
		})
	}
}

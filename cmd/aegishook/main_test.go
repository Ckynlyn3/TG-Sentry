package main

import (
	"aegishook/internal/core"
	"aegishook/internal/server"
	"aegishook/internal/teststore"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteCommandCLISession(t *testing.T) {
	for _, command := range []string{"install", "status", "uninstall"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "admin.token"), []byte("fixture-cli-token"), 0600); err != nil {
				t.Fatal(err)
			}
			var calls []string
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				peer, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil || !net.ParseIP(peer).IsLoopback() {
					t.Error("CLI peer is not loopback")
				}
				if r.URL.Path == "/api/v1/cli/session" {
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !reflect.DeepEqual(body, map[string]string{"token": "fixture-cli-token"}) || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
						t.Error("invalid CLI session request")
					}
					http.SetCookie(w, &http.Cookie{Name: "aegis_session", Value: "fixture-cli-session", Path: "/", HttpOnly: true})
					w.Write([]byte(`{"ok":true}`))
					return
				}
				cookie, err := r.Cookie("aegis_session")
				if r.URL.Path == "/api/v1/login" || err != nil || cookie.Value != "fixture-cli-session" {
					t.Error("legacy login called or CLI cookie not reused")
					http.Error(w, "session required", http.StatusUnauthorized)
					return
				}
				if command == "install" {
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !reflect.DeepEqual(body, map[string]string{"agent": "claude", "scope": "project", "project": dir}) {
						t.Error("invalid install request")
					}
				}
				w.Write([]byte(`[]`))
			}))
			defer live.Close()
			ok, err := remoteCommand(command, dir, strings.TrimPrefix(live.URL, "http://"), "project", dir, "fixture-install", "claude")
			if !ok || err != nil {
				t.Fatalf("handled=%v err=%v", ok, err)
			}
			want := []string{"POST /api/v1/cli/session"}
			switch command {
			case "install":
				want = append(want, "POST /api/v1/installations")
			case "uninstall":
				want = append(want, "DELETE /api/v1/installations/fixture-install")
			case "status":
				want = append(want, "GET /api/v1/agents", "GET /api/v1/instances", "GET /api/v1/installations")
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls=%v want=%v", calls, want)
			}
		})
	}
}

func TestRemoteCommandMissingToken(t *testing.T) {
	ok, err := remoteCommand("status", t.TempDir(), "127.0.0.1:18790", "", "", "", "")
	if !ok || err == nil || !strings.Contains(err.Error(), "admin.token") {
		t.Fatalf("missing token must give a clear error: handled=%v err=%v", ok, err)
	}
}

func TestRemoteCommandRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"example.invalid:18790", "192.0.2.1:18790", "localhost", "127.0.0.1:18790/path"} {
		ok, err := remoteCommand("status", t.TempDir(), addr, "", "", "", "")
		if !ok || err == nil {
			t.Fatalf("unsafe address %q accepted: handled=%v err=%v", addr, ok, err)
		}
	}
}

func runAdminTest(t *testing.T, args ...string) error {
	t.Helper()
	previous := os.Args
	defer func() { os.Args = previous }()
	os.Args = append([]string{"aegishook", "admin"}, args...)
	return run()
}

func TestAdminBindUnbind(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	for _, args := range [][]string{
		{"bind", "--issuer", "https://issuer.example", "--subject", "alice", "--name", "Alice"},
		{"bind", "--issuer", "https://other.example", "--subject", "alice"},
		{"bind", "--issuer", "https://issuer.example", "--subject", "alice", "--name", "Renamed"},
	} {
		if err := runAdminTest(t, append(args, "--data-dir", dir)...); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "admin-bindings.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bindings []core.AdminBinding
	if err := json.Unmarshal(data, &bindings); err != nil || len(bindings) != 2 || bindings[1].Name != "Renamed" {
		t.Fatalf("bindings=%+v err=%v", bindings, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("bindings must be private: %v %v", info, err)
	}
	if err := runAdminTest(t, "unbind", "--issuer", "https://issuer.example", "--subject", "alice", "--data-dir", dir); err != nil {
		t.Fatal(err)
	}
	e, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, tc := range []struct {
		issuer string
		want   bool
	}{{"https://issuer.example", false}, {"https://other.example", true}} {
		ok, err := e.IsRecoveryAdmin(core.Principal{Issuer: tc.issuer, Subject: "alice"})
		if err != nil || ok != tc.want {
			t.Fatalf("issuer=%s bound=%v err=%v", tc.issuer, ok, err)
		}
	}
	if err := runAdminTest(t, "bind", "--issuer", "https://issuer.example", "--subject", "alice", "--data-dir", dir); err == nil {
		t.Fatal("binding while another engine holds process.lock must fail")
	}
}

func TestAdminValidationAndHelp(t *testing.T) {
	for _, args := range [][]string{
		nil, {"unknown"}, {"bind"}, {"unbind"}, {"bind", "--issuer", "https://issuer.example"},
		{"unbind", "--subject", "alice"}, {"bind", "--unknown"},
		{"bind", "--issuer", "https://issuer.example", "--subject", "alice", "extra"},
		{"unbind", "--issuer", "https://issuer.example", "--subject", "alice", "--name", "Alice"},
	} {
		if err := runAdminTest(t, append(args, "--data-dir", t.TempDir())...); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	for _, args := range [][]string{{"--help"}, {"bind", "-h"}, {"unbind", "-h"}, {"help"}} {
		if err := runAdminTest(t, args...); err != nil {
			t.Fatalf("help %v: %v", args, err)
		}
	}
}

func TestAdminMalformedBindingsPreserved(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	path := filepath.Join(dir, "admin-bindings.json")
	if err := os.WriteFile(path, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runAdminTest(t, "bind", "--issuer", "https://issuer.example", "--subject", "alice", "--data-dir", dir); err == nil {
		t.Fatal("malformed binding file overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "malformed" {
		t.Fatalf("binding file changed: %q %v", data, err)
	}
}

func TestRemoteCommandRealInstallStatus(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	token, err := e.Secret("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.PrepareAdapter([]byte("fixture"), "http://127.0.0.1:1", "fixture-hook"); err != nil {
		t.Fatal(err)
	}
	if err := e.PrepareIntegrations([]byte("// fixture"), filepath.Join(t.TempDir(), "aegishook")); err != nil {
		t.Fatal(err)
	}
	s := server.New(e, nil, token, "fixture-hook", t.TempDir())
	live := httptest.NewServer(s.Handler())
	defer live.Close()
	addr, project := strings.TrimPrefix(live.URL, "http://"), t.TempDir()
	for _, command := range []string{"install", "status"} {
		ok, err := remoteCommand(command, dir, addr, "project", project, "", "claude")
		if !ok || err != nil {
			t.Fatalf("%s handled=%v err=%v", command, ok, err)
		}
	}
	installations, err := e.Installations()
	if err != nil || len(installations) != 1 || !installations[0].Installed {
		t.Fatalf("installations=%v err=%v", installations, err)
	}
	if ok, err := remoteCommand("uninstall", dir, addr, "", "", installations[0].ID, ""); !ok || err != nil {
		t.Fatalf("uninstall handled=%v err=%v", ok, err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, audit := range audits {
		if audit.Action == "hook.install" || audit.Action == "hook.uninstall" {
			if audit.Actor.Kind != "cli" || audit.Actor.Issuer != "local" || audit.Actor.Subject != "cli" {
				t.Fatalf("not CLI session actor: %+v", audit.Actor)
			}
			seen[audit.Action] = true
		}
	}
	if !seen["hook.install"] || !seen["hook.uninstall"] {
		t.Fatal("missing CLI install/uninstall audit")
	}
}

func TestRemoteCommandSessionFailuresAndNoRedirect(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		cookie   bool
		response string
	}{
		{"unauthorized", http.StatusUnauthorized, false, `{}`},
		{"missing cookie", http.StatusOK, false, `{}`},
		{"redirect", http.StatusTemporaryRedirect, false, `{}`},
		{"status error", http.StatusForbidden, true, `{}`},
		{"invalid status JSON", http.StatusOK, true, `not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "admin.token"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/api/v1/cli/session" && tc.cookie {
					http.SetCookie(w, &http.Cookie{Name: "aegis_session", Value: "fixture"})
					w.Write([]byte(`{}`))
					return
				}
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.response))
			}))
			defer live.Close()
			ok, err := remoteCommand("status", dir, strings.TrimPrefix(live.URL, "http://"), "", "", "", "")
			if !ok || err == nil {
				t.Fatalf("handled=%v err=%v", ok, err)
			}
			if !tc.cookie && calls != 1 {
				t.Fatalf("unexpected follow-up requests: %d", calls)
			}
		})
	}
}

func TestRemoteCommandRejectsOperationRedirect(t *testing.T) {
	for _, command := range []string{"install", "uninstall"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "admin.token"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/api/v1/cli/session" {
					http.SetCookie(w, &http.Cookie{Name: "aegis_session", Value: "fixture"})
					w.Write([]byte(`{}`))
					return
				}
				if r.URL.Path == "/must-not-follow" {
					t.Error("followed operation redirect")
				}
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer live.Close()
			ok, err := remoteCommand(command, dir, strings.TrimPrefix(live.URL, "http://"), "project", dir, "fixture-id", "claude")
			if !ok || err == nil || !strings.Contains(err.Error(), "307") {
				t.Fatalf("redirect reported success: handled=%v err=%v", ok, err)
			}
			if calls != 2 {
				t.Fatalf("calls=%d want session plus operation only", calls)
			}
		})
	}
}

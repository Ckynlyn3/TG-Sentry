package bridge

import (
	"aegishook/internal/core"
	"aegishook/internal/server"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func TestBundleHookConditionalFetchFailuresAndRevocation(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "hook bundle")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	rule := core.Rule{ID: "U_OFFLINE", Name: "offline deny", Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "offline-protected"}
	if err = e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
		t.Fatal(err)
	}
	older, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir()).Handler()
	var mode, polls, notModified atomic.Int32
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/client/bundle" {
			polls.Add(1)
			switch mode.Load() {
			case 1:
				signed, err := e.ClientPolicyBundle(conn.NodeID)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				signed.Payload = append(signed.Payload, ' ')
				json.NewEncoder(w).Encode(signed)
				return
			case 2:
				json.NewEncoder(w).Encode(older)
				return
			}
			if r.Header.Get("If-None-Match") != "" {
				recorded := httptest.NewRecorder()
				h.ServeHTTP(recorded, r)
				if recorded.Code == http.StatusNotModified {
					notModified.Add(1)
				}
				for k, values := range recorded.Header() {
					w.Header()[k] = values
				}
				w.WriteHeader(recorded.Code)
				w.Write(recorded.Body.Bytes())
				return
			}
		}
		h.ServeHTTP(w, r)
	}))
	defer live.Close()
	conn.Endpoint = live.URL
	connection := filepath.Join(t.TempDir(), "connection.json")
	if err = os.WriteFile(connection, mustJSON(conn), 0600); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	call := func(tool, path string, want int) string {
		t.Helper()
		code, output, log := invoke("claude", connection, native("claude", cwd, core.ID(), tool, "PreToolUse", map[string]any{"path": path}))
		if code != want {
			t.Fatalf("hook code=%d output=%s log=%s", code, output, log)
		}
		return log
	}
	call("Read", "README.md", 0)
	cache := filepath.Join(filepath.Dir(connection), "bundle.json")
	before, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal("hook did not persist verified bundle", err)
	}
	call("Read", "README.md", 0)
	if polls.Load() != 2 || notModified.Load() != 1 {
		t.Fatal("If-None-Match / 304 not exercised", polls.Load(), notModified.Load())
	}
	mode.Store(1)
	call("Read", "README.md", 2)
	after, err := os.ReadFile(cache)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("tamper replaced trusted cache")
	}
	mode.Store(0)
	rule.Message = "new revision"
	if err = e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
		t.Fatal(err)
	}
	call("Read", "README.md", 0)
	before, err = os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	mode.Store(2)
	call("Read", "README.md", 2)
	after, err = os.ReadFile(cache)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rollback replaced trusted cache")
	}
	mode.Store(0)
	if err = e.RevokeClient(core.WithActor(context.Background(), core.SystemActor("test")), conn.NodeID); err != nil {
		t.Fatal(err)
	}
	call("Read", "README.md", 2)
	live.Close()
	if log := call("Read", "offline-protected", 2); !strings.Contains(log, "U_OFFLINE") {
		t.Fatal("offline cached deny not used", log)
	}
	call("Read", "README.md", 2) // Cached A7 permit must never bypass default block.
	after, err = os.ReadFile(cache)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unreachable server lost last valid bundle")
	}
	connection = filepath.Join(t.TempDir(), "connection.json")
	if err = os.WriteFile(connection, mustJSON(conn), 0600); err != nil {
		t.Fatal(err)
	}
	call("Read", "README.md", 2) // First start, no bundle and no server.
}

func TestBundleFirstStartCannotUseServerPermitWithoutVerifiedBundle(t *testing.T) {
	for _, response := range []string{`{}`, `null`, `not json`} {
		t.Run(response, func(t *testing.T) {
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/client/bundle" {
					w.Write([]byte(response))
					return
				}
				// This would allow a Read through the old online-only path.
				if r.URL.Path == "/api/v1/reviews" {
					t.Error("review attempted without trusted initial bundle")
				}
				w.WriteHeader(200)
			}))
			defer live.Close()
			connection := filepath.Join(t.TempDir(), "connection.json")
			conn := core.ClientConnection{Endpoint: live.URL, Token: strings.Repeat("a", 64), NodeID: strings.Repeat("b", 32), BundlePublicKey: make([]byte, 32)}
			if err := os.WriteFile(connection, mustJSON(conn), 0600); err != nil {
				t.Fatal(err)
			}
			if code, _, _ := invoke("claude", connection, native("claude", t.TempDir(), "call", "Read", "PreToolUse", map[string]any{"path": "README.md"})); code != 2 {
				t.Fatal("first-start unverified bundle allowed")
			}
		})
	}
}

func TestBundlePollRejectsInvalidResponses(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := mustJSON(core.PolicyBundle{Revision: 1, NodeID: "node", Rules: []core.Rule{}})
	signed := core.SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
	for _, kind := range []string{"empty 304", "wrong 304", "oversize response", "trailing JSON", "wrong ETag", "no key", "bad cache", "invalid URL", "unwritable cache", "matching 304", "valid 200"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "empty 304", "wrong 304", "matching 304":
					if kind == "matching 304" {
						w.Header().Set("ETag", core.PolicyBundleETag(signed))
					} else {
						w.Header().Set("ETag", `"wrong"`)
					}
					w.WriteHeader(304)
				case "oversize response":
					w.Write(append(mustJSON(signed), bytes.Repeat([]byte(" "), core.PolicyBundleMaxBytes)...))
				case "trailing JSON":
					w.Write(append(mustJSON(signed), []byte(` {}`)...))
				case "wrong ETag":
					w.Header().Set("ETag", `"wrong"`)
					json.NewEncoder(w).Encode(signed)
				default:
					json.NewEncoder(w).Encode(signed)
				}
			}))
			defer live.Close()
			c := client{cfg: Config{Endpoint: live.URL, Token: "fixture", NodeID: "node", BundlePublicKey: pub}, http: live.Client()}
			switch kind {
			case "no key":
				c.cfg.BundlePublicKey = nil
			case "bad cache":
				if err = os.WriteFile(path, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid URL":
				c.cfg.Endpoint = "://invalid"
			case "unwritable cache":
				path = filepath.Join(path, "missing", "bundle.json")
			case "wrong 304", "matching 304":
				if _, err = core.CachePolicyBundle(path, signed, pub, "node"); err != nil {
					t.Fatal(err)
				}
			}
			got, err := c.policyBundle(context.Background(), path)
			wantValid := kind == "matching 304" || kind == "valid 200"
			if (err == nil) != wantValid || (wantValid && got == nil) {
				t.Fatalf("got=%v err=%v", got, err)
			}
		})
	}
}

func TestBundlePollSharesHookDeadline(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer live.Close()
	connection := filepath.Join(t.TempDir(), "connection.json")
	if err = os.WriteFile(connection, mustJSON(Config{Endpoint: live.URL, Token: "fixture", NodeID: "node", BundlePublicKey: pub}), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if code, _, _ := invoke("claude", connection, native("claude", t.TempDir(), "call", "Read", "PreToolUse", map[string]any{"path": "README.md"})); code != 2 {
		t.Fatal("slow bundle permitted")
	}
	if time.Since(start) >= 5*time.Second {
		t.Fatal("bundle fetch exceeded existing native hook timeout")
	}
}

// Rotation fixtures use the production trust/cache APIs; only HTTP and the
// durable interruption boundary are controlled by these tests.
type bundleRotationFixture struct {
	keys      []ed25519.PrivateKey
	records   []core.SignedTrustRecord
	bootstrap core.TrustState
	signed    core.SignedPolicyBundle
	path      string
}

func newBundleRotationFixture(t *testing.T, legacy bool) bundleRotationFixture {
	t.Helper()
	f := bundleRotationFixture{path: filepath.Join(t.TempDir(), "bundle.json")}
	for _, seed := range []byte{'A', 'B', 'C'} {
		f.keys = append(f.keys, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	}
	for i, indexes := range [][]int{{0}, {0, 1}, {1}, {1, 2}, {2}} {
		record := core.TrustRecord{Version: i + 1, Keys: []core.TrustKey{}}
		var signers []ed25519.PrivateKey
		for _, index := range indexes {
			key := f.keys[index]
			pub := key.Public().(ed25519.PublicKey)
			record.Keys = append(record.Keys, core.TrustKey{KeyID: core.BundleKeyID(pub), PublicKey: pub})
			signers = append(signers, key)
		}
		signed, err := core.SignTrustRecord(record, signers...)
		if err != nil {
			t.Fatal(err)
		}
		f.records = append(f.records, signed)
	}
	var err error
	f.bootstrap, err = core.BootstrapPolicyTrust(f.keys[0].Public().(ed25519.PublicKey), &f.records[0])
	if err != nil {
		t.Fatal(err)
	}
	payload := mustJSON(core.PolicyBundle{Revision: 7, NodeID: "node", Rules: []core.Rule{}})
	f.signed = core.SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(f.keys[0], payload), KeyID: core.BundleKeyID(f.keys[0].Public().(ed25519.PublicKey))}
	if legacy {
		f.signed.KeyID = ""
		if err := os.WriteFile(f.path, mustJSON(f.signed), 0600); err != nil {
			t.Fatal(err)
		}
	} else if _, err := core.CachePolicyBundleWithTrust(f.path, f.signed, f.signed.KeyID, f.bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f bundleRotationFixture) client(url string) client {
	return client{cfg: Config{Endpoint: url, Token: "fixture", NodeID: "node", BundlePublicKey: f.keys[0].Public().(ed25519.PublicKey), BundleTrust: &f.records[0]}, http: &http.Client{}}
}

func rotationState(t *testing.T, f bundleRotationFixture, version int) core.TrustState {
	t.Helper()
	state, err := core.ReadPolicyTrust(f.path, f.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var current core.TrustRecord
	if err := json.Unmarshal(state.Current.Payload, &current); err != nil || current.Version != version {
		t.Fatalf("trust version=%d want=%d err=%v", current.Version, version, err)
	}
	signed, signer, err := core.ReadPolicyBundleWithTrust(f.path, state, "node")
	if err != nil {
		t.Fatal("cache no longer loads", err)
	}
	bundle, _, err := core.VerifyCachedPolicyBundle(signed, signer, state, "node")
	if err != nil || bundle.Revision != 7 {
		t.Fatalf("floor lost: %v %v", bundle, err)
	}
	return state
}

func TestBundleRotation304AndLegacyRestart(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) {
			f := newBundleRotationFixture(t, legacy)
			before, _ := os.ReadFile(f.path)
			var requests []string
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.URL.Path)
				if r.Header.Get("Authorization") != "Bearer fixture" {
					t.Error("missing device auth")
				}
				if strings.Contains(r.URL.Path, "/keys/") {
					if r.URL.Path != "/api/v1/client/keys/2" {
						t.Error("nonsequential fetch", r.URL.Path)
					}
					json.NewEncoder(w).Encode(f.records[1])
					return
				}
				if r.Header.Get("If-None-Match") != core.PolicyBundleETag(f.signed) {
					t.Error("missing conditional validator")
				}
				w.Header().Set("ETag", core.PolicyBundleETag(f.signed))
				w.Header().Set("TG-Trust-Version", "2")
				w.WriteHeader(http.StatusNotModified)
			}))
			c := f.client(live.URL)
			if legacy {
				c.cfg.BundleTrust = nil
			}
			got, err := c.policyBundle(context.Background(), f.path)
			live.Close()
			if err != nil || got == nil {
				t.Fatalf("rotation failed: %v", err)
			}
			rotationState(t, f, 2)
			if len(requests) != 2 {
				t.Fatalf("requests=%v", requests)
			}
			after, _ := os.ReadFile(f.path)
			if !bytes.Equal(before, after) {
				t.Fatal("304 rewrote cache")
			}
			// A real new process reads the persisted legacy cache/trust while offline.
			command := exec.Command(os.Args[0], "-test.run=^TestBundleRotationRestartChild$")
			command.Env = append(os.Environ(), "TG_TEST_BRIDGE_ROTATION_PATH="+f.path, "TG_TEST_BRIDGE_ROTATION_CONFIG="+string(mustJSON(c.cfg)))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("restart: %v %s", err, output)
			}
		})
	}
}

func TestBundleRotationRestartChild(t *testing.T) {
	path := os.Getenv("TG_TEST_BRIDGE_ROTATION_PATH")
	if path == "" {
		return
	}
	var cfg Config
	if err := json.Unmarshal([]byte(os.Getenv("TG_TEST_BRIDGE_ROTATION_CONFIG")), &cfg); err != nil {
		t.Fatal(err)
	}
	c := client{cfg: cfg, http: &http.Client{Transport: rotationTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline fixture") })}}
	got, err := c.policyBundle(context.Background(), path)
	if got == nil || got.Revision != 7 || err == nil {
		t.Fatalf("offline restart got=%v err=%v", got, err)
	}
}

type rotationTransport func(*http.Request) (*http.Response, error)

func (f rotationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBundleRotationCatchUpAndInterruptedWrites(t *testing.T) {
	// Interrupt before the next request, immediately after each durable record.
	// The last case restores the precise post-bundle/pre-prune disk snapshot,
	// matching core's fault-boundary fixture without adding production IO hooks.
	for _, stop := range []int{0, 2, 3, 4, 5, 6} {
		t.Run(fmt.Sprint("after=", stop), func(t *testing.T) {
			f := newBundleRotationFixture(t, false)
			resigned := f.signed
			resigned.KeyID = core.BundleKeyID(f.keys[2].Public().(ed25519.PublicKey))
			resigned.Signature = ed25519.Sign(f.keys[2], resigned.Payload)
			var fetched []int
			var beforeBundle core.TrustState
			var conditional, unconditional int
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/keys/") {
					version, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v1/client/keys/"))
					if err != nil || version < 2 || version > 5 {
						t.Error("bad record path")
						w.WriteHeader(404)
						return
					}
					rotationState(t, f, version-1) // prior step persisted before next GET
					fetched = append(fetched, version)
					json.NewEncoder(w).Encode(f.records[version-1])
					return
				}
				w.Header().Set("ETag", core.PolicyBundleETag(f.signed))
				w.Header().Set("TG-Trust-Version", "5")
				if r.Header.Get("If-None-Match") != "" {
					conditional++
					w.WriteHeader(304)
					return
				}
				unconditional++
				state, err := core.ReadPolicyTrust(f.path, f.bootstrap)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				var current core.TrustRecord
				if err := json.Unmarshal(state.Current.Payload, &current); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				if current.Version == 5 {
					beforeBundle = rotationState(t, f, 5)
					if beforeBundle.Cache == nil {
						t.Error("old authority pruned before bundle")
					}
				}
				json.NewEncoder(w).Encode(resigned)
			}))
			defer live.Close()
			c := f.client(live.URL)
			interrupted := false
			c.http.Transport = rotationTransport(func(r *http.Request) (*http.Response, error) {
				state, err := core.ReadPolicyTrust(f.path, f.bootstrap)
				if err != nil {
					return nil, err
				}
				var current core.TrustRecord
				if err := json.Unmarshal(state.Current.Payload, &current); err != nil {
					return nil, err
				}
				if !interrupted && stop >= 2 && stop <= 5 && current.Version == stop {
					interrupted = true
					return nil, errors.New("injected interruption after record write")
				}
				return http.DefaultTransport.RoundTrip(r)
			})
			got, err := c.policyBundle(context.Background(), f.path)
			if stop >= 2 && stop <= 5 {
				if !interrupted || err == nil || got == nil {
					t.Fatalf("boundary not reached: %v %v", got, err)
				}
				rotationState(t, f, stop)
				c = f.client(live.URL) // no in-memory progress survives restart
				got, err = c.policyBundle(context.Background(), f.path)
			}
			if err != nil || got == nil {
				t.Fatalf("catch-up: %v", err)
			}
			if conditional == 0 || unconditional == 0 {
				t.Fatal("304 then unconditional re-sign not exercised")
			}
			if fmt.Sprint(fetched) != "[2 3 4 5]" {
				t.Fatalf("progress not resumed: %v", fetched)
			}
			state := rotationState(t, f, 5)
			if state.Cache != nil {
				t.Fatal("D6 did not prune after bundle write")
			}
			if stop == 6 {
				if err := core.AtomicFile(filepath.Join(filepath.Dir(f.path), "trust.json"), mustJSON(beforeBundle), 0600); err != nil {
					t.Fatal(err)
				}
				rotationState(t, f, 5)
				c = f.client(live.URL)
				if got, err = c.policyBundle(context.Background(), f.path); err != nil || got == nil {
					t.Fatalf("post-bundle restart: %v", err)
				}
			}
			// Old authority never resets the revision floor, even after interruption.
			lower := resigned
			lower.Payload = mustJSON(core.PolicyBundle{Revision: 6, NodeID: "node", Rules: []core.Rule{}})
			lower.Signature = ed25519.Sign(f.keys[2], lower.Payload)
			if _, err := core.CachePolicyBundleWithTrust(f.path, lower, lower.KeyID, f.bootstrap, "node"); err == nil {
				t.Fatal("revision floor reset")
			}
		})
	}
}

func TestBundleRotationRejectsUntrustedNetwork(t *testing.T) {
	for _, kind := range []string{"retired key", "forged keyId", "trust downgrade", "bad trust header", "skipped record", "bad record signature", "oversized record", "trailing record", "record HTTP failure", "unknown key without header", "legacy server", "retired cache 304"} {
		t.Run(kind, func(t *testing.T) {
			f := newBundleRotationFixture(t, false)
			for _, record := range f.records[1:3] {
				if _, err := core.CachePolicyTrustRecord(f.path, record, f.bootstrap, "node"); err != nil {
					t.Fatal(err)
				}
			}
			response := f.signed
			response.KeyID = core.BundleKeyID(f.keys[1].Public().(ed25519.PublicKey))
			response.Signature = ed25519.Sign(f.keys[1], response.Payload)
			version := "3"
			switch kind {
			case "retired key":
				response = f.signed
			case "forged keyId":
				response.Signature = f.signed.Signature
			case "trust downgrade":
				version = "2"
			case "bad trust header":
				version = "invalid"
			case "legacy server":
				f = newBundleRotationFixture(t, true)
				response, version = f.signed, ""
			case "unknown key without header":
				response.KeyID = core.BundleKeyID(f.keys[2].Public().(ed25519.PublicKey))
				version = ""
			case "retired cache 304":
			default:
				version = "4"
			}
			before, _ := os.ReadFile(f.path)
			trustBefore, _ := os.ReadFile(filepath.Join(filepath.Dir(f.path), "trust.json"))
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/keys/") {
					record := f.records[3]
					switch kind {
					case "skipped record":
						record = f.records[4]
					case "bad record signature":
						record.Signatures[0].Signature = make([]byte, ed25519.SignatureSize)
					case "oversized record":
						w.Write(bytes.Repeat([]byte(" "), core.PolicyBundleMaxBytes+1))
						return
					case "trailing record":
						w.Write(append(mustJSON(record), []byte(` {}`)...))
						return
					case "record HTTP failure", "unknown key without header", "retired key":
						w.WriteHeader(404)
						return
					}
					json.NewEncoder(w).Encode(record)
					return
				}
				if kind != "legacy server" && r.Header.Get("If-None-Match") != "" {
					t.Error("retired cache sent validator")
				}
				w.Header().Set("TG-Trust-Version", version)
				if kind == "retired cache 304" {
					w.Header().Set("ETag", core.PolicyBundleETag(f.signed))
					w.WriteHeader(304)
					return
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer live.Close()
			c := f.client(live.URL)
			if kind == "legacy server" {
				c.cfg.BundleTrust = nil
			}
			got, err := c.policyBundle(context.Background(), f.path)
			if kind == "legacy server" {
				if err != nil || got == nil {
					t.Fatalf("legacy behaviour: %v", err)
				}
				return
			}
			if err == nil || got == nil {
				t.Fatalf("did not fail closed with cache: %v %v", got, err)
			}
			after, _ := os.ReadFile(f.path)
			if !bytes.Equal(before, after) {
				t.Fatal("untrusted response replaced bundle")
			}
			trustAfter, _ := os.ReadFile(filepath.Join(filepath.Dir(f.path), "trust.json"))
			if !bytes.Equal(trustBefore, trustAfter) {
				t.Fatal("invalid response changed trust")
			}
		})
	}
}

func TestBundleRotationTrustFetchSharesContext(t *testing.T) {
	f := newBundleRotationFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := f.client("http://fixture.invalid")
	c.http.Transport = rotationTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/keys/") {
			if r.Context() != ctx {
				t.Error("trust request has a separate deadline")
			}
			cancel()
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 304, Header: http.Header{"Etag": {core.PolicyBundleETag(f.signed)}, "Tg-Trust-Version": {"2"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if got, err := c.policyBundle(ctx, f.path); got == nil || err == nil {
		t.Fatalf("canceled trust fetch: %v %v", got, err)
	}
	rotationState(t, f, 1)
}

func TestBundleRotationNewSigner200AndFreshBootstrap(t *testing.T) {
	for _, kind := range []string{"header", "unknown hint", "stale header", "fresh bootstrap"} {
		t.Run(kind, func(t *testing.T) {
			f := newBundleRotationFixture(t, false)
			signed := f.signed
			signed.KeyID = core.BundleKeyID(f.keys[1].Public().(ed25519.PublicKey))
			signed.Signature = ed25519.Sign(f.keys[1], signed.Payload)
			var fetched int
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/keys/") {
					fetched++
					if r.URL.Path != "/api/v1/client/keys/2" {
						t.Error("wrong successor")
					}
					json.NewEncoder(w).Encode(f.records[1])
					return
				}
				switch kind {
				case "header":
					w.Header().Set("TG-Trust-Version", "2")
				case "stale header":
					w.Header().Set("TG-Trust-Version", "1")
				case "fresh bootstrap":
					w.Header().Set("TG-Trust-Version", "3")
				}
				json.NewEncoder(w).Encode(signed)
			}))
			defer live.Close()
			c := f.client(live.URL)
			if kind == "fresh bootstrap" {
				f.path = filepath.Join(t.TempDir(), "bundle.json")
				c.cfg.BundlePublicKey = f.keys[1].Public().(ed25519.PublicKey)
				c.cfg.BundleTrust = &f.records[2]
				var err error
				f.bootstrap, err = core.BootstrapPolicyTrust(c.cfg.BundlePublicKey, c.cfg.BundleTrust)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := c.policyBundle(context.Background(), f.path)
			if err != nil || got == nil {
				t.Fatalf("new signer: %v", err)
			}
			wantVersion, wantFetched := 2, 1
			if kind == "fresh bootstrap" {
				wantVersion, wantFetched = 3, 0
			}
			if fetched != wantFetched {
				t.Fatalf("fetched=%d want=%d", fetched, wantFetched)
			}
			state := rotationState(t, f, wantVersion)
			if state.Cache != nil {
				t.Fatal("bundle commit did not compact trust")
			}
		})
	}
}

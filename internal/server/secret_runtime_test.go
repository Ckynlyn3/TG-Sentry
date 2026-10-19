package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"aegishook/internal/core"
	"aegishook/internal/teststore"
)

func TestSecretRuntimeHTTPResponsePrivacy(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Register(core.Instance{ID: "secret-http", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	h := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir()).Handler()
	// Frozen Gitleaks github-pat width; same named local seed as core/scanner.
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rng := rand.New(rand.NewSource(22))
	candidate := "ghp_"
	for range 36 {
		candidate += string(alphabet[rng.Intn(len(alphabet))])
	}
	for _, args := range []map[string]any{{"text": candidate}, {candidate: "benign"}, {"nested": []any{candidate}}} {
		in := core.ReviewInput{InstanceID: "secret-http", CallID: core.ID(), ToolName: "Read", Arguments: args, UserMessage: candidate, Context: candidate}
		body, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/reviews", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture-hook")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var got core.Review
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || got.Decision != "reject" || got.RuleID != "R_SECRET_GITHUB_PAT" {
			t.Fatal("HTTP secret detection failed")
		}
		if strings.Contains(w.Body.String(), candidate) {
			t.Fatal("HTTP response exposed planted secret")
		}
		saved, err := e.Review(got.ID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(saved)
		if err != nil || strings.Contains(string(raw), candidate) {
			t.Fatal("full emitted review exposed planted secret")
		}
	}
}

// Same synthetic recipes as core/secret_runtime_test.go and the pinned scanner
// fixtures; widths, alphabet and seed are inherited rather than tuned locally.
func secretHTTPFixtures() map[string]string {
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rng := rand.New(rand.NewSource(22))
	text := func(alphabet string, n int) string {
		var b strings.Builder
		for range n {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	return map[string]string{
		"aws-access-token":        "AKIA" + text("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
		"github-pat":              "ghp_" + text(alnum, 36),
		"github-fine-grained-pat": "github_pat_" + text(alnum+"_", 82),
		"gitlab-pat":              "glpat-" + text(alnum+"_-", 20),
		"openai-api-key":          "sk-proj-" + text(alnum+"_-", 58) + "T3BlbkFJ" + text(alnum+"_-", 58),
		"anthropic-api-key":       "sk-ant-api03-" + text(alnum+"_-", 93) + "AA",
		"anthropic-admin-api-key": "sk-ant-admin01-" + text(alnum+"_-", 93) + "AA",
		"private-key":             "-----BEGIN PRIVATE KEY-----\n" + text(alnum, 64) + "\n-----END PRIVATE KEY-----",
		"jwt":                     "ey" + text(alnum, 17) + ".ey" + text(alnum, 17) + "." + text(alnum+"_-", 10),
	}
}

func TestSecretOriginalSourceHTTPOverlapPrivacy(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "overlap-http", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	for entity, candidate := range secretHTTPFixtures() {
		t.Run(entity, func(t *testing.T) {
			deny := core.Rule{ID: "U_OVERLAP", Name: candidate, Matcher: "contains", Pattern: "public-fixture", Enabled: true, Decision: "reject", Priority: 999}
			if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), deny); err != nil {
				t.Fatal(err)
			}
			in := core.ReviewInput{InstanceID: "overlap-http", CallID: core.ID(), ToolName: "Read", Arguments: map[string]any{"operation": "public-fixture", "text": candidate}}
			for _, path := range []string{"/api/v1/rules/test", "/api/v1/reviews"} {
				token := ""
				if path == "/api/v1/reviews" {
					token = "fixture-hook"
				}
				got := h.call("POST", path, in, 200, token)
				if got["decision"] != "reject" || got["ruleId"] != deny.ID {
					t.Fatal("HTTP source redaction changed winning deny")
				}
				values := []any{got}
				if path == "/api/v1/reviews" {
					saved, err := h.engine.Review(got["id"].(string))
					if err != nil {
						t.Fatal(err)
					}
					values = append(values, saved)
				}
				quoted, _ := json.Marshal(candidate)
				for _, value := range values {
					raw, err := json.Marshal(value)
					if err != nil || strings.Contains(string(raw), candidate) || strings.Contains(string(raw), string(quoted[1:len(quoted)-1])) {
						t.Fatal("HTTP/full emitted snapshot leaked source secret")
					}
				}
			}
		})
	}
}

func TestSecretMetadataHTTPPrivacy(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "metadata-http", Agent: "claude", SessionID: "fixture", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	for entity, candidate := range secretHTTPFixtures() {
		for _, surface := range []string{"rule-echo", "script-sha256"} {
			t.Run(entity+"/"+surface, func(t *testing.T) {
				in := core.ReviewInput{InstanceID: "metadata-http", CallID: core.ID(), ToolName: "Read", Arguments: map[string]any{"text": "benign"}}
				want := "R_SECRET_" + strings.ToUpper(strings.ReplaceAll(entity, "-", "_"))
				if surface == "rule-echo" {
					var value any = "public-fixture"
					parts := strings.Split(candidate, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						value = map[string]any{parts[i]: value}
					}
					deny := core.Rule{ID: "U_METADATA", Name: "Metadata fixture", Matcher: "contains", Pattern: "public-fixture", Tool: candidate, Field: candidate, Enabled: true, Decision: "reject", Priority: 999}
					if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), deny); err != nil {
						t.Fatal(err)
					}
					in.ToolName, in.Arguments, want = candidate, value.(map[string]any), deny.ID
				} else {
					in.Scripts = []core.ReviewScript{{Path: "fixture", SHA256: candidate, Complete: true}}
				}
				got := h.call("POST", "/api/v1/reviews", in, 200, "fixture-hook")
				if got["decision"] != "reject" || got["ruleId"] != want {
					t.Fatal("metadata secret not rejected with correct attribution")
				}
				assertMetadataHTTPAbsent(t, candidate, got)
				stored, err := h.engine.Review(got["id"].(string))
				if err != nil {
					t.Fatal(err)
				}
				assertMetadataHTTPAbsent(t, candidate, stored)
				for _, path := range []string{"/api/v1/reviews/" + stored.ID, "/api/v1/calls", "/api/v1/calls/export"} {
					resp, err := h.client.Get(h.url + path)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil || resp.StatusCode != 200 {
						t.Fatal("admin projection request failed")
					}
					var decoded any
					if err := json.Unmarshal(body, &decoded); err != nil {
						t.Fatal(err)
					}
					assertMetadataHTTPAbsent(t, candidate, decoded)
				}
			})
		}
	}
}

func assertMetadataHTTPAbsent(t *testing.T, candidate string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	quoted, _ := json.Marshal(candidate)
	if err != nil || strings.Contains(string(raw), candidate) || strings.Contains(string(raw), string(quoted[1:len(quoted)-1])) {
		t.Fatal("metadata secret exposed in decoded HTTP/admin/export record")
	}
}

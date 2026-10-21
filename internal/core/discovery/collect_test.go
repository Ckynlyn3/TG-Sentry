package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Synthetic fixtures only. Plan §6 (issue38-41-plan-v2.md:97-99).
const collectorJSON = `{"mcpServers":{
 "local":{"command":"SENTINEL_command","args":["SENTINEL_positional","--token=SENTINEL_flag"],"env":{"Z_KEY":"SENTINEL_env","A_KEY":"SENTINEL_env2"}},
 "remote":{"type":"http","url":"https://SENTINEL_user:SENTINEL_password@example.invalid/mcp?token=SENTINEL_query","headers":{"Z-Header":"SENTINEL_header","A-Header":"SENTINEL_header2"}},
 "legacy":{"type":"sse","url":"https://example.invalid/sse?token=SENTINEL_sse"}}}`

const collectorTOML = `model = "not-an-asset"
[mcp_servers.local]
command = "SENTINEL_command"
args = ["SENTINEL_positional", "--token=SENTINEL_flag"]
env = { Z_KEY = "SENTINEL_env", A_KEY = "SENTINEL_env2" }
[mcp_servers.remote]
url = "https://SENTINEL_user:SENTINEL_password@example.invalid/mcp?token=SENTINEL_query"
http_headers = { Z-Header = "SENTINEL_header", A-Header = "SENTINEL_header2" }
`

func collectorPaths(t *testing.T, family string) AgentPaths {
	t.Helper()
	p, ok := PathsForFamily(family)
	if !ok {
		t.Fatal("missing fixture family")
	}
	return p
}

func homeCategory(t *testing.T, categories []Category, name string) Category {
	t.Helper()
	for _, c := range categories {
		if c.Category == name && c.Scope == ScopeHome {
			return c
		}
	}
	t.Fatal("missing home category")
	return Category{}
}

func requireCategory(t *testing.T, c Category, state ScanState, reason Reason, count int) {
	t.Helper()
	if c.ScanState != state || c.Reason != reason || len(c.Assets) != count {
		t.Fatalf("category %s: state=%s reason=%s assets=%d; want %s %s %d", c.Category, c.ScanState, c.Reason, len(c.Assets), state, reason, count)
	}
	if c.Assets == nil {
		t.Fatal("assets must serialize as []")
	}
}

func TestCollectorsMCPProjectionAndSentinels(t *testing.T) {
	for _, tc := range []struct {
		family, rel, data string
		count             int
	}{
		{"claude", ".claude.json", collectorJSON, 3},
		{"cursor", ".cursor/mcpServers.json", collectorJSON, 3},
		{"codex", ".codex/config.toml", collectorTOML, 2},
	} {
		t.Run(tc.family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			fixtureFile(t, home, tc.rel, []byte(tc.data))
			var got Category
			output := captureCollectorOutput(t, func() { got = r.CollectMCP(context.Background(), collectorPaths(t, tc.family), "node", "account") })
			requireCategory(t, got, ScanScanned, "", tc.count)
			report := Report{SchemaVersion: SchemaVersion, NodeID: "node", Scope: OwnHome, Mode: "full", Final: true,
				Accounts: []Account{{AccountID: "account", HomeState: HomeReadable, Agents: []Agent{{Family: tc.family, Found: Found, Version: "unknown", Categories: []Category{got}}}}}}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte("SENTINEL_")) || strings.Contains(output, "SENTINEL_") {
				t.Fatal("secret sentinel leaked into report or output")
			}
			if _, err := DecodeReport(bytes.NewReader(encoded)); err != nil {
				t.Fatal("collector output violates report contract")
			}
			for _, a := range got.Assets {
				if a.Descriptor == nil || a.HashKind != DescriptorSHA256 || a.Size != nil || a.Mtime != nil {
					t.Fatal("non-projection MCP metadata")
				}
				id, _ := AssetID("node", "account", tc.family, "mcp", tc.rel, a.Name)
				if a.AssetID != id || a.SourceRelPath != tc.rel {
					t.Fatal("MCP identity mismatch")
				}
				d := a.Descriptor
				if a.Name == "local" && (d.Transport != "stdio" || !reflect.DeepEqual(d.EnvKeys, []string{"A_KEY", "Z_KEY"})) {
					t.Fatal("stdio projection mismatch")
				}
				if a.Name == "remote" && (d.Transport != "http" || !reflect.DeepEqual(d.HeaderKeys, []string{"A-Header", "Z-Header"})) {
					t.Fatal("http projection mismatch")
				}
				if a.Name == "legacy" && d.Transport != "sse" {
					t.Fatal("SSE projection mismatch")
				}
				// Independent sorted-key projection encoding, plan :56.
				projection, _ := json.Marshal(map[string]any{"name": d.Name, "transport": d.Transport, "envKeys": d.EnvKeys, "headerKeys": d.HeaderKeys})
				sum := sha256.Sum256(projection)
				if a.Hash != hex.EncodeToString(sum[:]) {
					t.Fatal("descriptor fingerprint mismatch")
				}
			}
			fixtureFile(t, home, tc.rel, []byte(strings.ReplaceAll(tc.data, "SENTINEL_", "CHANGED_")))
			again := r.CollectMCP(context.Background(), collectorPaths(t, tc.family), "node", "account")
			if !reflect.DeepEqual(got, again) {
				t.Fatal("private values changed projection fingerprint")
			}
		})
	}
}

func TestCollectorsMCPFailuresAreClosedReasons(t *testing.T) {
	for _, tc := range []struct {
		name, family, rel, data string
		reason                  Reason
	}{
		{"json syntax", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_bad"},`, ReasonParseFailed},
		{"toml syntax", "codex", ".codex/config.toml", "[mcp_servers.x]\ncommand = \"SENTINEL_bad", ReasonParseFailed},
		{"unknown schema", "claude", ".claude.json", `{"unverified":"SENTINEL_shape"}`, ReasonUnparsedFormat},
		{"opencode keys", "opencode", ".config/opencode/opencode.json", `{"mcp":{"SENTINEL_shape":{}}}`, ReasonUnparsedFormat},
		{"opencode foreign schema", "opencode", ".config/opencode/opencode.json", collectorJSON, ReasonUnparsedFormat},
		{"opencode empty foreign schema", "opencode", ".config/opencode/opencode.json", `{"mcpServers":{}}`, ReasonUnparsedFormat},
		{"opencode genuine plus stray schema", "opencode", ".config/opencode/opencode.json", `{"mcp":{"local":{"type":"local","command":["SENTINEL_command"]}},"mcpServers":{}}`, ReasonUnparsedFormat},
		{"escaped duplicate member", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_command","env":{"TOKEN":"SENTINEL_one","\u0054OKEN":"SENTINEL_two"}}}}`, ReasonParseFailed},
		{"lone surrogate", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_command","env":{"\ud800":"SENTINEL_value"}}}}`, ReasonParseFailed},
		{"jsonc", "opencode", ".config/opencode/opencode.jsonc", `// SENTINEL_comment\n{}`, ReasonUnparsedFormat},
		{"null servers", "cursor", ".cursor/mcpServers.json", `{"mcpServers":null}`, ReasonUnparsedFormat},
		{"null entry", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":null}}`, ReasonUnparsedFormat},
		{"invalid env", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_cmd","env":{"KEY":4}}}}`, ReasonUnparsedFormat},
		{"unknown transport", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"type":"SENTINEL_type","url":"https://example.invalid"}}}`, ReasonUnparsedFormat},
		{"ambiguous transport", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_cmd","url":"https://example.invalid"}}}`, ReasonUnparsedFormat},
		{"duplicate member", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{},"mcpServers":{"SENTINEL_duplicate":{}}}`, ReasonParseFailed},
		{"trailing JSON", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{}} "SENTINEL_trailing"`, ReasonParseFailed},
		{"invalid TOML shape", "codex", ".codex/config.toml", `mcp_servers = "SENTINEL_shape"`, ReasonUnparsedFormat},
		{"invalid args", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_cmd","args":"SENTINEL_args"}}}`, ReasonUnparsedFormat},
		{"invalid argument", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"command":"SENTINEL_cmd","args":[{}]}}}`, ReasonUnparsedFormat},
		{"invalid header map", "cursor", ".cursor/mcpServers.json", `{"mcpServers":{"x":{"url":"SENTINEL_url","headers":[]}}}`, ReasonUnparsedFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, home := fixtureRoot(t)
			fixtureFile(t, home, tc.rel, []byte(tc.data))
			var got Category
			output := captureCollectorOutput(t, func() { got = r.CollectMCP(context.Background(), collectorPaths(t, tc.family), "node", "account") })
			requireCategory(t, got, ScanError, tc.reason, 0)
			data, _ := json.Marshal(got)
			if strings.Contains(string(data)+output+got.Reason.Error(), "SENTINEL_") {
				t.Fatal("parser leaked source text")
			}
		})
	}
}

func TestCollectorsMCPCaseDistinctVendorMembers(t *testing.T) {
	for _, family := range []string{"claude", "cursor"} {
		t.Run(family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			p := collectorPaths(t, family)
			rel := p.ConfigFiles[len(p.ConfigFiles)-1]
			fixtureFile(t, home, rel, []byte(`{"mcpServers":{
"Foo":{"command":"SENTINEL_command","env":{"TOKEN":"SENTINEL_one","token":"SENTINEL_two","\ud83d\ude00":"SENTINEL_unicode"}},
"foo":{"command":"SENTINEL_command"}}}`))
			got := r.CollectMCP(context.Background(), p, "node", "account")
			requireCategory(t, got, ScanScanned, "", 2)
			if got.Assets[0].Name != "Foo" || got.Assets[1].Name != "foo" ||
				!reflect.DeepEqual(got.Assets[0].Descriptor.EnvKeys, []string{"TOKEN", "token", "\U0001f600"}) {
				t.Fatal("case-distinct vendor names or valid surrogate pair lost")
			}
			data, _ := json.Marshal(got)
			if bytes.Contains(data, []byte("SENTINEL_")) {
				t.Fatal("vendor values leaked")
			}
		})
	}
}

func TestCollectorsCodexDocumentedKeyMappings(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, ".codex/config.toml", []byte(`[mcp_servers.local]
command = "SENTINEL_command"
env = { Z = "SENTINEL_value" }
env_vars = ["A", "Z"]
[mcp_servers.remote]
url = "https://example.invalid"
http_headers = { Z = "SENTINEL_header" }
env_http_headers = { A = "SENTINEL_variable_name", Z = "SENTINEL_variable_name2" }
`))
	got := r.CollectMCP(context.Background(), collectorPaths(t, "codex"), "node", "account")
	requireCategory(t, got, ScanScanned, "", 2)
	if !reflect.DeepEqual(got.Assets[0].Descriptor.EnvKeys, []string{"A", "Z"}) ||
		!reflect.DeepEqual(got.Assets[1].Descriptor.HeaderKeys, []string{"A", "Z"}) {
		t.Fatal("Codex documented env/header key mappings omitted")
	}
	data, _ := json.Marshal(got)
	if bytes.Contains(data, []byte("SENTINEL_")) {
		t.Fatal("Codex mapping values leaked")
	}
}

func TestCollectorsHashOnlyHomeAllowlist(t *testing.T) {
	r, home := fixtureRoot(t)
	files := map[string]string{
		".claude/skills/review/SKILL.md":           "skill body SENTINEL_skill",
		".claude/skills/review/secret.txt":         "SENTINEL_sibling",
		".claude/skills/nested/deeper/SKILL.md":    "SENTINEL_nested",
		".claude/skills/plain.txt":                 "SENTINEL_plain",
		".claude/CLAUDE.md":                        "memory body SENTINEL_claude",
		".codex/AGENTS.md":                         "SENTINEL_agents",
		".codex/AGENTS.override.md":                "SENTINEL_override",
		"project/CLAUDE.md":                        "SENTINEL_project",
		"project/.claude/skills/hidden/SKILL.md":   "SENTINEL_project_skill",
		".claude/projects/hidden/memory/MEMORY.md": "SENTINEL_auto",
	}
	for rel, body := range files {
		fixtureFile(t, home, rel, []byte(body))
	}
	for _, family := range []string{"claude", "codex"} {
		p := collectorPaths(t, family)
		categories := r.Collect(context.Background(), p, "node", "account")
		memory := homeCategory(t, categories, "memory")
		requireCategory(t, memory, ScanScanned, "", len(p.MemoryFiles))
		assets := append([]Asset{}, memory.Assets...)
		if family == "claude" {
			skills := homeCategory(t, categories, "skills")
			requireCategory(t, skills, ScanScanned, "", 1)
			if skills.Assets[0].Name != "review" {
				t.Fatal("skill name must be directory name")
			}
			assets = append(assets, skills.Assets...)
		}
		for _, a := range assets {
			sum := sha256.Sum256([]byte(files[a.SourceRelPath]))
			if a.HashKind != FileSHA256 || a.Hash != hex.EncodeToString(sum[:]) || a.Descriptor != nil || a.Size == nil || *a.Size != int64(len(files[a.SourceRelPath])) || a.Mtime == nil {
				t.Fatal("hash/metadata mismatch")
			}
			id, _ := AssetID("node", "account", family, a.Category, a.SourceRelPath, a.Name)
			if a.AssetID != id {
				t.Fatal("file asset identity mismatch")
			}
		}
		data, _ := json.Marshal(categories)
		if bytes.Contains(data, []byte("SENTINEL_")) || bytes.Contains(data, []byte("secret.txt")) || bytes.Contains(data, []byte("deeper")) {
			t.Fatal("out-of-scope contents included")
		}
	}
}

func TestCollectorsAllFamiliesAndDeferredScopes(t *testing.T) {
	r, _ := fixtureRoot(t)
	for _, family := range []string{"claude", "codex", "cursor", "opencode", "pi", "grok", "gemini", "trae", "hermes", "openclaw"} {
		t.Run(family, func(t *testing.T) {
			p := collectorPaths(t, family)
			categories := r.Collect(context.Background(), p, "node", "account")
			if len(categories) != len(probeCategories(p)) {
				t.Fatal("lost category/scope states")
			}
			for _, c := range categories {
				if c.Scope != ScopeHome {
					requireCategory(t, c, ScanNotScanned, ReasonProjectScopeDeferred, 0)
					continue
				}
				want := ScanNotSupported
				if p.Supported && ((c.Category == "skills" && p.SkillsDir != "") || (c.Category == "memory" && len(p.MemoryFiles) != 0) || (c.Category == "plugins" && p.PluginsDir != "") || (c.Category == "mcp" && len(p.ConfigFiles) != 0)) {
					want = ScanScanned
				}
				requireCategory(t, c, want, "", 0)
			}
		})
	}
}

func TestCollectorsDoNotPromoteTGOnlyPresence(t *testing.T) {
	for _, family := range []string{"claude", "codex", "cursor", "opencode", "pi", "grok"} {
		t.Run(family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			p := collectorPaths(t, family)
			for _, rel := range p.TGTargets {
				fixtureFile(t, home, rel, []byte("SENTINEL_tg"))
			}
			agent, reason := r.Probe(context.Background(), p)
			if agent.Found != FoundUnknown || reason != ReasonTGTargetOnly {
				t.Fatal("TG-only probe changed")
			}
			agent.Categories = r.Collect(context.Background(), p, "node", "account")
			if agent.Found != FoundUnknown {
				t.Fatal("collector promoted TG presence")
			}
		})
	}
}

func TestCollectorsPluginScopeIsOneLevel(t *testing.T) {
	for _, family := range []string{"opencode", "pi", "grok"} {
		t.Run(family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			p := collectorPaths(t, family)
			fixtureFile(t, home, p.PluginsDir+"/one.js", []byte("SENTINEL_plugin"))
			fixtureFile(t, home, p.PluginsDir+"/nested/two.js", []byte("SENTINEL_nested"))
			got := r.CollectPlugins(context.Background(), p, "node", "account")
			requireCategory(t, got, ScanScanned, "", 1)
			if got.Assets[0].SourceRelPath != p.PluginsDir+"/one.js" || got.Assets[0].HashKind != FileSHA256 {
				t.Fatal("plugin scope mismatch")
			}
		})
	}
}

func TestCollectorsCapsAndPartialAssets(t *testing.T) {
	t.Run("config bytes", func(t *testing.T) {
		r, home := fixtureRoot(t)
		p := collectorPaths(t, "cursor")
		for _, extra := range []int{0, 1} {
			base := `{"mcpServers":{}}`
			fixtureFile(t, home, ".cursor/mcpServers.json", []byte(base+strings.Repeat(" ", ConfigParseBudgetBytes-len(base)+extra)))
			got := r.CollectMCP(context.Background(), p, "node", "account")
			if extra == 0 {
				requireCategory(t, got, ScanScanned, "", 0)
			} else {
				requireCategory(t, got, ScanError, ReasonTooLarge, 0)
			}
		}
	})
	for _, kind := range []string{"skills", "plugins"} {
		t.Run(kind+" entries", func(t *testing.T) {
			r, home := fixtureRoot(t)
			p := collectorPaths(t, "claude")
			dir := p.SkillsDir
			if kind == "plugins" {
				p = collectorPaths(t, "pi")
				dir = p.PluginsDir
			}
			for i := range DirectoryEntryBudget {
				fixtureFile(t, home, fmt.Sprintf("%s/%04d", dir, i), nil)
			}
			got := homeCategory(t, r.Collect(context.Background(), p, "node", "account"), kind)
			if got.ScanState != ScanScanned {
				t.Fatal("exact entry cap rejected")
			}
			fixtureFile(t, home, dir+"/over-cap", nil)
			got = homeCategory(t, r.Collect(context.Background(), p, "node", "account"), kind)
			requireCategory(t, got, ScanError, ReasonTooManyEntries, 0)
		})
	}
	t.Run("earlier file assets survive error", func(t *testing.T) {
		r, home := fixtureRoot(t)
		p := collectorPaths(t, "codex")
		fixtureFile(t, home, p.MemoryFiles[0], []byte("good"))
		if err := os.MkdirAll(filepath.Join(home, p.MemoryFiles[1]), 0700); err != nil {
			t.Fatal(err)
		}
		got := r.CollectMemory(context.Background(), p, "node", "account")
		requireCategory(t, got, ScanError, ReasonNotRegularFile, 1)
	})
	t.Run("earlier config assets survive error", func(t *testing.T) {
		r, home := fixtureRoot(t)
		p := collectorPaths(t, "cursor")
		p.ConfigFiles = []string{"first/mcpServers.json", "second/mcpServers.json"}
		fixtureFile(t, home, p.ConfigFiles[0], []byte(collectorJSON))
		fixtureFile(t, home, p.ConfigFiles[1], []byte("SENTINEL_malformed"))
		requireCategory(t, r.CollectMCP(context.Background(), p, "node", "account"), ScanError, ReasonParseFailed, 3)
	})
}

func TestCollectorsConfinedAndCanceled(t *testing.T) {
	for _, kind := range []string{"skills", "memory", "plugins", "mcp"} {
		t.Run(kind, func(t *testing.T) {
			r, home := fixtureRoot(t)
			outside := t.TempDir()
			fixtureFile(t, outside, "secret", []byte(collectorJSON))
			p := collectorPaths(t, "claude")
			rel := ".claude/CLAUDE.md"
			switch kind {
			case "skills":
				rel = ".claude/skills/review/SKILL.md"
			case "plugins":
				p = collectorPaths(t, "pi")
				rel = p.PluginsDir + "/secret"
			case "mcp":
				rel = ".claude.json"
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(home, rel)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(home, rel)); err != nil {
				t.Fatal(err)
			}
			got := homeCategory(t, r.Collect(context.Background(), p, "node", "account"), kind)
			requireCategory(t, got, ScanError, ReasonNotRegularFile, 0)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			got = homeCategory(t, r.Collect(ctx, p, "node", "account"), kind)
			requireCategory(t, got, ScanError, ReasonCanceled, 0)
		})
	}
	r, home := fixtureRoot(t)
	outside := t.TempDir()
	fixtureFile(t, outside, "CLAUDE.md", []byte("SENTINEL_outside"))
	if err := os.Symlink(outside, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	requireCategory(t, r.CollectMemory(context.Background(), collectorPaths(t, "claude"), "node", "account"), ScanError, ReasonEscapedRoot, 0)
}

func captureCollectorOutput(t *testing.T, run func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdout, stderr, logger, structured := os.Stdout, os.Stderr, log.Writer(), slog.Default()
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
	defer func() { os.Stdout, os.Stderr = stdout, stderr; slog.SetDefault(structured); log.SetOutput(logger) }()
	run()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Named local exceptions: plan §9.2 (:134) requires large-file / 2000-entry
// fixture time and allocation measurements; these are not vendor limits.
func BenchmarkCollectorBudgets(b *testing.B) {
	for _, kind := range []string{"large_config", "2000_entries"} {
		b.Run(kind, func(b *testing.B) {
			home := b.TempDir()
			p, _ := PathsForFamily("cursor")
			if kind == "2000_entries" {
				p, _ = PathsForFamily("pi")
			}
			if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0700); err != nil {
				b.Fatal(err)
			}
			if kind == "large_config" {
				if err := os.WriteFile(filepath.Join(home, ".cursor/mcpServers.json"), bytes.Repeat([]byte("x"), ConfigParseBudgetBytes+1), 0600); err != nil {
					b.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Join(home, p.PluginsDir), 0700); err != nil {
					b.Fatal(err)
				}
				for i := range 2000 {
					if err := os.WriteFile(filepath.Join(home, p.PluginsDir, strconv.Itoa(i)), nil, 0600); err != nil {
						b.Fatal(err)
					}
				}
			}
			r, state, reason := OpenHome(home, strconv.Itoa(os.Getuid()))
			if state != HomeReadable || reason != "" {
				b.Fatal("fixture root unavailable")
			}
			defer r.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var got Category
				if kind == "large_config" {
					got = r.CollectMCP(context.Background(), p, "node", "account")
				} else {
					got = r.CollectPlugins(context.Background(), p, "node", "account")
				}
				if got.ScanState != ScanError {
					b.Fatal("budget failed open")
				}
			}
		})
	}
}

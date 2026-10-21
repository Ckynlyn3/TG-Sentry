package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Locked regression from the lead's S3 independent review: a hard link is a
// distinct pathname, even when it has the same device/inode as a TG resource.
func TestReviewDistinctHardLinkIsNonTGEntry(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, ".claude/settings.json", nil)
	if err := os.Link(filepath.Join(home, ".claude/settings.json"), filepath.Join(home, ".claude/CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	paths, _ := PathsForFamily("claude")
	agent, reason := r.Probe(context.Background(), paths)
	if agent.Found != Found || reason != "" || agent.Evidence.RelPath != ".claude/CLAUDE.md" {
		t.Fatalf("distinct non-TG path ignored: found=%s reason=%s evidence=%s", agent.Found, reason, agent.Evidence.RelPath)
	}
}

func TestDistinctCaseHardLinkIsNonTGEntryOnCaseSensitiveVolume(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, ".claude/settings.json", nil)
	if _, err := os.Lstat(filepath.Join(home, ".claude/SETTINGS.JSON")); err == nil {
		t.Skip("requires case-sensitive filesystem")
	}
	if err := os.Link(filepath.Join(home, ".claude/settings.json"), filepath.Join(home, ".claude/SETTINGS.JSON")); err != nil {
		t.Fatal(err)
	}
	paths, _ := PathsForFamily("claude")
	agent, reason := r.Probe(context.Background(), paths)
	if agent.Found != Found || reason != "" || agent.Evidence.RelPath != ".claude/SETTINGS.JSON" {
		t.Fatalf("distinct case hard link ignored: %+v %q", agent, reason)
	}
}

type checkContext struct {
	context.Context
	check func()
}

func (c checkContext) Err() error {
	c.check()
	return c.Context.Err()
}

func TestObservedVendorDisappearingCannotBecomeConfirmedAbsent(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, ".grok/a.json", nil)
	fixtureFile(t, home, ".grok/z.json", nil)
	checks := 0
	ctx := checkContext{Context: context.Background(), check: func() {
		checks++
		// Before the fix, this fifth checkpoint is between the entry Lstat
		// and probeFile's second Lstat. Synchronize the real removal there,
		// without timers, concurrent scheduling or a production test hook.
		if checks == 5 {
			if err := os.Remove(filepath.Join(home, ".grok/a.json")); err != nil {
				t.Fatal(err)
			}
		}
	}}
	paths, _ := PathsForFamily("grok")
	agent, reason := r.Probe(ctx, paths)
	if agent.Found == NotFound || (agent.Found == FoundUnknown && reason == "") {
		t.Fatalf("observed vendor race became absence: %+v %q", agent, reason)
	}
	if checks < 5 {
		t.Fatal("deletion interleaving was not exercised")
	}
}

func TestPiManagedSymlinkIsTGOnlyWithoutFollowingTarget(t *testing.T) {
	r, home := fixtureRoot(t)
	if err := os.MkdirAll(filepath.Join(home, ".pi/agent/extensions"), 0700); err != nil {
		t.Fatal(err)
	}
	// The installer uses a symlink to the client adapter outside the vendor
	// directory. It need not be readable or even exist for TG-only evidence.
	if err := os.Symlink(filepath.Join(t.TempDir(), "unreadable-adapter"), filepath.Join(home, ".pi/agent/extensions/aegishook.ts")); err != nil {
		t.Fatal(err)
	}
	paths, _ := PathsForFamily("pi")
	if agent, reason := r.Probe(context.Background(), paths); agent.Found != FoundUnknown || reason != ReasonTGTargetOnly || agent.Evidence.Kind != "tg_target_only" {
		t.Fatalf("Pi managed symlink = %+v %q", agent, reason)
	}
}

func TestCaseInsensitiveTGTargetAndAncestor(t *testing.T) {
	for _, tc := range []struct{ family, observed, lookup string }{
		{"claude", ".claude/SETTINGS.JSON", ".claude/settings.json"},
		{"pi", ".pi/agent/Extensions/AEGISHOOK.TS", ".pi/agent/extensions/aegishook.ts"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			fixtureFile(t, home, tc.observed, nil)
			if _, err := os.Lstat(filepath.Join(home, tc.lookup)); os.IsNotExist(err) {
				t.Skip("requires case-insensitive filesystem; native Darwin/Windows fixture")
			} else if err != nil {
				t.Fatal(err)
			}
			paths, _ := PathsForFamily(tc.family)
			if agent, reason := r.Probe(context.Background(), paths); agent.Found != FoundUnknown || reason != ReasonTGTargetOnly {
				t.Fatalf("case alias = %+v %q", agent, reason)
			}
		})
	}
}

func TestDistinctCaseVendorEntryOnCaseSensitiveVolume(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, ".claude/SETTINGS.JSON", nil)
	if _, err := os.Lstat(filepath.Join(home, ".claude/settings.json")); err == nil {
		t.Skip("requires case-sensitive filesystem")
	}
	paths, _ := PathsForFamily("claude")
	if agent, reason := r.Probe(context.Background(), paths); agent.Found != Found || reason != "" || agent.Evidence.RelPath != ".claude/SETTINGS.JSON" {
		t.Fatalf("distinct-case vendor = %+v %q", agent, reason)
	}
}

func TestVendorEvidenceTable(t *testing.T) {
	for _, tc := range []struct{ family, path string }{
		{"claude", ".claude.json"}, {"codex", ".codex/config.toml"},
		{"cursor", ".cursor/cli-config.json"}, {"cursor", ".cursor/mcpServers.json"},
		{"opencode", ".config/opencode/opencode.json"},
		{"opencode", ".config/opencode/opencode.jsonc"},
		{"opencode", ".config/opencode/config.json"},
		{"claude", ".claude/CLAUDE.md"}, {"pi", ".pi/agent/settings.json"},
		{"grok", ".grok/custom.json"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r, home := fixtureRoot(t)
			fixtureFile(t, home, tc.path, []byte("fixture"))
			paths, ok := PathsForFamily(tc.family)
			if !ok {
				t.Fatal("missing family")
			}
			agent, reason := r.Probe(context.Background(), paths)
			if reason != "" || agent.Found != Found || agent.Evidence.RelPath == "" || agent.Evidence.Mtime == nil || agent.Version != "unknown" {
				t.Fatalf("Probe = %+v %q", agent, reason)
			}
		})
	}
}

func TestTGOnlyIsUnknownIncludingNestedTargets(t *testing.T) {
	for _, tc := range []struct{ family, path string }{
		{"claude", ".claude/settings.json"}, {"codex", ".codex/hooks.json"},
		{"cursor", ".cursor/hooks.json"}, {"opencode", ".config/opencode/plugins/aegishook.js"},
		{"pi", ".pi/agent/extensions/aegishook.ts"}, {"grok", ".grok/hooks/aegishook.json"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			fixtureFile(t, home, tc.path, nil)
			paths, _ := PathsForFamily(tc.family)
			agent, reason := r.Probe(context.Background(), paths)
			if agent.Found != FoundUnknown || reason != ReasonTGTargetOnly || agent.Evidence.Kind != "tg_target_only" || agent.Evidence.RelPath != tc.path {
				t.Fatalf("Probe = %+v %q", agent, reason)
			}
		})
	}
}

func TestNonTGEntryAlongsideManagedNestedTarget(t *testing.T) {
	for _, tc := range []struct{ family, target, vendor string }{
		{"pi", ".pi/agent/extensions/aegishook.ts", ".pi/agent/extensions/vendor.ts"},
		{"grok", ".grok/hooks/aegishook.json", ".grok/hooks/vendor.json"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			r, home := fixtureRoot(t)
			fixtureFile(t, home, tc.target, nil)
			fixtureFile(t, home, tc.vendor, nil)
			paths, _ := PathsForFamily(tc.family)
			agent, reason := r.Probe(context.Background(), paths)
			if agent.Found != Found || reason != "" {
				t.Fatalf("Probe = %+v %q", agent, reason)
			}
		})
	}
}

func TestAbsentEmptyAndUnsupportedFamilies(t *testing.T) {
	r, home := fixtureRoot(t)
	for _, family := range []string{"claude", "codex", "cursor", "opencode", "pi", "grok"} {
		paths, _ := PathsForFamily(family)
		agent, reason := r.Probe(context.Background(), paths)
		if agent.Found != NotFound || reason != "" {
			t.Fatalf("%s: %+v %q", family, agent, reason)
		}
	}
	if err := os.Mkdir(filepath.Join(home, ".grok"), 0700); err != nil {
		t.Fatal(err)
	}
	paths, _ := PathsForFamily("grok")
	if agent, reason := r.Probe(context.Background(), paths); agent.Found != NotFound || reason != "" {
		t.Fatalf("empty directory = %+v %q", agent, reason)
	}
	for _, family := range []string{"gemini", "trae", "hermes", "openclaw"} {
		paths, ok := PathsForFamily(family)
		if !ok {
			t.Fatal(family)
		}
		agent, reason := r.Probe(context.Background(), paths)
		if agent.Found != FoundUnknown || reason != "" {
			t.Fatalf("unsupported = %+v %q", agent, reason)
		}
		assertDeferredScopes(t, agent)
	}
	if _, ok := PathsForFamily("invented"); ok {
		t.Fatal("invented family supported")
	}
}

func assertDeferredScopes(t *testing.T, agent Agent) {
	t.Helper()
	for _, name := range []string{"skills", "mcp", "plugins", "builtin_tools", "memory"} {
		for _, scope := range []Scope{ScopeHome, ScopeProject, ScopeAutoMemory} {
			found := false
			for _, c := range agent.Categories {
				if c.Category != name || c.Scope != scope {
					continue
				}
				found = true
				if scope == ScopeHome && c.ScanState != ScanNotSupported {
					t.Fatalf("probe claimed collector ran: %+v", c)
				}
				if scope != ScopeHome && (c.ScanState != ScanNotScanned || c.Reason != ReasonProjectScopeDeferred) {
					t.Fatalf("missing explicit scope deferral: %+v", c)
				}
			}
			if !found {
				t.Fatalf("missing %s/%s", name, scope)
			}
		}
	}
}

func TestProbeUnknownOnEscapeNonregularBudgetAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want Reason
	}{
		{"traversal", "../vendor", ReasonEscapedRoot},
		{"directory", "dir", ReasonNotRegularFile},
		{"escape", "escape/vendor", ReasonEscapedRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, home := fixtureRoot(t)
			if err := os.Mkdir(filepath.Join(home, "dir"), 0700); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			fixtureFile(t, outside, "vendor", nil)
			if err := os.Symlink(outside, filepath.Join(home, "escape")); err != nil {
				t.Fatal(err)
			}
			agent, reason := r.Probe(context.Background(), AgentPaths{Family: "codex", Supported: true, ConfigFiles: []string{tc.path}})
			if agent.Found != FoundUnknown || reason != tc.want {
				t.Fatalf("Probe = %+v %q", agent, reason)
			}
		})
	}
	r, _ := fixtureRoot(t)
	paths, _ := PathsForFamily("claude")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if agent, reason := r.Probe(ctx, paths); agent.Found != FoundUnknown || reason != ReasonCanceled {
		t.Fatalf("canceled Probe = %+v %q", agent, reason)
	}
}

func TestHomeAssetsCanCoexistWithDeferredScopes(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, ".claude/CLAUDE.md", []byte("memory"))
	paths, _ := PathsForFamily("claude")
	agent, reason := r.Probe(context.Background(), paths)
	if reason != "" {
		t.Fatal(reason)
	}
	digest, reason := r.HashFile(context.Background(), paths.MemoryFiles[0])
	if reason != "" {
		t.Fatal(reason)
	}
	// S4 fills the home scope only; project deferral must not occupy its key.
	for i, category := range agent.Categories {
		if category.Category == "memory" && category.Scope == ScopeHome {
			agent.Categories[i].ScanState = ScanScanned
			agent.Categories[i].Assets = []Asset{{AssetID: "fixture", Name: "CLAUDE.md", Category: "memory", SourceRelPath: paths.MemoryFiles[0], Hash: digest.Hash, HashKind: FileSHA256}}
		}
	}
	report := Report{SchemaVersion: SchemaVersion, Scope: OwnHome, Mode: "full", Final: true, Accounts: []Account{{HomeState: HomeReadable, Agents: []Agent{agent}}}}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	var homeAssets, deferred int
	for _, category := range report.Accounts[0].Agents[0].Categories {
		if category.Category == "memory" && category.Scope == ScopeHome {
			homeAssets += len(category.Assets)
		}
		if category.Category == "memory" && category.Scope != ScopeHome && category.Reason == ReasonProjectScopeDeferred {
			deferred++
		}
	}
	if homeAssets != 1 || deferred != 2 {
		t.Fatalf("home assets=%d deferred scopes=%d", homeAssets, deferred)
	}
}

func TestProbeDirectoryBudgetAndSpecialTargets(t *testing.T) {
	r, home := fixtureRoot(t)
	paths, _ := PathsForFamily("grok")
	for i := range DirectoryEntryBudget + 1 {
		fixtureFile(t, home, filepath.ToSlash(filepath.Join(".grok", fmt.Sprintf("vendor-%04d", i))), nil)
	}
	if agent, reason := r.Probe(context.Background(), paths); agent.Found != FoundUnknown || reason != ReasonTooManyEntries {
		t.Fatalf("oversize Probe = %+v %q", agent, reason)
	}
	codex, _ := PathsForFamily("codex")
	if err := os.MkdirAll(filepath.Join(home, ".codex", "hooks.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if agent, reason := r.Probe(context.Background(), codex); agent.Found != FoundUnknown || reason != ReasonNotRegularFile {
		t.Fatalf("nonregular target Probe = %+v %q", agent, reason)
	}
}

func TestPathsAreDataOnlyAndNotSharedMutableSlices(t *testing.T) {
	paths, _ := PathsForFamily("claude")
	paths.ConfigFiles[0] = "../poison"
	again, _ := PathsForFamily("claude")
	if again.ConfigFiles[0] != ".claude.json" || again.SkillsDir != ".claude/skills" || again.MemoryFiles[0] != ".claude/CLAUDE.md" {
		t.Fatalf("paths = %+v", again)
	}
	codex, _ := PathsForFamily("codex")
	if len(codex.MemoryFiles) != 2 || codex.MemoryFiles[1] != ".codex/AGENTS.override.md" {
		t.Fatalf("codex = %+v", codex)
	}
}

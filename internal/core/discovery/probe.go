package discovery

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
)

// Probe returns passive evidence, not protection status. A reason is separate
// from Agent because discovery/v1 has no agent-level reason field. S5 projects it
// into the affected scope's state. Unknown is never interpreted as absence.
func (r *HomeRoot) Probe(ctx context.Context, paths AgentPaths) (Agent, Reason) {
	agent := Agent{Family: paths.Family, Found: FoundUnknown, Version: "unknown", Categories: probeCategories(paths)}
	if !paths.Supported {
		return agent, ""
	}
	var firstFailure Reason
	for _, rel := range paths.ConfigFiles {
		evidence, reason := r.probeFile(ctx, rel)
		if evidence.Kind != "" {
			agent.Found, agent.Evidence = Found, evidence
			return agent, ""
		}
		if firstFailure == "" {
			firstFailure = reason
		}
	}
	if paths.VendorDir != "" {
		evidence, reason := r.probeDirectory(ctx, paths.VendorDir, paths.TGTargets)
		if evidence.Kind != "" {
			agent.Found, agent.Evidence = Found, evidence
			return agent, ""
		}
		if firstFailure == "" {
			firstFailure = reason
		}
	}
	for _, rel := range paths.TGTargets {
		info, err := r.lstat(ctx, rel)
		if err == nil {
			// The Pi installer creates this managed target as a symlink. Only
			// inspect its link metadata; never open/read/follow its target.
			piLink := paths.Family == "pi" && info.Mode()&os.ModeSymlink != 0
			if !info.Mode().IsRegular() && !piLink {
				return agent, ReasonNotRegularFile
			}
			mtime := info.ModTime()
			agent.Evidence = Evidence{Kind: "tg_target_only", RelPath: rel, Mtime: &mtime}
			if firstFailure != "" {
				return agent, firstFailure
			}
			return agent, ReasonTGTargetOnly
		}
		if !errors.Is(err, os.ErrNotExist) && firstFailure == "" {
			firstFailure = fileReason(err)
		}
	}
	if firstFailure == "" {
		agent.Found = NotFound
	}
	return agent, firstFailure
}

func (r *HomeRoot) probeFile(ctx context.Context, rel string) (Evidence, Reason) {
	info, err := r.lstat(ctx, rel)
	if errors.Is(err, os.ErrNotExist) {
		return Evidence{}, ""
	}
	if err != nil {
		return Evidence{}, fileReason(err)
	}
	return r.probeObservedFile(ctx, rel, info)
}

// A previously observed entry disappearing is an open failure, not confirmed
// absence. Do not run a second Lstat that could silently erase that observation.
func (r *HomeRoot) probeObservedFile(ctx context.Context, rel string, info os.FileInfo) (Evidence, Reason) {
	if !info.Mode().IsRegular() {
		return Evidence{}, ReasonNotRegularFile
	}
	f, info, reason := r.openRegular(rel)
	if reason != "" {
		return Evidence{}, reason
	}
	defer f.Close()
	if ctx.Err() != nil {
		return Evidence{}, ReasonCanceled
	}
	mtime := info.ModTime()
	return Evidence{Kind: "config_file", RelPath: rel, Mtime: &mtime}, ""
}

func (r *HomeRoot) probeDirectory(ctx context.Context, rel string, targets []string) (Evidence, Reason) {
	if _, err := r.lstat(ctx, rel); errors.Is(err, os.ErrNotExist) {
		return Evidence{}, ""
	} else if err != nil {
		return Evidence{}, fileReason(err)
	}
	entries, reason := r.ReadDir(ctx, rel)
	if reason != "" {
		return Evidence{}, reason
	}
	for _, entry := range entries {
		child := path.Join(rel, entry.Name())
		info, err := r.lstat(ctx, child)
		if err != nil {
			return Evidence{}, fileReason(err)
		}
		ignored, ancestor, reason := r.targetPath(ctx, child, targets)
		if reason != "" {
			return Evidence{}, reason
		}
		if ignored {
			continue // Never follow or read the client's managed resource.
		}
		if ancestor {
			evidence, reason := r.probeDirectory(ctx, child, targets)
			if evidence.Kind != "" || reason != "" {
				return evidence, reason
			}
			continue
		}
		if !info.IsDir() {
			evidence, reason := r.probeObservedFile(ctx, child, info)
			if evidence.Kind != "" {
				evidence.Kind = "non_tg_entry"
			}
			return evidence, reason
		}
		mtime := info.ModTime()
		return Evidence{Kind: "non_tg_entry", RelPath: child, Mtime: &mtime}, ""
	}
	return Evidence{}, ""
}

// Match pathnames, not inodes: a separately named hard link is not a TG entry.
// Walk only the fixed table's ancestors, never arbitrary subtrees.
func (r *HomeRoot) targetPath(ctx context.Context, rel string, targets []string) (exact, ancestor bool, reason Reason) {
	for _, target := range targets {
		for candidate := target; candidate != "."; candidate = path.Dir(candidate) {
			if !strings.EqualFold(rel, candidate) {
				continue
			}
			matches, reason := r.samePathname(ctx, rel, candidate)
			if reason != "" {
				return false, false, reason
			}
			if matches {
				if candidate == target {
					return true, false, ""
				}
				ancestor = true
			}
		}
	}
	return false, ancestor, ""
}

// Resolve case aliases using directory-entry spelling, as filepath.normBase does
// (Go 1.27.2 src/path/filepath/symlink_windows.go:24-40), but keep every lookup
// behind Root and the existing directory budget. An exact differently cased
// sibling is a distinct pathname, even if it is a hard link to the same inode.
// Native lookup must accept an alternate spelling before it can be an alias;
// EqualFold alone never decides a volume's case-sensitivity or follows a link.
func (r *HomeRoot) samePathname(ctx context.Context, observed, target string) (bool, Reason) {
	if observed == target {
		return true, ""
	}
	if !strings.EqualFold(observed, target) {
		return false, ""
	}
	actual, expected := strings.Split(observed, "/"), strings.Split(target, "/")
	for i, component := range actual {
		if component == expected[i] {
			continue
		}
		parent := path.Join(append([]string{"."}, actual[:i]...)...)
		entries, reason := r.ReadDir(ctx, parent)
		if reason != "" {
			return false, reason
		}
		for _, entry := range entries {
			if entry.Name() == expected[i] {
				return false, "" // Both spellings exist as separate directory entries.
			}
		}
		if _, err := r.lstat(ctx, path.Join(parent, expected[i])); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, ""
			}
			return false, fileReason(err)
		}
	}
	return true, ""
}

// Collectors replace home placeholders in S4; a probe alone never claims to
// have scanned a supported category. R3 keeps deferred scopes alongside home.
func probeCategories(paths AgentPaths) []Category {
	var categories []Category
	for _, name := range []string{"skills", "mcp", "plugins", "builtin_tools", "memory"} {
		state := ScanNotSupported
		if paths.Supported && ((name == "skills" && paths.SkillsDir != "") ||
			(name == "mcp" && len(paths.ConfigFiles) != 0) ||
			(name == "plugins" && paths.PluginsDir != "") || (name == "memory" && len(paths.MemoryFiles) != 0)) {
			state = ScanNotScanned
		}
		categories = append(categories, Category{Category: name, Scope: ScopeHome, ScanState: state, Assets: []Asset{}})
		for _, scope := range []Scope{ScopeProject, ScopeAutoMemory} {
			categories = append(categories, Category{Category: name, Scope: scope, ScanState: ScanNotScanned, Reason: ReasonProjectScopeDeferred, Assets: []Asset{}})
		}
	}
	return categories
}

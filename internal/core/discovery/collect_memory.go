package discovery

import (
	"context"
	"errors"
	"os"
	"path"
)

// Collect returns fresh scoped category states; Probe's presence observation is
// deliberately unchanged. Plan §3.3/3.5 (:52-56), F1/F2 (:141-142).
func (r *HomeRoot) Collect(ctx context.Context, paths AgentPaths, nodeID, accountID string) []Category {
	categories := probeCategories(paths)
	for i, c := range categories {
		if c.Scope != ScopeHome || c.ScanState == ScanNotSupported {
			continue
		}
		switch c.Category {
		case "skills":
			categories[i] = r.CollectSkills(ctx, paths, nodeID, accountID)
		case "mcp":
			categories[i] = r.CollectMCP(ctx, paths, nodeID, accountID)
		case "plugins":
			categories[i] = r.CollectPlugins(ctx, paths, nodeID, accountID)
		case "memory":
			categories[i] = r.CollectMemory(ctx, paths, nodeID, accountID)
		}
	}
	return categories
}

// CollectMemory hashes only the fixed home-level memory files (plan :44-45,
// :56). Project and auto-memory scopes remain deferred in Collect.
func (r *HomeRoot) CollectMemory(ctx context.Context, paths AgentPaths, nodeID, accountID string) Category {
	c := collection("memory", paths.Supported && len(paths.MemoryFiles) != 0)
	if c.ScanState == ScanNotSupported {
		return c
	}
	for _, rel := range paths.MemoryFiles {
		name := path.Base(rel)
		if (paths.Family != "claude" || name != "CLAUDE.md") &&
			(paths.Family != "codex" || (name != "AGENTS.md" && name != "AGENTS.override.md")) {
			return collectionFailure(c, ReasonUnparsedFormat)
		}
		present, reason := r.collectionPath(ctx, rel)
		if reason != "" {
			return collectionFailure(c, reason)
		}
		if !present {
			continue
		}
		asset, reason := r.fileAsset(ctx, paths.Family, nodeID, accountID, c.Category, rel, name)
		if reason != "" {
			return collectionFailure(c, reason)
		}
		c.Assets = append(c.Assets, asset)
	}
	return c
}

func collection(name string, supported bool) Category {
	state := ScanNotSupported
	if supported {
		state = ScanScanned
	}
	return Category{Category: name, Scope: ScopeHome, ScanState: state, Assets: []Asset{}}
}

// Only scanned authorizes reconciliation; an error preserves prior server assets
// and any assets already collected here (plan :62, :134).
func collectionFailure(c Category, reason Reason) Category {
	return Category{Category: c.Category, Scope: c.Scope, ScanState: ScanError, Reason: reason, Assets: c.Assets}
}

// Absence is empty only before an entry has been observed. Subsequent open/hash
// failures must remain errors, not erase previously observed inventory.
func (r *HomeRoot) collectionPath(ctx context.Context, rel string) (bool, Reason) {
	_, err := r.lstat(ctx, rel)
	if errors.Is(err, os.ErrNotExist) {
		return false, ""
	}
	if err != nil {
		return false, fileReason(err)
	}
	return true, ""
}

func (r *HomeRoot) fileAsset(ctx context.Context, family, nodeID, accountID, category, rel, name string) (Asset, Reason) {
	if !validSourcePath(rel) {
		return Asset{}, ReasonEscapedRoot
	}
	id, err := AssetID(nodeID, accountID, family, category, rel, name)
	if err != nil {
		return Asset{}, ReasonUnparsedFormat
	}
	digest, reason := r.HashFile(ctx, rel)
	if reason != "" {
		return Asset{}, reason
	}
	return Asset{AssetID: id, Name: name, Category: category, SourceRelPath: rel,
		Size: &digest.Size, Mtime: &digest.Mtime, Hash: digest.Hash, HashKind: FileSHA256}, ""
}

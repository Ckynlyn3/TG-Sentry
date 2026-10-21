package discovery

import (
	"context"
	"os"
	"path"
)

// CollectSkills lists one level and hashes only each directory's SKILL.md,
// never sibling bodies or nested skills. Plan §3.5 (:56), F1 (:141).
func (r *HomeRoot) CollectSkills(ctx context.Context, paths AgentPaths, nodeID, accountID string) Category {
	c := collection("skills", paths.Supported && paths.SkillsDir != "")
	if c.ScanState == ScanNotSupported {
		return c
	}
	present, reason := r.collectionPath(ctx, paths.SkillsDir)
	if reason != "" || !present {
		if reason != "" {
			return collectionFailure(c, reason)
		}
		return c
	}
	// S3 enforces DirectoryEntryBudget before allocating an unbounded listing.
	// Named local exception, plan §9.2 (:134), not a vendor/standard limit.
	entries, reason := r.ReadDir(ctx, paths.SkillsDir)
	if reason != "" {
		return collectionFailure(c, reason)
	}
	for _, entry := range entries {
		dir := path.Join(paths.SkillsDir, entry.Name())
		info, err := r.lstat(ctx, dir)
		if err != nil {
			return collectionFailure(c, fileReason(err))
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return collectionFailure(c, ReasonNotRegularFile)
		}
		if !info.IsDir() {
			continue
		}
		rel := path.Join(dir, "SKILL.md")
		present, reason := r.collectionPath(ctx, rel)
		if reason != "" {
			return collectionFailure(c, reason)
		}
		if !present {
			continue
		}
		asset, reason := r.fileAsset(ctx, paths.Family, nodeID, accountID, c.Category, rel, entry.Name())
		if reason != "" {
			return collectionFailure(c, reason)
		}
		c.Assets = append(c.Assets, asset)
	}
	return c
}

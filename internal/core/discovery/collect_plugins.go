package discovery

import (
	"context"
	"path"
)

// CollectPlugins is explicitly a PARTIAL, one-level regular-file inventory,
// not a complete plugin catalog; directories are not traversed (plan :52, :56,
// :110, F9 :149). S3 applies the named local entry cap (:134).
func (r *HomeRoot) CollectPlugins(ctx context.Context, paths AgentPaths, nodeID, accountID string) Category {
	c := collection("plugins", paths.Supported && paths.PluginsDir != "")
	if c.ScanState == ScanNotSupported {
		return c
	}
	present, reason := r.collectionPath(ctx, paths.PluginsDir)
	if reason != "" {
		return collectionFailure(c, reason)
	}
	if !present {
		return c
	}
	entries, reason := r.ReadDir(ctx, paths.PluginsDir)
	if reason != "" {
		return collectionFailure(c, reason)
	}
	for _, entry := range entries {
		rel := path.Join(paths.PluginsDir, entry.Name())
		info, err := r.lstat(ctx, rel)
		if err != nil {
			return collectionFailure(c, fileReason(err))
		}
		if info.IsDir() {
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

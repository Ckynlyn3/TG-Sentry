package core

import (
	"path"
	"strings"
)

// Remote paths are interpreted on the reporting node, never resolved on the server disk.
func agentPathAbs(p, platform string) bool {
	if platform != "windows" {
		return strings.HasPrefix(p, "/")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && p[2] == '/' {
		return true
	}
	if strings.HasPrefix(p, "//") {
		parts := strings.Split(strings.TrimPrefix(p, "//"), "/")
		return len(parts) >= 2 && parts[0] != "" && parts[0] != "?" && parts[1] != ""
	}
	return false
}
func agentPath(p, cwd, platform string) string {
	if p == "" {
		return ""
	}
	if platform == "windows" {
		p = strings.ReplaceAll(p, "\\", "/")
		cwd = strings.ReplaceAll(cwd, "\\", "/")
		if unresolvedWindowsPath(p) {
			return p // Preserve the form for fail-closed policy classification.
		}
		p = windowsRootedPath(p, cwd)
	}
	if !agentPathAbs(p, platform) && cwd != "" {
		p = cwd + "/" + p
	}
	if platform == "windows" {
		// Clean only below the volume so .. cannot remove a drive or UNC share.
		volume := windowsVolume(p)
		if volume != "" && p == volume {
			p += "/"
		}
		return strings.ToLower(volume + path.Clean(strings.TrimPrefix(p, volume)))
	}
	return path.Clean(p)
}

// Windows applies the current volume, not the current directory, to a single
// leading separator. This also works for remote nodes on a non-Windows server.
// https://learn.microsoft.com/dotnet/standard/io/file-path-formats#apply-the-current-directory
func windowsRootedPath(p, cwd string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
		return windowsVolume(strings.ReplaceAll(cwd, "\\", "/")) + p
	}
	return p
}

// p uses slash separators; a UNC server/share is a volume just like a drive.
func windowsVolume(p string) string {
	if len(p) >= 2 && p[1] == ':' {
		return p[:2]
	}
	if strings.HasPrefix(p, "//") {
		parts := strings.SplitN(p[2:], "/", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return "//" + parts[0] + "/" + parts[1]
		}
	}
	return ""
}

// Device and drive-relative paths need OS state that remote lexical resolution
// does not have. Refuse them rather than guessing, like filepath.IsLocal:
// https://go.dev/pkg/path/filepath#IsLocal
// https://learn.microsoft.com/dotnet/standard/io/file-path-formats
func unresolvedWindowsPath(p string) bool {
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.HasPrefix(p, "//?/") || strings.HasPrefix(p, "//./") ||
		(len(p) >= 2 && p[1] == ':' && (len(p) == 2 || p[2] != '/'))
}

func agentWithin(root, p, platform string) bool {
	if platform == "windows" && (unresolvedWindowsPath(root) || unresolvedWindowsPath(p)) {
		return false
	}
	root = agentPath(root, "", platform)
	p = agentPath(p, "", platform)
	return p == root || strings.HasPrefix(p, strings.TrimRight(root, "/")+"/")
}

package core

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMachinePlatformRoots(t *testing.T) {
	var wantDefault, wantPackage string
	switch runtime.GOOS {
	case "linux":
		wantDefault, wantPackage = "/var/opt/tg-sentry", "/opt/tg-sentry"
	case "windows":
		t.Setenv("ProgramData", `C:\ProgramData`)
		t.Setenv("ProgramFiles", `C:\Program Files`)
		wantDefault = filepath.Join(os.Getenv("ProgramData"), "TG-Sentry")
		wantPackage = filepath.Join(os.Getenv("ProgramFiles"), "TG-Sentry")
	default:
		wantDefault, wantPackage = "/Library/Application Support/TG-Sentry", "/Library/Application Support/TG-Sentry"
	}
	if got := DefaultRoot(); got != wantDefault {
		t.Errorf("DefaultRoot() = %q, want %q", got, wantDefault)
	}
	if got := PackageRoot(); got != wantPackage {
		t.Errorf("PackageRoot() = %q, want %q", got, wantPackage)
	}
}

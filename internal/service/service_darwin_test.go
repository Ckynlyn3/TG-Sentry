package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchdPlistT4Contract(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "macos", "launchd", "com.tg-sentry.endpoint.plist")
	if err := verifyLaunchdPlist(path); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchdPlistRefusesForeignDefinition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign.plist")
	if err := os.WriteFile(path, []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>foreign</string></dict></plist>`), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyLaunchdPlist(path) == nil {
		t.Fatal("foreign registration accepted")
	}
	if verifyLaunchdPlist(path+".missing") == nil {
		t.Fatal("missing registration accepted")
	}
}

func TestReviewPlistRejectsConflictingProgram(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("..", "..", "packaging", "macos", "launchd", launchdLabel+".plist"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"<string>/usr/bin/false</string>", "<string></string>", "<false/>"} {
		modified := strings.Replace(string(original), "<dict>", "<dict><key>Program</key>"+value, 1)
		path := filepath.Join(t.TempDir(), "override.plist")
		if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyLaunchdPlist(path); err == nil {
			t.Fatal("present Program key accepted", value)
		}
	}
}

func TestNativeDarwinMembership(t *testing.T) {
	// Real Apple membership API wrapper, not a simulated group-list scan.
	if _, err := isAdmin(uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
}

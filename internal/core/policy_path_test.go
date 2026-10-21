package core

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProtectedPathSeparators(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{`/etc`, true},
		{`\etc`, true},
		{`/etc/fixture`, true},
		{`\etc\fixture`, true},
		{`/private/etc/fixture`, true},
		{`\private\etc\fixture`, true},
		{`/Library/LaunchAgents/fixture.plist`, true},
		{`\Library\LaunchAgents\fixture.plist`, true},
		{`/System/Library/fixture`, true},
		{`\System\Library\fixture`, true},
		{`C:\Windows\System32\fixture`, true},
		{`c:\WINDOWS\System32\fixture`, true},
		{`C:/etc/fixture`, true},
		{`D:\private\etc\fixture`, true},
		{`D:/Library/LaunchAgents/fixture.plist`, true},
		{`D:/System/Library/fixture`, true},
		{`C:/etc-other/fixture`, false},
		{`C:/project/etc/fixture`, false},
		{`C:/ETC/fixture`, true},
		{`/ETC/fixture`, false},
		{`\ETC\fixture`, false},
		{`/system/Library/fixture`, false},
		{`\system\Library\fixture`, false},
		{`/library/LaunchAgents/fixture.plist`, false},
		{`\library\LaunchAgents\fixture.plist`, false},
		{`/private/ETC/fixture`, false},
		{`\private\ETC\fixture`, false},
		{`/etc-other/fixture`, false},
		{`\etc-other\fixture`, false},
		{`C:\Windows-other\fixture`, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			platform := "linux"
			if windowsVolume(strings.ReplaceAll(tc.path, "\\", "/")) != "" {
				platform = "windows"
			}
			if got := protectedPath(tc.path, platform); got != tc.want {
				t.Errorf("protectedPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestPolicyPathRootedPaths(t *testing.T) {
	cwd := t.TempDir()
	root := filepath.VolumeName(cwd) + string(filepath.Separator)
	for _, p := range []string{"/", "/etc/fixture", "/etc/../fixture"} {
		want := canonicalMissingPath(filepath.Join(root, filepath.FromSlash(p)))
		if got := policyPath(p, cwd); got != want {
			t.Errorf("policyPath(%q, %q) = %q, want %q", p, cwd, got, want)
		}
	}
	if runtime.GOOS == "windows" {
		if got, want := policyPath(`\etc\fixture`, cwd), filepath.Join(root, "etc", "fixture"); got != want {
			t.Errorf("backslash rooted path = %q, want %q", got, want)
		}
	}
	if got, want := policyPath("relative/fixture", cwd), filepath.Join(cwd, "relative", "fixture"); got != want {
		t.Errorf("relative path = %q, want %q", got, want)
	}
	in := input("rooted", "Bash", map[string]any{"command": "echo x > /etc/fixture"})
	if d := evaluateAt(in, BuiltinRules(), cwd); d == nil || d.RuleID != "R2" {
		t.Fatalf("local rooted redirect not blocked: %+v", d)
	}
	in.Arguments = map[string]any{"command": "rm /etc/fixture"}
	if d := evaluateAt(in, []Rule{catalogRule(t, "R_SYS_PATH")}, cwd); d == nil || d.RuleID != "R_SYS_PATH" {
		t.Fatalf("local rooted removal not blocked: %+v", d)
	}
}

func TestPOSIXLiteralBackslashesRemainProtected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backslashes are separators on native Windows")
	}
	for _, p := range []string{`/etc/a\..\..\tmp`, `/etc/fixture\..\..\unprotected`} {
		in := input("literal", "Write", map[string]any{"path": p})
		if d := evaluateAt(in, BuiltinRules(), t.TempDir()); d == nil || d.RuleID != "R2" || d.Decision != "reject" {
			t.Errorf("literal POSIX filename %q escaped R2: %+v", p, d)
		}
	}
}

func TestWindowsUnresolvablePathsDeniedWithoutScopes(t *testing.T) {
	e := engine(t)
	if err := e.Register(Instance{ID: "windows-node", SessionID: "windows-session", NodeID: ID(), Agent: "claude", Platform: "windows", Cwd: `C:\project`, HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{`\\?\C:\Windows\fixture`, `C:..\Windows\fixture`, `\\.\UNC\localhost\C$\Windows\fixture`, `D:fixture`, `C:`, `\\?\C:\project\fixture`} {
		for _, tool := range []string{"Write", "Bash"} {
			t.Run(tool+"/"+p, func(t *testing.T) {
				args := map[string]any{"path": p}
				if tool == "Bash" {
					args = map[string]any{"command": "echo x > '" + p + "'"}
				}
				r, err := e.Submit(ReviewInput{InstanceID: "windows-node", CallID: ID(), ToolName: tool, Arguments: args})
				if err != nil || r.Decision != "reject" || r.RuleID != "R2" {
					t.Errorf("remote Windows path %q was not denied without scopes: %+v, %v", p, r.Decision+"/"+r.RuleID, err)
				}
				if runtime.GOOS == "windows" {
					if d := evaluateAt(input(ID(), tool, args), BuiltinRules(), t.TempDir()); d == nil || d.Decision != "reject" || d.RuleID != "R2" {
						t.Errorf("native Windows path %q was not denied without scopes: %+v", p, d)
					}
				}
			})
		}
	}
}

func TestRemoteProtectedPathsUseTargetCaseRules(t *testing.T) {
	e := engine(t)
	for _, platform := range []string{"windows", "linux"} {
		cwd := "/project"
		if platform == "windows" {
			cwd = `C:\project`
		}
		if err := e.Register(Instance{ID: platform, SessionID: platform, NodeID: ID(), Agent: "claude", Platform: platform, Cwd: cwd, HookVersion: Version}); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{`/Library/LaunchAgents/fixture`, `/library/launchagents/fixture`, `/ETC/fixture`, `/SYSTEM/fixture`, `/etc/a\..\..\tmp`} {
			r, err := e.Submit(ReviewInput{InstanceID: platform, CallID: ID(), ToolName: "Write", Arguments: map[string]any{"path": p}})
			want := platform == "windows" || p == `/Library/LaunchAgents/fixture`
			if p == `/etc/a\..\..\tmp` {
				want = platform != "windows" // A literal filename only on POSIX.
			}
			if err != nil || (r.Decision == "reject" && r.RuleID == "R2") != want {
				t.Errorf("platform=%s path=%q: %+v, %v", platform, p, r.Decision+"/"+r.RuleID, err)
			}
		}
	}
}

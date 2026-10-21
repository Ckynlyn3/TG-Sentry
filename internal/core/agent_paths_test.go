package core

import "testing"

func TestAgentPathWindowsRootedPaths(t *testing.T) {
	for _, tc := range []struct{ path, cwd, want string }{
		{`/etc/fixture`, `C:\project`, `c:/etc/fixture`},
		{`\etc\fixture`, `D:\project`, `d:/etc/fixture`},
		{`/`, `D:\project`, `d:/`},
		{`/etc/../fixture`, `D:\project`, `d:/fixture`},
		{`/../etc/fixture`, `D:\project`, `d:/etc/fixture`},
		{`/../etc/fixture`, `\\server\share\project`, `//server/share/etc/fixture`},
		{`relative/fixture`, `\\server\share\project`, `//server/share/project/relative/fixture`},
		{`relative/fixture`, `D:\project`, `d:/project/relative/fixture`},
		{`C:\etc\fixture`, `D:\project`, `c:/etc/fixture`},
		{`\\server\share\fixture`, `D:\project`, `//server/share/fixture`},
		{`\\server\share`, `D:\project`, `//server/share/`},
		{`/etc/fixture`, `\\server\share\project`, `//server/share/etc/fixture`},
	} {
		t.Run(tc.path+" in "+tc.cwd, func(t *testing.T) {
			if got := agentPath(tc.path, tc.cwd, "windows"); got != tc.want {
				t.Fatalf("agentPath = %q, want %q", got, tc.want)
			}
		})
	}
	if got := agentPath(`/etc/fixture`, `/project`, "linux"); got != `/etc/fixture` {
		t.Fatalf("POSIX root changed: %q", got)
	}
	in := input("rooted", "Bash", map[string]any{"command": "echo x > /etc/fixture"})
	resolve := func(p, cwd string) string { return agentPath(p, cwd, "windows") }
	if d := evaluatePaths(in, BuiltinRules(), `D:\project`, resolve, "windows"); d == nil || d.RuleID != "R2" {
		t.Fatalf("remote Windows rooted redirect not blocked: %+v", d)
	}
	in.Arguments = map[string]any{"command": "rm /etc/fixture"}
	if d := evaluatePaths(in, []Rule{catalogRule(t, "R_SYS_PATH")}, `D:\project`, resolve, "windows"); d == nil || d.RuleID != "R_SYS_PATH" {
		t.Fatalf("remote Windows rooted removal not blocked: %+v", d)
	}
}

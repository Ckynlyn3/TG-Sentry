package core

import "testing"

// Commands are data only: this corpus never invokes a shell or runs a command.
// Sources and the operation #5/#9 reduction are recorded in docs/rules.md.
func TestHighRiskManagementFixtures(t *testing.T) {
	cases := []struct {
		operation   int
		id, command string
		match       bool
	}{
		// #5 System control: literal shutdown/restart/halt, PowerShell and cmd
		// wrappers, and service stops.
		{5, "R_SYS_SHUTDOWN", `shutdown /s`, true},
		{5, "R_SYS_SHUTDOWN", `shutdown /r`, true},
		{5, "R_SYS_SHUTDOWN", `shutdown -h now`, true},
		{5, "R_SYS_SHUTDOWN", `Stop-Computer`, true},
		{5, "R_SYS_SHUTDOWN", `Restart-Computer -Force`, true},
		{5, "R_SYS_SHUTDOWN", `powershell.exe -Command "Stop-Computer"`, true},
		{5, "R_SYS_SHUTDOWN", `cmd.exe /c "shutdown /r /t 0"`, true},
		{5, "R5", `shutdown /s`, true},
		{5, "R5", `systemctl stop nginx`, true},
		{5, "R5", `systemctl restart nginx`, true},
		// #5 Negatives: documented help/version switches, query-only verbs and
		// quoted examples are not a shutdown request.
		{5, "R_SYS_SHUTDOWN", `shutdown /?`, false},
		{5, "R_SYS_SHUTDOWN", `shutdown --help`, false},
		{5, "R_SYS_SHUTDOWN", `cmd.exe /c "shutdown /?"`, false},
		{5, "R5", `shutdown /?`, false},
		{5, "R5", `shutdown --help`, false},
		{5, "R5", `systemctl status nginx`, false},
		{5, "R5", `Get-Service`, false},
		{5, "R_SYS_SHUTDOWN", `echo "shutdown /s"`, false},
		{5, "R5", `echo "shutdown /s"`, false},
		// Only the documented bare invocation is exempt: with any other argument
		// the "/?" is an operand ("[TIME] [WALL...]" wall message, or Microsoft's
		// shutdown /c comment), so the command still shuts the host down.
		{5, "R_SYS_SHUTDOWN", `shutdown -h now '/?'`, true},
		{5, "R5", `shutdown -h now '/?'`, true},
		{5, "R_SYS_SHUTDOWN", `shutdown /s /t 0 /c "/?"`, true},
		{5, "R5", `shutdown /s /t 0 /c "/?"`, true},
		{5, "R_SYS_SHUTDOWN", `powershell.exe -Command "shutdown /?"`, false},
		// #9 Account mutation: net.exe add/delete and dscl mutation verbs.
		{9, "R3", `net user fixture /add`, true},
		{9, "R3", `net user fixture /delete`, true},
		{9, "R3", `net localgroup Administrators fixture /add`, true},
		{9, "R3", `net1 user fixture /add`, true},
		{9, "R3", `cmd.exe /c "net user fixture /add"`, true},
		{9, "R3", `powershell.exe -Command "net localgroup Administrators fixture /add"`, true},
		{9, "R3", `dscl . -create /Users/fixture`, true},
		{9, "R3", `dscl . -append /Groups/admin GroupMembership fixture`, true},
		{9, "R3", `sudo dscl . -delete /Users/fixture`, true},
		// dscl [options] [datasource [command]]: -u, -P and -f take a value, so an
		// option value that reads like a verb is not the command.
		{9, "R3", `dscl -u read -p . -create /Users/fixture`, true},
		{9, "R3", `dscl -f /tmp/read . -create /Users/fixture`, true},
		{9, "R3", `dscl -u create . -read /Users/fixture`, false},
		{9, "R3", `dscl -u list -P create . -read /Users/fixture`, false},
		// #9 Negatives: enumeration/listing and dscl reads only inspect records.
		{9, "R3", `net user`, false},
		{9, "R3", `net user fixture`, false},
		{9, "R3", `net localgroup`, false},
		{9, "R3", `net localgroup Administrators`, false},
		{9, "R3", `dscl . -read /Users/fixture`, false},
		{9, "R3", `dscl . -list /Users`, false},
		{9, "R3", `dscl . -search /Users RealName fixture`, false},
		{9, "R3", `echo "net user fixture /add"`, false},
		{9, "R3", `Write-Output "dscl . -create /Users/fixture"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			in := ReviewInput{ToolName: "Bash", Arguments: map[string]any{"command": tc.command}}
			r := catalogRule(t, tc.id)
			if !r.Enabled {
				t.Fatalf("operation #%d: baseline rule %s must be enabled", tc.operation, tc.id)
			}
			d := evaluateAt(in, []Rule{r}, "/Users/fixture/project")
			if tc.match {
				if d == nil || d.RuleID != tc.id || d.Decision != "reject" {
					t.Fatalf("operation #%d: want %s rejection, got %+v", tc.operation, tc.id, d)
				}
			} else if d != nil {
				t.Fatalf("operation #%d: want no %s match or parse failure, got %+v", tc.operation, tc.id, d)
			}
			d = evaluateAt(in, BuiltinRules(), "/Users/fixture/project")
			if got := d != nil && d.Decision == "reject"; got != tc.match {
				t.Fatalf("operation #%d: default rejection=%v, want %v: %+v", tc.operation, got, tc.match, d)
			}
		})
	}
}

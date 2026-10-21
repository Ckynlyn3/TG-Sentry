//go:build windows

package discovery

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ProfileList subkeys are SIDs; ProfileImagePath is the registered profile root.
// https://devblogs.microsoft.com/scripting/how-can-i-list-all-the-user-profiles-on-a-computer/
const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

func enumerateLocalAccounts(ctx context.Context) ([]AccountHome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profiles, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.READ)
	if err != nil {
		return nil, errors.New("discovery: open registered profiles")
	}
	defer profiles.Close()
	sids, err := profiles.ReadSubKeyNames(-1)
	if err != nil {
		return nil, errors.New("discovery: enumerate registered profiles")
	}
	var accounts []AccountHome
	// ponytail: registered roots only; State-bit temporary/mandatory profile handling is deferred.
	for _, sid := range sids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !isEnumerableProfileSID(sid) {
			continue
		}
		home, err := readProfileImagePath(profiles, sid)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, accountHomeFromProfile(sid, home))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return accounts, nil
}

func readProfileImagePath(profiles registry.Key, sid string) (string, error) {
	profile, err := registry.OpenKey(profiles, sid, registry.READ)
	if err != nil {
		return "", errors.New("discovery: open registered profile")
	}
	defer profile.Close()
	home, valueType, err := profile.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", errors.New("discovery: read registered profile path")
	}
	// GetStringValue does not expand EXPAND_SZ; ExpandString does.
	// https://pkg.go.dev/golang.org/x/sys/windows/registry#ExpandString
	if valueType == registry.EXPAND_SZ {
		home, err = registry.ExpandString(home)
		if err != nil {
			return "", errors.New("discovery: expand registered profile path")
		}
	}
	return home, nil
}

func isEnumerableProfileSID(sid string) bool {
	// Registry names are case-insensitive; preserve the original SID in the record.
	// https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry
	sid = strings.ToUpper(sid)
	// Documented service identities, not a numeric RID floor:
	// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return false
	}
	// Microsoft flags .bak entries separately from active ProfileList entries:
	// https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-to-cleanup-profile-folder-information-and-prevent-temp-user-profiles-from-being-created
	return !strings.HasPrefix(sid, "S-1-5-80-") && !strings.HasSuffix(sid, ".BAK")
}

func accountHomeFromProfile(sid, home string) AccountHome {
	// Observed folder name, not SID→name resolution; it may lag an account rename.
	// https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/renaming-user-account-not-change-profile-path
	return AccountHome{ObservedLocalAccount: filepath.Base(home), AccountID: sid, HomePath: home}
}

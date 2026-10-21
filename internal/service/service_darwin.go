package service

import (
	"aegishook/internal/core"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
)

const launchdLabel = "com.tg-sentry.endpoint"
const launchdPath = "/Library/LaunchDaemons/" + launchdLabel + ".plist"

// Apple mbr_check_membership(3) includes nested groups. dsmemberutil(1) is
// Apple's CLI wrapper for that API, used because release builds disable CGO.
func isAdmin(uid uint32) (bool, error) {
	data, err := boundedCommand("/usr/bin/dsmemberutil", "checkmembership", "-u", strconv.FormatUint(uint64(uid), 10), "-G", "admin")
	return err == nil && string(data) == "user is a member of the group\n", err
}

func checkRegistration() error {
	if err := validatePublicChain(filepath.Dir(launchdPath), core.ValidateMachinePath); err != nil {
		return err
	}
	if err := core.ValidateMachinePath(launchdPath, false); err != nil {
		return err
	}
	if err := verifyLaunchdPlist(launchdPath); err != nil {
		return err
	}
	_, err := boundedCommand("/bin/launchctl", "print", "system/"+launchdLabel)
	return err
}

func verifyLaunchdPlist(path string) error {
	data, err := boundedCommand("/usr/bin/plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		return err
	}
	var plist struct {
		// launchd.plist(5): Program overrides ProgramArguments[0]. This
		// template supports no Program key, including empty or non-string values.
		Program             json.RawMessage
		Label               string
		ProgramArguments    []string
		KeepAlive           bool
		UserName, GroupName string
	}
	if json.Unmarshal(data, &plist) != nil || plist.Program != nil || plist.Label != launchdLabel || !plist.KeepAlive || plist.UserName != "root" || plist.GroupName != "wheel" || len(plist.ProgramArguments) != 2 || plist.ProgramArguments[0] != filepath.Join(core.PackageRoot(), "aegishook") || plist.ProgramArguments[1] != "service" {
		return errors.New("unexpected machine LaunchDaemon registration")
	}
	return nil
}

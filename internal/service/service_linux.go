package service

import (
	"aegishook/internal/core"
	"errors"
	"path/filepath"
	"strings"
)

const systemdUnit = "tg-sentry.service"

// Function-var test seam follows core.machineUninstallPreflight; production
// retains the fixed unit path and bounded native command runner.
var systemdPath = "/etc/systemd/system/" + systemdUnit
var systemdCommand = boundedCommand

// Linux machine administration requires root (e.g. sudo), not a group lookup.
func isAdmin(uint32) (bool, error) { return false, nil }

func checkRegistration() error {
	if err := validatePublicChain(filepath.Dir(systemdPath), core.ValidateMachinePath); err != nil {
		return err
	}
	if err := core.ValidateMachinePath(systemdPath, false); err != nil {
		return err
	}
	// systemctl(1): show is the manager's merged view, including drop-ins;
	// --value omits property names. Never parse only the on-disk unit.
	// https://www.freedesktop.org/software/systemd/man/latest/systemctl.html
	if _, err := systemdCommand("/usr/bin/systemctl", "is-enabled", systemdUnit); err != nil {
		return err
	}
	data, err := systemdCommand("/usr/bin/systemctl", "show", "--property=ExecStart", "--value", systemdUnit)
	if err != nil {
		return err
	}
	return verifySystemdExecStart(data)
}

func verifySystemdExecStart(data []byte) error {
	// systemd.service(5), ExecStart: require one command with the packaged
	// executable and exactly the service argument, like the launchd precedent.
	// https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#ExecStart=
	value := strings.TrimSpace(string(data))
	if !strings.HasPrefix(value, "{ ") || !strings.HasSuffix(value, " }") || strings.Count(value, "{") != 1 || strings.Count(value, "}") != 1 {
		return errors.New("unexpected machine systemd registration")
	}
	// v257 systemctl-show.c:1418–1451 joins argv without quoting. Validate
	// the entire ordered record so an argument containing " ; " cannot hide.
	// https://github.com/systemd/systemd/blob/v257/src/systemctl/systemctl-show.c#L1418-L1451
	fields := strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, "{ "), " }"), " ; ")
	keys := []string{"path", "argv[]", "ignore_errors", "start_time", "stop_time", "pid", "code", "status"}
	if len(fields) != len(keys) {
		return errors.New("unexpected machine systemd field count")
	}
	for i, key := range keys {
		name, field, found := strings.Cut(fields[i], "=")
		if !found || name != key || field == "" {
			return errors.New("unexpected machine systemd field")
		}
	}
	binary := filepath.Join(core.PackageRoot(), "aegishook")
	if fields[0] != "path="+binary || fields[1] != "argv[]="+binary+" service" {
		return errors.New("unexpected machine systemd command")
	}
	return nil
}

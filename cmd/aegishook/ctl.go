package main

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"aegishook/internal/service"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
)

func runCtl(args []string, output io.Writer) int {
	if len(args) == 0 {
		return ctlError(output, errors.New("usage: aegishook ctl system-install|commit|rollback|system-uninstall|status|repair"))
	}
	action := args[0]
	if action == "discover" {
		return runCtlDiscover(args[1:], output)
	}
	switch action {
	case "system-install", "commit", "rollback", "system-uninstall", "status", "repair":
	default:
		return ctlError(output, errors.New("unknown ctl command"))
	}
	f := flag.NewFlagSet("ctl "+action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	o := core.MachineOptions{}
	f.StringVar(&o.Root, "machine-dir", core.DefaultRoot(), "machine runtime root")
	require, target := "hooks", ""
	switch action {
	case "system-install":
		f.StringVar(&o.Endpoint, "endpoint", "", "enrollment endpoint (nonsecret)")
		f.StringVar(&o.Owner, "owner", "", "control endpoint owner (nonsecret)")
		f.BoolVar(&o.NoCommit, "no-commit", false, "retain MSI rollback snapshot")
	case "system-uninstall":
		f.BoolVar(&o.AcknowledgeManaged, "acknowledge-managed", false, "acknowledge removal of administrator-managed hooks")
	case "status":
		f.StringVar(&require, "require", "hooks", "installed, service, enrolled or hooks")
		f.StringVar(&target, "user", "", "target hook configuration user")
	}
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(output, "aegishook ctl", action)
			return 0
		}
		return ctlError(output, err)
	}
	if f.NArg() != 0 {
		return ctlError(output, errors.New("unexpected positional arguments"))
	}
	if action == "status" {
		if (service.Status{}).ExitCode(require) == service.ExitUsage {
			return ctlError(output, errors.New("unknown status requirement"))
		}
		return ctlStatus(o, target, require, output)
	}
	if action == "repair" {
		state, err := service.Call(o.Root, service.Request{Verb: "repair"})
		if err != nil {
			return ctlError(output, err)
		}
		return writeCtlStatus(output, state, "enrolled")
	}
	var err error
	o.Binary, err = os.Executable()
	if err != nil {
		return ctlError(output, err)
	}
	o.ManagedFiles = managedDestinations(runtime.GOOS)
	result, err := core.MachineOperation(action, o)
	if err != nil {
		return ctlError(output, err)
	}
	if err = json.NewEncoder(output).Encode(result); err != nil {
		return service.ExitUsage
	}
	return service.ExitOK
}

// T6: setup codes and bearer credentials are 64 hexadecimal characters.
var machineSecretPattern = regexp.MustCompile(`[0-9a-fA-F]{64}`)

func ctlError(output io.Writer, err error) int {
	fmt.Fprintln(output, machineSecretPattern.ReplaceAllString(core.RedactText(err.Error()), "[REDACTED]"))
	return service.ExitUsage
}
func writeCtlStatus(output io.Writer, state service.Status, require string) int {
	state.Loaded = "unknown"
	if err := json.NewEncoder(output).Encode(state); err != nil {
		return service.ExitUsage
	}
	return state.ExitCode(require)
}

// Hook details belong to invoking-user ctl output, not the machine service contract.
type ctlStatusOutput struct {
	service.Status
	Hooks []core.DriftEntry `json:"hooks"`
}

var currentCtlUser = user.Current
var lookupCtlUser = user.Lookup

func ctlStatus(o core.MachineOptions, target, require string, output io.Writer) int {
	state, err := service.Call(o.Root, service.Request{Verb: "status"})
	if err != nil {
		state = service.Status{Installed: core.MachineInstalled(o)}
	}
	state.Hooks = "unknown"
	// Status never interprets administrator-private credentials as user hook data.
	var account *user.User
	if target != "" {
		account, err = lookupCtlUser(target)
	} else {
		account, err = currentCtlUser()
		if err == nil && (account.Uid == "0" || account.Uid == "S-1-5-18") {
			account = nil
		}
	}
	if err != nil {
		return ctlError(output, errors.New("cannot resolve target user"))
	}
	hooksState, hooks := ctlUserHooks(account, target != "")
	state.Hooks, state.Loaded = hooksState, "unknown"
	if err := json.NewEncoder(output).Encode(ctlStatusOutput{Status: state, Hooks: hooks}); err != nil {
		return service.ExitUsage
	}
	return state.ExitCode(require)
}

func ctlUserHooks(account *user.User, explicit bool) (string, []core.DriftEntry) {
	empty := []core.DriftEntry{}
	if account == nil {
		return "unknown", empty
	}
	if explicit {
		// Reuse #38/41 R1's opened-handle owner check. Windows ownership remains
		// not evaluated; S1 independently confines reads to invoking-user roots.
		home, state, _ := discovery.OpenHome(account.HomeDir, account.Uid)
		if state != discovery.HomeReadable {
			return "unknown", empty
		}
		defer home.Close()
	}
	report, err := core.ClientDrift(account.HomeDir)
	if err != nil {
		return "unknown", empty
	}
	return ctlDriftState(report), report.Entries
}

// #39 LD6/A3: unreadability wins over drift; staging alone is not configured.
func ctlDriftState(report core.DriftReport) string {
	if report.Manifest == core.ManifestAbsent {
		return "missing"
	}
	if report.Manifest != core.ManifestOK {
		return "unknown"
	}
	evaluated, drifted := false, false
	for _, entry := range report.Entries {
		switch entry.OwnerState {
		case core.OwnerNotEvaluated:
			continue
		case core.OwnerUnreadable:
			return "unknown"
		case core.OwnedExact:
			evaluated = true
		default:
			drifted = true
		}
	}
	if evaluated && !drifted {
		return "configured"
	}
	return "missing"
}

// Destinations from docs/research/AGENT-HOOK-CONTRACTS.md and docs/codex-hooks.md.
func managedDestinations(platform string) []string {
	if platform == "windows" {
		return []string{
			filepath.Join(os.Getenv("ProgramFiles"), "ClaudeCode", "managed-settings.json"),
			filepath.Join(os.Getenv("ProgramData"), "OpenAI", "Codex", "requirements.toml"),
			core.CursorEnterprisePath(platform),
		}
	}
	if platform == "darwin" {
		return []string{"/Library/Application Support/ClaudeCode/managed-settings.json", "/etc/codex/requirements.toml", core.CursorEnterprisePath(platform)}
	}
	return []string{"/etc/claude-code/managed-settings.json", "/etc/codex/requirements.toml", core.CursorEnterprisePath(platform)}
}

func refusePackageClient(binary, root string) error {
	packaged, err := core.PackageBinary(binary, root)
	if err != nil {
		return err
	}
	if packaged {
		return errors.New("client install cannot use the package binary; use hook.sh or hook.ps1 to create a verified private copy")
	}
	return nil
}

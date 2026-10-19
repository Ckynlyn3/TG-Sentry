package main

import (
	"aegishook/internal/core"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Do not wrap underlying errors: initialization and key IO can contain secret paths.
// https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude
var errServerKeysUnavailable = errors.New("signing key management unavailable: stop AegisHook and check the server data directory permissions, state, and rotation/retirement preconditions before retrying")

// Issue #65 §3.7: offline operator ceremony, never the remote admin path.
func runServerKeys(args []string, output io.Writer) error {
	if len(args) > 0 && args[0] == "help" {
		args = append(append([]string{}, args[1:]...), "-h")
	}
	action := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	if action != "" && action != "rotate-bundle-key" && action != "retire-bundle-key" {
		return errors.New("usage: aegishook server rotate-bundle-key|retire-bundle-key [options]")
	}
	f := flag.NewFlagSet("aegishook server "+action, flag.ContinueOnError)
	f.SetOutput(output)
	home, _ := os.UserHomeDir()
	dir := f.String("data-dir", filepath.Join(home, ".aegishook"), "Private server data directory; stop the server first")
	keyID := ""
	if action == "retire-bundle-key" {
		f.StringVar(&keyID, "key-id", "", "Predecessor key ID to retire (not the current signer)")
	}
	f.Usage = func() {
		fmt.Fprintln(output, "Usage: aegishook server rotate-bundle-key|retire-bundle-key [options]")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if action == "" || f.NArg() != 0 || (action == "retire-bundle-key" && keyID == "") {
		return errors.New("usage: aegishook server rotate-bundle-key [--data-dir DIR] or retire-bundle-key --key-id ID [--data-dir DIR]")
	}
	// Open already takes process.lock; S2 owns atomic 0600 key/manifest writes (§3.3).
	e, err := core.Open(*dir)
	if err != nil {
		return errServerKeysUnavailable
	}
	defer e.Close()
	if action == "rotate-bundle-key" {
		err = e.RotateBundleKey()
	} else {
		err = e.RetireBundleKey(keyID)
	}
	if err != nil {
		return errServerKeysUnavailable
	}
	return printServerKeys(e, action, keyID, output)
}

func printServerKeys(e *core.Engine, action, retiredID string, output io.Writer) error {
	version := e.BundleTrustVersion()
	signed, err := e.BundleTrustRecord(version)
	if err != nil {
		return errServerKeysUnavailable
	}
	var record core.TrustRecord
	if err := json.Unmarshal(signed.Payload, &record); err != nil {
		return errServerKeysUnavailable
	}
	ids := make([]string, 0, len(record.Keys))
	for _, key := range record.Keys {
		ids = append(ids, key.KeyID)
	}
	if _, err := fmt.Fprintf(output, "%s trust-version=%d key-ids=%s\n", action, version, strings.Join(ids, ",")); err != nil {
		return err
	}
	if action == "rotate-bundle-key" {
		_, err = fmt.Fprintln(output, "Next steps: Restart the server. Verify enrolled agents accept the new signer before retiring the predecessor with server retire-bundle-key --key-id ID.")
	} else {
		_, err = fmt.Fprintf(output, "Retired key-id=%s\nNext steps: Restart the server. Verify enrolled agents accept the current signer. For compromise recovery, revoke device credentials, uninstall, and enroll again.\n", retiredID)
	}
	return err
}

package main

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"aegishook/internal/service"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

var scanDiscovery = discovery.Scan
var currentDiscoveryUser = user.Current
var discoveryMachinePrivileged = func() bool {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0
	}
	account, err := currentCtlUser()
	return err == nil && account != nil && account.Uid == "S-1-5-18"
}

func runClientDiscover(args []string, output io.Writer) error {
	f := flag.NewFlagSet("client discover", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	home, _ := os.UserHomeDir()
	dir := f.String("client-dir", filepath.Join(home, ".aegishook-client"), "private client directory")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = fmt.Fprintln(output, "aegishook client discover [--client-dir DIR]")
			return err
		}
		return errors.New("invalid discovery options")
	}
	if f.NArg() != 0 {
		return errors.New("unexpected discovery arguments")
	}
	return runDiscovery(context.Background(), *dir, discovery.OwnHome)
}

func runCtlDiscover(args []string, output io.Writer) int {
	f := flag.NewFlagSet("ctl discover", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("machine-dir", core.DefaultRoot(), "machine runtime root")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err = fmt.Fprintln(output, "aegishook ctl discover [--machine-dir DIR]"); err == nil {
				return service.ExitOK
			}
		}
		return ctlError(output, errors.New("invalid discovery options"))
	}
	if f.NArg() != 0 {
		return ctlError(output, errors.New("unexpected discovery arguments"))
	}
	if err := validateDiscoveryMachine(*root); err != nil {
		return ctlError(output, err)
	}
	if err := runDiscovery(context.Background(), core.MachinePaths(*root).Private, discovery.AllLocalAccounts); err != nil {
		return ctlError(output, err)
	}
	return service.ExitOK
}

// Reuse the daemon's FIO15-C chain/private-tree validation pattern and the
// existing native owner/ACL validator; never accept a per-user client directory.
func validateDiscoveryMachine(root string) error {
	if !discoveryMachinePrivileged() {
		return errors.New("discovery requires machine context")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == filepath.VolumeName(root)+string(filepath.Separator) {
		return errors.New("invalid discovery machine directory")
	}
	for dir := root; ; dir = filepath.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() || core.ValidateMachinePath(dir, false) != nil {
			return errors.New("discovery machine context unavailable")
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	err := filepath.WalkDir(core.MachinePaths(root).Private, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return core.ValidateMachinePath(path, true)
	})
	if err != nil {
		return errors.New("discovery machine context unavailable")
	}
	return nil
}

func runDiscovery(ctx context.Context, dir string, scope discovery.ReportScope) error {
	var accounts func(context.Context) ([]discovery.AccountHome, error)
	if scope == discovery.OwnHome {
		accounts = discoveryOwnAccount
	}
	_, err := core.RunDiscovery(ctx, dir, scope, accounts, scanDiscovery)
	return err
}

func discoveryOwnAccount(ctx context.Context) ([]discovery.AccountHome, error) {
	if ctx.Err() != nil {
		return nil, errors.New("discovery canceled")
	}
	account, err := currentDiscoveryUser()
	if err != nil || account == nil {
		return nil, errors.New("discovery account unavailable")
	}
	return []discovery.AccountHome{{ObservedLocalAccount: account.Username, AccountID: account.Uid, HomePath: account.HomeDir}}, nil
}

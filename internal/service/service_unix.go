//go:build darwin

package service

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const launchdLabel = "com.tg-sentry.endpoint"
const launchdPath = "/Library/LaunchDaemons/" + launchdLabel + ".plist"

func init() {
	Run = runDarwin
	Call = callDarwin
}

type unixDaemon struct {
	options    core.MachineOptions
	owner      string
	registered func() error
	admin      func(uint32) (bool, error)
	uid        uint32
	listener   *net.UnixListener
	directory  *os.File
	socketInfo os.FileInfo
}

func daemonContext() (context.Context, context.CancelFunc) {
	// Apple: Creating Launch Daemons and Agents, Recommended Behaviors.
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
}

func runDarwin(root string) error {
	if os.Geteuid() != 0 {
		return errors.New("machine daemon requires root")
	}
	ctx, stop := daemonContext()
	defer stop()
	d := &unixDaemon{options: core.MachineOptions{Root: root, ValidatePath: core.ValidateMachinePath}, registered: checkLaunchd, admin: isDarwinAdmin}
	if err := d.configure(); err != nil {
		return err
	}
	if err := d.listen(); err != nil {
		return err
	}
	return d.serve(ctx)
}

func (d *unixDaemon) configure() error {
	if err := d.validate(); err != nil {
		return err
	}
	data, err := os.ReadFile(core.MachinePaths(d.options.Root).Config)
	var config core.MachineConfig
	if err != nil || json.Unmarshal(data, &config) != nil {
		return errors.New("machine configuration unavailable")
	}
	if config.Owner != "" {
		var account *user.User
		_, numericErr := strconv.ParseUint(config.Owner, 10, 32)
		if numericErr == nil {
			account, err = user.LookupId(config.Owner)
		} else {
			account, err = user.Lookup(config.Owner)
		}
		if err != nil || account == nil {
			return errors.New("machine owner identity unavailable")
		}
		d.owner = account.Uid
	}
	return nil
}

func (d *unixDaemon) validate() error {
	return validateDaemonPaths(d.options.Root, d.options.ValidatePath)
}

func (d *unixDaemon) listen() error {
	if err := d.validate(); err != nil {
		return err
	}
	if err := d.registered(); err != nil {
		return err
	}
	if !core.MachineInstalled(d.options) {
		return errors.New("machine binary integrity check failed")
	}
	// An offline or unenrolled machine still serves diagnostic status. This
	// startup revalidation never authorizes hook verdicts or commits a snapshot.
	_ = core.MachineEnrolled(d.options)
	p := core.MachinePaths(d.options.Root)
	if err := validatePublicChain(p.Run, d.options.ValidatePath); err != nil {
		return err
	}
	dir, err := os.Open(p.Private)
	if err != nil {
		return err
	}
	// Lifetime flock stays on the validated root-only private directory, never
	// public run/. It is separate from client.lock so repair can take that lock.
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		dir.Close()
		return errors.New("machine daemon already running")
	}
	if err := removeStaleSocket(p.Socket, d.uid); err != nil {
		dir.Close()
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p.Socket, Net: "unix"})
	if err != nil {
		dir.Close()
		return err
	}
	d.listener, d.directory = listener, dir
	listener.SetUnlinkOnClose(false)
	d.socketInfo, err = os.Lstat(p.Socket)
	if err == nil {
		err = os.Chmod(p.Socket, 0666)
	} // N3: authorization is kernel-UID based, not mode based.
	if err != nil {
		d.close()
		return err
	}
	return nil
}

func removeStaleSocket(path string, uid uint32) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || st.Mode()&os.ModeSocket == 0 {
		return errors.New("foreign control endpoint retained")
	}
	conn, err := net.DialTimeout("unix", path, controlTimeout)
	if err == nil {
		conn.Close()
		return errors.New("control endpoint already listening")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return errors.New("control endpoint state unknown")
	}
	return os.Remove(path)
}

func (d *unixDaemon) close() error {
	defer d.directory.Close()
	err := d.listener.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	path := core.MachinePaths(d.options.Root).Socket
	st, statErr := os.Lstat(path)
	if statErr == nil && d.socketInfo != nil && os.SameFile(st, d.socketInfo) {
		return errors.Join(err, os.Remove(path))
	}
	if os.IsNotExist(statErr) {
		return err
	}
	if statErr != nil {
		return errors.Join(err, statErr)
	}
	return errors.Join(err, errors.New("replacement control endpoint retained"))
}

func (d *unixDaemon) serve(ctx context.Context) (err error) {
	defer func() { err = errors.Join(err, d.close()) }()
	stop := context.AfterFunc(ctx, func() { d.listener.Close() })
	defer stop()
	// ponytail: serialize this low-volume maintenance endpoint. One bounded
	// active request avoids unbounded goroutines for local unauthenticated peers.
	for {
		conn, err := d.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		stopConn := context.AfterFunc(ctx, func() { conn.Close() })
		d.handle(ctx, conn)
		stopConn()
	}
}

func (d *unixDaemon) status(ctx context.Context, verb string) (Status, error) {
	state := Status{Hooks: "unknown", Loaded: "unknown"}
	if err := d.validate(); err != nil {
		return state, err
	}
	state.Installed = core.MachineInstalled(d.options)
	state.Service = d.registered() == nil
	if state.Installed && state.Service {
		if verb == "repair" {
			state.Enrolled = core.MachineRepairContext(ctx, d.options) == nil
		} else {
			state.Enrolled = core.MachineEnrolledContext(ctx, d.options) == nil
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			state.Enrolled = false
			state.Enrollment, state.EnrollmentReason = "unknown", "timeout"
		}
	}
	return state, nil
}

// Apple mbr_check_membership(3) includes nested groups. dsmemberutil(1) is
// Apple's CLI wrapper for that API, used because release builds disable CGO.
func isDarwinAdmin(uid uint32) (bool, error) {
	data, err := boundedCommand("/usr/bin/dsmemberutil", "checkmembership", "-u", strconv.FormatUint(uint64(uid), 10), "-G", "admin")
	return err == nil && string(data) == "user is a member of the group\n", err
}

// Do not embed bytes.Buffer: io.Copy would bypass Write via its ReadFrom.
type commandOutput struct{ buffer bytes.Buffer }

func (w *commandOutput) Write(p []byte) (int, error) {
	if len(p) > controlMaxFrame-w.buffer.Len() {
		return 0, errors.New("native command output exceeds input budget")
	}
	return w.buffer.Write(p)
}
func boundedCommand(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var output commandOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("native command failed: %w", err)
	}
	return output.buffer.Bytes(), nil
}

func checkLaunchd() error {
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

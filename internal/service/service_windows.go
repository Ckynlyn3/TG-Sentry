//go:build windows

package service

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Lead integration decision: S4 ServiceInstall Name/DisplayName must match.
const serviceName = "TGSentryEndpoint"
const serviceDisplayName = "TG-Sentry Endpoint"

func init() { Run = runWindows; Call = callWindows }

type windowsDaemon struct {
	options    core.MachineOptions
	owner      string
	registered func() error
	peer       func(windows.Handle, string) (bool, error)
	pipe       windows.Handle
}

type windowsHandler struct {
	serve func(context.Context, chan<- error) error
	err   error
}

func runWindows(root string) error {
	// This fixed pipe belongs to the single default machine install. Keep disk
	// validation in Execute so svc.Run can register promptly with SCM.
	if !validWindowsMachineRoot(root) {
		return errors.New("invalid machine root")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("machine service requires LocalSystem")
	}
	hosted, err := svc.IsWindowsService()
	if err != nil || !hosted {
		return errors.New("machine service must run under SCM")
	}
	d := &windowsDaemon{options: core.MachineOptions{Root: root, ValidatePath: core.ValidateMachinePath}, registered: checkSCM, peer: pipeAuthorized}
	handler := &windowsHandler{serve: d.run}
	if err := svc.Run(serviceName, handler); err != nil {
		return err
	}
	return handler.err
}

// Microsoft ServiceMain / Service Control Handler: report START_PENDING before
// startup work; accept Stop/Shutdown only when Running; returning ends service.
// https://learn.microsoft.com/en-us/windows/win32/services/service-servicemain-function
func (h *windowsHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: uint32(controlTimeout / time.Millisecond)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan error, 1), make(chan error, 1)
	go func() { done <- h.serve(ctx, started) }()
	var current = svc.Status{State: svc.StartPending, WaitHint: uint32(controlTimeout / time.Millisecond)}
	for {
		select {
		case err := <-started:
			if err == nil {
				current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				changes <- current
			}
		case err := <-done:
			h.err = err
			if err != nil {
				return true, uint32(ExitService)
			}
			return false, 0
		case request, open := <-requests:
			if !open || request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				changes <- svc.Status{State: svc.StopPending, WaitHint: uint32(controlTimeout / time.Millisecond)}
				cancel()
				h.err = <-done
				if h.err != nil {
					return true, uint32(ExitService)
				}
				return false, 0
			}
			if request.Cmd == svc.Interrogate {
				changes <- current
			}
		}
	}
}

func (d *windowsDaemon) run(ctx context.Context, started chan<- error) error {
	// Execute reports SERVICE_STOPPED with a nonzero exit code on serving errors.
	// Configure this once at startup, never through status/repair's query handles.
	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag
	service, err := openSCMService(windows.SERVICE_CHANGE_CONFIG)
	if err == nil {
		err = errors.Join(service.SetRecoveryActionsOnNonCrashFailures(true), service.Close())
	}
	if err == nil {
		err = d.configure(ctx)
	}
	started <- err
	if err != nil {
		return err
	}
	stopRefresh := startPolicyRefresh(ctx, d.options)
	defer stopRefresh()
	return d.serve(ctx)
}

func (d *windowsDaemon) validate() error {
	return validateDaemonPaths(d.options.Root, d.options.ValidatePath)
}

func (d *windowsDaemon) configure(ctx context.Context) error {
	if err := d.validate(); err != nil {
		return err
	}
	data, err := os.ReadFile(core.MachinePaths(d.options.Root).Config)
	var config core.MachineConfig
	if err != nil || json.Unmarshal(data, &config) != nil {
		return errors.New("machine configuration unavailable")
	}
	if config.Owner != "" {
		sid, err := windows.StringToSid(config.Owner)
		if err != nil {
			return errors.New("machine owner must be a SID")
		}
		// A syntactically valid but unresolvable account is not an authorized owner.
		if _, _, kind, err := sid.LookupAccount(""); err != nil || kind != windows.SidTypeUser {
			return errors.New("machine owner identity unavailable")
		}
		d.owner = sid.String()
	}
	if err := d.registered(); err != nil {
		return err
	}
	if !core.MachineInstalled(d.options) {
		return errors.New("machine binary integrity check failed")
	}
	// Offline/unenrolled machines still answer diagnostics. Never commits a snapshot.
	_ = core.MachineEnrolledContext(ctx, d.options)
	d.pipe, err = newControlPipe(controlPipe, d.owner)
	return err
}

func (d *windowsDaemon) serve(ctx context.Context) (err error) {
	defer func() { err = errors.Join(err, windows.CloseHandle(d.pipe)) }()
	stream := &pipeStream{handle: d.pipe, ctx: ctx}
	// ponytail: one bounded maintenance request at a time, as on Unix. Keep the
	// same instance open for its lifetime so there is no name-squatting gap.
	for {
		stream.deadline = time.Time{}
		_, err := stream.operation(func(o *windows.Overlapped, _ *uint32) error { return windows.ConnectNamedPipe(d.pipe, o) })
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		d.handle(ctx, stream)
		// DisconnectNamedPipe discards unread replies. Wait for client close under
		// the SAME deadline; don't use unbounded synchronous FlushFileBuffers.
		var ack [1]byte
		_, _ = stream.Read(ack[:])
		if err := windows.DisconnectNamedPipe(d.pipe); err != nil && err != windows.ERROR_PIPE_NOT_CONNECTED {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func (d *windowsDaemon) status(ctx context.Context, verb string) (Status, error) {
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

// Query-only SCM handles: neither status nor repair changes installer-owned
// registration/recovery. Microsoft OpenSCManagerW/OpenServiceW, dwDesiredAccess.
func openSCMService(access uint32) (*mgr.Service, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return nil, err
	}
	handle, err := windows.OpenService(manager, name, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: serviceName, Handle: handle}, nil
}

func checkSCM() error {
	service, err := openSCMService(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return err
	}
	if err := verifySCMConfig(config); err != nil {
		return err
	}
	state, err := service.Query()
	if err != nil {
		return err
	}
	if state.State != svc.Running && state.State != svc.StartPending {
		return errors.New("machine service is not running")
	}
	actions, err := service.RecoveryActions()
	if err != nil {
		return err
	}
	reset, err := service.ResetPeriod()
	if err != nil {
		return err
	}
	nonCrashFailures, err := service.RecoveryActionsOnNonCrashFailures()
	if err != nil {
		return err
	}
	// Issue #33 acceptance, not invented tuning values.
	if !nonCrashFailures || len(actions) != 3 || reset != 86400 {
		return errors.New("unexpected SCM recovery configuration")
	}
	for i, seconds := range []time.Duration{5, 10, 30} {
		if actions[i].Type != mgr.ServiceRestart || actions[i].Delay != seconds*time.Second {
			return errors.New("unexpected SCM recovery action")
		}
	}
	return nil
}

func verifySCMConfig(config mgr.Config) error {
	expected := filepath.Join(core.PackageRoot(), "aegishook.exe")
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(args) != 2 || !strings.EqualFold(args[0], expected) || args[1] != "service" ||
		config.StartType != mgr.StartAutomatic ||
		config.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || !strings.EqualFold(config.ServiceStartName, "LocalSystem") {
		return errors.New("unexpected machine SCM registration")
	}
	if err := validatePublicChain(filepath.Dir(expected), core.ValidateMachinePath); err != nil {
		return err
	}
	return core.ValidateMachinePath(expected, false)
}

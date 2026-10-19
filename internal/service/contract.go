// Package service defines the machine endpoint contract shared by ctl and native hosts.
package service

import (
	"errors"
	"time"
)

var ErrPlatformUnsupported = errors.New("machine service platform support is not available")

// Native implementations are supplied by S2/S3. Missing support fails closed.
var Run = func(root string) error { return ErrPlatformUnsupported }
var Call = func(root string, request Request) (Status, error) { return Status{}, ErrPlatformUnsupported }

type Request struct {
	Verb string `json:"verb"`
	// Optional same-host deadline, clamped by the daemon; never extends its budget.
	Deadline time.Time `json:"deadline,omitempty"`
}

func (r Request) Validate() error {
	if r.Verb != "status" && r.Verb != "repair" {
		return errors.New("control endpoint accepts status or repair only")
	}
	return nil
}

type Status struct {
	Installed bool `json:"installed"`
	Service   bool `json:"service"`
	Enrolled  bool `json:"enrolled"`
	// Condition status and reason follow the Kubernetes condition pattern.
	// Unknown enrollment never satisfies the enrolled requirement.
	Enrollment       string `json:"enrollment,omitempty"`
	EnrollmentReason string `json:"enrollmentReason,omitempty"`
	Hooks            string `json:"hooksConfigured"`
	Loaded           string `json:"loaded"`
}

// N1 is a named local exception: frozen MDM exit codes and lowest-level precedence.
const (
	ExitOK           = 0
	ExitUsage        = 2
	ExitNotInstalled = 10
	ExitService      = 20
	ExitNotEnrolled  = 30
	ExitHooksMissing = 40
	ExitHooksUnknown = 50
)

func (s Status) ExitCode(require string) int {
	switch require {
	case "installed", "service", "enrolled", "hooks":
	default:
		return ExitUsage
	}
	if !s.Installed {
		return ExitNotInstalled
	}
	if require == "installed" {
		return ExitOK
	}
	if !s.Service {
		return ExitService
	}
	if require == "service" {
		return ExitOK
	}
	if !s.Enrolled {
		return ExitNotEnrolled
	}
	if require == "enrolled" {
		return ExitOK
	}
	if s.Hooks == "unknown" || s.Hooks == "" {
		return ExitHooksUnknown
	}
	if s.Hooks != "configured" {
		return ExitHooksMissing
	}
	return ExitOK
}

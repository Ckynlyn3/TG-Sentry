//go:build linux

package discovery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Unexported I/O seams keep tests independent of the host's account databases.
var (
	runGetent = func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, executable, args...)
		var output getentOutputBuffer
		cmd.Stdout = &output
		if err := cmd.Run(); err != nil {
			return nil, err
		}
		return output.buffer.Bytes(), nil
	}
	readLoginDefs = func() ([]byte, error) { return os.ReadFile("/etc/login.defs") }
)

// Reuse ConfigParseBudgetBytes, the named local resource-budget exception in
// report.go, for getent stdout. Do not embed bytes.Buffer: its ReadFrom method
// would let io.Copy bypass this bounded Write implementation.
type getentOutputBuffer struct {
	buffer bytes.Buffer
}

func (output *getentOutputBuffer) Write(data []byte) (int, error) {
	if len(data) > ConfigParseBudgetBytes-output.buffer.Len() {
		return 0, ErrUnsupportedPlatform
	}
	return output.buffer.Write(data)
}

func enumerateLocalAccounts(ctx context.Context) ([]AccountHome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defs, readErr := readLoginDefs()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, ErrUnsupportedPlatform
	}
	minUID, maxUID, err := localUIDBounds(defs)
	if err != nil {
		return nil, err
	}
	// getent(1), OPTIONS: --service overrides NSS with files only. Domain and
	// directory enumeration is deferred; never retry unrestricted NSS or PATH.
	// https://man7.org/linux/man-pages/man1/getent.1.html
	output, runErr := runGetent(ctx, "/usr/bin/getent", "--service=files", "passwd")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runErr != nil || len(output) > ConfigParseBudgetBytes {
		// Neither process errors nor stdout/stderr may expose account data.
		return nil, ErrUnsupportedPlatform
	}
	return localPasswdAccounts(ctx, output, minUID, maxUID)
}

func localUIDBounds(data []byte) (uint64, uint64, error) {
	// login.defs(5), DESCRIPTION and UID_MIN/UID_MAX: regular-user allocation
	// defaults, used only when omitted in a readable, valid configuration.
	// https://man7.org/linux/man-pages/man5/login.defs.5.html
	bounds := map[string]uint64{"UID_MIN": 1000, "UID_MAX": 60000}
	seen := map[string]bool{}
	if !utf8.Valid(data) || strings.ContainsFunc(string(data), func(r rune) bool {
		return (r < ' ' && r != '\n' && r != '\r' && r != '\t') || r == '\x7f'
	}) {
		return 0, 0, ErrUnsupportedPlatform
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return 0, 0, ErrUnsupportedPlatform
		}
		key := fields[0]
		if key != "UID_MIN" && key != "UID_MAX" {
			continue
		}
		if len(fields) != 2 {
			return 0, 0, ErrUnsupportedPlatform
		}
		value, err := loginDefUID(fields[1])
		if err != nil || (seen[key] && bounds[key] != value) {
			return 0, 0, ErrUnsupportedPlatform
		}
		bounds[key], seen[key] = value, true
	}
	if bounds["UID_MIN"] > bounds["UID_MAX"] {
		return 0, 0, ErrUnsupportedPlatform
	}
	return bounds["UID_MIN"], bounds["UID_MAX"], nil
}

func loginDefUID(value string) (uint64, error) {
	// shadow-utils 4.19.0 lib/getdef.c getdef_unum uses base 0. Reject Go-only
	// binary/0o prefixes and underscores; keep documented decimal/octal/hex.
	// https://github.com/shadow-maint/shadow/blob/4.19.0/lib/getdef.c
	if strings.ContainsAny(value, "_+-") || strings.HasPrefix(value, "0b") || strings.HasPrefix(value, "0B") || strings.HasPrefix(value, "0o") || strings.HasPrefix(value, "0O") {
		return 0, ErrUnsupportedPlatform
	}
	// Match the Linux UID width already required by fsroot_unix.go.
	return strconv.ParseUint(value, 0, 32)
}

func localPasswdAccounts(ctx context.Context, output []byte, minUID, maxUID uint64) ([]AccountHome, error) {
	var accounts []AccountHome
	if len(output) == 0 {
		return accounts, ctx.Err()
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(output), "\n"), "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// passwd(5), DESCRIPTION: seven colon-delimited fields. Store only the
		// name, UID and home; GID, password, GECOS and shell are never retained.
		// https://man7.org/linux/man-pages/man5/passwd.5.html
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return nil, errors.New("discovery: invalid local account records")
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || !validAccountField(fields[0]) || (fields[6] != "" && !validAccountField(fields[6])) {
			return nil, errors.New("discovery: invalid local account records")
		}
		// This is regular local-account scope, not a universal human detector.
		// System accounts are outside the site allocation range; root (UID 0
		// per passwd(5)) and nobody remain excluded even within that range.
		if uid == 0 || uid < minUID || uid > maxUID || fields[0] == "root" || fields[0] == "nobody" || nonLoginShell(fields[6]) {
			continue
		}
		// Clone retained substrings so AccountHome cannot retain the backing
		// getent output containing the discarded password/GECOS fields.
		accounts = append(accounts, AccountHome{
			ObservedLocalAccount: strings.Clone(fields[0]),
			AccountID:            strings.Clone(fields[2]),
			HomePath:             strings.Clone(fields[5]),
		})
	}
	return accounts, ctx.Err()
}

func nonLoginShell(shell string) bool {
	// Issue #38 eligibility policy; this does not determine authentication.
	return strings.HasSuffix(shell, "/false") || strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/shutdown") || strings.HasSuffix(shell, "/halt")
}

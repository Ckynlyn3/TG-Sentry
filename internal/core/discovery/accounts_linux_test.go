//go:build linux

package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The seams are process-wide: these tests deliberately do not run in parallel.
func injectLinuxAccounts(t *testing.T, defs, output string) {
	t.Helper()
	previousRun, previousRead := runGetent, readLoginDefs
	t.Cleanup(func() { runGetent, readLoginDefs = previousRun, previousRead })
	readLoginDefs = func() ([]byte, error) { return []byte(defs), nil }
	runGetent = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(output), nil
	}
}

func TestLinuxAccountsUIDBounds(t *testing.T) {
	tests := []struct {
		name, defs string
		min, max   int
	}{
		{"documented defaults", "# site leaves allocation bounds unset\n", 1000, 60000},
		{"empty valid file", "", 1000, 60000},
		{"legacy site range", "UID_MIN 500\nUID_MAX 999\n", 500, 999},
		{"comments and whitespace", " \t# comment\n\tUID_MIN\t500  # legacy\n UID_MAX 999 \nMAIL_DIR /var/mail\n", 500, 999},
		{"octal and hexadecimal", "UID_MIN 0764\nUID_MAX 0x3e7\n", 500, 999},
		{"only minimum configured", "UID_MIN 500\n", 500, 60000},
		{"only maximum configured", "UID_MAX 2000\n", 1000, 2000},
		{"identical duplicate bounds", "UID_MIN 500\nUID_MIN 0x1f4\nUID_MAX 999\n", 500, 999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output strings.Builder
			for _, uid := range []int{tt.min - 1, tt.min, tt.min + 1, tt.max - 1, tt.max, tt.max + 1} {
				fmt.Fprintf(&output, "person%d:x:%d:100:discarded:/custom/Person %d:/bin/sh\n", uid, uid, uid)
			}
			injectLinuxAccounts(t, tt.defs, output.String())
			got, err := EnumerateLocalAccounts(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var want []AccountHome
			for _, uid := range []int{tt.min, tt.min + 1, tt.max - 1, tt.max} {
				want = append(want, AccountHome{fmt.Sprint("person", uid), fmt.Sprint(uid), fmt.Sprint("/custom/Person ", uid)})
			}
			slices.SortFunc(want, func(a, b AccountHome) int { return strings.Compare(a.AccountID, b.AccountID) })
			if !slices.Equal(got, want) {
				t.Fatalf("accounts = %#v, want %#v", got, want)
			}
		})
	}
}

func TestLinuxAccountsEligibility(t *testing.T) {
	tests := []struct {
		name, record string
		keep         bool
	}{
		{"regular custom home", "person:x:1000:100:Secret Name:/srv/People/Person One:/bin/bash", true},
		{"UID spelling preserved", "person:x:01000:100:Secret Name:/home/person:/bin/bash", true},
		{"Unicode home", "person:x:1000:100:Secret Name:/srv/Élodie 東京:/bin/bash", true},
		{"empty shell defaults to sh", "person:x:1000:100:Secret Name:/home/person:", true},
		{"root UID", "alias:x:0:0:Secret Name:/root:/bin/bash", false},
		{"root name", "root:x:1000:100:Secret Name:/root:/bin/bash", false},
		{"system UID", "daemon:x:1:1:Secret Name:/srv/daemon:/bin/bash", false},
		{"nobody", "nobody:x:1000:100:Secret Name:/home/nobody:/bin/bash", false},
		{"false", "person:x:1000:100:Secret Name:/home/person:/bin/false", false},
		{"nologin", "person:x:1000:100:Secret Name:/home/person:/usr/sbin/nologin", false},
		{"shutdown", "person:x:1000:100:Secret Name:/home/person:/sbin/shutdown", false},
		{"halt", "person:x:1000:100:Secret Name:/home/person:/sbin/halt", false},
		{"suffix not substring", "person:x:1000:100:Secret Name:/home/person:/bin/false-custom", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injectLinuxAccounts(t, "", tt.record+"\n")
			got, err := EnumerateLocalAccounts(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var want []AccountHome
			if tt.keep {
				fields := strings.Split(tt.record, ":")
				want = []AccountHome{{fields[0], fields[2], fields[5]}}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("accounts = %#v, want %#v", got, want)
			}
		})
	}
}

func TestLinuxAccountsInvalidLoginDefsUnavailable(t *testing.T) {
	for _, defs := range []string{
		"UID_MIN", "UID_MAX", "UID_MIN \n", "UID_MIN=1000", "malformed",
		"UID_MIN private-invalid", "UID_MAX -1", "UID_MIN +1000", "UID_MIN 1_000",
		"UID_MIN 0b1111101000", "UID_MIN 0o1750", "UID_MIN 08", "UID_MIN 0xZZ",
		"UID_MAX 4294967296", "UID_MAX 18446744073709551616",
		"UID_MIN 1000 extra", "UID_MIN 1000\nUID_MIN 500", "UID_MAX 60000\nUID_MAX 999",
		"UID_MIN 2000\nUID_MAX 1000", "UID_MIN 70000", "UID_MAX 500",
		"UID_MIN 1000\x00", "# private-invalid\xff", "MAIL_DIR /var/\x01mail",
	} {
		t.Run(fmt.Sprintf("case-%x", []byte(defs)), func(t *testing.T) {
			injectLinuxAccounts(t, defs, "person:x:1000:100:private-gecos:/private-home:/bin/sh\n")
			runGetent = func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("invalid configuration must not start getent")
				return nil, nil
			}
			got, err := EnumerateLocalAccounts(context.Background())
			if !errors.Is(err, ErrUnsupportedPlatform) || got != nil || err.Error() != ErrUnsupportedPlatform.Error() {
				t.Fatalf("invalid configuration returned accounts=%v error=%v", got, err)
			}
		})
	}
}

func TestLinuxAccountsMalformedPasswdFailsClosed(t *testing.T) {
	for _, record := range []string{
		"private-account:x:1000:100:private-gecos:/private-home",
		"private-account:x:1000:100:private-gecos:/private-home:/bin/sh:extra",
		"private-account:x:not-a-uid:100:private-gecos:/private-home:/bin/sh",
		"private-account:x:-1:100:private-gecos:/private-home:/bin/sh",
		"private-account:x:+1000:100:private-gecos:/private-home:/bin/sh",
		"private-account:x:0x3e8:100:private-gecos:/private-home:/bin/sh",
		"private-account:x:4294967296:100:private-gecos:/private-home:/bin/sh",
		"private-account:x::100:private-gecos:/private-home:/bin/sh",
		":x:1000:100:private-gecos:/private-home:/bin/sh",
		"private-account\x00:x:1000:100:private-gecos:/private-home:/bin/sh",
		"private-account:x:1000:100:private-gecos:/private-home:/sbin/nologin\x00",
	} {
		t.Run(fmt.Sprintf("case-%x", []byte(record)), func(t *testing.T) {
			injectLinuxAccounts(t, "", "safe:x:1001:100:ignored:/home/safe:/bin/sh\n"+record+"\n")
			got, err := EnumerateLocalAccounts(context.Background())
			if got != nil || err == nil || err.Error() != "discovery: invalid local account records" {
				t.Fatalf("malformed records returned accounts=%v error=%v", got, err)
			}
		})
	}
}

func TestLinuxAccountsUseSharedNormalization(t *testing.T) {
	tests := []struct {
		name, output, wantError string
		want                    []AccountHome
	}{
		{"duplicates and sorting", "second:x:2000:100:ignored:/home/second:/bin/sh\nfirst:x:1000:100:ignored:/home/first:/bin/sh\nfirst:x:1000:100:ignored:/home/first:/bin/sh\n", "", []AccountHome{{"first", "1000", "/home/first"}, {"second", "2000", "/home/second"}}},
		{"conflict", "first:x:1000:100:ignored:/home/first:/bin/sh\nother:x:1000:100:ignored:/home/other:/bin/sh", "discovery: conflicting local account records", nil},
		{"invalid relative home", "first:x:1000:100:ignored:relative:/bin/sh", "discovery: invalid local account", nil},
		{"root home", "first:x:1000:100:ignored:/:/bin/sh", "discovery: invalid local account", nil},
		{"empty output", "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injectLinuxAccounts(t, "", tt.output)
			got, err := EnumerateLocalAccounts(context.Background())
			if tt.wantError != "" {
				if got != nil || err == nil || err.Error() != tt.wantError {
					t.Fatalf("accounts=%v error=%v", got, err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("accounts=%v error=%v, want %v", got, err, tt.want)
			}
		})
	}
}

func TestLinuxAccountsDependenciesUnavailable(t *testing.T) {
	for _, failure := range []error{
		os.ErrNotExist, os.ErrPermission,
		&exec.ExitError{Stderr: []byte("unsupported --service=files private-account")},
		errors.New("nonzero exit private-account /private-home private-gecos"),
	} {
		t.Run(fmt.Sprintf("%T-%s", failure, failure.Error()), func(t *testing.T) {
			for _, failRead := range []bool{false, true} {
				injectLinuxAccounts(t, "", "")
				calls := 0
				readLoginDefs = func() ([]byte, error) {
					if failRead {
						return nil, failure
					}
					return nil, nil
				}
				runGetent = func(context.Context, string, ...string) ([]byte, error) {
					calls++
					return []byte("private-account:x:1000:100:private-gecos:/private-home:/bin/sh"), failure
				}
				got, err := EnumerateLocalAccounts(context.Background())
				if got != nil || !errors.Is(err, ErrUnsupportedPlatform) || err.Error() != ErrUnsupportedPlatform.Error() {
					t.Fatalf("dependency failure returned accounts=%v error=%v", got, err)
				}
				wantCalls := 1
				if failRead {
					wantCalls = 0
				}
				if calls != wantCalls {
					t.Fatalf("getent calls=%d, want %d; no fallback allowed", calls, wantCalls)
				}
			}
		})
	}
}

func TestLinuxAccountsFixedCommand(t *testing.T) {
	injectLinuxAccounts(t, "", "")
	calls := 0
	runGetent = func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		calls++
		if executable != "/usr/bin/getent" || !slices.Equal(args, []string{"--service=files", "passwd"}) {
			t.Fatalf("unexpected command %q %q; no shell, shadow, remote NSS or fallback", executable, args)
		}
		if ctx == nil {
			t.Fatal("command missing context")
		}
		return []byte("person:x:1000:100:ignored:/custom/person:/bin/sh\n"), nil
	}
	got, err := EnumerateLocalAccounts(context.Background())
	if err != nil || len(got) != 1 || calls != 1 {
		t.Fatalf("accounts=%v error=%v calls=%d", got, err, calls)
	}
}

func TestLinuxAccountsGetentOutputBudget(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("budget-plus-%d", extra), func(t *testing.T) {
			const prefix = "person:x:1000:100:"
			const suffix = ":/home/person:/bin/sh\n"
			output := prefix + strings.Repeat("x", ConfigParseBudgetBytes-len(prefix)-len(suffix)+extra) + suffix
			injectLinuxAccounts(t, "", output)
			got, err := EnumerateLocalAccounts(context.Background())
			if extra != 0 {
				if got != nil || !errors.Is(err, ErrUnsupportedPlatform) || err.Error() != ErrUnsupportedPlatform.Error() {
					t.Fatal("over-budget output must return nil accounts and a static error")
				}
				return
			}
			want := []AccountHome{{"person", "1000", "/home/person"}}
			if err != nil || !slices.Equal(got, want) {
				t.Fatal("exact-budget output must preserve the eligible account")
			}
		})
	}
}

func TestLinuxGetentOutputBufferBudget(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("budget-plus-%d", extra), func(t *testing.T) {
			var output getentOutputBuffer
			// LimitedReader has no WriterTo, so io.Copy would use ReadFrom if
			// bytes.Buffer were embedded and accidentally bypassed Write.
			input := strings.NewReader(strings.Repeat("x", ConfigParseBudgetBytes+extra))
			n, err := io.Copy(&output, io.LimitReader(input, int64(input.Len())))
			if output.buffer.Len() > ConfigParseBudgetBytes {
				t.Fatal("stdout buffer exceeded the existing resource budget")
			}
			if extra != 0 {
				if !errors.Is(err, ErrUnsupportedPlatform) || err.Error() != ErrUnsupportedPlatform.Error() {
					t.Fatal("stdout collection must fail closed on overflow")
				}
				return
			}
			if err != nil || n != ConfigParseBudgetBytes || output.buffer.Len() != ConfigParseBudgetBytes {
				t.Fatal("stdout collection must accept exactly the budget")
			}
		})
	}
}

func TestLinuxAccountsCancelled(t *testing.T) {
	for _, stage := range []string{"before read", "during read", "during command"} {
		t.Run(stage, func(t *testing.T) {
			injectLinuxAccounts(t, "", "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before read" {
				cancel()
			}
			readLoginDefs = func() ([]byte, error) {
				if stage == "before read" {
					t.Fatal("cancelled request read login.defs")
				}
				if stage == "during read" {
					cancel()
				}
				return nil, nil
			}
			runGetent = func(context.Context, string, ...string) ([]byte, error) {
				if stage != "during command" {
					t.Fatal("cancelled request started getent")
				}
				cancel()
				return []byte("person:x:1000:100:ignored:/home/person:/bin/sh"), errors.New("private-error")
			}
			got, err := EnumerateLocalAccounts(ctx)
			if !errors.Is(err, context.Canceled) || got != nil {
				t.Fatalf("cancelled enumeration returned accounts=%v error=%v", got, err)
			}
		})
	}
}

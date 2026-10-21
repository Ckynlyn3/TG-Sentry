//go:build darwin

package discovery

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestDarwinLocalAccounts(t *testing.T) {
	person := dsclTestRecord("Person One", "501", "/Volumes/Homes/Person One", "/bin/zsh")
	unicode := dsclTestRecord("Élodie 東京", "502", "/homes/Élodie 東京", "/bin/bash")
	admin := dsclTestRecord("hidden-admin", "499", "/private/var/hidden-admin", "/bin/zsh")
	tests := []struct {
		name string
		xml  string
		want []AccountHome
	}{
		{"multiple records and outside Users", person + unicode, []AccountHome{{"Person One", "501", "/Volumes/Homes/Person One"}, {"Élodie 東京", "502", "/homes/Élodie 東京"}}},
		{"sub-500 hidden admin retained", dsclTestRecord("_service", "200", "/var/empty", "/bin/zsh") + dsclTestRecord("root", "0", "/var/root", "/bin/sh") + admin, []AccountHome{{"hidden-admin", "499", "/private/var/hidden-admin"}}},
		{"machine account excluded", dsclTestRecord("machine$", "503", "/homes/machine", "/bin/zsh"), nil},
		{"UID zero excluded", dsclTestRecord("renamed-root", "0", "/var/root", "/bin/sh"), nil},
		{"Fleet sync excluded", dsclTestRecord("sync", "4", "/var/empty", "/bin/sync"), nil},
		{"sync login shell retained", dsclTestRecord("sync", "504", "/homes/sync", "/bin/zsh"), []AccountHome{{"sync", "504", "/homes/sync"}}},
		{"empty enumeration", "", nil},
		{"canonical RecordName alias", strings.Replace(person, "<string>Person One</string>", "<string>Person One</string><string>alias</string>", 1), []AccountHome{{"Person One", "501", "/Volumes/Homes/Person One"}}},
		{"shared duplicate collapse and sort", unicode + person + person, []AccountHome{{"Person One", "501", "/Volumes/Homes/Person One"}, {"Élodie 東京", "502", "/homes/Élodie 東京"}}},
	}
	for _, shell := range []string{"/usr/bin/false", "/sbin/nologin", "/sbin/shutdown", "/sbin/halt"} {
		tests = append(tests, struct {
			name string
			xml  string
			want []AccountHome
		}{"non-login shell " + shell, dsclTestRecord("system", "201", "/var/empty", shell), nil})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injectDscl(t, []byte(dsclTestPlist(tt.xml)), nil)
			got, err := EnumerateLocalAccounts(context.Background())
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("accounts = %#v, error = %v, want %#v", got, err, tt.want)
			}
		})
	}
}

func TestDarwinLocalAccountsRejectsPartialOrMalformedOutput(t *testing.T) {
	record := dsclTestRecord("private-person", "501", "/homes/private-person", "/bin/zsh")
	uid := dsclTestAttribute("UniqueID", "501")
	home := dsclTestAttribute("NFSHomeDirectory", "/homes/private-person")
	tests := []struct {
		name string
		data string
	}{
		{"missing UID", dsclTestPlist(record + strings.Replace(record, uid, "", 1))},
		{"multiple UIDs", dsclTestPlist(strings.Replace(record, uid, dsclTestAttribute("UniqueID", "501", "502"), 1))},
		{"duplicate UID key", dsclTestPlist(strings.Replace(record, uid, uid+uid, 1))},
		{"missing home", dsclTestPlist(record + strings.Replace(record, home, "", 1))},
		{"multiple homes", dsclTestPlist(strings.Replace(record, home, dsclTestAttribute("NFSHomeDirectory", "/homes/a", "/homes/b"), 1))},
		{"missing name", dsclTestPlist(strings.Replace(record, dsclTestAttribute("RecordName", "private-person"), "", 1))},
		{"missing shell", dsclTestPlist(strings.Replace(record, dsclTestAttribute("UserShell", "/bin/zsh"), "", 1))},
		{"multiple shells", dsclTestPlist(strings.Replace(record, dsclTestAttribute("UserShell", "/bin/zsh"), dsclTestAttribute("UserShell", "/bin/zsh", "/bin/false"), 1))},
		{"integer UID", dsclTestPlist(strings.Replace(record, "<string>501</string>", "<integer>501</integer>", 1))},
		{"dangling key", dsclTestPlist("<dict><key>dsAttrTypeStandard:UniqueID</key></dict>")},
		{"malformed", dsclTestPlist(record) + "<"},
		{"truncated", "<plist><array>" + record},
		{"wrong root", "<dict/>"},
		{"missing array", "<plist/>"},
		{"wrong record shape", dsclTestPlist("<string>private-person</string>")},
		{"unexpected container text", "<plist>private-person<array/></plist>"},
		{"extra document", dsclTestPlist(record) + dsclTestPlist(record)},
		{"leading text", "private-person" + dsclTestPlist(record)},
		{"empty bytes", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injectDscl(t, []byte(tt.data), nil)
			got, err := EnumerateLocalAccounts(context.Background())
			if got != nil || err == nil || err.Error() != "discovery: malformed local account plist" {
				t.Fatalf("expected static plist error and no partial result, got %v", err)
			}
		})
	}
}

func TestDarwinLocalAccountsExecutionErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		err     error
		cancel  bool
		wantErr string
	}{
		{"command failure discards partial output", []byte(dsclTestPlist(dsclTestRecord("private-person", "501", "/homes/private-person", "/bin/zsh"))), errors.New("private command detail /homes/private-person"), false, "discovery: local account command failed"},
		{"oversized output", []byte(strings.Repeat(" ", dsclOutputBudgetBytes+1)), nil, false, "discovery: local account output budget exceeded"},
		{"cancelled context", nil, nil, true, "context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injectDscl(t, tt.data, tt.err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			got, err := EnumerateLocalAccounts(ctx)
			if got != nil || err == nil || err.Error() != tt.wantErr {
				t.Fatalf("expected static failure with no accounts, got %v", err)
			}
		})
	}
}

func TestDarwinLocalAccountsCommandRecorder(t *testing.T) {
	original := runDscl
	t.Cleanup(func() { runDscl = original })
	ctx := context.Background()
	calls := 0
	runDscl = func(gotCtx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		want := []string{"-plist", ".", "-readall", "/Users", "RecordName", "UniqueID", "NFSHomeDirectory", "UserShell"}
		if gotCtx != ctx || name != "/usr/bin/dscl" || !slices.Equal(args, want) {
			t.Fatal("command must directly execute dscl with the fixed local-node argv, never a shell")
		}
		return []byte(dsclTestPlist("")), nil
	}
	if _, err := EnumerateLocalAccounts(ctx); err != nil || calls != 1 {
		t.Fatalf("calls = %d, error = %v", calls, err)
	}
}

func TestDarwinDsclOutputBudget(t *testing.T) {
	var output dsclOutputBuffer
	if n, err := output.Write([]byte(strings.Repeat("x", dsclOutputBudgetBytes))); n != dsclOutputBudgetBytes || err != nil {
		t.Fatal("exact budget must fit")
	}
	if _, err := output.Write([]byte("x")); !errors.Is(err, errDsclOutputBudget) || output.data.Len() != dsclOutputBudgetBytes {
		t.Fatal("writer must reject overflow without retaining extra output")
	}
	var copied dsclOutputBuffer
	reader := io.LimitReader(strings.NewReader(strings.Repeat("x", dsclOutputBudgetBytes+1)), int64(dsclOutputBudgetBytes+1))
	if _, err := io.Copy(&copied, reader); !errors.Is(err, errDsclOutputBudget) || copied.data.Len() > dsclOutputBudgetBytes || !copied.exceeded {
		t.Fatal("io.Copy must not bypass the output ceiling")
	}
}

func TestDarwinLocalAccountsExactOutputBudget(t *testing.T) {
	data := dsclTestPlist("")
	data += strings.Repeat(" ", dsclOutputBudgetBytes-len(data))
	injectDscl(t, []byte(data), nil)
	if got, err := EnumerateLocalAccounts(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("exact budget must be accepted, error = %v", err)
	}
}

func TestDarwinLocalAccountsCancellationDuringCommand(t *testing.T) {
	original := runDscl
	t.Cleanup(func() { runDscl = original })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDscl = func(context.Context, string, ...string) ([]byte, error) {
		cancel()
		return []byte(dsclTestPlist("")), errors.New("private command detail")
	}
	if got, err := EnumerateLocalAccounts(ctx); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must discard command output and preserve context error, got %v", err)
	}
}

func injectDscl(t *testing.T, data []byte, err error) {
	t.Helper()
	original := runDscl
	t.Cleanup(func() { runDscl = original })
	runDscl = func(context.Context, string, ...string) ([]byte, error) { return data, err }
}

func dsclTestPlist(records string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><array>` + records + `</array></plist>`
}

func dsclTestRecord(name, uid, home, shell string) string {
	return "<dict>" + dsclTestAttribute("RecordName", name) + dsclTestAttribute("UniqueID", uid) + dsclTestAttribute("NFSHomeDirectory", home) + dsclTestAttribute("UserShell", shell) + "</dict>"
}

func dsclTestAttribute(key string, values ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<key>dsAttrTypeStandard:%s</key><array>", key)
	for _, value := range values {
		b.WriteString("<string>")
		if err := xml.EscapeText(&b, []byte(value)); err != nil {
			panic(err)
		}
		b.WriteString("</string>")
	}
	b.WriteString("</array>")
	return b.String()
}

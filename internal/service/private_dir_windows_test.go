//go:build windows && native

package service

import (
	"aegishook/internal/core"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDescriptorT2(t *testing.T) {
	for _, c := range []struct {
		name, sddl               string
		private, directory, good bool
	}{
		{"private inherited admins", "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true, true, true},
		{"private alternate equivalent", "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", true, false, true},
		{"private inherit-only Users read", "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FR;;;BU)", true, true, false},
		{"public inherit-only Users read", "O:SYD:P(A;OICI;FA;;;SY)(A;OICIIO;FR;;;BU)", false, true, true},
		{"deny before allow", "O:SYD:P(A;;FA;;;SY)(D;;FR;;;BU)(A;;FR;;;BU)", true, false, true},
		{"allow before deny", "O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)(D;;FR;;;BU)", true, false, false},
		{"partial deny", "O:SYD:P(A;;FA;;;SY)(D;;0x1;;;BU)(A;;FR;;;BU)", true, false, false},
		{"different SID deny", "O:SYD:P(A;;FA;;;SY)(D;;FR;;;WD)(A;;FR;;;BU)", true, false, false},
		{"inherit-only deny not effective", "O:SYD:P(A;;FA;;;SY)(D;OIIO;FR;;;BU)(A;;FR;;;BU)", true, true, false},
		{"effective deny not inherited", "O:SYD:P(A;OICI;FA;;;SY)(D;;FR;;;BU)(A;OIIO;FR;;;BU)", true, true, false},
		{"inherited deny before allow", "O:SYD:P(A;OICI;FA;;;SY)(D;OICIIO;FR;;;BU)(A;OICIIO;FR;;;BU)", true, true, true},
		{"object deny not container deny", "O:SYD:P(A;OICI;FA;;;SY)(D;OIIO;FR;;;BU)(A;CIIO;FR;;;BU)", true, true, false},
		{"nonpropagating deny not transitive", "O:SYD:P(A;OICI;FA;;;SY)(D;OICINPIO;FR;;;BU)(A;OICIIO;FR;;;BU)", true, true, false},
		{"generic deny covers specific read", "O:SYD:P(A;;FA;;;SY)(D;;GR;;;BU)(A;;FR;;;BU)", true, false, true},
		{"specific deny covers generic read", "O:SYD:P(A;;FA;;;SY)(D;;FR;;;BU)(A;;GR;;;BU)", true, false, true},
		{"unsupported object ACE", "O:SYD:P(OA;;FR;00000000-0000-0000-0000-000000000001;;BU)", true, false, false},
		{"ordinary read", "O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)", true, false, false},
		{"ordinary write", "O:SYD:P(A;;FA;;;SY)(A;;FW;;;BU)", true, false, false},
		{"public read", "O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)", false, true, true},
		{"ProgramData create only", "O:SYD:P(A;;FA;;;SY)(A;;0x4;;;BU)", false, true, true},
		{"parent delete child", "O:SYD:P(A;;FA;;;SY)(A;;0x40;;;BU)", false, true, false},
		{"foreign owner", "O:BUD:P(A;;FA;;;SY)", true, true, false},
		{"null dacl", "O:SYD:NO_ACCESS_CONTROL", true, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(c.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateWindowsDescriptor(sd, c.private, c.directory); (err == nil) != c.good {
				t.Fatalf("validation = %v; want accepted %v", err, c.good)
			}
		})
	}
}

func TestNativeWindowsPrivateDirT2OrdinaryUserDenied(t *testing.T) {
	root := nativeMachineRoot(t)
	if os.Getenv("TG_SENTRY_NATIVE_ROLE") != "OTHER" {
		t.Skip("NOT RUN: T2 access denial must execute as the ordinary OTHER Windows fixture")
	}
	p := core.MachinePaths(root)
	// Gate B provisions canary-only fixtures. Never read any credential bytes.
	for _, path := range []string{p.Code, p.Enrolled, p.Connection, p.Rollback, filepath.Join(p.Private, ".native-temp")} {
		for _, access := range []uint32{windows.GENERIC_READ, windows.GENERIC_WRITE, windows.FILE_READ_DATA, windows.FILE_WRITE_DATA} {
			assertNativeFixtureOpen(t, path, access, false)
		}
	}
}

// Gate B runs SYSTEM first, then OTHER against the same canary-only root.
// The unsafe fixture proves the inherited-read exploit without touching secrets;
// the accepted private descriptor must protect both creation and atomic replacement.
func TestNativeWindowsPrivateInheritanceT2(t *testing.T) {
	root := nativeMachineRoot(t)
	fixture := filepath.Join(root, ".native-acl-regression")
	switch os.Getenv("TG_SENTRY_NATIVE_ROLE") {
	case "SYSTEM":
		requireNativeSystem(t)
		setNativeFixtureDACL(t, fixture, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FRFX;;;BU)")
		for _, kind := range []string{"unsafe", "private"} {
			dir := filepath.Join(fixture, kind)
			sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
			if kind == "unsafe" {
				sddl += "(A;OICIIO;FR;;;BU)"
			}
			setNativeFixtureDACL(t, dir, sddl)
			if err := validateWindowsPath(dir, true); (err == nil) != (kind == "private") {
				t.Fatalf("%s descriptor validation = %v", kind, err)
			}
			for _, name := range []string{"created", "replaced"} {
				path := filepath.Join(dir, name)
				if err := core.AtomicFile(path, []byte("native canary"), 0600); err != nil {
					t.Fatal(err)
				}
				if name == "replaced" {
					if err := core.AtomicFile(path, []byte("replacement canary"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		path := filepath.Join(fixture, "narrow-read-control")
		if err := core.AtomicFile(path, []byte("native canary"), 0600); err != nil {
			t.Fatal(err)
		}
		setNativeFixtureDACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1;;;BU)")
	case "OTHER":
		for _, name := range []string{"created", "replaced"} {
			assertNativeFixtureOpen(t, filepath.Join(fixture, "unsafe", name), windows.FILE_READ_DATA, true)
			for _, access := range []uint32{windows.GENERIC_READ, windows.GENERIC_WRITE, windows.FILE_READ_DATA, windows.FILE_WRITE_DATA} {
				assertNativeFixtureOpen(t, filepath.Join(fixture, "private", name), access, false)
			}
		}
		path := filepath.Join(fixture, "narrow-read-control")
		assertNativeFixtureOpen(t, path, windows.GENERIC_READ, false)
		assertNativeFixtureOpen(t, path, windows.FILE_WRITE_DATA, false)
		assertNativeFixtureOpen(t, path, windows.FILE_READ_DATA, true)
	default:
		t.Skip("NOT RUN: requires the SYSTEM then ordinary OTHER Windows fixtures")
	}
}

func setNativeFixtureDACL(t *testing.T, path, sddl string) {
	t.Helper()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func assertNativeFixtureOpen(t *testing.T, path string, access uint32, allowed bool) {
	t.Helper()
	// NtCreateFile requests exactly these rights; Win32 CreateFile may add
	// SYNCHRONIZE/FILE_READ_ATTRIBUTES and miss a FILE_READ_DATA-only leak.
	// x/sys/windows/syscall_windows_test.go: TestNtCreateFileAndNtSetInformationFile.
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile
	name, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		t.Fatal(err)
	}
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &oa, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, 0, 0, 0)
	if status, ok := err.(windows.NTStatus); ok {
		err = status.Errno()
	}
	if err == nil {
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatal(err)
		}
	}
	if (err == nil) != allowed || (!allowed && !errors.Is(err, windows.ERROR_ACCESS_DENIED)) {
		t.Fatalf("canary open %s access=%#x allowed=%v: %v", path, access, allowed, err)
	}
}

func TestWindowsPrivatePathRejectsReparseT2(t *testing.T) {
	requireNativeSystem(t)
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "private")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("native SYSTEM runner must support reparse fixture", err)
	}
	if validateWindowsPath(link, true) == nil {
		t.Fatal("reparse point accepted")
	}
}

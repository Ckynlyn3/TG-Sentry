//go:build windows

package service

import (
	"aegishook/internal/core"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() { core.ValidateMachinePath = validateWindowsPath }

// SHGetKnownFolderPath resolves the system location, not caller-controlled env.
// https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
func validWindowsMachineRoot(root string) bool {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	return err == nil && validWindowsRoot(root) && strings.EqualFold(root, filepath.Join(programData, "TG-Sentry"))
}

func validWindowsRoot(root string) bool {
	volume := filepath.VolumeName(root)
	return filepath.IsAbs(root) && filepath.Clean(root) == root && len(volume) == len("C:") &&
		!strings.HasPrefix(volume, `\`) && root != volume+string(filepath.Separator)
}

func validateDaemonPaths(root string, validate func(string, bool) error) error {
	if !validWindowsRoot(root) {
		return errors.New("machine root must be a clean local absolute non-root directory")
	}
	if err := validatePublicChain(root, validate); err != nil {
		return err
	}
	return filepath.WalkDir(core.MachinePaths(root).Private, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return validate(path, true)
	})
}

func validatePublicChain(path string, validate func(string, bool) error) error {
	for dir := path; ; dir = filepath.Dir(dir) {
		if err := validate(dir, false); err != nil {
			return err
		}
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			return errors.New("machine ancestor must be a real directory")
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

// CreateFileW, dwFlagsAndAttributes: inspect the link itself, not its target.
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
func validateWindowsPath(path string, private bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("machine path must not be a reparse point or special file")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return validateWindowsDescriptor(sd, private, info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0)
}

func administratorSID(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func trustedFilesystemSID(sid *windows.SID, private bool) bool {
	if administratorSID(sid) {
		return true
	}
	// Windows Resource Protection owns OS ancestors as TrustedInstaller, not the
	// application private directory. Resolve the OS service SID; never trust names
	// supplied by a client. Microsoft: "About Windows Resource Protection".
	if !private && sid != nil {
		installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
		return err == nil && sid.Equals(installer)
	}
	return false
}

// GetSecurityInfo + GetAce inspect binary rights rather than comparing SDDL
// text. Inheritance, ACE ordering and narrower admin grants may differ. Unknown
// ACE forms fail closed; this endpoint does not rewrite or "repair" foreign ACLs.
// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace
func validateWindowsDescriptor(sd *windows.SECURITY_DESCRIPTOR, private, directory bool) error {
	owner, _, err := sd.Owner()
	if err != nil || !trustedFilesystemSID(owner, private) {
		return errors.New("machine path has an untrusted owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("machine path requires a non-null DACL")
	}
	// Keep effective, direct child-file/directory, and propagating file/directory
	// scopes separate: an effective-only or non-propagating deny is not enough
	// to cover an allow inherited by further descendants.
	// https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules
	denied := map[string][5]uint32{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if (ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE) ||
			ace.Header.AceFlags & ^byte(windows.VALID_INHERIT_FLAGS) != 0 {
			return errors.New("unsupported machine access-control entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trustedFilesystemSID(sid, private) {
			continue
		}
		key, mask := sid.String(), filesystemRights(uint32(ace.Mask))
		prior := denied[key]
		files := private && directory && ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0
		dirs := private && directory && ace.Header.AceFlags&windows.CONTAINER_INHERIT_ACE != 0
		propagates := ace.Header.AceFlags&windows.NO_PROPAGATE_INHERIT_ACE == 0
		scopes := [5]bool{ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0, files, dirs, files && propagates, dirs && propagates}
		for scope, applies := range scopes {
			if !applies {
				continue
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				prior[scope] |= mask
			} else if unsafeFilesystemRights(mask, private, directory) && mask & ^prior[scope] != 0 {
				return errors.New("machine path grants access to non-administrators")
			}
		}
		// Only earlier simple denies for this exact SID can cover an allow.
		// https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object
		denied[key] = prior
	}
	return nil
}

// FILE_DELETE_CHILD is a WinNT.h constant not exported by x/sys v0.48.0.
const fileDeleteChild = 0x40

// File generic-rights mapping from WinNT.h / FILE_GENERIC_* in x/sys.
// https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
func filesystemRights(mask uint32) uint32 {
	for _, mapping := range []struct{ generic, specific uint32 }{
		{windows.GENERIC_READ, windows.FILE_GENERIC_READ},
		{windows.GENERIC_WRITE, windows.FILE_GENERIC_WRITE},
		{windows.GENERIC_EXECUTE, windows.FILE_GENERIC_EXECUTE},
		{windows.GENERIC_ALL, windows.STANDARD_RIGHTS_ALL | windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | fileDeleteChild},
	} {
		if mask&mapping.generic != 0 {
			mask = mask & ^mapping.generic | mapping.specific
		}
	}
	return mask
}

func unsafeFilesystemRights(mask uint32, private, directory bool) bool {
	if private {
		return mask != 0
	}
	// ProgramData's create-file/create-directory grants are normal. They do not
	// permit replacement of an existing protected child; DELETE_CHILD does.
	// https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild |
		windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	if !directory {
		dangerous |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	return mask&dangerous != 0
}

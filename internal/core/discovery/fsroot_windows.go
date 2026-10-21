//go:build windows

package discovery

import "os"

// Unix UID validation does not apply to Windows SIDs. os.Root enforces Windows
// reparse-point confinement; OpenRegular separately validates the opened handle.
func homeOwnerMatches(_ os.FileInfo, _ string) bool { return true }
func readOnlyFlags() int                            { return os.O_RDONLY }

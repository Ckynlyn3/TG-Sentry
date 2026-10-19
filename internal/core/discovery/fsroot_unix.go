//go:build unix

package discovery

import (
	"os"
	"strconv"
	"syscall"
)

// OpenSSH StrictModes checks home ownership; plan R1 requires the enumerated UID
// exactly (not OpenSSH's additional root-owner allowance).
func homeOwnerMatches(info os.FileInfo, accountID string) bool {
	uid, err := strconv.ParseUint(accountID, 10, 32)
	stat, ok := info.Sys().(*syscall.Stat_t)
	return err == nil && ok && stat != nil && uint64(stat.Uid) == uid
}

// POSIX open(2), O_NONBLOCK: a read-only FIFO open returns without delay; regular
// files are unaffected. The opened handle is type-checked before any read.
// https://pubs.opengroup.org/onlinepubs/007904875/functions/open.html
func readOnlyFlags() int { return os.O_RDONLY | syscall.O_NONBLOCK }

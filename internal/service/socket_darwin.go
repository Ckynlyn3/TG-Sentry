package service

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var lookupErr error
	err = raw.Control(func(fd uintptr) {
		// getpeereid(3), via the existing x/sys LOCAL_PEERCRED wrapper.
		// https://github.com/golang/sys/blob/v0.48.0/unix/syscall_darwin.go
		cred, lookupErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil || lookupErr != nil || cred == nil || cred.Version != 0 {
		return 0, errors.New("kernel peer identity unavailable")
	}
	return cred.Uid, nil
}

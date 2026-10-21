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
	var cred *unix.Ucred
	var lookupErr error
	err = raw.Control(func(fd uintptr) {
		// unix(7), SO_PEERCRED: credentials captured by the kernel at connect.
		// https://man7.org/linux/man-pages/man7/unix.7.html
		cred, lookupErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || lookupErr != nil || cred == nil {
		return 0, errors.New("kernel peer identity unavailable")
	}
	return cred.Uid, nil
}

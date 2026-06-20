//go:build linux

package server

import (
	"net"
	"syscall"
)

// peerUID returns the UID of the process on the other end of uc, via
// getsockopt(SO_PEERCRED). Kernel-verified — the peer can't forge it.
func peerUID(uc *net.UnixConn) (uint32, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cred    *syscall.Ucred
		credErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

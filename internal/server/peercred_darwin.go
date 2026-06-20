//go:build darwin

package server

import (
	"net"
	"syscall"
	"unsafe"
)

// macOS peer-credential socket options (from <sys/un.h> / <sys/socket.h>).
const (
	sysSOL_LOCAL      = 0 // SOL_LOCAL
	sysLOCAL_PEERCRED = 1 // LOCAL_PEERCRED
)

// xucred mirrors struct xucred from <sys/ucred.h>. Layout/size (76 bytes) must
// match the C struct exactly, since getsockopt copies into it directly.
type xucred struct {
	version uint32     // cr_version (XUCRED_VERSION == 0)
	uid     uint32     // cr_uid — the effective uid of the peer
	ngroups int16      // cr_ngroups
	groups  [16]uint32 // cr_groups[NGROUPS]
}

// peerUID returns the effective UID of the process on the other end of uc, via
// getsockopt(LOCAL_PEERCRED). Kernel-verified — the peer can't forge it.
func peerUID(uc *net.UnixConn) (uint32, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cred    xucred
		size    = uint32(unsafe.Sizeof(cred))
		callErr syscall.Errno
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		_, _, callErr = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(sysSOL_LOCAL),
			uintptr(sysLOCAL_PEERCRED),
			uintptr(unsafe.Pointer(&cred)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if callErr != 0 {
		return 0, callErr
	}
	return cred.uid, nil
}

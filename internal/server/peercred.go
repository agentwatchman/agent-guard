package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
)

// errPeerCredUnsupported is returned by peerUID on platforms where we can't read
// the connecting process's credentials (e.g. Windows). On those platforms the
// 0600 socket permissions remain the access control; we don't fail closed and
// break the daemon over a missing syscall.
var errPeerCredUnsupported = errors.New("peer credential check unsupported on this platform")

// peerCredListener wraps a Unix-domain listener and rejects any connection whose
// peer process is NOT running as the same UID as the daemon.
//
// This is the trust boundary between the AI agent and the daemon. The 0600
// socket mode already restricts access to the owning user, but the peer-UID
// check is kernel-verified (LOCAL_PEERCRED on macOS, SO_PEERCRED on Linux) and
// can't be spoofed by the connecting process — so it holds even if the socket
// mode is ever loosened, the socket dir is group-shared, etc. Defense in depth.
type peerCredListener struct {
	net.Listener
	log *slog.Logger
}

// newPeerCredListener wraps ln so every accepted connection is peer-UID checked.
func newPeerCredListener(ln net.Listener, log *slog.Logger) net.Listener {
	return &peerCredListener{Listener: ln, log: log}
}

// Accept returns the next connection whose peer passes the UID check, silently
// dropping (and logging) any that don't. http.Server keeps calling Accept, so
// rejecting a bad peer never tears down the listener.
func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if verr := verifyPeer(c); verr != nil {
			if l.log != nil {
				l.log.Warn("rejected socket connection", "err", verr)
			}
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// verifyPeer enforces that the connection's peer runs as the daemon's UID.
// Returns nil (allow) for non-Unix conns or platforms that can't read creds.
func verifyPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil // not a unix socket — nothing to verify
	}
	uid, err := peerUID(uc)
	if errors.Is(err, errPeerCredUnsupported) {
		return nil // can't verify here; rely on 0600 socket perms
	}
	if err != nil {
		return fmt.Errorf("reading peer credentials: %w", err)
	}
	if self := uint32(os.Getuid()); uid != self {
		return fmt.Errorf("peer uid %d != daemon uid %d", uid, self)
	}
	return nil
}

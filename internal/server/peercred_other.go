//go:build !darwin && !linux

package server

import "net"

// peerUID is unsupported on this platform (e.g. Windows). verifyPeer treats the
// sentinel as "can't verify" and falls back to the 0600 socket permissions.
func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, errPeerCredUnsupported
}

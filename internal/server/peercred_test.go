//go:build darwin || linux

package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortSock returns a short socket path. Unix socket paths are capped (~104
// bytes on macOS), and t.TempDir() embeds the (long) test name, so we use a
// short os.MkdirTemp dir instead to stay under the limit.
func shortSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// dialAccept sets up a unix listener at a temp path, dials it, and returns the
// server-side accepted conn plus the client conn.
func dialAccept(t *testing.T, ln net.Listener, sock string) (net.Conn, net.Conn) {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	select {
	case r := <-accepted:
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		return r.c, client
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept")
		return nil, nil
	}
}

// TestPeerUIDMatchesSelf verifies the platform getsockopt path returns this
// process's own UID for a loopback unix connection.
func TestPeerUIDMatchesSelf(t *testing.T) {
	sock := shortSock(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvConn, cliConn := dialAccept(t, ln, sock)
	defer srvConn.Close()
	defer cliConn.Close()

	uc, ok := srvConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("accepted conn is %T, want *net.UnixConn", srvConn)
	}
	uid, err := peerUID(uc)
	if err != nil {
		t.Fatalf("peerUID: %v", err)
	}
	if want := uint32(os.Getuid()); uid != want {
		t.Fatalf("peerUID = %d, want %d", uid, want)
	}
}

// TestPeerCredListenerAcceptsSameUID confirms a same-user connection passes the
// wrapped listener's check end to end (we are necessarily the same UID here).
func TestPeerCredListenerAcceptsSameUID(t *testing.T) {
	sock := shortSock(t)
	raw, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := newPeerCredListener(raw, nil)
	defer ln.Close()

	srvConn, cliConn := dialAccept(t, ln, sock)
	defer srvConn.Close()
	defer cliConn.Close()

	if srvConn == nil {
		t.Fatal("expected a connection to be accepted for same-uid peer")
	}
}

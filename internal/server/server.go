// Package server runs AgentGuard's local policy daemon: a Unix-domain-socket
// HTTP server that evaluates tool calls (/v1/evaluate) and scans prompts for
// secrets (/v1/scan), writing a redacted audit record for each decision.
package server

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"agentguard/internal/audit"
	"agentguard/internal/policy"
	"agentguard/internal/scan"
	"agentguard/internal/types"
)

// Daemon holds the running daemon's state: the hot-swappable policy config and
// the audit logger. Bundling it in a struct (rather than package globals) keeps
// the state explicit, lets handlers be methods, and makes the daemon testable.
type Daemon struct {
	cfgMu sync.RWMutex
	cfg   types.Config
	audit *audit.Logger
}

// Run starts the daemon on a Unix domain socket. No TCP port means nothing to
// conflict with another process; only this user can reach it (0600).
func Run(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config.json", "path to policy config")
	_ = fs.Parse(args)

	d := &Daemon{}
	if err := d.loadConfig(*cfgPath); err != nil {
		log.Fatalf("failed to load config %s: %v", *cfgPath, err)
	}

	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentguard", "audit.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	if l, err := audit.Open(logPath); err != nil {
		log.Printf("warning: could not open audit log: %v", err)
	} else {
		d.audit = l
		defer d.audit.Close()
	}

	sock := types.SocketPath()
	_ = os.MkdirAll(filepath.Dir(sock), 0o755)
	_ = os.Remove(sock) // clear any stale socket from a previous crash
	ln, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatalf("failed to listen on socket %s: %v", sock, err)
	}
	_ = os.Chmod(sock, 0o600) // restrict to the current user
	defer os.Remove(sock)

	// Clean up the socket file on SIGINT/SIGTERM (launchd sends SIGTERM).
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		_ = os.Remove(sock)
		os.Exit(0)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evaluate", d.handleEvaluate)
	mux.HandleFunc("/v1/scan", d.handleScan)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	log.Printf("AgentGuard listening on unix socket %s", sock)
	log.Printf("audit log: %s", logPath)
	log.Printf("inline scanner: builtin + kingfisherd (if running)")
	log.Fatal(srv.Serve(ln))
}

// loadConfig reads the policy config from disk and swaps it in under the lock.
func (d *Daemon) loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c types.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	d.cfgMu.Lock()
	d.cfg = c
	d.cfgMu.Unlock()
	return nil
}

// config returns a snapshot of the current policy config.
func (d *Daemon) config() types.Config {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg
}

// maxRequestBytes caps the size of a hook/scan request body. Hook events are
// tiny and even a large prompt is well under this; the limit just stops a
// malformed or hostile client from forcing the daemon to buffer unbounded input.
const maxRequestBytes = 1 << 20 // 1 MiB

// decodeJSON reads a size-capped request body into dst, replying 400 on any
// error (malformed JSON or a body over maxRequestBytes). Returns false if the
// caller should stop.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func (d *Daemon) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var e types.HookEvent
	if !decodeJSON(w, r, &e) {
		return
	}

	resp := policy.Evaluate(d.config(), e)
	d.audit.Evaluate(e, resp)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (d *Daemon) handleScan(w http.ResponseWriter, r *http.Request) {
	var req types.ScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// scan.ScanAll runs the always-on builtin scanner plus the resident
	// kingfisherd (if up) and merges every finding, so a multi-secret prompt is
	// fully reported. A resident error is ignored, so the hot path never blocks.
	res := scan.ScanAll(req)
	d.audit.Scan(res, req.Agent)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

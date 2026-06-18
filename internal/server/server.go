// Package server runs AgentGuard's local policy daemon: a Unix-domain-socket
// HTTP server that evaluates tool calls (/v1/evaluate) and scans prompts for
// secrets (/v1/scan), writing a redacted audit record for each decision.
package server

import (
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
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

// Daemon holds the running daemon's state: the hot-swappable policy config, the
// audit logger, a structured logger, and aggregate counters. Bundling it in a
// struct (rather than package globals) keeps the state explicit, lets handlers
// be methods, and makes the daemon testable.
type Daemon struct {
	cfgMu sync.RWMutex
	cfg   types.Config
	audit *audit.Logger
	log   *slog.Logger
	met   metrics
}

// logger returns the daemon's structured logger, falling back to the default.
func (d *Daemon) logger() *slog.Logger {
	if d.log != nil {
		return d.log
	}
	return slog.Default()
}

// Run starts the daemon on a Unix domain socket. No TCP port means nothing to
// conflict with another process; only this user can reach it (0600).
func Run(args []string) {
	home, _ := os.UserHomeDir()
	defaultCfg := filepath.Join(home, ".agentguard", "config.json")

	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultCfg, "path to policy config")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	d := &Daemon{log: logger}
	if err := d.loadConfig(*cfgPath); err != nil {
		logger.Error("failed to load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}

	logPath := filepath.Join(home, ".agentguard", "audit.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	if l, err := audit.Open(logPath); err != nil {
		logger.Warn("could not open audit log", "err", err)
	} else {
		d.audit = l
		defer d.audit.Close()
	}

	sock := types.SocketPath()
	_ = os.MkdirAll(filepath.Dir(sock), 0o755)
	_ = os.Remove(sock) // clear any stale socket from a previous crash
	ln, err := net.Listen("unix", sock)
	if err != nil {
		logger.Error("failed to listen on socket", "socket", sock, "err", err)
		os.Exit(1)
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

	// Hot-reload the policy config two ways, both without dropping the socket:
	//  - automatically, by watching the file for edits (the common case), and
	//  - on SIGHUP, for scripted reloads (`make service-reload`).
	// On a bad config we keep the previous one rather than failing open/crashing.
	go d.watchConfig(*cfgPath)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			d.reload(*cfgPath, "SIGHUP")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evaluate", d.handleEvaluate)
	mux.HandleFunc("/v1/scan", d.handleScan)
	mux.HandleFunc("/metrics", d.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	logger.Info("AgentGuard daemon started",
		"socket", sock,
		"config", *cfgPath,
		"audit_log", logPath,
		"scanner", "builtin + kingfisherd (if running)",
		"reload", "auto (file watch) + SIGHUP",
	)
	if err := srv.Serve(ln); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// loadConfig reads the policy config from disk and swaps it in under the lock.
// If the file doesn't exist yet (fresh machine, no installer run), it seeds a
// sensible default so the daemon is usable out of the box and the user has a
// file to edit.
func (d *Daemon) loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		b = defaultConfigJSON()
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if werr := os.WriteFile(path, b, 0o644); werr != nil {
			d.logger().Warn("could not seed default config", "path", path, "err", werr)
		} else {
			d.logger().Info("seeded default config", "path", path)
		}
	} else if err != nil {
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

// reload re-reads the config, logging the outcome and the trigger. A bad config
// is logged and ignored so the daemon keeps running on the last good policy.
func (d *Daemon) reload(path, trigger string) {
	if err := d.loadConfig(path); err != nil {
		d.logger().Error("config reload failed (keeping previous config)", "trigger", trigger, "err", err)
	} else {
		d.logger().Info("config reloaded", "trigger", trigger, "path", path)
	}
}

// watchConfig polls the config file's modification time + size and hot-reloads
// on any change, so editing the config takes effect within a couple of seconds
// with no command to run. Polling (vs. fsnotify) keeps us dependency-free and
// handles editors that save via atomic rename, which would break a file watch.
func (d *Daemon) watchConfig(path string) {
	lastMod, lastSize := statSig(path)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		mod, size := statSig(path)
		if mod.Equal(lastMod) && size == lastSize {
			continue
		}
		lastMod, lastSize = mod, size
		d.reload(path, "file-change")
	}
}

// statSig returns the file's modification time and size, or zero values if it
// can't be stat'd (e.g. mid-rename); a transient miss just defers the reload.
func statSig(path string) (time.Time, int64) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, 0
	}
	return fi.ModTime(), fi.Size()
}

// defaultConfigJSON is the built-in starter policy used to seed a missing config
// file. Keep it in sync with the repo's config.json (the installer's copy).
func defaultConfigJSON() []byte {
	c := types.Config{
		AllowedEgress: []string{"github.com", "api.github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"},
		ApprovedMCP:   []string{"github", "linear"},
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return append(b, '\n')
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

	dec := policy.EvaluateDetailed(d.config(), e)
	resp := dec.Response
	// Some hook surfaces (e.g. Cursor's preToolUse) can't render an "ask" prompt;
	// the handler that knows this sets ClientCannotAsk, so we downgrade to a
	// definitive deny and record the decision we actually enforce.
	if e.ClientCannotAsk && resp.HookSpecificOutput.PermissionDecision == types.Ask {
		resp = types.Decide(types.Deny, resp.HookSpecificOutput.PermissionDecisionReason)
	}
	d.met.recordEvaluate(resp.HookSpecificOutput.PermissionDecision)
	d.audit.Evaluate(e, resp, dec.RuleID, dec.Severity)

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
	d.met.recordScan(res.Found)
	d.audit.Scan(res, req.Agent)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

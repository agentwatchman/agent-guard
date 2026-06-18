// AgentGuard MVP — local-first runtime guardrails for AI coding agents.
//
// Runs as a local daemon that listens on a Unix domain socket (no TCP port, so
// nothing to conflict with). Both Claude Code and Cursor are wired via
// command-type hooks that spawn this binary, which forwards the tool call to the
// daemon over the socket and returns allow / deny / ask. Nothing leaves the
// machine: the raw command is evaluated locally, and only a redacted one-line
// record is written to a local audit log. Pilot build — no cloud, no tenancy.
//
// Commands:
//   agentguard [serve] [--config ...]                 run the daemon (default)
//   agentguard install-hooks   [--claude] [--cursor]  wire AI agents to the daemon
//   agentguard uninstall-hooks [--claude] [--cursor]  remove our hook entries
//   agentguard claude-hook                            Claude Code hook handler (stdin/stdout)
//   agentguard cursor-hook                            Cursor hook handler (stdin/stdout)
//   agentguard version
//
// NOTE: the exact hook request/response schema evolves — verify against
// https://code.claude.com/docs/en/hooks before a wide rollout.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const version = "0.1.0"

var (
	cfg     Config
	cfgMu   sync.RWMutex
	auditFp *os.File
)

func main() {
	args := os.Args[1:]

	// First non-flag arg selects a subcommand; otherwise default to `serve`
	// (keeps `agentguard --config ...` working for backwards compatibility).
	cmd := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "", "serve":
		serve(args)
	case "install-hooks":
		mustRun(cmdInstallHooks(args))
	case "uninstall-hooks":
		mustRun(cmdUninstallHooks(args))
	case "claude-hook":
		claudeHook()
	case "cursor-hook":
		cursorHook()
	case "scan":
		cmdScan(args)
	case "version":
		fmt.Println("agentguard", version)
	case "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "agentguard: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `agentguard — runtime guardrails for AI coding agents

Usage:
  agentguard [serve] [--config path]                run the daemon (default; Unix socket)
  agentguard install-hooks   [--claude] [--cursor]  wire Claude Code / Cursor to the daemon
  agentguard uninstall-hooks [--claude] [--cursor]  remove AgentGuard hook entries
  agentguard claude-hook                            Claude Code hook handler (reads stdin)
  agentguard cursor-hook                            Cursor hook handler (reads stdin)
  agentguard scan [file|-]                          secret scan (builtin + kingfisherd); reads file or stdin
  agentguard version

With no --claude/--cursor flag, install-hooks/uninstall-hooks auto-detect which
agents are installed (~/.claude, ~/.cursor) and configure those.
`)
}

func mustRun(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard:", err)
		os.Exit(1)
	}
}

// serve runs the local policy daemon on a Unix domain socket. No TCP port means
// nothing to conflict with another process; only this user can reach it (0600).
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config.json", "path to policy config")
	_ = fs.Parse(args)

	if err := loadConfig(*cfgPath); err != nil {
		log.Fatalf("failed to load config %s: %v", *cfgPath, err)
	}

	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentguard", "audit.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	if fp, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		log.Printf("warning: could not open audit log: %v", err)
	} else {
		auditFp = fp
		defer fp.Close()
	}

	sock := socketPath()
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
	mux.HandleFunc("/v1/evaluate", handleEvaluate)
	mux.HandleFunc("/v1/scan", handleScan)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	log.Printf("AgentGuard listening on unix socket %s", sock)
	log.Printf("audit log: %s", logPath)
	log.Printf("inline scanner: builtin (fast path; use `agentguard scan` for Kingfisher deep scans)")
	log.Fatal(srv.Serve(ln))
}

// cmdScan is an explicit, on-demand scan (CI / manual audits). It runs the same
// union as the inline path — the builtin scanner plus the resident kingfisherd
// (if running) — and reports every finding. Reads a file path or stdin.
// Exit codes mirror common scanners: 0 = clean, 200 = secret found.
func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	_ = fs.Parse(args)

	var text string
	if rest := fs.Args(); len(rest) > 0 && rest[0] != "-" {
		b, err := os.ReadFile(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "agentguard scan:", err)
			os.Exit(2)
		}
		text = string(b)
	} else {
		b, _ := io.ReadAll(os.Stdin)
		text = string(b)
	}

	reportScan(scanAll(ScanRequest{Text: text}))
}

func reportScan(res ScanResult) {
	if res.Found {
		fmt.Println(res.Reason)
		for _, f := range res.Findings {
			fmt.Printf("  - [%s] %s\n", f.Source, f.Rule)
		}
		os.Exit(200)
	}
	fmt.Println("no secrets found")
}

func loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	cfgMu.Lock()
	cfg = c
	cfgMu.Unlock()
	return nil
}

func handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var e HookEvent
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()

	resp := Evaluate(c, e)
	writeAudit(e, resp)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res := scanAll(req)
	writeScanAudit(res, req.Agent)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func writeScanAudit(res ScanResult, agent string) {
	if auditFp == nil {
		return
	}
	decision := "allow"
	if res.Found {
		decision = "deny"
	}
	rec := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339),
		"tool":     "Prompt",
		"decision": decision,
		"reason":   res.Reason,
		"session":  "",
	}
	if agent != "" {
		rec["agent"] = agent // "claude-code" or "cursor"
	}
	if res.Source != "" {
		rec["source"] = res.Source // "builtin" or "kingfisher" (first finding)
	}
	if res.Rule != "" {
		rec["rule"] = res.Rule // first finding's rule
	}
	if len(res.Findings) > 0 {
		rec["findings"] = res.Findings // every secret detected, with source+rule
	}
	line, _ := json.Marshal(rec)
	fmt.Fprintln(auditFp, string(line))
}

// writeAudit appends a redacted, one-line JSON record.
// IMPORTANT: it logs the decision + reason only — never the raw command,
// file contents, or any secret value.
func writeAudit(e HookEvent, resp HookResponse) {
	if auditFp == nil {
		return
	}
	rec := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339),
		"tool":     e.ToolName,
		"decision": resp.HookSpecificOutput.PermissionDecision,
		"reason":   resp.HookSpecificOutput.PermissionDecisionReason,
		"session":  e.SessionID,
	}
	if e.Agent != "" {
		rec["agent"] = e.Agent // "claude-code" or "cursor"
	}
	line, _ := json.Marshal(rec)
	fmt.Fprintln(auditFp, string(line))
}

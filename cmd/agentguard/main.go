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
//   agentguard [serve] [--config ...]                          run the daemon (default)
//   agentguard install-hooks   [--claude] [--cursor] [--codex]  wire AI agents to the daemon
//   agentguard uninstall-hooks [--claude] [--cursor] [--codex]  remove our hook entries
//   agentguard claude-hook                                     Claude Code hook handler (stdin/stdout)
//   agentguard cursor-hook                                     Cursor hook handler (stdin/stdout)
//   agentguard codex-hook                                      Codex hook handler (stdin/stdout)
//   agentguard scan [file|-]                                   secret scan (builtin + kingfisherd)
//   agentguard version
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"agentguard/internal/hooks"
	"agentguard/internal/scan"
	"agentguard/internal/server"
	"agentguard/internal/types"
)

const version = "0.1.0"

func main() {
	args := os.Args[1:]

	// First non-flag arg selects a subcommand; otherwise default to `serve`
	// (keeps `agentguard --config ...` working for backwards compatibility).
	cmd := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	server.Version = version

	switch cmd {
	case "", "serve":
		server.Run(args)
	case "install-hooks":
		mustRun(hooks.Install(args))
	case "uninstall-hooks":
		mustRun(hooks.Uninstall(args))
	case "scan":
		cmdScan(args)
	case "version":
		fmt.Println("agentguard", version)
	case "help":
		usage(os.Stdout)
	default:
		// Per-agent runtime hook handlers (claude-hook, cursor-hook, …) are
		// resolved from the agent registry rather than enumerated here.
		if run, ok := hooks.HandlerFor(cmd); ok {
			run()
			return
		}
		fmt.Fprintf(os.Stderr, "agentguard: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `agentguard — runtime guardrails for AI coding agents

Usage:
  agentguard [serve] [--config path]                         run the daemon (default; Unix socket)
  agentguard install-hooks   [--claude] [--cursor] [--codex]  wire Claude Code / Cursor / Codex to the daemon
  agentguard uninstall-hooks [--claude] [--cursor] [--codex]  remove AgentGuard hook entries
  agentguard claude-hook                                     Claude Code hook handler (reads stdin)
  agentguard cursor-hook                                     Cursor hook handler (reads stdin)
  agentguard codex-hook                                      Codex hook handler (reads stdin)
  agentguard scan [file|-]                                   secret scan (builtin + kingfisherd); reads file or stdin
  agentguard version

With no --claude/--cursor/--codex flag, install-hooks/uninstall-hooks auto-detect
which agents are installed (~/.claude, ~/.cursor, ~/.codex) and configure those.
`)
}

func mustRun(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard:", err)
		os.Exit(1)
	}
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

	reportScan(scan.ScanAll(types.ScanRequest{Text: text}))
}

func reportScan(res types.ScanResult) {
	if res.Found {
		fmt.Println(res.Reason)
		for _, f := range res.Findings {
			fmt.Printf("  - [%s] %s\n", f.Source, f.Rule)
		}
		os.Exit(200)
	}
	fmt.Println("no secrets found")
}

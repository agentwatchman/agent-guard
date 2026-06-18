// Package hooks wires AI coding agents (Claude Code, Cursor) to the AgentGuard
// daemon: it installs/uninstalls the hook entries in each agent's config and
// provides the runtime handlers those entries invoke.
package hooks

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// markers identify hook entries we own, so install is idempotent and uninstall
// is precise.
const (
	claudeMarker = "claude-hook"
	cursorMarker = "cursor-hook"
	codexMarker  = "codex-hook"
)

func claudeSettingsPath(home string) string { return filepath.Join(home, ".claude", "settings.json") }
func cursorHooksPath(home string) string    { return filepath.Join(home, ".cursor", "hooks.json") }
func codexHooksPath(home string) string     { return filepath.Join(home, ".codex", "hooks.json") }

// ---- install / uninstall commands ------------------------------------------

// Install wires the detected (or flag-selected) agents to the daemon. self is
// resolved from the running executable.
func Install(args []string) error {
	sel, auto, err := selectAgents("install-hooks", args)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.Abs(self)

	for _, a := range sel {
		p := a.configPath(home)
		if auto && !dirExists(filepath.Dir(p)) {
			fmt.Printf("%s not detected (%s missing) — skipping\n", a.Label, filepath.Dir(p))
			continue
		}
		if err := a.install(p, self); err != nil {
			return fmt.Errorf("%s: %w", a.Label, err)
		}
		fmt.Printf("installed %s %s -> %s\n", a.Label, a.installMsg, p)
	}
	fmt.Println("Done. Make sure the daemon is running (brew services start agentguard, or make install).")
	return nil
}

// Uninstall removes AgentGuard's hook entries from the selected agents.
func Uninstall(args []string) error {
	sel, auto, err := selectAgents("uninstall-hooks", args)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	for _, a := range sel {
		p := a.configPath(home)
		if auto && !fileExists(p) {
			fmt.Printf("no %s config found — skipping\n", a.Label)
			continue
		}
		if err := a.uninstall(p); err != nil {
			return fmt.Errorf("%s: %w", a.Label, err)
		}
		fmt.Printf("removed AgentGuard hooks from %s\n", p)
	}
	return nil
}

// selectAgents resolves which registered agents a command should act on. A flag
// is registered per agent (--claude, --cursor, …). With no flag set, ALL agents
// are selected in "auto" mode (callers then only touch agents actually present).
func selectAgents(name string, args []string) (sel []*Agent, auto bool, err error) {
	fset := flag.NewFlagSet(name, flag.ContinueOnError)
	want := make(map[*Agent]*bool, len(agents))
	for _, a := range agents {
		want[a] = fset.Bool(a.Flag, false, "act on "+a.Label+" ("+a.configPath("~")+")")
	}
	if err = fset.Parse(args); err != nil {
		return nil, false, err
	}
	for _, a := range agents { // registry order, deterministic
		if *want[a] {
			sel = append(sel, a)
		}
	}
	if len(sel) == 0 {
		return agents, true, nil
	}
	return sel, false, nil
}

// ---- Claude-format agents: Claude Code (~/.claude/settings.json) and Codex
// (~/.codex/hooks.json) ------------------------------------------------------
//
// Both agents use the same hook wire format — a top-level "hooks" object keyed
// by event (PreToolUse, UserPromptSubmit) with matcher groups of command
// handlers — so the install/uninstall logic is shared and parameterized only by
// the marker that identifies our entries (claude-hook vs codex-hook).

func installClaude(path, self string) error { return installClaudeFormat(path, self, claudeMarker) }
func installCodex(path, self string) error  { return installClaudeFormat(path, self, codexMarker) }
func uninstallClaude(path string) error     { return uninstallClaudeFormat(path, claudeMarker) }
func uninstallCodex(path string) error      { return uninstallClaudeFormat(path, codexMarker) }

func installClaudeFormat(path, self, marker string) error {
	m, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := childObject(m, "hooks")
	cmd := self + " " + marker
	entry := func() map[string]any {
		return map[string]any{"type": "command", "command": cmd, "timeout": 10}
	}

	// Strip any existing AgentGuard entry (incl. legacy HTTP ones) then add the
	// current command hook — idempotent and upgrade-safe.
	// PreToolUse: gate every tool call (allow/deny/ask).
	pre := stripOurs(childArray(hooks, "PreToolUse"), marker)
	pre = append(pre, map[string]any{
		"matcher": "*",
		"hooks":   []any{entry()},
	})
	hooks["PreToolUse"] = pre

	// UserPromptSubmit: scan the prompt text for secrets before it's sent — the
	// analogue of Cursor's beforeSubmitPrompt. (No matcher: not tool-scoped.)
	ups := stripOurs(childArray(hooks, "UserPromptSubmit"), marker)
	ups = append(ups, map[string]any{
		"hooks": []any{entry()},
	})
	hooks["UserPromptSubmit"] = ups

	m["hooks"] = hooks
	return writeJSONObjectAtomic(path, m)
}

func uninstallClaudeFormat(path, marker string) error {
	if !fileExists(path) {
		return nil
	}
	m, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, ok := m["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	for _, ev := range []string{"PreToolUse", "UserPromptSubmit"} {
		kept := stripOurs(childArray(hooks, ev), marker)
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
	if len(hooks) == 0 {
		delete(m, "hooks")
	} else {
		m["hooks"] = hooks
	}
	return writeJSONObjectAtomic(path, m)
}

// stripOurs removes our hooks (matched by marker) from each event entry,
// dropping entries that become empty, and preserves everything we don't own.
func stripOurs(pre []any, marker string) []any {
	kept := make([]any, 0, len(pre))
	for _, entry := range pre {
		em, ok := entry.(map[string]any)
		if !ok {
			kept = append(kept, entry)
			continue
		}
		inner := childArray(em, "hooks")
		filtered := make([]any, 0, len(inner))
		for _, h := range inner {
			if hm, ok := h.(map[string]any); ok && isOurHook(hm, marker) {
				continue
			}
			filtered = append(filtered, h)
		}
		if len(filtered) == 0 {
			continue
		}
		em["hooks"] = filtered
		kept = append(kept, em)
	}
	return kept
}

func hasOurHook(pre []any, marker string) bool {
	for _, entry := range pre {
		em, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, h := range childArray(em, "hooks") {
			if hm, ok := h.(map[string]any); ok && isOurHook(hm, marker) {
				return true
			}
		}
	}
	return false
}

func isOurHook(h map[string]any, marker string) bool {
	cmd, _ := h["command"].(string)
	url, _ := h["url"].(string) // legacy HTTP installs
	return strings.Contains(cmd, marker) || strings.Contains(url, "/v1/evaluate")
}

// ---- Cursor: ~/.cursor/hooks.json ------------------------------------------

// cursorEvents are the hook surfaces we gate. We map cleanly onto these:
//   - preToolUse:           generic gate that fires for ALL tools, so it covers
//     tools without a dedicated hook (WebFetch, Write, Delete, Task, …). Our
//     handler defers Shell/Read to their richer dedicated hooks below. Note
//     Cursor's preToolUse accepts but does not enforce "ask", so the daemon
//     downgrades ask -> deny for it (see ClientCannotAsk).
//   - beforeShellExecution: shell commands (supports allow/deny/ask)
//   - beforeReadFile:       secret/credential file reads (allow/deny)
//   - beforeSubmitPrompt:   ggshield-style scan of the prompt + attached files
//     for secrets (blocks submission). Catches secrets
//     that reach context outside the agent-read path.
//
// beforeMCPExecution is intentionally NOT wired yet — Cursor's MCP payload
// doesn't expose the server name our allowlist needs, so gating it would risk
// false-blocking. Tracked as a follow-up.
var cursorEvents = []string{"preToolUse", "beforeShellExecution", "beforeReadFile", "beforeSubmitPrompt"}

func installCursor(path, self string) error {
	m, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if _, ok := m["version"]; !ok {
		m["version"] = 1
	}
	hooks := childObject(m, "hooks")
	command := self + " " + cursorMarker

	for _, ev := range cursorEvents {
		arr := childArray(hooks, ev)
		if !cursorHasOurHook(arr) {
			// failClosed: block the action if our hook crashes/times out — the
			// secure default Cursor offers (Claude's HTTP hooks can't do this).
			arr = append(arr, map[string]any{
				"command":    command,
				"failClosed": true,
			})
		}
		hooks[ev] = arr
	}
	m["hooks"] = hooks
	return writeJSONObjectAtomic(path, m)
}

func uninstallCursor(path string) error {
	if !fileExists(path) {
		return nil
	}
	m, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, ok := m["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	for _, ev := range cursorEvents {
		arr := childArray(hooks, ev)
		kept := make([]any, 0, len(arr))
		for _, h := range arr {
			if hm, ok := h.(map[string]any); ok && cursorIsOurHook(hm) {
				continue
			}
			kept = append(kept, h)
		}
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
	if len(hooks) == 0 {
		delete(m, "hooks")
	} else {
		m["hooks"] = hooks
	}
	return writeJSONObjectAtomic(path, m)
}

func cursorHasOurHook(arr []any) bool {
	for _, h := range arr {
		if hm, ok := h.(map[string]any); ok && cursorIsOurHook(hm) {
			return true
		}
	}
	return false
}

func cursorIsOurHook(h map[string]any) bool {
	cmd, _ := h["command"].(string)
	return strings.Contains(cmd, cursorMarker)
}

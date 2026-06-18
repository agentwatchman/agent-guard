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
)

func claudeSettingsPath(home string) string { return filepath.Join(home, ".claude", "settings.json") }
func cursorHooksPath(home string) string    { return filepath.Join(home, ".cursor", "hooks.json") }

// ---- install / uninstall commands ------------------------------------------

// Install wires the detected (or flag-selected) agents to the daemon. self is
// resolved from the running executable.
func Install(args []string) error {
	claude, cursor, auto, err := parseAgentFlags("install-hooks", args)
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

	if claude {
		p := claudeSettingsPath(home)
		if auto && !dirExists(filepath.Dir(p)) {
			fmt.Println("Claude Code not detected (~/.claude missing) — skipping")
		} else if err := installClaude(p, self); err != nil {
			return fmt.Errorf("Claude Code: %w", err)
		} else {
			fmt.Printf("installed Claude Code hooks (PreToolUse + UserPromptSubmit) -> %s\n", p)
		}
	}
	if cursor {
		p := cursorHooksPath(home)
		if auto && !dirExists(filepath.Dir(p)) {
			fmt.Println("Cursor not detected (~/.cursor missing) — skipping")
		} else if err := installCursor(p, self); err != nil {
			return fmt.Errorf("Cursor: %w", err)
		} else {
			fmt.Printf("installed Cursor hooks -> %s\n", p)
		}
	}
	fmt.Println("Done. Make sure the daemon is running (brew services start agentguard, or make install).")
	return nil
}

// Uninstall removes AgentGuard's hook entries from the selected agents.
func Uninstall(args []string) error {
	claude, cursor, auto, err := parseAgentFlags("uninstall-hooks", args)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if claude {
		p := claudeSettingsPath(home)
		if auto && !fileExists(p) {
			fmt.Println("no Claude Code settings found — skipping")
		} else if err := uninstallClaude(p); err != nil {
			return fmt.Errorf("Claude Code: %w", err)
		} else {
			fmt.Printf("removed AgentGuard hook from %s\n", p)
		}
	}
	if cursor {
		p := cursorHooksPath(home)
		if auto && !fileExists(p) {
			fmt.Println("no Cursor hooks found — skipping")
		} else if err := uninstallCursor(p); err != nil {
			return fmt.Errorf("Cursor: %w", err)
		} else {
			fmt.Printf("removed AgentGuard hooks from %s\n", p)
		}
	}
	return nil
}

// parseAgentFlags returns which agents to act on. With neither flag set, both
// are selected in "auto" mode (only configure agents that are actually present).
func parseAgentFlags(name string, args []string) (claude, cursor, auto bool, err error) {
	fset := flag.NewFlagSet(name, flag.ContinueOnError)
	c := fset.Bool("claude", false, "act on Claude Code (~/.claude/settings.json)")
	cu := fset.Bool("cursor", false, "act on Cursor (~/.cursor/hooks.json)")
	if err = fset.Parse(args); err != nil {
		return
	}
	if !*c && !*cu {
		return true, true, true, nil
	}
	return *c, *cu, false, nil
}

// ---- Claude Code: ~/.claude/settings.json ----------------------------------

func installClaude(path, self string) error {
	m, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := childObject(m, "hooks")
	cmd := self + " " + claudeMarker
	entry := func() map[string]any {
		return map[string]any{"type": "command", "command": cmd, "timeout": 10}
	}

	// Strip any existing AgentGuard entry (incl. legacy HTTP ones) then add the
	// current command hook — idempotent and upgrade-safe.
	// PreToolUse: gate every tool call (allow/deny/ask).
	pre := stripClaudeOurs(childArray(hooks, "PreToolUse"))
	pre = append(pre, map[string]any{
		"matcher": "*",
		"hooks":   []any{entry()},
	})
	hooks["PreToolUse"] = pre

	// UserPromptSubmit: scan the prompt text for secrets before it's sent — the
	// Claude Code analogue of Cursor's beforeSubmitPrompt. (No matcher: this
	// event isn't tool-scoped.)
	ups := stripClaudeOurs(childArray(hooks, "UserPromptSubmit"))
	ups = append(ups, map[string]any{
		"hooks": []any{entry()},
	})
	hooks["UserPromptSubmit"] = ups

	m["hooks"] = hooks
	return writeJSONObjectAtomic(path, m)
}

func uninstallClaude(path string) error {
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
		kept := stripClaudeOurs(childArray(hooks, ev))
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

// stripClaudeOurs removes our hooks from each PreToolUse entry, dropping entries
// that become empty, and preserves everything we don't own.
func stripClaudeOurs(pre []any) []any {
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
			if hm, ok := h.(map[string]any); ok && isOurClaudeHook(hm) {
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

func claudeHasOurHook(pre []any) bool {
	for _, entry := range pre {
		em, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, h := range childArray(em, "hooks") {
			if hm, ok := h.(map[string]any); ok && isOurClaudeHook(hm) {
				return true
			}
		}
	}
	return false
}

func isOurClaudeHook(h map[string]any) bool {
	cmd, _ := h["command"].(string)
	url, _ := h["url"].(string) // legacy HTTP installs
	return strings.Contains(cmd, claudeMarker) || strings.Contains(url, "/v1/evaluate")
}

// ---- Cursor: ~/.cursor/hooks.json ------------------------------------------

// cursorEvents are the hook surfaces we gate. We map cleanly onto these:
//   - beforeShellExecution: shell commands (supports allow/deny/ask)
//   - beforeReadFile:       secret/credential file reads (allow/deny)
//   - beforeSubmitPrompt:   ggshield-style scan of the prompt + attached files
//     for secrets (blocks submission). Catches secrets
//     that reach context outside the agent-read path.
//
// beforeMCPExecution is intentionally NOT wired yet — Cursor's MCP payload
// doesn't expose the server name our allowlist needs, so gating it would risk
// false-blocking. Tracked as a follow-up.
var cursorEvents = []string{"beforeShellExecution", "beforeReadFile", "beforeSubmitPrompt"}

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

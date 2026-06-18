package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// socketPath is the Unix domain socket the daemon listens on and the hook
// handlers dial. Override with AGENTGUARD_SOCKET.
func socketPath() string {
	if p := strings.TrimSpace(os.Getenv("AGENTGUARD_SOCKET")); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentguard", "agentguard.sock")
}

// socketURL/socketScanURL are dummy URLs; the transport dials the Unix socket,
// so the host is ignored. The path must match the daemon's mux route.
const (
	socketURL     = "http://unix/v1/evaluate"
	socketScanURL = "http://unix/v1/scan"
)

// markers identify hook entries we own, so install is idempotent and uninstall
// is precise.
const (
	claudeMarker = "claude-hook"
	cursorMarker = "cursor-hook"
)

// agent identifiers stamped onto events/scan requests for audit attribution.
const (
	agentClaude = "claude-code"
	agentCursor = "cursor"
)

func claudeSettingsPath(home string) string { return filepath.Join(home, ".claude", "settings.json") }
func cursorHooksPath(home string) string    { return filepath.Join(home, ".cursor", "hooks.json") }

// ---- install / uninstall commands ------------------------------------------

func cmdInstallHooks(args []string) error {
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

func cmdUninstallHooks(args []string) error {
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

// ---- claude-hook runtime handler -------------------------------------------

// claudeHook is the command Claude Code spawns on PreToolUse. It reads Claude's
// event JSON on stdin, asks the daemon for a decision over the socket, and
// writes Claude's response format on stdout. If the daemon can't be reached it
// fails CLOSED (denies) rather than letting the action through.
func claudeHook() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: read error:", err)
		_ = json.NewEncoder(os.Stdout).Encode(decide(Deny, "AgentGuard could not read the event — failing closed."))
		return
	}

	// UserPromptSubmit scans the prompt for secrets and uses a different output
	// contract ({decision: block}); PreToolUse is a per-tool decision.
	var probe struct {
		HookEventName string `json:"hook_event_name"`
		Prompt        string `json:"prompt"`
	}
	_ = json.Unmarshal(data, &probe)
	if probe.HookEventName == "UserPromptSubmit" {
		claudePromptScan(probe.Prompt)
		return
	}

	var e HookEvent
	if err := json.Unmarshal(data, &e); err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: bad input:", err)
		_ = json.NewEncoder(os.Stdout).Encode(decide(Deny, "AgentGuard could not parse the tool call — failing closed."))
		return
	}
	e.Agent = agentClaude
	resp, err := postEvaluate(e)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: daemon unreachable:", err)
		resp = decide(Deny, "AgentGuard daemon unreachable — failing closed. Start it: brew services start agentguard")
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}

// claudePromptScan handles Claude Code's UserPromptSubmit: it scans the prompt
// text for secrets and blocks the submission if any are found. It fails closed
// (blocks) if the daemon is unreachable, matching the PreToolUse posture.
func claudePromptScan(prompt string) {
	res, err := postScan(ScanRequest{Text: prompt, Agent: agentClaude})
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: scanner unreachable:", err)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"decision": "block",
			"reason":   "AgentGuard: secret scanner unreachable (failing closed).",
		})
		return
	}
	if res.Found {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"decision": "block",
			"reason":   "AgentGuard blocked prompt — " + res.Reason,
		})
		return
	}
	// Allow: no output / exit 0 lets the prompt through.
}

// ---- cursor-hook runtime handler -------------------------------------------

// cursorHook is the command Cursor spawns per gated action. It reads Cursor's
// event JSON on stdin, asks the daemon for a decision, and writes Cursor's
// response format on stdout. On daemon failure it exits non-zero so Cursor's
// failClosed setting governs the outcome (block).
func cursorHook() {
	var in map[string]any
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "agentguard cursor-hook: bad input:", err)
		os.Exit(1)
	}

	// beforeSubmitPrompt uses a different output contract ({continue,...}) and is
	// a content scan rather than a tool decision — handle it separately.
	if event, _ := in["hook_event_name"].(string); event == "beforeSubmitPrompt" {
		cursorPromptScan(in)
		return
	}

	ev, gated := cursorToEvent(in)
	if !gated {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"permission": Allow})
		return
	}
	ev.Agent = agentCursor

	resp, err := postEvaluate(ev)
	if err != nil {
		// Fail closed: deny when we can't get a decision (defense in depth on top
		// of failClosed:true in hooks.json).
		fmt.Fprintln(os.Stderr, "agentguard cursor-hook: daemon unreachable:", err)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"permission":    Deny,
			"user_message":  "AgentGuard: daemon unreachable (failing closed).",
			"agent_message": "Blocked: AgentGuard daemon unreachable.",
		})
		return
	}

	d := resp.HookSpecificOutput.PermissionDecision
	reason := resp.HookSpecificOutput.PermissionDecisionReason
	out := map[string]any{"permission": d}
	if d != Allow {
		out["user_message"] = "AgentGuard: " + reason
		out["agent_message"] = "Blocked by AgentGuard security policy: " + reason
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

// cursorPromptScan handles beforeSubmitPrompt: it scans the prompt text and any
// attached file paths for secrets and blocks submission if found. Output uses
// Cursor's {continue, user_message} contract for this event.
func cursorPromptScan(in map[string]any) {
	prompt, _ := in["prompt"].(string)
	var paths []string
	if atts, ok := in["attachments"].([]any); ok {
		for _, a := range atts {
			if am, ok := a.(map[string]any); ok {
				if fp, _ := am["file_path"].(string); fp != "" {
					paths = append(paths, fp)
				}
			}
		}
	}

	res, err := postScan(ScanRequest{Text: prompt, Paths: paths, Agent: agentCursor})
	if err != nil {
		// Fail closed: block the submission if the scanner is unreachable.
		fmt.Fprintln(os.Stderr, "agentguard cursor-hook: scanner unreachable:", err)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"continue":     false,
			"user_message": "AgentGuard: secret scanner unreachable (failing closed).",
		})
		return
	}
	if res.Found {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"continue":     false,
			"user_message": "AgentGuard blocked submission — " + res.Reason,
		})
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"continue": true})
}

// cursorToEvent translates a Cursor hook payload into the daemon's HookEvent.
// Returns gated=false for events we don't police (handler then allows).
func cursorToEvent(in map[string]any) (HookEvent, bool) {
	event, _ := in["hook_event_name"].(string)
	cwd, _ := in["cwd"].(string)

	switch event {
	case "beforeShellExecution":
		cmd, _ := in["command"].(string)
		return HookEvent{ToolName: "Bash", CWD: cwd, ToolInput: map[string]any{"command": cmd}}, true
	case "beforeReadFile":
		fp, _ := in["file_path"].(string)
		return HookEvent{ToolName: "Read", CWD: cwd, ToolInput: map[string]any{"file_path": fp}}, true
	}

	// Fallback inference if hook_event_name is absent.
	if cmd, ok := in["command"].(string); ok && cmd != "" {
		return HookEvent{ToolName: "Bash", CWD: cwd, ToolInput: map[string]any{"command": cmd}}, true
	}
	if fp, ok := in["file_path"].(string); ok && fp != "" {
		return HookEvent{ToolName: "Read", CWD: cwd, ToolInput: map[string]any{"file_path": fp}}, true
	}
	return HookEvent{}, false
}

// postEvaluate forwards a tool-call event to the daemon over the Unix socket.
func postEvaluate(ev HookEvent) (HookResponse, error) {
	var hr HookResponse
	err := socketPostJSON(socketURL, ev, &hr)
	return hr, err
}

// postScan asks the daemon to scan text/paths for secrets.
func postScan(req ScanRequest) (ScanResult, error) {
	var res ScanResult
	err := socketPostJSON(socketScanURL, req, &res)
	return res, err
}

// socketPostJSON POSTs payload as JSON to the daemon over the Unix socket and
// decodes the response into out.
func socketPostJSON(url string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	sock := socketPath()
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("daemon returned status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ---- JSON file helpers (preserve unknown fields, back up, write atomically) -

func readJSONObject(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (refusing to overwrite): %w", path, err)
	}
	return m, nil
}

func writeJSONObjectAtomic(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if !json.Valid(out) {
		return errors.New("internal error: generated invalid JSON")
	}

	// Back up any existing file before replacing it.
	if data, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", data, 0o600)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentguard-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func childObject(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func childArray(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return []any{}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

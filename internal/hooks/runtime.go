package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"agentguard/internal/types"
)

// agent identifiers stamped onto events/scan requests for audit attribution.
const (
	agentClaude = "claude-code"
	agentCursor = "cursor"
)

// socketURL/socketScanURL are dummy URLs; the transport dials the Unix socket,
// so the host is ignored. The path must match the daemon's mux route.
const (
	socketURL     = "http://unix/v1/evaluate"
	socketScanURL = "http://unix/v1/scan"
)

// ---- claude-hook runtime handler -------------------------------------------

// ClaudeHook is the command Claude Code spawns on PreToolUse. It reads Claude's
// event JSON on stdin, asks the daemon for a decision over the socket, and
// writes Claude's response format on stdout. If the daemon can't be reached it
// fails CLOSED (denies) rather than letting the action through.
func ClaudeHook() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: read error:", err)
		_ = json.NewEncoder(os.Stdout).Encode(types.Decide(types.Deny, "AgentGuard could not read the event — failing closed."))
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

	var e types.HookEvent
	if err := json.Unmarshal(data, &e); err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: bad input:", err)
		_ = json.NewEncoder(os.Stdout).Encode(types.Decide(types.Deny, "AgentGuard could not parse the tool call — failing closed."))
		return
	}
	e.Agent = agentClaude
	resp, err := postEvaluate(e)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentguard claude-hook: daemon unreachable:", err)
		resp = types.Decide(types.Deny, "AgentGuard daemon unreachable — failing closed. Start it: brew services start agentguard")
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}

// claudePromptScan handles Claude Code's UserPromptSubmit: it scans the prompt
// text for secrets and blocks the submission if any are found. It fails closed
// (blocks) if the daemon is unreachable, matching the PreToolUse posture.
func claudePromptScan(prompt string) {
	res, err := postScan(types.ScanRequest{Text: prompt, Agent: agentClaude})
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

// CursorHook is the command Cursor spawns per gated action. It reads Cursor's
// event JSON on stdin, asks the daemon for a decision, and writes Cursor's
// response format on stdout. On daemon failure it exits non-zero so Cursor's
// failClosed setting governs the outcome (block).
func CursorHook() {
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
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"permission": types.Allow})
		return
	}
	ev.Agent = agentCursor

	resp, err := postEvaluate(ev)
	if err != nil {
		// Fail closed: deny when we can't get a decision (defense in depth on top
		// of failClosed:true in hooks.json).
		fmt.Fprintln(os.Stderr, "agentguard cursor-hook: daemon unreachable:", err)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"permission":    types.Deny,
			"user_message":  "AgentGuard: daemon unreachable (failing closed).",
			"agent_message": "Blocked: AgentGuard daemon unreachable.",
		})
		return
	}

	d := resp.HookSpecificOutput.PermissionDecision
	reason := resp.HookSpecificOutput.PermissionDecisionReason
	out := map[string]any{"permission": d}
	if d != types.Allow {
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

	res, err := postScan(types.ScanRequest{Text: prompt, Paths: paths, Agent: agentCursor})
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
func cursorToEvent(in map[string]any) (types.HookEvent, bool) {
	event, _ := in["hook_event_name"].(string)
	cwd, _ := in["cwd"].(string)

	switch event {
	case "beforeShellExecution":
		cmd, _ := in["command"].(string)
		return types.HookEvent{ToolName: "Bash", CWD: cwd, ToolInput: map[string]any{"command": cmd}}, true
	case "beforeReadFile":
		fp, _ := in["file_path"].(string)
		return types.HookEvent{ToolName: "Read", CWD: cwd, ToolInput: map[string]any{"file_path": fp}}, true
	}

	// Fallback inference if hook_event_name is absent.
	if cmd, ok := in["command"].(string); ok && cmd != "" {
		return types.HookEvent{ToolName: "Bash", CWD: cwd, ToolInput: map[string]any{"command": cmd}}, true
	}
	if fp, ok := in["file_path"].(string); ok && fp != "" {
		return types.HookEvent{ToolName: "Read", CWD: cwd, ToolInput: map[string]any{"file_path": fp}}, true
	}
	return types.HookEvent{}, false
}

// ---- socket client ---------------------------------------------------------

// postEvaluate forwards a tool-call event to the daemon over the Unix socket.
func postEvaluate(ev types.HookEvent) (types.HookResponse, error) {
	var hr types.HookResponse
	err := socketPostJSON(socketURL, ev, &hr)
	return hr, err
}

// postScan asks the daemon to scan text/paths for secrets.
func postScan(req types.ScanRequest) (types.ScanResult, error) {
	var res types.ScanResult
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

	sock := types.SocketPath()
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

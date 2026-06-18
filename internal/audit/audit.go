// Package audit writes redacted, one-line JSON records of every decision to a
// local append-only log.
//
// IMPORTANT: records contain the decision + reason only — never the raw command,
// file contents, or any secret value.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"agentguard/internal/types"
)

// Logger appends audit records to an open file. All methods are nil-safe so the
// daemon can run (best-effort) even if the log file couldn't be opened.
type Logger struct {
	fp *os.File
}

// Open opens (creating/appending) the audit log at path.
func Open(path string) (*Logger, error) {
	fp, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{fp: fp}, nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l == nil || l.fp == nil {
		return nil
	}
	return l.fp.Close()
}

func (l *Logger) write(rec map[string]any) {
	if l == nil || l.fp == nil {
		return
	}
	line, _ := json.Marshal(rec)
	fmt.Fprintln(l.fp, string(line))
}

// Evaluate records a tool-call decision.
func (l *Logger) Evaluate(e types.HookEvent, resp types.HookResponse) {
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
	l.write(rec)
}

// Scan records a prompt-scan decision, including every detected secret.
func (l *Logger) Scan(res types.ScanResult, agent string) {
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
	l.write(rec)
}

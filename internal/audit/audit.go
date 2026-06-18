// Package audit writes redacted, one-line JSON records of every decision to a
// local append-only log.
//
// IMPORTANT: records contain the decision + reason only — never the raw command,
// file contents, or any secret value.
//
// The writer is safe for concurrent use (the daemon serves requests on multiple
// goroutines) and rotates the log by size so it can't grow without bound.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"agentguard/internal/types"
)

// Defaults for size-based rotation.
const (
	defaultMaxBytes int64 = 10 << 20 // 10 MiB per file before rotating
	defaultKeep           = 5        // audit.log.1 .. audit.log.5 retained
)

// Record is the typed shape of one audit line. ts/tool/decision/reason/session
// are always present; the rest are omitted when empty. Centralizing the schema
// here (instead of ad-hoc maps) keeps the evaluate and scan records consistent
// and is the natural input for the future cloud redact()/ship boundary.
type Record struct {
	TS       string          `json:"ts"`
	Tool     string          `json:"tool"`
	Decision string          `json:"decision"`
	Reason   string          `json:"reason"`
	Session  string          `json:"session"`
	Agent    string          `json:"agent,omitempty"`    // "claude-code" or "cursor"
	Source   string          `json:"source,omitempty"`   // "builtin" or "kingfisher" (first finding)
	Rule     string          `json:"rule,omitempty"`     // first finding's rule
	Findings []types.Finding `json:"findings,omitempty"` // every secret detected
}

// Logger appends audit records to a rotating file. All methods are nil-safe so
// the daemon can run (best-effort) even if the log file couldn't be opened.
type Logger struct {
	mu       sync.Mutex
	fp       *os.File
	path     string
	size     int64
	maxBytes int64
	keep     int
}

// Open opens (creating/appending) the audit log at path with default rotation.
func Open(path string) (*Logger, error) {
	fp, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	var size int64
	if fi, err := fp.Stat(); err == nil {
		size = fi.Size()
	}
	return &Logger{
		fp:       fp,
		path:     path,
		size:     size,
		maxBytes: defaultMaxBytes,
		keep:     defaultKeep,
	}, nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fp == nil {
		return nil
	}
	err := l.fp.Close()
	l.fp = nil
	return err
}

// write serializes rec and appends one line, rotating first if the line would
// push the file past maxBytes. Concurrency-safe.
func (l *Logger) write(rec Record) {
	if l == nil {
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fp == nil {
		return
	}
	l.rotateIfNeeded(int64(len(line)))
	n, _ := l.fp.Write(line)
	l.size += int64(n)
}

// rotateIfNeeded rotates the log when the next write would exceed maxBytes:
// audit.log.(keep-1)->.keep, ..., audit.log->.1, then a fresh audit.log. Caller
// must hold l.mu. Best-effort: on any error it keeps writing to the current fp.
func (l *Logger) rotateIfNeeded(incoming int64) {
	if l.maxBytes <= 0 || l.size+incoming <= l.maxBytes {
		return
	}
	if err := l.fp.Close(); err != nil {
		return
	}
	for i := l.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	if l.keep >= 1 {
		_ = os.Rename(l.path, l.path+".1")
	}
	fp, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.fp = nil // give up logging rather than crash the daemon
		return
	}
	l.fp = fp
	l.size = 0
}

// Evaluate records a tool-call decision.
func (l *Logger) Evaluate(e types.HookEvent, resp types.HookResponse) {
	l.write(Record{
		TS:       time.Now().UTC().Format(time.RFC3339),
		Tool:     e.ToolName,
		Decision: resp.HookSpecificOutput.PermissionDecision,
		Reason:   resp.HookSpecificOutput.PermissionDecisionReason,
		Session:  e.SessionID,
		Agent:    e.Agent,
	})
}

// Scan records a prompt-scan decision, including every detected secret.
func (l *Logger) Scan(res types.ScanResult, agent string) {
	decision := "allow"
	if res.Found {
		decision = "deny"
	}
	l.write(Record{
		TS:       time.Now().UTC().Format(time.RFC3339),
		Tool:     "Prompt",
		Decision: decision,
		Reason:   res.Reason,
		Session:  "",
		Agent:    agent,
		Source:   res.Source,
		Rule:     res.Rule,
		Findings: res.Findings,
	})
}

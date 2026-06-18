// Package types holds the shared domain types passed between AgentGuard's
// policy engine, scanners, hook handlers, audit log, and daemon. Keeping them
// in one dependency-free package avoids import cycles between those components.
package types

import (
	"os"
	"path/filepath"
	"strings"
)

// PreToolUse permission decisions understood by Claude Code / Cursor.
const (
	Allow = "allow"
	Deny  = "deny"
	Ask   = "ask"
)

// HookEvent is what an agent POSTs to us before a tool runs.
type HookEvent struct {
	SessionID string         `json:"session_id"`
	CWD       string         `json:"cwd"`
	ToolName  string         `json:"tool_name"`  // "Bash", "Read", "Edit", "Write", "mcp__<server>__<tool>"
	ToolInput map[string]any `json:"tool_input"` // shape varies by tool
	Agent     string         `json:"agent,omitempty"`
	// ClientCannotAsk is set by a hook handler when the calling agent's hook
	// surface cannot render an interactive "ask" prompt (e.g. Cursor's
	// preToolUse, which gates WebFetch). When true, the daemon downgrades an
	// "ask" decision to "deny" so the action is cleanly blocked rather than
	// erroring, and the audit log records what was actually enforced.
	ClientCannotAsk bool `json:"client_cannot_ask,omitempty"`
}

// HookResponse is what we return. PermissionDecision is one of allow/deny/ask.
type HookResponse struct {
	HookSpecificOutput HookOutput `json:"hookSpecificOutput"`
}

type HookOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// Decide builds a PreToolUse hook response.
func Decide(decision, reason string) HookResponse {
	return HookResponse{HookOutput{"PreToolUse", decision, reason}}
}

// Config is the per-team policy, loaded from config.json so it can be tuned
// without rebuilding.
type Config struct {
	Version       int          `json:"version,omitempty"`        // config schema version (forward-compat)
	AllowedEgress []string     `json:"allowed_egress"`           // domains the agent may reach
	ApprovedMCP   []string     `json:"approved_mcp"`             // MCP servers the agent may call
	DisabledRules []string     `json:"disabled_rules,omitempty"` // policy rule IDs to turn off
	Cloud         *CloudConfig `json:"cloud,omitempty"`          // optional control-plane shipping (off unless set)
}

// CloudConfig configures the optional, additive event-shipping layer. It is nil
// (and the agent fully cloud-free) unless explicitly set. Enforcement never
// depends on this — it's a redacted read path only.
type CloudConfig struct {
	Enabled bool        `json:"enabled"`
	Sinks   []CloudSink `json:"sinks,omitempty"` // one or more destinations for redacted events
}

// CloudSink is a single destination for the redacted event stream. M0 supports
// a local "file" sink (NDJSON); an HTTPS sink (endpoint/enrollment) lands in M1.
type CloudSink struct {
	Name            string `json:"name"`                       // label for logs/dashboard
	Type            string `json:"type,omitempty"`             // "file" (M0) | "https" (M1)
	Path            string `json:"path,omitempty"`             // file sink: NDJSON output path
	Endpoint        string `json:"endpoint,omitempty"`         // https sink: ingest URL
	EnrollmentToken string `json:"enrollment_token,omitempty"` // https sink: exchanged at enroll
	OrgSalt         string `json:"org_salt,omitempty"`         // https sink: per-sink finding-hash salt
}

// ScanRequest is the body of /v1/scan: free text plus any attachment paths.
// Agent identifies the originating coding agent ("claude-code" or "cursor") so
// the audit log can attribute each block to its source.
type ScanRequest struct {
	Text  string   `json:"text"`
	Paths []string `json:"paths"`
	Agent string   `json:"agent,omitempty"`
}

// Finding is a single detected secret: which backend caught it ("builtin" or
// "kingfisher") and the rule/pattern name that matched.
type Finding struct {
	Source string `json:"source"`
	Rule   string `json:"rule"`
}

// ScanResult reports whether secret material was found and a redacted reason.
// Source/Rule reflect the FIRST finding (for the block message); Findings lists
// EVERY secret detected so a multi-secret prompt is fully reported. Severity is
// the audit/dashboard severity of the detection (uniform with policy decisions).
type ScanResult struct {
	Found    bool      `json:"found"`
	Reason   string    `json:"reason"`
	Source   string    `json:"source,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// CloudEvent is the ONLY shape permitted to leave the machine: the redacted,
// allowlisted projection of a decision or scan. It is constructed exclusively by
// the cloud.Redact* boundary. Anything NOT on this struct — raw secret values,
// prompt text, command strings, full file paths, session ids — is dropped by
// construction (enforced by the redaction test). Adding a field here is a
// privacy decision: it widens what can egress.
type CloudEvent struct {
	Schema       int            `json:"schema"`                 // redacted-event schema version
	EventID      string         `json:"event_id"`               // client-generated idempotency key
	TS           string         `json:"ts"`                     // RFC3339 UTC
	DeviceID     string         `json:"device_id,omitempty"`    // set per-sink at ship time (enrollment)
	OrgID        string         `json:"org_id,omitempty"`       // set per-sink at ship time (enrollment)
	Agent        string         `json:"agent,omitempty"`        // claude-code | cursor | codex
	Tool         string         `json:"tool"`                   // Prompt | Bash | Read | mcp__<server>__<tool>
	Decision     string         `json:"decision"`               // allow | deny | ask
	Reason       string         `json:"reason,omitempty"`       // redacted reason (names secret TYPE / domain, never values)
	Source       string         `json:"source,omitempty"`       // builtin | kingfisher
	Rule         string         `json:"rule,omitempty"`         // policy rule id or finding rule
	Severity     string         `json:"severity,omitempty"`     // critical | high | medium
	Findings     []CloudFinding `json:"findings,omitempty"`     // every secret detected (redacted)
	CWDBase      string         `json:"cwd_base,omitempty"`     // basename ONLY — never the full path
	AgentVersion string         `json:"agent_version,omitempty"`
}

// CloudFinding is one detected secret, redacted: backend + rule name only. Hash
// (sha256(org_salt || value)) is added per-sink at ship time once enrollment
// provides org_salt; it is empty for a local sink (M0).
type CloudFinding struct {
	Source string `json:"source"`
	Rule   string `json:"rule"`
	Hash   string `json:"hash,omitempty"`
}

// SocketPath is the Unix domain socket the daemon listens on and the hook
// handlers dial. Override with AGENTGUARD_SOCKET.
func SocketPath() string {
	if p := strings.TrimSpace(os.Getenv("AGENTGUARD_SOCKET")); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentguard", "agentguard.sock")
}

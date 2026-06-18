// Package cloud builds and ships the redacted, additive event stream that the
// optional control plane consumes — without ever weakening local enforcement or
// privacy.
//
// The Redact* functions are the SINGLE boundary at which an outbound payload may
// be constructed. Nothing else may build a types.CloudEvent. Everything not on
// the CloudEvent allowlist — raw secret values, prompt text, command strings,
// full file paths, session ids — is dropped here by construction. redact_test.go
// proves this and fails the build if anything leaks, so this file is the place
// to scrutinize on any change.
package cloud

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"time"

	"agentguard/internal/types"
)

// schemaVersion is the redacted-event contract version (see docs/cloud-mvp.md §3).
const schemaVersion = 1

// RedactEvaluate projects a tool-call decision into the redacted CloudEvent.
//
// Note what is deliberately NOT carried over from the HookEvent: ToolInput (the
// raw command / file_path / url), the full CWD (only its basename ships), and
// SessionID. Only the decision metadata and the tool identifier leave.
func RedactEvaluate(e types.HookEvent, resp types.HookResponse, ruleID, severity, agentVersion string) types.CloudEvent {
	return types.CloudEvent{
		Schema:       schemaVersion,
		EventID:      newEventID(),
		TS:           nowRFC3339(),
		Agent:        e.Agent,
		Tool:         e.ToolName,
		Decision:     resp.HookSpecificOutput.PermissionDecision,
		Reason:       resp.HookSpecificOutput.PermissionDecisionReason,
		Rule:         ruleID,
		Severity:     severity,
		CWDBase:      baseOrEmpty(e.CWD),
		AgentVersion: agentVersion,
	}
}

// RedactScan projects a prompt secret-scan result into the redacted CloudEvent.
// The scan result already holds only redacted metadata (backend + rule name per
// finding) — never the matched value — so the projection copies those directly.
func RedactScan(res types.ScanResult, agent, agentVersion string) types.CloudEvent {
	decision := types.Allow
	if res.Found {
		decision = types.Deny
	}
	ev := types.CloudEvent{
		Schema:       schemaVersion,
		EventID:      newEventID(),
		TS:           nowRFC3339(),
		Agent:        agent,
		Tool:         "Prompt",
		Decision:     decision,
		Reason:       res.Reason,
		Source:       res.Source,
		Rule:         res.Rule,
		Severity:     res.Severity,
		AgentVersion: agentVersion,
	}
	for _, f := range res.Findings {
		// Hash is intentionally omitted in M0: it requires a per-sink org_salt
		// from enrollment, which a local sink doesn't have. Added in M1.
		ev.Findings = append(ev.Findings, types.CloudFinding{Source: f.Source, Rule: f.Rule})
	}
	return ev
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// newEventID returns a random 128-bit hex id, used as the ingest idempotency key.
func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// baseOrEmpty returns just the final path element (e.g. "fagent"), never the
// full path. An empty input stays empty.
func baseOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

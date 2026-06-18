package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// PreToolUse permission decisions understood by Claude Code.
const (
	Allow = "allow"
	Deny  = "deny"
	Ask   = "ask"
)

// HookEvent is what Claude Code POSTs to us before a tool runs.
type HookEvent struct {
	SessionID string         `json:"session_id"`
	CWD       string         `json:"cwd"`
	ToolName  string         `json:"tool_name"`  // "Bash", "Read", "Edit", "Write", "mcp__<server>__<tool>"
	ToolInput map[string]any `json:"tool_input"` // shape varies by tool
	Agent     string         `json:"agent,omitempty"` // "claude-code" or "cursor"
}

// HookResponse is what we return. permissionDecision is one of allow/deny/ask.
type HookResponse struct {
	HookSpecificOutput HookOutput `json:"hookSpecificOutput"`
}

type HookOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

func decide(decision, reason string) HookResponse {
	return HookResponse{HookOutput{"PreToolUse", decision, reason}}
}

// Config is the per-team policy, loaded from config.json so Fyxer can tune it
// without rebuilding.
type Config struct {
	AllowedEgress []string `json:"allowed_egress"` // domains the agent may reach
	ApprovedMCP   []string `json:"approved_mcp"`   // MCP servers the agent may call

	// Scanner selects the secret-detection backend for the prompt scanner:
	//   "auto"       — use Kingfisher if installed, else the builtin scanner (default)
	//   "builtin"    — always use the builtin regex+entropy scanner (zero-dependency)
	//   "kingfisher" — always use Kingfisher (falls back to builtin if it errors)
	Scanner        string `json:"scanner,omitempty"`
	KingfisherPath string `json:"kingfisher_path,omitempty"` // optional explicit path
}

// Detection patterns — Tier 1. Fast, deterministic, explainable.
var (
	secretPath  = regexp.MustCompile(`(^|[^a-zA-Z0-9])\.env([^a-zA-Z0-9]|$)|/\.aws/|/\.ssh/|\.pem([^a-zA-Z0-9]|$)|id_rsa|credentials|secrets?/`)
	destructive = regexp.MustCompile(`rm\s+-rf|git\s+push\s+.*--force|git\s+reset\s+--hard|DROP\s+(TABLE|DATABASE)|chmod\s+777|mkfs`)
	netExfil    = regexp.MustCompile(`\b(curl|wget|nc|ncat|scp|telnet)\b`)
	urlHost     = regexp.MustCompile(`https?://([a-zA-Z0-9.\-]+)`)
)

// extract pulls the relevant fields out of the tool input.
func extract(e HookEvent) (cmd, filePath, mcpServer string) {
	get := func(k string) string {
		if v, ok := e.ToolInput[k].(string); ok {
			return v
		}
		return ""
	}
	cmd = get("command")        // Bash
	filePath = get("file_path") // Read / Edit / Write
	if strings.HasPrefix(e.ToolName, "mcp__") {
		if parts := strings.Split(e.ToolName, "__"); len(parts) >= 2 {
			mcpServer = parts[1]
		}
	}
	return
}

// Evaluate runs the policy. Order matters: highest-severity first.
func Evaluate(cfg Config, e HookEvent) HookResponse {
	cmd, filePath, mcpServer := extract(e)

	readsSecret := secretPath.MatchString(filePath) || (cmd != "" && secretPath.MatchString(cmd))
	touchesNet := netExfil.MatchString(cmd)

	// 1) Highest-confidence hijack: read a secret AND push it over the network.
	if readsSecret && touchesNet {
		return decide(Deny, "Reads a secret and sends it over the network (exfiltration pattern).")
	}

	// 2) Any access to secret material.
	if readsSecret {
		return decide(Deny, "Access to secrets/credentials is not permitted for the agent.")
	}

	// 3) Egress control — outbound network must target an approved domain.
	if touchesNet {
		host := ""
		if m := urlHost.FindStringSubmatch(cmd); len(m) > 1 {
			host = m[1]
		}
		if !domainAllowed(host, cfg.AllowedEgress) {
			return decide(Ask, "Network call to unapproved domain ("+host+") — needs approval.")
		}
	}

	// 4) Destructive actions — require explicit confirmation.
	if destructive.MatchString(cmd) {
		return decide(Ask, "Destructive command detected — confirm before running.")
	}

	// 5) MCP vetting — only approved servers.
	if mcpServer != "" && !contains(cfg.ApprovedMCP, mcpServer) {
		return decide(Deny, "MCP server '"+mcpServer+"' is not on the approved list.")
	}

	return decide(Allow, "")
}

func domainAllowed(host string, allow []string) bool {
	if host == "" {
		return false
	}
	for _, d := range allow {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ---- Secret content scanner (ggshield-style) -------------------------------
//
// The builtin scanner powers the INLINE path (beforeSubmitPrompt / Claude
// UserPromptSubmit): it catches secrets pasted into a prompt (or a secret file
// attached to it) regardless of how they entered the model's context — the gap
// per-tool read hooks can't cover in Cursor. It must stay fast (sub-ms) because
// it runs synchronously on every prompt.

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
// Source/Rule reflect the FIRST finding (kept for back-compat and the block
// message); Findings lists EVERY secret detected so a multi-secret prompt is
// fully reported in the audit log rather than just its first hit.
type ScanResult struct {
	Found    bool      `json:"found"`
	Reason   string    `json:"reason"`
	Source   string    `json:"source,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// resultFromFindings builds a ScanResult from a (deduped) finding list. The
// reason summarizes one or many: "secret detected in prompt (X)" or "N secrets
// detected in prompt (X, Y, ...)".
func resultFromFindings(fs []Finding) ScanResult {
	if len(fs) == 0 {
		return ScanResult{}
	}
	rules := make([]string, len(fs))
	for i, f := range fs {
		rules[i] = f.Rule
	}
	reason := "secret detected in prompt (" + fs[0].Rule + ")"
	if len(fs) > 1 {
		reason = fmt.Sprintf("%d secrets detected in prompt (%s)", len(fs), strings.Join(rules, ", "))
	}
	return ScanResult{Found: true, Reason: reason, Source: fs[0].Source, Rule: fs[0].Rule, Findings: fs}
}

// mergeFindings concatenates builtin + resident findings, deduping by a
// normalized rule name (lowercased, alphanumerics only) so "AWS access key id"
// (builtin) and "AWS Access Key ID" (kingfisher) collapse to one entry.
func mergeFindings(builtin, resident []Finding) []Finding {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	seen := make(map[string]bool)
	out := make([]Finding, 0, len(builtin)+len(resident))
	for _, f := range append(append([]Finding{}, builtin...), resident...) {
		k := norm(f.Rule)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// High-confidence patterns: these are specific enough that a match is a secret.
var secretContentPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`)},
	{"GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
}

// assignmentRe captures the *value* of a secret-looking assignment so we can
// judge it (entropy/placeholder) instead of blindly flagging any long string.
var assignmentRe = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9/_+\-.]{12,})`)

// placeholderRe matches obvious non-secrets: env references, templating, and
// common placeholder words used in docs/examples.
var placeholderRe = regexp.MustCompile(`(?i)^(x{3,}$|changeme|your[_-]?|my[_-]?(api|secret|token|key|password)|example|placeholder|dummy|sample|redacted|none$|null$|true$|false$|todo|fixme|insert|<|\$\{|\$\(|process\.env|os\.environ|import\.meta)`)

// ScanSecrets returns whether the text contains a recognized secret pattern.
func ScanSecrets(text string) (bool, string) {
	for _, p := range secretContentPatterns {
		if p.re.MatchString(text) {
			return true, p.name
		}
	}
	if m := assignmentRe.FindStringSubmatch(text); m != nil && looksLikeSecret(m[1]) {
		return true, "secret assignment"
	}
	return false, ""
}

// looksLikeSecret filters the generic assignment match to cut false positives:
// it requires a long, high-entropy value that isn't an obvious placeholder or
// an environment-variable reference.
func looksLikeSecret(v string) bool {
	if len(v) < 16 {
		return false
	}
	if placeholderRe.MatchString(v) {
		return false
	}
	// A value with whitespace-y separators or no digits *and* low variety reads
	// more like prose than a credential; entropy is the deciding factor.
	return shannonEntropy(v) >= 3.2
}

// shannonEntropy returns bits-of-entropy per character. Random tokens land
// around 4–6; English words and repetitive strings sit below ~3.2.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// Scan checks attachment paths (a secret file referenced by the prompt) and the
// prompt text itself, collecting EVERY match (not just the first).
func Scan(req ScanRequest) ScanResult {
	return resultFromFindings(scanBuiltin(req))
}

// scanBuiltin returns every builtin match: sensitive attachment paths plus all
// distinct secret patterns found in the text.
func scanBuiltin(req ScanRequest) []Finding {
	var fs []Finding
	for _, p := range req.Paths {
		if secretPath.MatchString(p) {
			fs = append(fs, Finding{Source: "builtin", Rule: "file:" + baseName(p)})
		}
	}
	for _, p := range secretContentPatterns {
		if p.re.MatchString(req.Text) {
			fs = append(fs, Finding{Source: "builtin", Rule: p.name})
		}
	}
	if m := assignmentRe.FindStringSubmatch(req.Text); m != nil && looksLikeSecret(m[1]) {
		fs = append(fs, Finding{Source: "builtin", Rule: "secret assignment"})
	}
	return fs
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ---- Pluggable scanner backend --------------------------------------------
//
// Scanner picks the detection backend for the on-demand `agentguard scan`
// command (CI / manual audits) — NOT the inline hook path, which always uses the
// fast builtin Scan above. If Kingfisher (mongodb/kingfisher, 950+ maintained
// rules + offline checksum validation) is available we route content through it
// for far higher fidelity; its ~4s/call cost is acceptable off the hot path. We
// always run it with --no-validate so no secret is sent to a third-party API —
// detection stays local, preserving the privacy promise.

type Scanner struct {
	Mode           string // "auto" | "builtin" | "kingfisher"
	KingfisherPath string // resolved binary path, or "" if not found
}

// NewScanner resolves the backend once at startup. An explicit path wins;
// otherwise we look on PATH so "auto" can light up Kingfisher transparently.
func NewScanner(mode, path string) *Scanner {
	s := &Scanner{Mode: strings.ToLower(strings.TrimSpace(mode)), KingfisherPath: path}
	if s.Mode == "" {
		s.Mode = "auto"
	}
	if s.KingfisherPath == "" {
		if p, err := exec.LookPath("kingfisher"); err == nil {
			s.KingfisherPath = p
		} else {
			// launchd/systemd start services with a minimal PATH that excludes
			// Homebrew dirs, so LookPath fails even when kingfisher is installed.
			// Probe the common absolute install locations so "auto" still works.
			for _, cand := range []string{
				"/opt/homebrew/bin/kingfisher",              // Homebrew, Apple Silicon
				"/usr/local/bin/kingfisher",                 // Homebrew, Intel / manual
				"/home/linuxbrew/.linuxbrew/bin/kingfisher", // Linuxbrew
			} {
				if isExecutableFile(cand) {
					s.KingfisherPath = cand
					break
				}
			}
		}
	}
	return s
}

func isExecutableFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// Backend reports which scanner will actually run (for startup logging).
func (s *Scanner) Backend() string {
	if s.useKingfisher() {
		return "kingfisher (" + s.KingfisherPath + ")"
	}
	return "builtin"
}

func (s *Scanner) useKingfisher() bool {
	switch s.Mode {
	case "kingfisher":
		return s.KingfisherPath != ""
	case "builtin":
		return false
	default: // auto
		return s.KingfisherPath != ""
	}
}

// Scan runs the configured backend, falling back to the builtin scanner if the
// external one errors out (fail-safe: we'd rather catch common secrets than
// nothing).
func (s *Scanner) Scan(req ScanRequest) ScanResult {
	if s.useKingfisher() {
		if res, err := kingfisherScan(s.KingfisherPath, req); err == nil {
			return res
		}
	}
	return Scan(req)
}

var kingfisherRuleName = regexp.MustCompile(`"rule_name"\s*:\s*"([^"]+)"`)

// kingfisherScan pipes the prompt text into Kingfisher over stdin and decides by
// its documented exit codes (0 = none, 200 = found, 205 = validated). Sensitive
// attachment paths are caught by the cheap filename check without invoking it.
func kingfisherScan(bin string, req ScanRequest) (ScanResult, error) {
	for _, p := range req.Paths {
		if secretPath.MatchString(p) {
			return ScanResult{Found: true, Reason: "secret file attached to prompt (" + baseName(p) + ")", Source: "builtin", Rule: baseName(p)}, nil
		}
	}
	if strings.TrimSpace(req.Text) == "" {
		return ScanResult{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "scan", "-", "--format", "json", "--no-validate", "--turbo")
	cmd.Stdin = strings.NewReader(req.Text)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard

	err := cmd.Run()
	if ctx.Err() != nil {
		return ScanResult{}, ctx.Err()
	}

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			return ScanResult{}, err // couldn't even run it → fall back to builtin
		}
	}

	switch code {
	case 0:
		return ScanResult{}, nil
	case 200, 205:
		reason := "secret detected in prompt"
		rule := ""
		if m := kingfisherRuleName.FindSubmatch(out.Bytes()); m != nil {
			rule = string(m[1])
			reason = "secret detected in prompt (" + rule + ")"
		}
		return ScanResult{Found: true, Reason: reason, Source: "kingfisher", Rule: rule}, nil
	default:
		return ScanResult{}, fmt.Errorf("kingfisher exited %d", code)
	}
}

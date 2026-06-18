// Package scan implements AgentGuard's secret detection: a fast builtin
// regex+entropy scanner plus a client for the resident kingfisherd, unified
// behind ScanAll.
//
// The builtin scanner powers the INLINE path (beforeSubmitPrompt / Claude
// UserPromptSubmit): it catches secrets pasted into a prompt (or a secret file
// attached to it) regardless of how they entered the model's context. It must
// stay fast (sub-ms) because it runs synchronously on every prompt.
package scan

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"agentguard/internal/types"
)

// secretPath matches references to sensitive files (.env, ~/.aws, ~/.ssh, PEM
// keys, id_rsa, credentials/secrets dirs). Shared by the policy engine (to deny
// secret-file reads) and the scanner (to flag a secret file attached to a
// prompt).
var secretPath = regexp.MustCompile(`(^|[^a-zA-Z0-9])\.env([^a-zA-Z0-9]|$)|/\.aws/|/\.ssh/|\.pem([^a-zA-Z0-9]|$)|id_rsa|credentials|secrets?/`)

// IsSecretPath reports whether s references a sensitive file or directory.
func IsSecretPath(s string) bool { return secretPath.MatchString(s) }

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

// Scan checks attachment paths (a secret file referenced by the prompt) and the
// prompt text itself, collecting EVERY match (not just the first).
func Scan(req types.ScanRequest) types.ScanResult {
	return resultFromFindings(scanBuiltin(req))
}

// scanBuiltin returns every builtin match: sensitive attachment paths plus all
// distinct secret patterns found in the text.
func scanBuiltin(req types.ScanRequest) []types.Finding {
	var fs []types.Finding
	for _, p := range req.Paths {
		if secretPath.MatchString(p) {
			fs = append(fs, types.Finding{Source: "builtin", Rule: "file:" + baseName(p)})
		}
	}
	for _, p := range secretContentPatterns {
		if p.re.MatchString(req.Text) {
			fs = append(fs, types.Finding{Source: "builtin", Rule: p.name})
		}
	}
	if m := assignmentRe.FindStringSubmatch(req.Text); m != nil && looksLikeSecret(m[1]) {
		fs = append(fs, types.Finding{Source: "builtin", Rule: "secret assignment"})
	}
	return fs
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
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

// resultFromFindings builds a ScanResult from a (deduped) finding list. The
// reason summarizes one or many: "secret detected in prompt (X)" or "N secrets
// detected in prompt (X, Y, ...)".
func resultFromFindings(fs []types.Finding) types.ScanResult {
	if len(fs) == 0 {
		return types.ScanResult{}
	}
	rules := make([]string, len(fs))
	for i, f := range fs {
		rules[i] = f.Rule
	}
	reason := "secret detected in prompt (" + fs[0].Rule + ")"
	if len(fs) > 1 {
		reason = fmt.Sprintf("%d secrets detected in prompt (%s)", len(fs), strings.Join(rules, ", "))
	}
	// A leaked credential is the highest-severity event AgentGuard catches.
	return types.ScanResult{Found: true, Reason: reason, Source: fs[0].Source, Rule: fs[0].Rule, Severity: "critical", Findings: fs}
}

// mergeFindings concatenates builtin + resident findings, deduping by a
// normalized rule name (lowercased, alphanumerics only) so "AWS access key id"
// (builtin) and "AWS Access Key ID" (kingfisher) collapse to one entry.
func mergeFindings(builtin, resident []types.Finding) []types.Finding {
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
	out := make([]types.Finding, 0, len(builtin)+len(resident))
	for _, f := range append(append([]types.Finding{}, builtin...), resident...) {
		k := norm(f.Rule)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

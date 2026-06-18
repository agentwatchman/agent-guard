package scan

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentguard/internal/types"
)

// resident.go connects the daemon's inline scan path to kingfisherd — the
// long-running Kingfisher scanner that compiles its 950+ rules once and answers
// in milliseconds. This is how we get Kingfisher's coverage INLINE without the
// ~4s/call cost of the CLI. If kingfisherd isn't running (or hangs), we fall
// back to the builtin scanner, so the hot path never blocks.

func residentSocketPath() string {
	if p := strings.TrimSpace(os.Getenv("AGENTGUARD_KINGFISHERD_SOCKET")); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentguard", "kingfisherd.sock")
}

// ScanAll is the single secret-detection entry point shared by the inline hook
// path (the daemon's /v1/scan) and the on-demand CLI (`agentguard scan`). It
// runs the full union: the always-on builtin scanner (sub-ms; also handles the
// attachment-path check and catches high-confidence patterns Kingfisher
// deliberately suppresses, e.g. well-known example keys) plus the resident
// kingfisherd when there's text to scan and it's reachable. Findings are merged
// and deduped so multi-secret input is fully reported. A resident error is
// ignored — the builtin result stands, so the hot path never blocks.
func ScanAll(req types.ScanRequest) types.ScanResult {
	builtin := Scan(req)
	var resident []types.Finding
	if strings.TrimSpace(req.Text) != "" {
		if rr, err := residentScan(req.Text); err == nil {
			resident = rr.Findings
		}
	}
	return resultFromFindings(mergeFindings(builtin.Findings, resident))
}

// residentScan asks kingfisherd to scan text. Protocol: write the bytes,
// half-close to signal EOF, then read a single JSON response. Tight deadlines
// keep this safely under the daemon's HTTP write timeout.
func residentScan(text string) (types.ScanResult, error) {
	sock := residentSocketPath()
	conn, err := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if err != nil {
		return types.ScanResult{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	if _, err := io.WriteString(conn, text); err != nil {
		return types.ScanResult{}, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite() // signal EOF so the server starts scanning
	}

	var out struct {
		Found    bool   `json:"found"`
		RuleName string `json:"rule_name"` // legacy single-finding (older kingfisherd)
		Findings []struct {
			RuleName string `json:"rule_name"`
			RuleID   string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(conn).Decode(&out); err != nil {
		return types.ScanResult{}, err
	}
	fs := make([]types.Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		fs = append(fs, types.Finding{Source: "kingfisher", Rule: f.RuleName})
	}
	// Back-compat: older kingfisherd returns a single top-level rule_name.
	if len(fs) == 0 && out.Found && out.RuleName != "" {
		fs = append(fs, types.Finding{Source: "kingfisher", Rule: out.RuleName})
	}
	return resultFromFindings(fs), nil
}

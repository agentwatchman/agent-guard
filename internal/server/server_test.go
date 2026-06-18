package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentguard/internal/types"
)

func do(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://unix/x", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func testDaemon() *Daemon {
	d := &Daemon{}
	d.cfg = types.Config{AllowedEgress: []string{"github.com"}, ApprovedMCP: []string{"github"}}
	return d
}

func TestHandleEvaluate(t *testing.T) {
	d := testDaemon()

	rec := do(d.handleEvaluate, `{"tool_name":"Read","tool_input":{"file_path":"/repo/.env"}}`)
	var deny types.HookResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &deny); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if deny.HookSpecificOutput.PermissionDecision != types.Deny {
		t.Errorf("read .env: got %q want deny", deny.HookSpecificOutput.PermissionDecision)
	}

	rec = do(d.handleEvaluate, `{"tool_name":"Bash","tool_input":{"command":"go build ./..."}}`)
	var allow types.HookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &allow)
	if allow.HookSpecificOutput.PermissionDecision != types.Allow {
		t.Errorf("go build: got %q want allow", allow.HookSpecificOutput.PermissionDecision)
	}

	if d.met.evalDeny.Load() != 1 || d.met.evalAllow.Load() != 1 {
		t.Errorf("counters wrong: deny=%d allow=%d", d.met.evalDeny.Load(), d.met.evalAllow.Load())
	}
}

func TestClientCannotAskDowngradesToDeny(t *testing.T) {
	d := testDaemon()

	// Off-allowlist WebFetch normally yields "ask".
	asked := do(d.handleEvaluate, `{"tool_name":"WebFetch","tool_input":{"url":"https://example.com"}}`)
	var a types.HookResponse
	_ = json.Unmarshal(asked.Body.Bytes(), &a)
	if a.HookSpecificOutput.PermissionDecision != types.Ask {
		t.Fatalf("baseline: got %q want ask", a.HookSpecificOutput.PermissionDecision)
	}

	// Same call from a client that can't render "ask" -> downgraded to deny,
	// reason preserved.
	denied := do(d.handleEvaluate, `{"tool_name":"WebFetch","tool_input":{"url":"https://example.com"},"client_cannot_ask":true}`)
	var dn types.HookResponse
	_ = json.Unmarshal(denied.Body.Bytes(), &dn)
	if dn.HookSpecificOutput.PermissionDecision != types.Deny {
		t.Errorf("downgrade: got %q want deny", dn.HookSpecificOutput.PermissionDecision)
	}
	if dn.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Error("downgrade should keep the original reason")
	}

	// A would-be "allow" is unaffected by the flag.
	allowed := do(d.handleEvaluate, `{"tool_name":"WebFetch","tool_input":{"url":"https://api.github.com"},"client_cannot_ask":true}`)
	var al types.HookResponse
	_ = json.Unmarshal(allowed.Body.Bytes(), &al)
	if al.HookSpecificOutput.PermissionDecision != types.Allow {
		t.Errorf("allow with flag: got %q want allow", al.HookSpecificOutput.PermissionDecision)
	}
}

func TestHandleScan(t *testing.T) {
	d := testDaemon()

	rec := do(d.handleScan, `{"text":"key sk-abcdef0123456789ABCDEF01 here"}`)
	var found types.ScanResult
	_ = json.Unmarshal(rec.Body.Bytes(), &found)
	if !found.Found {
		t.Error("expected secret to be found")
	}

	rec = do(d.handleScan, `{"text":"please refactor the login handler"}`)
	var clean types.ScanResult
	_ = json.Unmarshal(rec.Body.Bytes(), &clean)
	if clean.Found {
		t.Error("benign prompt should be clean")
	}

	if d.met.scanDeny.Load() != 1 || d.met.scanClean.Load() != 1 {
		t.Errorf("scan counters wrong: deny=%d clean=%d", d.met.scanDeny.Load(), d.met.scanClean.Load())
	}
}

func TestBodyCapRejected(t *testing.T) {
	d := testDaemon()
	big := strings.Repeat("a", 2<<20) // 2 MiB, over the 1 MiB cap
	rec := do(d.handleScan, `{"text":"`+big+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got %d want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLoadConfigSeedsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	d := &Daemon{}
	if err := d.loadConfig(path); err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected config to be seeded on disk: %v", err)
	}
	if len(d.config().AllowedEgress) == 0 {
		t.Error("seeded config should have a non-empty allowed_egress")
	}
}

func TestReloadPicksUpEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"allowed_egress":["github.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	if err := d.loadConfig(path); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(`{"allowed_egress":["example.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d.reload(path, "test")

	got := d.config().AllowedEgress
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("reload didn't swap config: got %v", got)
	}
}

func TestReloadKeepsPreviousOnBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"allowed_egress":["github.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	if err := d.loadConfig(path); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(`{ this is not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	d.reload(path, "test") // should log + ignore, not panic or wipe config

	got := d.config().AllowedEgress
	if len(got) != 1 || got[0] != "github.com" {
		t.Errorf("bad config should keep previous: got %v", got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	d := testDaemon()
	do(d.handleEvaluate, `{"tool_name":"Bash","tool_input":{"command":"go build ./..."}}`)
	do(d.handleEvaluate, `{"tool_name":"Read","tool_input":{"file_path":"/repo/.env"}}`)

	req := httptest.NewRequest(http.MethodGet, "http://unix/metrics", nil)
	rec := httptest.NewRecorder()
	d.handleMetrics(rec, req)

	var snap map[string]int64
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	if snap["evaluate_total"] != 2 || snap["evaluate_allow"] != 1 || snap["evaluate_deny"] != 1 {
		t.Errorf("metrics snapshot wrong: %v", snap)
	}
}

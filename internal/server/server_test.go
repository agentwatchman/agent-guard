package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

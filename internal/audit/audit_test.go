package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"agentguard/internal/types"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Record shape: required fields always present; optional fields omitted when
// empty; multi-secret findings serialized.
func TestRecordShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Evaluate with no agent → "agent" must be omitted.
	l.Evaluate(types.HookEvent{ToolName: "Read", SessionID: "s1"},
		types.Decide(types.Deny, "no secrets for you"))
	// Scan with agent + multiple findings.
	l.Scan(types.ScanResult{
		Found:    true,
		Reason:   "2 secrets detected",
		Source:   "builtin",
		Rule:     "AWS access key id",
		Findings: []types.Finding{{Source: "builtin", Rule: "AWS access key id"}, {Source: "kingfisher", Rule: "GitLab Private Token"}},
	}, "cursor")
	l.Close()

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}

	var eval map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &eval); err != nil {
		t.Fatalf("evaluate record not valid JSON: %v", err)
	}
	if eval["tool"] != "Read" || eval["decision"] != "deny" || eval["session"] != "s1" {
		t.Errorf("evaluate record wrong: %v", eval)
	}
	for _, k := range []string{"agent", "source", "rule", "findings"} {
		if _, ok := eval[k]; ok {
			t.Errorf("evaluate record should omit %q, got %v", k, eval[k])
		}
	}

	var scan map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &scan); err != nil {
		t.Fatalf("scan record not valid JSON: %v", err)
	}
	if scan["tool"] != "Prompt" || scan["decision"] != "deny" || scan["agent"] != "cursor" {
		t.Errorf("scan record wrong: %v", scan)
	}
	if scan["source"] != "builtin" || scan["rule"] != "AWS access key id" {
		t.Errorf("scan source/rule wrong: %v", scan)
	}
	if fs, ok := scan["findings"].([]any); !ok || len(fs) != 2 {
		t.Errorf("expected 2 findings, got %v", scan["findings"])
	}
}

// Concurrent writers must not interleave/corrupt lines or drop records.
func TestConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const writers, perWriter = 20, 50
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				l.Scan(types.ScanResult{Found: true, Reason: "secret detected"}, "cursor")
			}
		}()
	}
	wg.Wait()
	l.Close()

	lines := readLines(t, path)
	if len(lines) != writers*perWriter {
		t.Fatalf("expected %d records, got %d (lost/torn writes)", writers*perWriter, len(lines))
	}
	for i, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("line %d corrupt: %q: %v", i, ln, err)
		}
	}
}

// Rotation kicks in past maxBytes, keeps at most `keep` old files, and never
// corrupts a record across the boundary.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.maxBytes = 300 // tiny, to force frequent rotation
	l.keep = 2

	for i := 0; i < 200; i++ {
		l.Scan(types.ScanResult{Found: true, Reason: "secret detected in prompt (X)"}, "cursor")
	}
	l.Close()

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated file %s.1 to exist: %v", path, err)
	}
	// keep=2 → at most audit.log + .1 + .2; .3 must not exist.
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Errorf("expected no %s.3 (keep=2 exceeded)", path)
	}
	// Every retained file is well-formed and within (roughly) the size bound.
	for _, p := range []string{path, path + ".1", path + ".2"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue // .2 may not exist yet depending on volume; fine
		}
		if fi.Size() > l.maxBytes*2 {
			t.Errorf("%s is %d bytes, well over maxBytes=%d", p, fi.Size(), l.maxBytes)
		}
		for i, ln := range readLines(t, p) {
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Fatalf("%s line %d corrupt: %v", p, i, err)
			}
		}
	}
}

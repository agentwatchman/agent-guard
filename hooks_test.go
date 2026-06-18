package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readBack(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return m
}

// Claude: existing unrelated settings are preserved; install is idempotent.
func TestInstallClaudeIdempotentAndPreserves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"model":"opus[1m]"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	self := "/usr/local/bin/agentguard"
	for i := 0; i < 2; i++ { // run twice — must not duplicate
		if err := installClaude(path, self); err != nil {
			t.Fatalf("installClaude run %d: %v", i, err)
		}
	}

	m := readBack(t, path)
	if m["model"] != "opus[1m]" {
		t.Errorf("existing setting lost: model=%v", m["model"])
	}
	pre := childArray(childObject(m, "hooks"), "PreToolUse")
	if !claudeHasOurHook(pre) {
		t.Fatal("our hook not present after install")
	}
	count := 0
	for _, e := range pre {
		em := e.(map[string]any)
		for _, h := range childArray(em, "hooks") {
			if isOurClaudeHook(h.(map[string]any)) {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 of our hooks, got %d (not idempotent)", count)
	}
}

// Claude: uninstall removes only our entry and keeps the rest.
func TestUninstallClaudeRemovesOnlyOurs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	seed := `{
      "model": "opus",
      "hooks": { "PreToolUse": [
        { "matcher": "Bash", "hooks": [ { "type": "command", "command": "echo keep" } ] }
      ]}
    }`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installClaude(path, "/usr/local/bin/agentguard"); err != nil {
		t.Fatal(err)
	}
	if err := uninstallClaude(path); err != nil {
		t.Fatal(err)
	}
	m := readBack(t, path)
	pre := childArray(childObject(m, "hooks"), "PreToolUse")
	if claudeHasOurHook(pre) {
		t.Error("our hook still present after uninstall")
	}
	// the user's pre-existing entry must survive
	found := false
	for _, e := range pre {
		em := e.(map[string]any)
		for _, h := range childArray(em, "hooks") {
			if c, _ := h.(map[string]any)["command"].(string); c == "echo keep" {
				found = true
			}
		}
	}
	if !found {
		t.Error("pre-existing user hook was wrongly removed")
	}
}

// Cursor: install creates gated events, is idempotent, and uninstall reverts.
func TestInstallUninstallCursor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	self := "/usr/local/bin/agentguard"

	for i := 0; i < 2; i++ {
		if err := installCursor(path, self); err != nil {
			t.Fatalf("installCursor run %d: %v", i, err)
		}
	}
	m := readBack(t, path)
	hooks := childObject(m, "hooks")
	for _, ev := range cursorEvents {
		arr := childArray(hooks, ev)
		if !cursorHasOurHook(arr) {
			t.Errorf("event %s missing our hook", ev)
		}
		n := 0
		for _, h := range arr {
			if cursorIsOurHook(h.(map[string]any)) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("event %s: expected 1 of our hooks, got %d", ev, n)
		}
	}

	if err := uninstallCursor(path); err != nil {
		t.Fatal(err)
	}
	m = readBack(t, path)
	hooks = childObject(m, "hooks")
	for _, ev := range cursorEvents {
		if cursorHasOurHook(childArray(hooks, ev)) {
			t.Errorf("event %s still has our hook after uninstall", ev)
		}
	}
}

// Refuse to clobber a corrupt config rather than silently destroying it.
func TestReadJSONObjectRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readJSONObject(path); err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}

// Secret scanner catches common secret shapes and a secret file attachment.
func TestScan(t *testing.T) {
	cases := []struct {
		name string
		req  ScanRequest
		want bool
	}{
		{"openai key in prompt", ScanRequest{Text: "use sk-abcdef0123456789ABCDEF01 please"}, true},
		{"aws key id", ScanRequest{Text: "AKIAIOSFODNN7EXAMPLE"}, true},
		{"private key block", ScanRequest{Text: "-----BEGIN RSA PRIVATE KEY-----\nMII..."}, true},
		{"secret assignment high entropy", ScanRequest{Text: "API_KEY=xQ9fK2mP7zR4aL8nW1bV"}, true},
		{"github token", ScanRequest{Text: "token ghp_0123456789012345678901234567890123ab"}, true},
		{"secret file attached", ScanRequest{Text: "look at this", Paths: []string{"/repo/.env"}}, true},
		{"benign prompt", ScanRequest{Text: "please refactor the login handler"}, false},
		{"benign attachment", ScanRequest{Text: "review", Paths: []string{"/repo/main.go"}}, false},
		// noise reduction: placeholders / env refs must NOT trip the scanner
		{"placeholder your_api_key", ScanRequest{Text: "api_key=your_api_key_here"}, false},
		{"env reference", ScanRequest{Text: "API_KEY=process.env.OPENAI_API_KEY"}, false},
		{"template reference", ScanRequest{Text: "api_key: ${OPENAI_API_KEY}"}, false},
		{"xxxx placeholder", ScanRequest{Text: "secret=xxxxxxxxxxxxxxxxxxxx"}, false},
		{"short value", ScanRequest{Text: "token=abc123"}, false},
		{"prose after keyword", ScanRequest{Text: "the api key is stored in the vault somewhere"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Scan(c.req).Found; got != c.want {
				t.Errorf("Scan(%q) found=%v, want %v", c.req, got, c.want)
			}
		})
	}
}

// Cursor install includes the beforeSubmitPrompt scan gate.
func TestCursorInstallsPromptScan(t *testing.T) {
	if !contains(cursorEvents, "beforeSubmitPrompt") {
		t.Fatal("beforeSubmitPrompt not in cursorEvents")
	}
}

// Cursor event translation maps onto the daemon's schema.
func TestCursorToEvent(t *testing.T) {
	shell, ok := cursorToEvent(map[string]any{"hook_event_name": "beforeShellExecution", "command": "rm -rf x"})
	if !ok || shell.ToolName != "Bash" || shell.ToolInput["command"] != "rm -rf x" {
		t.Errorf("shell mapping wrong: %+v ok=%v", shell, ok)
	}
	read, ok := cursorToEvent(map[string]any{"hook_event_name": "beforeReadFile", "file_path": "/repo/.env"})
	if !ok || read.ToolName != "Read" || read.ToolInput["file_path"] != "/repo/.env" {
		t.Errorf("read mapping wrong: %+v ok=%v", read, ok)
	}
	if _, ok := cursorToEvent(map[string]any{"hook_event_name": "afterAgentThought"}); ok {
		t.Error("non-gated event should not be gated")
	}
}

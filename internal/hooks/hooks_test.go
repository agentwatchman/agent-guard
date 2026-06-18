package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

// Cursor install includes the beforeSubmitPrompt scan gate.
func TestCursorInstallsPromptScan(t *testing.T) {
	if !slices.Contains(cursorEvents, "beforeSubmitPrompt") {
		t.Fatal("beforeSubmitPrompt not in cursorEvents")
	}
}

// underCursor detects Cursor-run hooks via the env vars Cursor documents as
// always present (CURSOR_PROJECT_DIR, CURSOR_VERSION).
func TestUnderCursor(t *testing.T) {
	for _, v := range []string{"CURSOR_PROJECT_DIR", "CURSOR_VERSION", "CURSOR_AGENT"} {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
	if underCursor() {
		t.Error("should be false when no Cursor env vars are set")
	}

	t.Setenv("CURSOR_VERSION", "1.7.2")
	if !underCursor() {
		t.Error("should be true when CURSOR_VERSION is set")
	}

	os.Unsetenv("CURSOR_VERSION")
	t.Setenv("CURSOR_PROJECT_DIR", "/repo")
	if !underCursor() {
		t.Error("should be true when CURSOR_PROJECT_DIR is set")
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

// preToolUse is the generic gate: it covers tools without a dedicated hook
// (e.g. WebFetch) and defers Shell/Read to their dedicated hooks.
func TestCursorPreToolUse(t *testing.T) {
	fetch, ok := cursorToEvent(map[string]any{
		"hook_event_name": "preToolUse",
		"tool_name":       "WebFetch",
		"tool_input":      map[string]any{"url": "https://example.com"},
	})
	if !ok {
		t.Fatal("WebFetch preToolUse should be gated")
	}
	if fetch.ToolName != "WebFetch" || fetch.ToolInput["url"] != "https://example.com" {
		t.Errorf("WebFetch mapping wrong: %+v", fetch)
	}
	if !fetch.ClientCannotAsk {
		t.Error("preToolUse must set ClientCannotAsk (Cursor can't render ask there)")
	}

	// Shell and Read are owned by their dedicated hooks — preToolUse defers.
	for _, tool := range []string{"Shell", "Read"} {
		if _, ok := cursorToEvent(map[string]any{"hook_event_name": "preToolUse", "tool_name": tool}); ok {
			t.Errorf("%s preToolUse should defer to its dedicated hook", tool)
		}
	}
}

// preToolUse is registered so Cursor gates all tools natively.
func TestCursorEventsIncludesPreToolUse(t *testing.T) {
	if !slices.Contains(cursorEvents, "preToolUse") {
		t.Error("preToolUse not in cursorEvents")
	}
}

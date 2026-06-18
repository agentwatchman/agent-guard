package hooks

// Agent describes one supported coding agent: its identity, where its hook
// config lives, how to (un)install our hook entries, and the runtime handler
// that hook entry invokes. The whole package is driven off the registry below,
// so adding support for a new agent is a single append here — install,
// uninstall, CLI flags, and runtime dispatch all pick it up automatically.
type Agent struct {
	Name       string                   // audit identifier, e.g. "claude-code"
	Label      string                   // human label, e.g. "Claude Code"
	Flag       string                   // install/uninstall CLI flag, e.g. "claude"
	HookCmd    string                   // subcommand + config marker, e.g. "claude-hook"
	installMsg string                   // suffix in the "installed <label> ..." line
	configPath func(home string) string // absolute path to the agent's hook config
	install    func(path, self string) error
	uninstall  func(path string) error
	run        func() // runtime handler (reads stdin, writes stdout)
}

// agents is the registry of supported coding agents, in display order.
var agents = []*Agent{
	{
		Name:       agentClaude,
		Label:      "Claude Code",
		Flag:       "claude",
		HookCmd:    claudeMarker,
		installMsg: "hooks (PreToolUse + UserPromptSubmit)",
		configPath: claudeSettingsPath,
		install:    installClaude,
		uninstall:  uninstallClaude,
		run:        ClaudeHook,
	},
	{
		Name:       agentCursor,
		Label:      "Cursor",
		Flag:       "cursor",
		HookCmd:    cursorMarker,
		installMsg: "hooks",
		configPath: cursorHooksPath,
		install:    installCursor,
		uninstall:  uninstallCursor,
		run:        CursorHook,
	},
	{
		Name:       agentCodex,
		Label:      "Codex",
		Flag:       "codex",
		HookCmd:    codexMarker,
		installMsg: "hooks (PreToolUse + UserPromptSubmit)",
		configPath: codexHooksPath,
		install:    installCodex,
		uninstall:  uninstallCodex,
		run:        CodexHook,
	},
}

// HandlerFor returns the runtime handler registered for a hook subcommand
// (e.g. "claude-hook"), so main can dispatch without enumerating agents.
func HandlerFor(cmd string) (func(), bool) {
	for _, a := range agents {
		if a.HookCmd == cmd {
			return a.run, true
		}
	}
	return nil, false
}

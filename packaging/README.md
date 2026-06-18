# Distributing AgentGuard

Two supported install paths. Both run the daemon in the **background** (no
terminal to keep open) and need **no code-signing** for the pilot, because the
binary is compiled locally on each machine.

Replace `OWNER` with your GitHub org/user throughout.

---

## Option A — Homebrew tap (private repo)

Best long-term developer experience. The formula builds from source, so the
only requirement is **read access to the private repo**.

### 1. Create the tap repo

A Homebrew tap is just a git repo named `homebrew-<name>`. Create a private
`OWNER/homebrew-tap` and put the formula at `Formula/agentguard.rb`:

```
homebrew-tap/                  (private repo)
└── Formula/
    └── agentguard.rb          (copy of packaging/homebrew/agentguard.rb)
```

Edit the formula's `OWNER`, and either point `url`/`sha256` at a tagged release
tarball or rely on `--HEAD` (below).

### 2. Each developer installs

Because the repo is private, the source fetch needs auth — either an SSH tap or
a token:

```bash
# token approach (PAT with 'repo' read scope)
export HOMEBREW_GITHUB_API_TOKEN=ghp_xxx
brew tap OWNER/tap https://github.com/OWNER/homebrew-tap

# or SSH approach
brew tap OWNER/tap git@github.com:OWNER/homebrew-tap.git

# install (use --HEAD to build the latest main without a tagged release)
brew install OWNER/tap/agentguard          # from a tagged release
brew install --HEAD OWNER/tap/agentguard   # from main

# run it in the background, starting at login
brew services start agentguard
```

This is normal for an internal tool: private repo + each dev authenticated. See
`packaging/homebrew/agentguard.rb` for the formula and its caveats.

---

## Option B — Clone + `make install` (simplest for the pilot)

For a handful of devs who already have repo access, skip Homebrew entirely:

```bash
git clone git@github.com:OWNER/agentguard.git
cd agentguard
make install          # builds, installs to /usr/local, loads launchd agent
```

`make install`:
- builds `bin/agentguard`
- copies it to `/usr/local/bin/agentguard`
- installs the default config to `/usr/local/etc/agentguard/config.json`
  (existing config is preserved)
- installs `~/Library/LaunchAgents/com.agentguard.daemon.plist` and starts it

Useful targets:

```bash
make service-status     # is the background agent running?
make service-restart    # after editing the config
make uninstall          # remove binary + service (config kept)
make install PREFIX=/opt # custom prefix
```

---

## Wiring the AI agents to the daemon

One command — it auto-detects Claude Code and Cursor and **safely merges** into
any existing config (backs up to `*.bak`, idempotent, atomic write):

```bash
agentguard install-hooks            # both, auto-detected
agentguard install-hooks --claude   # just Claude Code
agentguard install-hooks --cursor   # just Cursor
agentguard uninstall-hooks          # cleanly remove our entries
```

`make install` runs `install-hooks` for you. What it writes:

- **Claude Code** → `~/.claude/settings.json`: a `PreToolUse` command hook
  running `agentguard claude-hook`.
- **Cursor** → `~/.cursor/hooks.json`: `beforeShellExecution` + `beforeReadFile`
  + `beforeSubmitPrompt` command hooks running `agentguard cursor-hook`, with
  `failClosed: true`. `beforeSubmitPrompt` is a ggshield-style secret scanner
  that blocks a prompt (or attached file) containing secrets before it's sent —
  closing the gap where content already in Cursor's context bypasses the
  per-tool read hook.

Both hook handlers translate their agent's event into the daemon's schema and
forward it over the **Unix socket** (`~/.agentguard/agentguard.sock`) — so both
agents share one policy engine and one audit log, and there's no TCP port to
conflict with.

> Cursor `beforeMCPExecution` is intentionally **not** wired yet: Cursor's MCP
> payload doesn't expose the server name our allowlist needs, so gating it would
> risk false-blocking. Tracked as a follow-up.

> Both agents **fail closed**: if the daemon is unreachable the hook denies the
> action rather than letting it through. The launchd/`brew services` setup with
> `KeepAlive` keeps the daemon up and restarts it on crash.

### Manual / MDM templates

For fleet rollout via MDM (no per-user command), push these templates into the
managed locations instead of running `install-hooks`:

- Cursor: `packaging/cursor/hooks.json` → `~/.cursor/hooks.json` or
  `/Library/Application Support/Cursor/hooks.json` (system-wide).
- Claude Code: `packaging/claude/settings.json` → `~/.claude/settings.json` or
  Claude's enterprise managed settings.

Both templates assume the binary at `/usr/local/bin/agentguard` — edit the
command path if you install elsewhere.

---

## Background on macOS (what `brew services` / `make install` do under the hood)

Both register a **launchd LaunchAgent** (`com.agentguard.daemon`) with
`RunAtLoad` + `KeepAlive`, so the daemon starts at login, survives reboots, and
auto-restarts. The standalone template lives at
`packaging/launchd/com.agentguard.daemon.plist`.

## Linux

The equivalent of the LaunchAgent is a **systemd user service**
(`~/.config/systemd/user/agentguard.service` + `systemctl --user enable --now
agentguard`). Not scripted yet — add when Linux dev machines join the pilot.

## Signing (later)

Building from source avoids Gatekeeper for now. Once you distribute **prebuilt**
binaries (faster installs, no Go toolchain needed), codesign + notarize them with
an Apple Developer ID, or downloads will be quarantined.

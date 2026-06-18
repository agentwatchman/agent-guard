# AgentGuard Homebrew formula.
#
# Builds from source (depends_on "go"), so:
#   * no prebuilt binary needs to be hosted, and
#   * the binary is compiled locally => no macOS Gatekeeper quarantine and
#     no code-signing/notarization required for the pilot.
#
# The only requirement is read access to the (private) source repo. Set a token
# so Homebrew can fetch the private tarball:
#   export HOMEBREW_GITHUB_API_TOKEN=ghp_xxx   # PAT with 'repo' (read) scope
#
# To ship: put this file in a tap repo named `homebrew-tap` at
# `Formula/agentguard.rb`, then:
#   brew tap OWNER/tap git@github.com:OWNER/homebrew-tap.git
#   brew install OWNER/tap/agentguard
#   brew services start agentguard
#
# Replace OWNER and the release url/sha256 (or just use `--HEAD`) before use.
class Agentguard < Formula
  desc "Local-first runtime guardrails for AI coding agents (Claude Code, Cursor)"
  homepage "https://github.com/OWNER/agentguard"
  url "https://github.com/OWNER/agentguard/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_TARBALL_SHA256"
  license :cannot_represent # proprietary / private
  head "https://github.com/OWNER/agentguard.git", branch: "main"

  depends_on "go" => :build

  def install
    # Compiles ./main.go + ./policy.go into `agentguard`.
    system "go", "build", *std_go_args(ldflags: "-s -w"), "."

    # Install the default policy config without clobbering a user's edits on
    # upgrade (Homebrew preserves files written into `etc`).
    (etc/"agentguard").install "config.json" unless (etc/"agentguard/config.json").exist?
  end

  # `brew services start agentguard` runs this as a background launchd agent.
  service do
    run [opt_bin/"agentguard", "--config", etc/"agentguard/config.json"]
    keep_alive true
    run_type :immediate
    log_path var/"log/agentguard.log"
    error_log_path var/"log/agentguard.log"
  end

  def caveats
    <<~EOS
      AgentGuard installed. Two steps to finish:

      1) Run it in the background (no terminal needed):

           brew services start agentguard

      2) Wire your AI coding agents to it (safely merges into existing config,
         auto-detects Claude Code + Cursor):

           agentguard install-hooks

      It listens on a local Unix socket (~/.agentguard/agentguard.sock) — no TCP
      port — and writes a redacted audit log to ~/.agentguard/audit.log. Tune
      allowlists in:

        #{etc}/agentguard/config.json   (then: brew services restart agentguard)

      To remove the agent hooks later:  agentguard uninstall-hooks
    EOS
  end

  test do
    # Bring up the daemon on a test socket; the claude-hook handler should reach
    # it and deny a secret read.
    sock = testpath/"ag.sock"
    pid = spawn({ "AGENTGUARD_SOCKET" => sock.to_s }, bin/"agentguard", "--config", etc/"agentguard/config.json")
    sleep 1
    begin
      out = pipe_output(
        "AGENTGUARD_SOCKET=#{sock} #{bin}/agentguard claude-hook",
        '{"tool_name":"Read","tool_input":{"file_path":"/repo/.env"}}',
      )
      assert_match "deny", out
    ensure
      Process.kill("TERM", pid)
    end
  end
end

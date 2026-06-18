// Package policy is AgentGuard's command/tool-call decision engine: given a
// hook event and the team config, it returns allow / deny / ask.
package policy

import (
	"regexp"
	"strings"

	"agentguard/internal/scan"
	"agentguard/internal/types"
)

// Detection patterns — fast, deterministic, explainable. (Secret-file paths are
// detected via scan.IsSecretPath so the policy engine and the scanner share one
// definition of "sensitive file".)
var (
	destructive = regexp.MustCompile(`rm\s+-rf|git\s+push\s+.*--force|git\s+reset\s+--hard|DROP\s+(TABLE|DATABASE)|chmod\s+777|mkfs`)
	netExfil    = regexp.MustCompile(`\b(curl|wget|nc|ncat|scp|telnet)\b`)
	urlHost     = regexp.MustCompile(`https?://([a-zA-Z0-9.\-]+)`)
)

// extract pulls the relevant fields out of the tool input.
//
// fetchURL is the target of an agent-native fetch tool (Claude's WebFetch,
// Cursor's web fetch, etc.) whose URL lives in a `url`/`uri` field rather than a
// shell command — so the shell-based egress check (netExfil over `command`)
// never sees it. We deliberately skip MCP tools here: they carry their own URLs
// but are governed by the separate approved_mcp gate below.
func extract(e types.HookEvent) (cmd, filePath, mcpServer, fetchURL string) {
	get := func(k string) string {
		if v, ok := e.ToolInput[k].(string); ok {
			return v
		}
		return ""
	}
	cmd = get("command")        // Bash
	filePath = get("file_path") // Read / Edit / Write
	if strings.HasPrefix(e.ToolName, "mcp__") {
		if parts := strings.Split(e.ToolName, "__"); len(parts) >= 2 {
			mcpServer = parts[1]
		}
		return
	}
	fetchURL = get("url")
	if fetchURL == "" {
		fetchURL = get("uri")
	}
	return
}

// Evaluate runs the policy. Order matters: highest-severity first.
func Evaluate(cfg types.Config, e types.HookEvent) types.HookResponse {
	cmd, filePath, mcpServer, fetchURL := extract(e)

	readsSecret := scan.IsSecretPath(filePath) || (cmd != "" && scan.IsSecretPath(cmd))
	touchesNet := netExfil.MatchString(cmd)

	// 1) Highest-confidence hijack: read a secret AND push it over the network.
	if readsSecret && touchesNet {
		return types.Decide(types.Deny, "Reads a secret and sends it over the network (exfiltration pattern).")
	}

	// 2) Any access to secret material.
	if readsSecret {
		return types.Decide(types.Deny, "Access to secrets/credentials is not permitted for the agent.")
	}

	// 3) Egress control — outbound network must target an approved domain. This
	// covers both shell network tools (curl/wget/…) and agent-native fetch tools
	// (WebFetch/…) under the SAME allowlist. An unresolvable host fails closed to
	// ask, never allow.
	if touchesNet {
		if host := hostOf(cmd); !domainAllowed(host, cfg.AllowedEgress) {
			return types.Decide(types.Ask, "Network call to unapproved domain ("+host+") — needs approval.")
		}
	}
	if fetchURL != "" {
		if host := hostOf(fetchURL); !domainAllowed(host, cfg.AllowedEgress) {
			return types.Decide(types.Ask, "Web fetch to unapproved domain ("+host+") — needs approval.")
		}
	}

	// 4) Destructive actions — require explicit confirmation.
	if destructive.MatchString(cmd) {
		return types.Decide(types.Ask, "Destructive command detected — confirm before running.")
	}

	// 5) MCP vetting — only approved servers.
	if mcpServer != "" && !contains(cfg.ApprovedMCP, mcpServer) {
		return types.Decide(types.Deny, "MCP server '"+mcpServer+"' is not on the approved list.")
	}

	return types.Decide(types.Allow, "")
}

// hostOf pulls the hostname out of the first http(s) URL in s, or "" if there
// is none (e.g. a scheme-less URL), which callers treat as not-allowed.
func hostOf(s string) string {
	if m := urlHost.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

func domainAllowed(host string, allow []string) bool {
	if host == "" {
		return false
	}
	for _, d := range allow {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

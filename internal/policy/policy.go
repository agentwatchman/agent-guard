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

// signals are the parsed inputs a rule reasons over — computed once per event so
// rules stay cheap and declarative.
type signals struct {
	cfg         types.Config
	cmd         string
	mcpServer   string
	fetchURL    string
	readsSecret bool
	touchesNet  bool
}

// rule is one policy check. Each has a stable id (for audit attribution and the
// disabled_rules toggle) and a severity. Rules are evaluated in order and the
// FIRST match wins, so higher-severity / more-specific rules come first.
type rule struct {
	id       string
	severity string
	eval     func(s signals) (types.HookResponse, bool)
}

// rules is the ordered policy pipeline. To add a check, append a rule — no need
// to touch Evaluate. Order encodes precedence (most severe first).
var rules = []rule{
	{
		id: "secret-network-exfiltration", severity: "critical",
		eval: func(s signals) (types.HookResponse, bool) {
			if s.readsSecret && s.touchesNet {
				return types.Decide(types.Deny, "Reads a secret and sends it over the network (exfiltration pattern)."), true
			}
			return types.HookResponse{}, false
		},
	},
	{
		id: "secret-access", severity: "high",
		eval: func(s signals) (types.HookResponse, bool) {
			if s.readsSecret {
				return types.Decide(types.Deny, "Access to secrets/credentials is not permitted for the agent."), true
			}
			return types.HookResponse{}, false
		},
	},
	{
		// Egress for shell network tools (curl/wget/…). An unresolvable host
		// fails closed to ask, never allow.
		id: "egress-shell", severity: "medium",
		eval: func(s signals) (types.HookResponse, bool) {
			if s.touchesNet {
				if host := hostOf(s.cmd); !domainAllowed(host, s.cfg.AllowedEgress) {
					return types.Decide(types.Ask, "Network call to unapproved domain ("+host+") — needs approval."), true
				}
			}
			return types.HookResponse{}, false
		},
	},
	{
		// Egress for agent-native fetch tools (WebFetch/…), same allowlist.
		id: "egress-fetch", severity: "medium",
		eval: func(s signals) (types.HookResponse, bool) {
			if s.fetchURL != "" {
				if host := hostOf(s.fetchURL); !domainAllowed(host, s.cfg.AllowedEgress) {
					return types.Decide(types.Ask, "Web fetch to unapproved domain ("+host+") — needs approval."), true
				}
			}
			return types.HookResponse{}, false
		},
	},
	{
		id: "destructive-command", severity: "medium",
		eval: func(s signals) (types.HookResponse, bool) {
			if destructive.MatchString(s.cmd) {
				return types.Decide(types.Ask, "Destructive command detected — confirm before running."), true
			}
			return types.HookResponse{}, false
		},
	},
	{
		id: "unapproved-mcp", severity: "high",
		eval: func(s signals) (types.HookResponse, bool) {
			if s.mcpServer != "" && !contains(s.cfg.ApprovedMCP, s.mcpServer) {
				return types.Decide(types.Deny, "MCP server '"+s.mcpServer+"' is not on the approved list."), true
			}
			return types.HookResponse{}, false
		},
	},
}

// Decision is the full result of evaluating an event: the response plus which
// rule produced it (for the audit log / dashboards). RuleID/Severity are empty
// when nothing matched (allow).
type Decision struct {
	Response types.HookResponse
	RuleID   string
	Severity string
}

// EvaluateDetailed runs the policy pipeline and reports which rule fired.
func EvaluateDetailed(cfg types.Config, e types.HookEvent) Decision {
	cmd, filePath, mcpServer, fetchURL := extract(e)
	s := signals{
		cfg:         cfg,
		cmd:         cmd,
		mcpServer:   mcpServer,
		fetchURL:    fetchURL,
		readsSecret: scan.IsSecretPath(filePath) || (cmd != "" && scan.IsSecretPath(cmd)),
		touchesNet:  netExfil.MatchString(cmd),
	}
	for _, r := range rules {
		if contains(cfg.DisabledRules, r.id) {
			continue
		}
		if resp, matched := r.eval(s); matched {
			return Decision{Response: resp, RuleID: r.id, Severity: r.severity}
		}
	}
	return Decision{Response: types.Decide(types.Allow, "")}
}

// Evaluate runs the policy and returns just the decision (back-compat helper).
func Evaluate(cfg types.Config, e types.HookEvent) types.HookResponse {
	return EvaluateDetailed(cfg, e).Response
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

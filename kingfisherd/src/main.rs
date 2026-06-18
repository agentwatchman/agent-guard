// kingfisherd — resident Kingfisher secret scanner for AgentGuard.
//
// The Kingfisher CLI recompiles its 950+ Hyperscan rules on every invocation
// (~4s), which is far too slow for a synchronous, per-prompt guardrail hook.
// This daemon pays that compilation cost ONCE at startup, holds the compiled
// RulesDatabase in memory, and then answers scan requests in milliseconds over a
// Unix domain socket — giving AgentGuard's inline scanner Kingfisher's full rule
// coverage without the latency.
//
// Protocol (deliberately minimal, no HTTP framework):
//   client connects -> writes the raw bytes to scan -> half-closes (EOF)
//   server scans     -> writes one JSON object -> closes
//   response: {"found": bool, "findings": [{"rule_name": "...", "rule_id": "..."}]}
//
// All distinct findings are returned (deduped by rule id) so a multi-secret
// input is fully reported, not just its first hit.
//
// No secret material is logged or sent anywhere: scanning is fully local and we
// never enable validation (which would call provider APIs).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::{env, fs, thread};

use anyhow::Result;
use kingfisher_rules::{get_builtin_rules, Rule, RulesDatabase};
use kingfisher_scanner::Scanner;
use serde::Serialize;

#[derive(Serialize)]
struct FindingOut {
    rule_name: String,
    rule_id: String,
}

#[derive(Serialize, Default)]
struct Resp {
    found: bool,
    findings: Vec<FindingOut>,
}

fn default_socket() -> String {
    if let Ok(p) = env::var("AGENTGUARD_KINGFISHERD_SOCKET") {
        if !p.is_empty() {
            return p;
        }
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.agentguard/kingfisherd.sock")
}

fn parse_socket_arg() -> String {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--socket" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        i += 1;
    }
    default_socket()
}

// build_scanner loads the builtin rules and compiles them into a database. This
// is the expensive step (~seconds) — done exactly once, at startup.
fn build_scanner() -> Result<Scanner> {
    let rules = get_builtin_rules(None)?;
    let rule_vec: Vec<Rule> = rules.iter_rules().map(|s| Rule::new(s.clone())).collect();
    let db = Arc::new(RulesDatabase::from_rules(rule_vec)?);
    Ok(Scanner::new(db))
}

fn handle(scanner: &Scanner, mut stream: UnixStream) {
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return;
    }
    let findings = scanner.scan_bytes(&buf);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for f in &findings {
        // Dedupe by rule id so N keys of the same kind report as one entry.
        if seen.insert(f.rule_id.clone()) {
            out.push(FindingOut {
                rule_name: f.rule_name.clone(),
                rule_id: f.rule_id.clone(),
            });
        }
    }
    let resp = Resp {
        found: !out.is_empty(),
        findings: out,
    };
    let _ = serde_json::to_writer(&mut stream, &resp);
    let _ = stream.flush();
}

fn main() -> Result<()> {
    let socket = parse_socket_arg();

    eprintln!("kingfisherd: compiling builtin rules (one-time)...");
    let scanner = Arc::new(build_scanner()?);
    eprintln!("kingfisherd: rules compiled, scanner ready");

    if let Some(dir) = std::path::Path::new(&socket).parent() {
        let _ = fs::create_dir_all(dir);
    }
    // Clear any stale socket left by a previous crash, then bind.
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600));
    }
    eprintln!("kingfisherd: listening on {socket}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let sc = Arc::clone(&scanner);
                thread::spawn(move || handle(&sc, s));
            }
            Err(e) => eprintln!("kingfisherd: accept error: {e}"),
        }
    }
    Ok(())
}

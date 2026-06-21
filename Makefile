.PHONY: build run run-local test release clean install uninstall deploy setup bootstrap doctor purge service-restart service-reload service-status \
        build-kingfisher install-kingfisher uninstall-kingfisher svc-install-macos svc-install-linux svc-remove-macos svc-remove-linux

# Where the manual (non-Homebrew) install puts things. Override with: make install PREFIX=/opt
PREFIX ?= /usr/local
LABEL   = com.agentguard.daemon
PLIST   = $(HOME)/Library/LaunchAgents/$(LABEL).plist
# Policy config lives in the user's home (no sudo to edit) and the daemon
# auto-reloads it on change.
USERCFG = $(HOME)/.agentguard/config.json

# Resident Kingfisher scanner (optional; gives inline scans the full rule set).
KFLABEL  = com.agentguard.kingfisherd
KFPLIST  = $(HOME)/Library/LaunchAgents/$(KFLABEL).plist
KFSOCKET = $(HOME)/.agentguard/kingfisherd.sock

# --- OS detection: macOS (launchd) vs Linux (systemd) ----------------------
# Detect the platform once, then define per-OS commands so the targets below
# stay platform-agnostic and `make <target>` works on both.
#   - one-liner differences (status/restart/reload) -> command variables
#   - multi-step differences (install/uninstall)     -> a TARGET NAME to dispatch to
UNAME := $(shell uname -s)

ifeq ($(UNAME),Darwin)
  # ---- macOS / launchd ----
  BIN_PATH    := $(PREFIX)/bin/agentguard
  BIN_INSTALL := sudo install -d "$(PREFIX)/bin" && sudo install -m 0755 bin/agentguard "$(PREFIX)/bin/agentguard"
  BIN_REMOVE  := sudo rm -f "$(PREFIX)/bin/agentguard"
  SVC_INSTALL := svc-install-macos
  SVC_REMOVE  := svc-remove-macos
  SVC_STATUS  := launchctl print gui/$$(id -u)/$(LABEL) | grep -E 'state|pid' || echo "not loaded"
  SVC_RESTART := launchctl kickstart -k gui/$$(id -u)/$(LABEL)
  SVC_RELOAD  := launchctl kill SIGHUP gui/$$(id -u)/$(LABEL) && echo "sent SIGHUP - config reloaded (check: make service-status or tail /tmp/agentguard.err.log)"
else
  # ---- Linux / systemd user service ----
  BIN_PATH    := $(HOME)/.local/bin/agentguard
  BIN_INSTALL := install -d "$(HOME)/.local/bin" && install -m 0755 bin/agentguard "$(HOME)/.local/bin/agentguard"
  BIN_REMOVE  := rm -f "$(HOME)/.local/bin/agentguard"
  SVC_INSTALL := svc-install-linux
  SVC_REMOVE  := svc-remove-linux
  SVC_STATUS  := systemctl --user status agentguard
  SVC_RESTART := systemctl --user restart agentguard
  SVC_RELOAD  := systemctl --user reload agentguard && echo "sent SIGHUP via systemd - config reloaded"
endif

# Local build
build:
	go build -o bin/agentguard ./cmd/agentguard

# Run the daemon with the example config
run: build
	./bin/agentguard --config config.json

# Run with the local (gitignored) config — used to test cloud shipping against
# the preview control plane in tools/cloud-preview/ without committing settings.
run-local: build
	./bin/agentguard --config config.local.json

# Run the smoke test (daemon must already be running)
test:
	chmod +x test.sh && ./test.sh

# Cross-compile signed-ready binaries for the platforms Fyxer's devs use.
# (Signing/notarization happens in your release pipeline, not here.)
release:
	GOOS=darwin  GOARCH=arm64 go build -o dist/agentguard-darwin-arm64 ./cmd/agentguard
	GOOS=darwin  GOARCH=amd64 go build -o dist/agentguard-darwin-amd64 ./cmd/agentguard
	GOOS=linux   GOARCH=amd64 go build -o dist/agentguard-linux-amd64 ./cmd/agentguard
	GOOS=windows GOARCH=amd64 go build -o dist/agentguard-windows-amd64.exe ./cmd/agentguard

# --- Manual install path (no Homebrew) -------------------------------------
# Installs the binary + config, then registers the background service for the
# host OS (launchd on macOS, systemd --user on Linux) so the daemon runs at
# login. Cross-platform: the OS-specific steps live in the svc-install-* targets,
# selected by $(SVC_INSTALL) in the OS-detection block above.
install: build
	$(BIN_INSTALL)
	mkdir -p "$(HOME)/.agentguard"
	@[ -f "$(USERCFG)" ] \
		&& echo "keeping existing $(USERCFG)" \
		|| install -m 0644 config.json "$(USERCFG)"
	$(MAKE) $(SVC_INSTALL)
	@echo "Policy config: $(USERCFG) (edit it — the daemon auto-reloads within ~2s)"
	@echo "Wiring detected AI agents (Claude Code / Cursor / Codex)..."
	"$(BIN_PATH)" install-hooks

# macOS service registration (launchd). Dispatched to via $(SVC_INSTALL).
svc-install-macos:
	mkdir -p "$(HOME)/Library/LaunchAgents"
	sed -e 's#/usr/local/bin/agentguard#$(PREFIX)/bin/agentguard#' \
	    -e 's#CONFIG_PATH#$(USERCFG)#' \
	    packaging/launchd/$(LABEL).plist > "$(PLIST)"
	@# Robustly (re)load: clear any prior registration via BOTH the modern
	@# (bootout) and legacy (unload/remove) APIs first, otherwise a half-
	@# registered label makes bootstrap fail with "5: Input/output error".
	@launchctl bootout gui/$$(id -u)/$(LABEL) 2>/dev/null; \
	 launchctl bootout gui/$$(id -u) "$(PLIST)" 2>/dev/null; \
	 launchctl unload "$(PLIST)" 2>/dev/null; \
	 launchctl remove $(LABEL) 2>/dev/null; \
	 sleep 1; \
	 launchctl bootstrap gui/$$(id -u) "$(PLIST)" 2>/dev/null \
	   || launchctl load -w "$(PLIST)" \
	   || launchctl kickstart -k gui/$$(id -u)/$(LABEL)
	@echo "AgentGuard running in the background (launchd: $(LABEL))"

# Linux service registration (systemd user service). Dispatched to via $(SVC_INSTALL).
svc-install-linux:
	mkdir -p "$(HOME)/.config/systemd/user"
	cp packaging/systemd/agentguard.service "$(HOME)/.config/systemd/user/agentguard.service"
	systemctl --user daemon-reload
	systemctl --user enable --now agentguard
	@echo "AgentGuard running in the background (systemd --user: agentguard.service)"

uninstall:
	-"$(BIN_PATH)" uninstall-hooks 2>/dev/null
	$(MAKE) $(SVC_REMOVE)
	$(BIN_REMOVE)
	@echo "Removed binary + service + agent hooks. Config kept at $(USERCFG) (delete manually if desired)."

# macOS service removal (launchd). Dispatched to via $(SVC_REMOVE).
svc-remove-macos:
	-launchctl bootout gui/$$(id -u)/$(LABEL) 2>/dev/null
	rm -f "$(PLIST)"

# Linux service removal (systemd user service). Dispatched to via $(SVC_REMOVE).
svc-remove-linux:
	-systemctl --user disable --now agentguard 2>/dev/null
	rm -f "$(HOME)/.config/systemd/user/agentguard.service"
	systemctl --user daemon-reload

# --- Complete teardown -----------------------------------------------------
# Removes EVERYTHING AgentGuard installed: both binaries, both launchd services,
# the Claude Code / Cursor hooks, the installed config, and all local state
# (~/.agentguard: sockets, audit log). Use before a from-scratch reinstall test.
# Leaves toolchains (go/rust/cmake/boost) untouched — those are yours.
purge:
	-"$(PREFIX)/bin/agentguard" uninstall-hooks 2>/dev/null
	-pkill -f 'agentguard --config' 2>/dev/null
	-pkill -f 'kingfisherd' 2>/dev/null
	-launchctl bootout gui/$$(id -u)/$(LABEL) 2>/dev/null
	-launchctl bootout gui/$$(id -u)/$(KFLABEL) 2>/dev/null
	-launchctl unload "$(PLIST)" 2>/dev/null
	-launchctl unload "$(KFPLIST)" 2>/dev/null
	-launchctl remove $(LABEL) 2>/dev/null
	-launchctl remove $(KFLABEL) 2>/dev/null
	rm -f "$(PLIST)" "$(KFPLIST)"
	sudo rm -f "$(PREFIX)/bin/agentguard" "$(PREFIX)/bin/kingfisherd"
	sudo rm -rf "$(PREFIX)/etc/agentguard"
	rm -rf "$(HOME)/.agentguard"
	@echo ""
	@echo "Purged: binaries, launchd services, agent hooks, config, and ~/.agentguard."
	@echo "Toolchains were left alone. Verify a clean slate with: make doctor"

# --- Preflight check -------------------------------------------------------
# Reports which toolchains are present before building, so you get a clear
# shopping list instead of a confusing mid-build failure. Required: go.
# Optional (only for kingfisherd): cargo (Rust), cmake, boost — if any are
# missing, the agent still deploys on the builtin scanner.
doctor:
	@ok=1; \
	echo "AgentGuard preflight"; \
	echo "===================="; \
	if command -v go >/dev/null 2>&1; then \
		echo "  [ok]      go      $$(go version | awk '{print $$3}')  (required)"; \
	else \
		echo "  [MISSING] go              (required)  ->  brew install go   (or https://go.dev/dl)"; ok=0; \
	fi; \
	if command -v cargo >/dev/null 2>&1 || [ -x "$$HOME/.cargo/bin/cargo" ]; then \
		echo "  [ok]      cargo           (kingfisherd)"; \
	else \
		echo "  [warn]    cargo           (kingfisherd)  ->  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
	fi; \
	if command -v cmake >/dev/null 2>&1; then \
		echo "  [ok]      cmake           (kingfisherd)"; \
	else \
		echo "  [warn]    cmake           (kingfisherd)  ->  brew install cmake"; \
	fi; \
	if [ -d "$(BREW_PREFIX)/include/boost" ] || brew list boost >/dev/null 2>&1; then \
		echo "  [ok]      boost           (kingfisherd)"; \
	else \
		echo "  [warn]    boost           (kingfisherd)  ->  brew install boost"; \
	fi; \
	echo ""; \
	if [ $$ok -eq 0 ]; then \
		echo "Missing a REQUIRED tool — install it and re-run. Aborting."; \
		exit 1; \
	fi; \
	echo "Required tools present. [warn] items only disable kingfisherd (agent still runs on the builtin scanner)."

# --- Bootstrap toolchains (invasive) ---------------------------------------
# Installs the build prerequisites: go/cmake/boost via Homebrew and Rust via the
# official rustup installer. Idempotent — skips anything already present. macOS
# only. This MODIFIES your system, so it's kept out of `deploy`; use `make setup`
# to bootstrap then deploy in one go.
bootstrap:
	@command -v brew >/dev/null 2>&1 || { \
		echo "Homebrew is required but not installed — get it from https://brew.sh, then re-run."; \
		exit 1; \
	}
	@if command -v go >/dev/null 2>&1; then echo "  go: present"; else echo ">> installing go...";   brew install go; fi
	@if command -v cmake >/dev/null 2>&1; then echo "  cmake: present"; else echo ">> installing cmake..."; brew install cmake; fi
	@if [ -d "$(BREW_PREFIX)/include/boost" ] || brew list boost >/dev/null 2>&1; then echo "  boost: present"; else echo ">> installing boost..."; brew install boost; fi
	@if command -v cargo >/dev/null 2>&1 || [ -x "$$HOME/.cargo/bin/cargo" ]; then echo "  rust: present"; else \
		echo ">> installing Rust (rustup)..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	fi
	@echo ""
	@echo "Bootstrap complete."

# --- Fresh machine -> running agent, in one command ------------------------
# Installs every prerequisite (bootstrap) then builds + installs + wires up
# everything (deploy). The do-everything path. Adds ~/.cargo/bin to PATH so a
# freshly installed Rust is found without opening a new shell.
setup: bootstrap
	@PATH="$$HOME/.cargo/bin:$(BREW_PREFIX)/bin:$$PATH" $(MAKE) deploy

# --- One command to rule them all ------------------------------------------
# Builds + installs the daemon, wires up Claude Code / Cursor / Codex hooks, and (best
# effort) builds + installs the resident Kingfisher scanner. kingfisherd is
# optional: if the Rust toolchain isn't present the build is skipped and inline
# scans use the builtin scanner. Prompts for your sudo password once.
# Runs the preflight check first so missing tools fail fast with guidance.
deploy: doctor install
	@echo ""
	@echo ">> Building resident Kingfisher scanner (optional)..."
	@$(MAKE) install-kingfisher || { \
		echo ""; \
		echo ">> Skipped kingfisherd (Rust toolchain or build deps missing)."; \
		echo ">> Inline scans use the builtin scanner. To enable Kingfisher's 950+ rules:"; \
		echo ">>   brew install cmake boost && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		echo ">>   source ~/.cargo/env && make install-kingfisher"; \
	}
	@echo ""
	@echo "================================================================"
	@echo " AgentGuard is deployed and running."
	@echo "   daemon:   $(PREFIX)/bin/agentguard  (launchd: $(LABEL))"
	@echo "   hooks:    Claude Code / Cursor / Codex (detected agents wired — see above)"
	@echo "   inline:   kingfisherd if present, else builtin scanner"
	@echo "================================================================"

# --- Resident Kingfisher scanner (optional) --------------------------------
# Requires the Rust toolchain (>= 1.94) plus cmake and boost (Vectorscan build
# deps):
#   brew install cmake boost
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # then: source ~/.cargo/env
#   (or, with Homebrew's keg-only rustup: export PATH="$(brew --prefix rustup)/bin:$PATH" && rustup default stable)
# Once installed, AgentGuard's inline scanner automatically uses kingfisherd
# (detected via its socket) and falls back to the builtin scanner if it's down.
BREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /usr/local)
# Find cargo no matter how Rust was installed (rustup script -> ~/.cargo/bin,
# Homebrew keg-only rustup -> $(brew --prefix rustup)/bin, or already on PATH).
CARGO_PATH := $(HOME)/.cargo/bin:$(BREW_PREFIX)/opt/rustup/bin:$(PATH)
build-kingfisher:
	cd kingfisherd && PATH="$(CARGO_PATH)" BOOST_ROOT="$(BREW_PREFIX)" CMAKE_PREFIX_PATH="$(BREW_PREFIX)" cargo build --release

install-kingfisher: build-kingfisher
	sudo install -m 0755 kingfisherd/target/release/kingfisherd "$(PREFIX)/bin/kingfisherd"
	mkdir -p "$(HOME)/Library/LaunchAgents"
	sed -e 's#/usr/local/bin/kingfisherd#$(PREFIX)/bin/kingfisherd#' \
	    -e 's#SOCKET_PATH#$(KFSOCKET)#' \
	    packaging/launchd/$(KFLABEL).plist > "$(KFPLIST)"
	@launchctl bootout gui/$$(id -u)/$(KFLABEL) 2>/dev/null; \
	 launchctl bootout gui/$$(id -u) "$(KFPLIST)" 2>/dev/null; \
	 launchctl unload "$(KFPLIST)" 2>/dev/null; \
	 launchctl remove $(KFLABEL) 2>/dev/null; \
	 sleep 1; \
	 launchctl bootstrap gui/$$(id -u) "$(KFPLIST)" 2>/dev/null \
	   || launchctl load -w "$(KFPLIST)" \
	   || launchctl kickstart -k gui/$$(id -u)/$(KFLABEL)
	@echo "kingfisherd running — inline scans now use Kingfisher's 950+ rules (fast, compiled once)."

uninstall-kingfisher:
	-launchctl bootout gui/$$(id -u)/$(KFLABEL) 2>/dev/null
	rm -f "$(KFPLIST)"
	sudo rm -f "$(PREFIX)/bin/kingfisherd"
	@echo "Removed kingfisherd; inline scans fall back to the builtin scanner."

service-restart:
	$(SVC_RESTART)

# Force a config reload via SIGHUP. Usually unnecessary: the daemon auto-reloads
# $(USERCFG) within ~2s of an edit. Kept for scripted/immediate reloads.
service-reload:
	$(SVC_RELOAD)

service-status:
	@$(SVC_STATUS)

clean:
	rm -rf bin dist

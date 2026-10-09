SHELL := /bin/bash

.DEFAULT_GOAL := demo

CONNECTOR_PORT ?= 9091
CONNECTOR_URL ?= http://localhost:$(CONNECTOR_PORT)
SERVER_DIR ?= platform/server
# Writable cargo out-dir (avoid stale root-owned platform/server/.cargo-target).
PLATFORM_CARGO_TARGET ?= $(SERVER_DIR)/.cargo-target-umesh
PLATFORM_CARGO_TARGET_DIR = $(patsubst $(SERVER_DIR)/%,%,$(PLATFORM_CARGO_TARGET))
PLATFORM_BIN ?= $(PLATFORM_CARGO_TARGET)/debug/connector-platform
PLATFORM_CTL ?= $(PLATFORM_CARGO_TARGET)/debug/connectorctl

# Resolve platform binaries (umesh target → legacy .cargo-target → target/debug).
platform-resolve-bin = $(firstword $(wildcard $(SERVER_DIR)/.cargo-target-umesh/debug/$(1)) $(wildcard $(SERVER_DIR)/.cargo-target/debug/$(1)) $(SERVER_DIR)/target/debug/$(1))
CONNECTOR_DEV_MODE ?= 1
CONNECTOR_ENV ?= development
CONNECTOR_LLM_PROVIDER ?= deepseek
CONNECTOR_LLM_MODEL ?= deepseek-chat
DEMO_LOG ?= .demo-node.log
DEMO_PID_FILE ?= .demo-node.pid
DEMO2_LOG ?= .demo2-node.log
DEMO2_PID_FILE ?= .demo2-node.pid
DEMO3_LOG ?= .demo3-node.log
DEMO3_PID_FILE ?= .demo3-node.pid
DEMO4_LOG ?= .demo4-node.log
DEMO4_PID_FILE ?= .demo4-node.pid
DEMO5_LOG ?= .demo5-node.log
DEMO5_PID_FILE ?= .demo5-node.pid
DEMO6_LOG ?= .demo6-node.log
DEMO6_PID_FILE ?= .demo6-node.pid
LOCAL_BIN_DIR ?= $(HOME)/.local/bin
LOCAL_UI_DIR ?= $(HOME)/.local/share/connector/ui
DEMO_PLUGIN_LAUNCHER ?= python3 scripts/demo-plugin-launcher.py

.PHONY: doctor clean-workspace package microvm-vendor-check kernel-prod-preflight kernel-prod-preflight-with-connector platform-build platform-check platform-test cage-smoke custom-domain-smoke cnp-l2-smoke smoke-all one-green-start-smoke ci-beta-gate prod-dogfood-smoke upgrade-persist-smoke prod-readiness-gate final-reach-light-gate engineering-reach-gate l4-claim-gate l5-mesh-soak custody-multinode-soak iia-p0-gate iia-n4-gate iia-qpr-gate docklock-bypass-adversarial matrix-isolation-gate iia-continuity-gate iia-forensics-gate agent-identity-envelope-gate iia-court-gate iia-flagship-demo clean-vm-tarball-smoke multi-tenant-test start demo demo2 demo2-stop demo2-status demo3 demo3-stop demo3-status demo4 demo4-stop demo4-status demo5 demo5-stop demo6 demo6-stop demo6-status demo-stop demo-status install-local run-local tracetramp witnessctl devguard tracetramp-dry witnessctl-dry devguard-dry plugin-demo llm-fallback-cap-smoke l4-story-offline-check story-qa-smoke cvr-soft-acceptance cvr-kvm-acceptance cvr-acceptance seven-backends-verify

# Phase 0.5 — chown hint via scripts/audit-target-not-root-owned.sh, port, cargo check, dist freshness
doctor:
	@bash scripts/doctor.sh

# Reclaim disk: stale target/, temp smokes; CLEAN_DOCKER=1 CLEAN_DOCKER_IMAGES=1 CLEAN_CARGO_TARGET=1 optional
clean-workspace:
	@bash scripts/clean-workspace.sh

# Phase 1.7 — single release tarball under dist/ (override dir with CONNECTOR_PACKAGE_DIR=...)
package:
	@bash scripts/package-connector-os.sh

microvm-vendor-check:
	@set -euo pipefail; \
	test -f vendor/firecracker/manifest.json || { echo "missing vendor/firecracker/manifest.json"; exit 1; }; \
	test -f vendor/microvm/manifest.json || { echo "missing vendor/microvm/manifest.json"; exit 1; }; \
	echo "MicroVM vendor manifests are present"; \
	if rg -n "REPLACE_WITH_REAL_SHA256" "vendor/firecracker/manifest.json" "vendor/microvm/manifest.json" >/dev/null 2>&1; then \
		echo "WARN: placeholder SHA256 values still present in vendor manifests"; \
	else \
		echo "Vendor manifests have concrete SHA256 values"; \
	fi

# CVR isolation acceptance (Linux-level Connector gate)
# soft = always (LAB honesty). kvm = Effective when /dev/kvm + assets green.
cvr-soft-acceptance:
	@bash platform/scripts/cvr-soft-acceptance.sh

cvr-kvm-acceptance:
	@bash platform/scripts/cvr-kvm-acceptance.sh

cvr-acceptance: cvr-soft-acceptance cvr-kvm-acceptance

seven-backends-verify:
	@bash platform/scripts/seven-backends-deployment-verify.sh

# Host checks before kernel enforcement; optional connectorctl JSON when CONNECTOR_API_URL is set (see script --help).
kernel-prod-preflight:
	@bash platform/scripts/connector-kernel-prod-preflight.sh

kernel-prod-preflight-with-connector:
	@bash platform/scripts/connector-kernel-prod-preflight.sh --with-connector

# Non-interactive local kernel: CONNECTOR_PRESET=local + stub LLM (no API key). Same as: CONNECTOR_PRESET=local CONNECTOR_LLM_STUB=1 cargo run ...
run-local:
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=.cargo-target CONNECTOR_PRESET=local CONNECTOR_LLM_STUB=1 CONNECTOR_PORT=$(CONNECTOR_PORT) cargo run --bin connector-platform

# T1: build connectorctl + platform, then boot node (foreground). Plugin lab autostart when Docker is available.
start:
	@set -euo pipefail; \
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=.cargo-target cargo build -q --bin connector-platform --bin connectorctl; \
	exec ./.cargo-target/debug/connectorctl start --foreground

# Build connector-platform into $(PLATFORM_CARGO_TARGET) (avoids stale root-owned target/debug binary).
platform-build:
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=$(PLATFORM_CARGO_TARGET_DIR) cargo build -p connector-platform --bin connector-platform

platform-check:
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=$(PLATFORM_CARGO_TARGET_DIR) cargo check -p connector-platform --bin connector-platform

# Fast router + tenant unit tests (no live server).
platform-test:
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=$(PLATFORM_CARGO_TARGET_DIR) cargo test -p connector-platform --bin connector-platform router_build_tests -- --test-threads=1
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=$(PLATFORM_CARGO_TARGET_DIR) cargo test -p connector-platform --bin connector-platform middleware::tenant::tests -- --test-threads=1

# Requires a running node on CONNECTOR_TEST_URL (default http://127.0.0.1:9091).
cage-smoke:
	@CONNECTOR_TEST_URL="$(CONNECTOR_TEST_URL)" \
	CONNECTOR_TEST_API_KEY="$(CONNECTOR_TEST_API_KEY)" \
	CONNECTOR_DEV_MODE="$(CONNECTOR_DEV_MODE)" \
	CONNECTOR_DEV_TOKEN="$(CONNECTOR_DEV_TOKEN)" \
	SKIP_PUBLIC_DNS="$(SKIP_PUBLIC_DNS)" \
	bash platform/scripts/cage-e2e-smoke.sh

custom-domain-smoke:
	@CONNECTOR_TEST_URL="$(CONNECTOR_TEST_URL)" \
	CONNECTOR_TEST_API_KEY="$(CONNECTOR_TEST_API_KEY)" \
	CONNECTOR_DEV_MODE="$(CONNECTOR_DEV_MODE)" \
	CONNECTOR_DEV_TOKEN="$(CONNECTOR_DEV_TOKEN)" \
	bash platform/scripts/custom-domain-e2e-smoke.sh

# Self-contained: boots platform, proves CNP L2 TCP + HTTP send/inbox.
cnp-l2-smoke:
	@bash platform/scripts/cnp-l2-smoke.sh

# Two-node static 1-hop forward via CONNECTOR_CNP_PEERS.
cnp-l5-smoke:
	@bash platform/scripts/cnp-l5-smoke.sh

smoke-all: cage-smoke custom-domain-smoke cnp-l2-smoke cnp-l5-smoke
	@echo "[ok] cage + custom-domain smoke"

# P0.1: build + background connectorctl start + health/apps/cage-proof (needs Docker for plugin lab).
one-green-start-smoke:
	@bash platform/scripts/one-green-start-smoke.sh

ci-beta-gate:
	@bash platform/scripts/ci_beta_gate.sh

prod-dogfood-smoke:
	@bash platform/scripts/prod-dogfood-smoke.sh

upgrade-persist-smoke:
	@bash platform/scripts/upgrade-persist-smoke.sh

prod-readiness-gate:
	@bash platform/scripts/prod-readiness-gate.sh

story-qa-smoke:
	@bash platform/scripts/story-qa-smoke.sh

l4-story-offline-check:
	@bash platform/scripts/l4-story-offline-check.sh

tt-wc-prod-smoke:
	@bash platform/scripts/tt-wc-prod-smoke.sh

cage-tt-load-smoke:
	@bash platform/scripts/cage-tt-load-smoke.sh

k6-cage-load:
	@bash platform/scripts/k6-cage-load.sh

witness-bundle-smoke:
	@bash platform/scripts/witness-bundle-smoke.sh

custody-quorum-smoke:
	@bash platform/scripts/custody-quorum-smoke.sh

audit-tracetramp-tenancy:
	@bash scripts/audit-tracetramp-tenancy.sh

helm-lint-smoke:
	@bash platform/scripts/helm-lint-smoke.sh

tt-wc-prod-gate:
	@bash platform/scripts/tt-wc-prod-gate.sh

package-plugins:
	@bash scripts/package-tracetramp.sh
	@bash scripts/package-witnessctl.sh

package-plugins-smoke:
	@bash platform/scripts/package-plugins-smoke.sh

plugin-demo:
	@$(DEMO_PLUGIN_LAUNCHER)

tracetramp:
	@$(DEMO_PLUGIN_LAUNCHER) --plugin tracetramp

witnessctl:
	@$(DEMO_PLUGIN_LAUNCHER) --plugin witnessctl

devguard:
	@$(DEMO_PLUGIN_LAUNCHER) --plugin devguard

tracetramp-dry:
	@$(DEMO_PLUGIN_LAUNCHER) --plugin tracetramp --dry-run

witnessctl-dry:
	@$(DEMO_PLUGIN_LAUNCHER) --plugin witnessctl --dry-run

devguard-dry:
	@$(DEMO_PLUGIN_LAUNCHER) --plugin devguard --dry-run

section10-automated-smoke:
	@bash platform/scripts/section10-automated-smoke.sh

llm-fallback-cap-smoke:
	@bash platform/scripts/llm-fallback-cap-smoke.sh

sign-release-artifacts:
	@bash scripts/sign-release-artifacts.sh

verify-release-artifacts:
	@bash scripts/verify-release-artifacts.sh

# Laptop-safe FINAL_REACH green gate (no monolith test link; see docs/LOW_MEMORY_DEV.md)
final-reach-light-gate:
	@bash platform/scripts/final-reach-light-gate.sh

# Laptop engineering exit: light-gate + L5 mesh + custody multinode soak evidence files.
engineering-reach-gate: final-reach-light-gate
	@test -f platform/scripts/.l5-mesh-soak.ok || (echo "[fail] missing .l5-mesh-soak.ok — run ARGS='--start-local --claim-fabric' make l5-mesh-soak" >&2; exit 1)
	@test -f platform/scripts/.custody-multinode-soak.ok || (echo "[fail] missing .custody-multinode-soak.ok — run make custody-multinode-soak" >&2; exit 1)
	@echo "== engineering-reach-gate: OK (CORE + L5 soaks) =="

l4-claim-gate:
	@bash platform/scripts/l4-claim-gate.sh

l5-mesh-soak:
	@CONNECTOR_BIN="$${CONNECTOR_BIN:-$(PLATFORM_BIN)}" bash platform/scripts/l5-mesh-soak.sh $(ARGS)

custody-multinode-soak:
	@bash platform/scripts/custody-multinode-soak.sh

iia-p0-gate:
	@bash platform/scripts/iia-p0-gate.sh

iia-n4-gate:
	@bash platform/scripts/iia-n4-gate.sh

iia-qpr-gate:
	@bash platform/scripts/iia-qpr-gate.sh

docklock-bypass-adversarial:
	@bash platform/scripts/docklock-bypass-adversarial.sh

matrix-isolation-gate:
	@bash platform/scripts/matrix-isolation-gate.sh

iia-continuity-gate:
	@bash platform/scripts/iia-continuity-gate.sh

iia-forensics-gate:
	@bash platform/scripts/iia-forensics-gate.sh

agent-identity-envelope-gate:
	@bash platform/scripts/agent-identity-envelope-gate.sh

iia-court-gate:
	@bash platform/scripts/iia-court-gate.sh

iia-flagship-demo:
	@bash platform/scripts/iia-flagship-demo.sh

clean-vm-tarball-smoke:
	@bash platform/scripts/clean-vm-tarball-smoke.sh

multi-tenant-test:
	@CONNECTOR_MULTI_TENANT=1 CONNECTOR_DEV_MODE=1 CONNECTOR_TEST_URL="$(CONNECTOR_TEST_URL)" \
	cd $(SERVER_DIR) && CARGO_TARGET_DIR=.cargo-target cargo test --test multi_tenant_http -- --test-threads=1

demo:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	DASHBOARD_URL="$(CONNECTOR_URL)/"; \
	PORT="$(CONNECTOR_PORT)"; \
	SERVER_DIR="$(SERVER_DIR)"; \
	DEV_MODE="$(CONNECTOR_DEV_MODE)"; \
	DEV_ENV="$(CONNECTOR_ENV)"; \
	LLM_PROVIDER="$(CONNECTOR_LLM_PROVIDER)"; \
	LLM_MODEL="$(CONNECTOR_LLM_MODEL)"; \
	LOG_FILE="$(DEMO_LOG)"; \
	PID_FILE="$(DEMO_PID_FILE)"; \
	if [[ "$${CONNECTOR_LLM_STUB:-}" == "1" ]]; then \
		ENTERED_LLM_KEY=""; \
	elif [[ -z "$${CONNECTOR_LLM_API_KEY:-}" && -z "$${DEEPSEEK_API_KEY:-}" ]]; then \
		read -rsp "Enter DEEPSEEK_API_KEY (press Enter for stub mode): " ENTERED_LLM_KEY; \
		echo; \
	else \
		ENTERED_LLM_KEY="$${CONNECTOR_LLM_API_KEY:-$${DEEPSEEK_API_KEY:-}}"; \
	fi; \
	export CONNECTOR_PORT="$$PORT"; \
	export CONNECTOR_URL="$$BASE_URL"; \
	export CONNECTOR_DEV_MODE="$$DEV_MODE"; \
	export CONNECTOR_ENV="$$DEV_ENV"; \
	export SERVER_DIR="$$SERVER_DIR"; \
	export CONNECTOR_API_KEY="$${CONNECTOR_API_KEY:-dev-token}"; \
	export CONNECTOR_AGENT_TOKEN_BUDGET="$${CONNECTOR_AGENT_TOKEN_BUDGET:-64000}"; \
	export CONNECTOR_LLM_FALLBACK="$${CONNECTOR_LLM_FALLBACK:-openai:gpt-4o-mini}"; \
	export CONNECTOR_LLM_FALLBACK_KEY="$${CONNECTOR_LLM_FALLBACK_KEY:-$$ENTERED_LLM_KEY}"; \
	if [[ -n "$$ENTERED_LLM_KEY" ]]; then \
		export DEEPSEEK_API_KEY="$$ENTERED_LLM_KEY"; \
		export CONNECTOR_LLM_API_KEY="$$ENTERED_LLM_KEY"; \
		export CONNECTOR_LLM_PROVIDER="$$LLM_PROVIDER"; \
		export CONNECTOR_LLM_MODEL="$$LLM_MODEL"; \
		unset CONNECTOR_LLM_STUB; \
	else \
		export CONNECTOR_LLM_STUB=1; \
		unset CONNECTOR_LLM_API_KEY; \
	fi; \
	if [[ -f "$$PID_FILE" ]]; then \
		OLDPID="$$(cat "$$PID_FILE")"; \
		echo "Restarting demo-managed Connector process $$OLDPID to load latest code ..."; \
		kill -- -"$$OLDPID" 2>/dev/null || kill "$$OLDPID" 2>/dev/null || true; \
		rm -f "$$PID_FILE"; \
		sleep 1; \
	elif curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector already running at $$BASE_URL — reusing existing node for demo."; \
		touch "$$PID_FILE"; \
	fi; \
	if [[ ! -s "$$PID_FILE" ]]; then \
	echo "Building real infra binaries in $$SERVER_DIR ..."; \
	CARGO_TARGET_DIR="$$SERVER_DIR/.cargo-target" cargo build --manifest-path "$$SERVER_DIR/Cargo.toml" --bin connector-platform --bin connectorctl; \
	$(MAKE) install-local SERVER_DIR="$$SERVER_DIR"; \
	echo "Starting Connector Node through connectorctl on $$BASE_URL ..."; \
	setsid bash -lc 'cd "$$SERVER_DIR" && exec ./.cargo-target/debug/connectorctl start --foreground 2>/dev/null || exec ./target/debug/connectorctl start --foreground' >"$$LOG_FILE" 2>&1 & \
	echo $$! > "$$PID_FILE"; \
	echo "Boot log: $$LOG_FILE"; \
	echo "PID file: $$PID_FILE"; \
	fi; \
	READY=0; \
	for _ in $$(seq 1 120); do \
		if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1 && curl -fsS "$$BASE_URL/api/v1" >/dev/null 2>&1; then \
			READY=1; \
			break; \
		fi; \
		if [[ -f "$$PID_FILE" ]] && [[ -s "$$PID_FILE" ]] && ! kill -0 "$$(cat "$$PID_FILE")" 2>/dev/null; then \
			echo "Connector exited during boot. Check $$LOG_FILE"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	if [[ "$$READY" -ne 1 ]]; then \
		echo "Connector did not become API-ready at $$BASE_URL"; \
		if [[ -f "$$LOG_FILE" ]]; then tail -n 40 "$$LOG_FILE"; fi; \
		exit 1; \
	fi; \
	LLM_WIRED="$$(curl -fsS -H "Authorization: Bearer $${CONNECTOR_API_KEY:-dev-token}" "$$BASE_URL/api/v1/monitor/health" | python -c 'import json,sys; print("1" if json.load(sys.stdin).get("governance", {}).get("llm_router_wired") else "0")')"; \
	if [[ "$${CONNECTOR_LLM_STUB:-0}" != "1" && "$$LLM_WIRED" != "1" ]]; then \
		echo "Connector is up but LLM router is not wired; refusing to launch enterprise demo against partial runtime."; \
		echo "Set CONNECTOR_LLM_API_KEY correctly and restart the node."; \
		if [[ -f "$$LOG_FILE" ]]; then tail -n 40 "$$LOG_FILE"; fi; \
		exit 1; \
	fi; \
	if command -v firefox >/dev/null 2>&1; then \
		(firefox --new-tab "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard in Firefox: $$DASHBOARD_URL"; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		(xdg-open "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard: $$DASHBOARD_URL"; \
	else \
		echo "Dashboard ready at $$DASHBOARD_URL"; \
	fi; \
	connectorctl policy --dev 50 >/dev/null 2>&1 || true; \
	echo "Bootstrapping demo state ..."; \
	BOOTSTRAP_JSON="$$(python demos/demo.py bootstrap)"; \
	printf '%s\n' "$$BOOTSTRAP_JSON"; \
	eval "$$(printf '%s\n' "$$BOOTSTRAP_JSON" | python -c 'import json,sys; data=json.load(sys.stdin); [print(line) for line in data.get("exports", [])]')"; \
	echo "Bootstrap complete. Launching live demo (all decisions generated from runtime) ..."; \
	python demos/demo.py

demo2:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	DASHBOARD_URL="$(CONNECTOR_URL)/"; \
	PORT="$(CONNECTOR_PORT)"; \
	SERVER_DIR="$(SERVER_DIR)"; \
	DEV_MODE="$(CONNECTOR_DEV_MODE)"; \
	DEV_ENV="$(CONNECTOR_ENV)"; \
	LOG_FILE="$(DEMO2_LOG)"; \
	PID_FILE="$(DEMO2_PID_FILE)"; \
	LLM_PROVIDER="deepseek"; \
	LLM_MODEL="deepseek-chat"; \
	USE_EXISTING_SERVER=0; \
	if [[ -z "$${DEEPSEEK_API_KEY:-}" && -z "$${CONNECTOR_LLM_API_KEY:-}" ]]; then \
		read -rsp "Enter DEEPSEEK_API_KEY for demo2: " ENTERED_LLM_KEY; \
		echo; \
	else \
		ENTERED_LLM_KEY="$${DEEPSEEK_API_KEY:-$${CONNECTOR_LLM_API_KEY:-}}"; \
	fi; \
	if [[ -z "$$ENTERED_LLM_KEY" ]]; then \
		echo "demo2 requires a DeepSeek LLM key"; \
		exit 1; \
	fi; \
	export CONNECTOR_PORT="$$PORT"; \
	export CONNECTOR_URL="$$BASE_URL"; \
	export CONNECTOR_DEV_MODE="$$DEV_MODE"; \
	export CONNECTOR_ENV="$$DEV_ENV"; \
	export SERVER_DIR="$$SERVER_DIR"; \
	export CONNECTOR_API_KEY="$${CONNECTOR_API_KEY:-dev-token}"; \
	export CONNECTOR_AGENT_TOKEN_BUDGET="$${CONNECTOR_AGENT_TOKEN_BUDGET:-64000}"; \
	export CONNECTOR_LLM_FALLBACK="$${CONNECTOR_LLM_FALLBACK:-deepseek:deepseek-chat}"; \
	export CONNECTOR_LLM_FALLBACK_KEY="$${CONNECTOR_LLM_FALLBACK_KEY:-$$ENTERED_LLM_KEY}"; \
	export DEEPSEEK_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_PROVIDER="$$LLM_PROVIDER"; \
	export CONNECTOR_LLM_MODEL="$$LLM_MODEL"; \
	export DEMO2_PROVIDER="deepseek"; \
	export DEMO2_UPSTREAM="deepseek"; \
	export DEMO2_MODEL="deepseek-chat"; \
	unset CONNECTOR_LLM_STUB; \
	if [[ -f "$$PID_FILE" ]]; then \
		OLDPID="$$(cat "$$PID_FILE")"; \
		echo "Restarting demo2-managed Connector process $$OLDPID to load latest code ..."; \
		kill -- -"$$OLDPID" 2>/dev/null || kill "$$OLDPID" 2>/dev/null || true; \
		rm -f "$$PID_FILE"; \
		sleep 1; \
	elif curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Reusing existing Connector instance at $$BASE_URL for demo2 ..."; \
		USE_EXISTING_SERVER=1; \
	fi; \
	if [[ "$$USE_EXISTING_SERVER" -ne 1 ]]; then \
		echo "Building real infra binaries in $$SERVER_DIR ..."; \
		CARGO_TARGET_DIR="$$SERVER_DIR/.cargo-target" cargo build --manifest-path "$$SERVER_DIR/Cargo.toml" --bin connector-platform --bin connectorctl; \
		$(MAKE) install-local SERVER_DIR="$$SERVER_DIR"; \
		echo "Starting Connector Node through connectorctl on $$BASE_URL ..."; \
		setsid bash -lc 'cd "$$SERVER_DIR" && exec ./.cargo-target/debug/connectorctl start --foreground 2>/dev/null || exec ./target/debug/connectorctl start --foreground' >"$$LOG_FILE" 2>&1 & \
		echo $$! > "$$PID_FILE"; \
		echo "Boot log: $$LOG_FILE"; \
		echo "PID file: $$PID_FILE"; \
	fi; \
	READY=0; \
	for _ in $$(seq 1 120); do \
		if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1 && curl -fsS "$$BASE_URL/api/v1" >/dev/null 2>&1; then \
			READY=1; \
			break; \
		fi; \
		if [[ -f "$$PID_FILE" ]] && ! kill -0 "$$(cat "$$PID_FILE")" 2>/dev/null; then \
			echo "Connector exited during boot. Check $$LOG_FILE"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	if [[ "$$READY" -ne 1 ]]; then \
		echo "Connector did not become API-ready at $$BASE_URL"; \
		if [[ -f "$$LOG_FILE" ]]; then tail -n 40 "$$LOG_FILE"; fi; \
		exit 1; \
	fi; \
	if command -v firefox >/dev/null 2>&1; then \
		(firefox --new-tab "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard in Firefox: $$DASHBOARD_URL"; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		(xdg-open "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard: $$DASHBOARD_URL"; \
	else \
		echo "Dashboard ready at $$DASHBOARD_URL"; \
	fi; \
	echo "Running demo2 preflight ..."; \
	python demos/demo2/workflow_demo.py preflight; \
	echo "Bootstrapping demo2 state ..."; \
	DEMO2_BOOT_JSON="$$(python demos/demo2/workflow_demo.py bootstrap)"; \
	printf '%s\n' "$$DEMO2_BOOT_JSON"; \
	eval "$$(printf '%s\n' "$$DEMO2_BOOT_JSON" | python -c 'import json,sys; d=json.load(sys.stdin); [print(x) for x in d.get("exports_shell") or []]')"; \
	echo "Launching demo2 governed coding workflow ..."; \
	python demos/demo2/workflow_demo.py

demo2-stop:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	PID_FILE="$(DEMO2_PID_FILE)"; \
	if [[ ! -f "$$PID_FILE" ]]; then \
		echo "No demo2-managed Connector PID file found"; \
		exit 0; \
	fi; \
	PID="$$(cat "$$PID_FILE")"; \
	if [[ -x "$$SERVER_DIR/.cargo-target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./.cargo-target/debug/connectorctl stop ) || true; \
	elif [[ -x "$$SERVER_DIR/target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./target/debug/connectorctl stop ) || true; \
	fi; \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill -- -"$$PID" 2>/dev/null || kill "$$PID" 2>/dev/null || true; \
		echo "Stopped demo2 Connector process group $$PID"; \
	else \
		echo "PID $$PID is not running"; \
	fi; \
	rm -f "$$PID_FILE"

demo2-status:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector is healthy at $$BASE_URL"; \
	else \
		echo "Connector is not responding at $$BASE_URL"; \
	fi; \
	if [[ -f "$(DEMO2_PID_FILE)" ]]; then \
		echo "Demo2 PID: $$(cat "$(DEMO2_PID_FILE)") (make demo2-stop)"; \
	else \
		echo "No demo2-managed PID file"; \
	fi

demo3:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	DASHBOARD_URL="$(CONNECTOR_URL)/"; \
	PORT="$(CONNECTOR_PORT)"; \
	SERVER_DIR="$(SERVER_DIR)"; \
	DEV_MODE="$(CONNECTOR_DEV_MODE)"; \
	DEV_ENV="$(CONNECTOR_ENV)"; \
	LOG_FILE="$(DEMO3_LOG)"; \
	PID_FILE="$(DEMO3_PID_FILE)"; \
	LLM_PROVIDER="deepseek"; \
	LLM_MODEL="deepseek-chat"; \
	USE_EXISTING_SERVER=0; \
	if [[ -z "$${DEEPSEEK_API_KEY:-}" && -z "$${CONNECTOR_LLM_API_KEY:-}" ]]; then \
		read -rsp "Enter DEEPSEEK_API_KEY for demo3: " ENTERED_LLM_KEY; \
		echo; \
	else \
		ENTERED_LLM_KEY="$${DEEPSEEK_API_KEY:-$${CONNECTOR_LLM_API_KEY:-}}"; \
	fi; \
	if [[ -z "$$ENTERED_LLM_KEY" ]]; then \
		echo "demo3 requires a DeepSeek LLM key (attack payloads need a real LLM)"; \
		exit 1; \
	fi; \
	export CONNECTOR_PORT="$$PORT"; \
	export CONNECTOR_URL="$$BASE_URL"; \
	export CONNECTOR_DEV_MODE="$$DEV_MODE"; \
	export CONNECTOR_ENV="$$DEV_ENV"; \
	export SERVER_DIR="$$SERVER_DIR"; \
	export CONNECTOR_API_KEY="$${CONNECTOR_API_KEY:-dev-token}"; \
	export CONNECTOR_AGENT_TOKEN_BUDGET="$${CONNECTOR_AGENT_TOKEN_BUDGET:-64000}"; \
	export CONNECTOR_LLM_FALLBACK="$${CONNECTOR_LLM_FALLBACK:-deepseek:deepseek-chat}"; \
	export CONNECTOR_LLM_FALLBACK_KEY="$${CONNECTOR_LLM_FALLBACK_KEY:-$$ENTERED_LLM_KEY}"; \
	export DEEPSEEK_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_PROVIDER="$$LLM_PROVIDER"; \
	export CONNECTOR_LLM_MODEL="$$LLM_MODEL"; \
	unset CONNECTOR_LLM_STUB; \
	if [[ -f "$$PID_FILE" ]]; then \
		OLDPID="$$(cat "$$PID_FILE")"; \
		echo "Restarting demo3-managed Connector process $$OLDPID to load latest code ..."; \
		kill -- -"$$OLDPID" 2>/dev/null || kill "$$OLDPID" 2>/dev/null || true; \
		rm -f "$$PID_FILE"; \
		sleep 2; \
	elif curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Reusing existing Connector instance at $$BASE_URL for demo3 ..."; \
		USE_EXISTING_SERVER=1; \
	fi; \
	if [[ "$$USE_EXISTING_SERVER" -ne 1 ]]; then \
		echo "Building real infra binaries in $$SERVER_DIR ..."; \
		CARGO_TARGET_DIR="$$SERVER_DIR/.cargo-target" cargo build --manifest-path "$$SERVER_DIR/Cargo.toml" --bin connector-platform --bin connectorctl; \
		$(MAKE) install-local SERVER_DIR="$$SERVER_DIR"; \
		fuser -k "$$PORT"/tcp 2>/dev/null || true; sleep 1; \
		echo "Starting Connector Node through connectorctl on $$BASE_URL ..."; \
		setsid bash -lc 'cd "$$SERVER_DIR" && exec ./.cargo-target/debug/connectorctl start --foreground 2>/dev/null || exec ./target/debug/connectorctl start --foreground' >"$$LOG_FILE" 2>&1 & \
		echo $$! > "$$PID_FILE"; \
		echo "Boot log: $$LOG_FILE"; \
		echo "PID file: $$PID_FILE"; \
	fi; \
	READY=0; \
	for _ in $$(seq 1 120); do \
		if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1 && curl -fsS "$$BASE_URL/api/v1" >/dev/null 2>&1; then \
			READY=1; \
			break; \
		fi; \
		if [[ -f "$$PID_FILE" ]] && ! kill -0 "$$(cat "$$PID_FILE")" 2>/dev/null; then \
			echo "Connector exited during boot. Check $$LOG_FILE"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	if [[ "$$READY" -ne 1 ]]; then \
		echo "Connector did not become API-ready at $$BASE_URL"; \
		if [[ -f "$$LOG_FILE" ]]; then tail -n 40 "$$LOG_FILE"; fi; \
		exit 1; \
	fi; \
	if command -v firefox >/dev/null 2>&1; then \
		(firefox --new-tab "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard in Firefox: $$DASHBOARD_URL"; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		(xdg-open "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard: $$DASHBOARD_URL"; \
	else \
		echo "Dashboard ready at $$DASHBOARD_URL"; \
	fi; \
	echo "Running demo3 preflight ..."; \
	python demos/demo3/attack_demo.py preflight; \
	echo "Launching demo3: 7 Most Dangerous Attacks on Agentic Infrastructure ..."; \
	python demos/demo3/attack_demo.py

demo3-stop:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	PID_FILE="$(DEMO3_PID_FILE)"; \
	if [[ ! -f "$$PID_FILE" ]]; then \
		echo "No demo3-managed Connector PID file found"; \
		exit 0; \
	fi; \
	PID="$$(cat "$$PID_FILE")"; \
	if [[ -x "$$SERVER_DIR/.cargo-target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./.cargo-target/debug/connectorctl stop ) || true; \
	elif [[ -x "$$SERVER_DIR/target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./target/debug/connectorctl stop ) || true; \
	fi; \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill -- -"$$PID" 2>/dev/null || kill "$$PID" 2>/dev/null || true; \
		echo "Stopped demo3 Connector process group $$PID"; \
	else \
		echo "PID $$PID is not running"; \
	fi; \
	rm -f "$$PID_FILE"

demo3-status:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector is healthy at $$BASE_URL"; \
	else \
		echo "Connector is not responding at $$BASE_URL"; \
	fi; \
	if [[ -f "$(DEMO3_PID_FILE)" ]]; then \
		echo "Demo3 PID: $$(cat "$(DEMO3_PID_FILE)") (make demo3-stop)"; \
	else \
		echo "No demo3-managed PID file"; \
	fi

demo4:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	DASHBOARD_URL="$(CONNECTOR_URL)/"; \
	PORT="$(CONNECTOR_PORT)"; \
	SERVER_DIR="$(SERVER_DIR)"; \
	DEV_MODE="$(CONNECTOR_DEV_MODE)"; \
	DEV_ENV="$(CONNECTOR_ENV)"; \
	LOG_FILE="$(DEMO4_LOG)"; \
	PID_FILE="$(DEMO4_PID_FILE)"; \
	LLM_PROVIDER="deepseek"; \
	LLM_MODEL="deepseek-chat"; \
	USE_EXISTING_SERVER=0; \
	if [[ -z "$${DEEPSEEK_API_KEY:-}" && -z "$${CONNECTOR_LLM_API_KEY:-}" ]]; then \
		read -rsp "Enter DEEPSEEK_API_KEY for demo4: " ENTERED_LLM_KEY; \
		echo; \
	else \
		ENTERED_LLM_KEY="$${DEEPSEEK_API_KEY:-$${CONNECTOR_LLM_API_KEY:-}}"; \
	fi; \
	if [[ -z "$$ENTERED_LLM_KEY" ]]; then \
		echo "demo4 requires a DeepSeek LLM key (stability tests need a real LLM)"; \
		exit 1; \
	fi; \
	export CONNECTOR_PORT="$$PORT"; \
	export CONNECTOR_URL="$$BASE_URL"; \
	export CONNECTOR_DEV_MODE="$$DEV_MODE"; \
	export CONNECTOR_ENV="$$DEV_ENV"; \
	export CONNECTOR_LLM_PROVIDER="$$LLM_PROVIDER"; \
	export CONNECTOR_LLM_MODEL="$$LLM_MODEL"; \
	export CONNECTOR_LLM_API_KEY="$$ENTERED_LLM_KEY"; \
	export DEEPSEEK_API_KEY="$$ENTERED_LLM_KEY"; \
	export DEEPSEEK_MODEL="$$LLM_MODEL"; \
	export CONNECTOR_API_KEY="dev-key"; \
	unset CONNECTOR_LLM_STUB; \
	if [[ -f "$$PID_FILE" ]]; then \
		OLDPID="$$(cat "$$PID_FILE")"; \
		echo "Restarting demo4-managed Connector process $$OLDPID to load latest code ..."; \
		kill -- -"$$OLDPID" 2>/dev/null || kill "$$OLDPID" 2>/dev/null || true; \
		rm -f "$$PID_FILE"; \
		sleep 1; \
	elif curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Reusing existing Connector instance at $$BASE_URL for demo4 ..."; \
		USE_EXISTING_SERVER=1; \
	fi; \
	if [[ "$$USE_EXISTING_SERVER" -ne 1 ]]; then \
		echo "Building Connector ..."; \
		( cd "$$SERVER_DIR" && cargo build 2>&1 | tail -5 ); \
		echo "Starting Connector on port $$PORT (log → $$LOG_FILE) ..."; \
		setsid "$$SERVER_DIR/target/debug/connector-platform" > "$$LOG_FILE" 2>&1 & \
		echo "$$!" > "$$PID_FILE"; \
		for i in $$(seq 1 30); do \
			if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then break; fi; \
			sleep 1; \
		done; \
		if ! curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
			echo "Connector did not become healthy after 30s — check $$LOG_FILE"; \
			exit 1; \
		fi; \
	fi; \
	if command -v xdg-open >/dev/null 2>&1; then \
		xdg-open "$$DASHBOARD_URL" 2>/dev/null &>/dev/null & \
	elif command -v open >/dev/null 2>&1; then \
		open "$$DASHBOARD_URL" 2>/dev/null & \
	else \
		echo "Dashboard ready at $$DASHBOARD_URL"; \
	fi; \
	echo "Running demo4 preflight ..."; \
	python demos/demo4/stable_thinking.py preflight; \
	echo "Launching demo4: Stable Thinking Engine ..."; \
	python demos/demo4/stable_thinking.py

demo4-stop:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	PID_FILE="$(DEMO4_PID_FILE)"; \
	if [[ ! -f "$$PID_FILE" ]]; then \
		echo "No demo4-managed Connector PID file found"; \
		exit 0; \
	fi; \
	PID="$$(cat "$$PID_FILE")"; \
	if [[ -x "$$SERVER_DIR/.cargo-target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./.cargo-target/debug/connectorctl stop ) || true; \
	elif [[ -x "$$SERVER_DIR/target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./target/debug/connectorctl stop ) || true; \
	fi; \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill -- -"$$PID" 2>/dev/null || kill "$$PID" 2>/dev/null || true; \
		echo "Stopped demo4 Connector process group $$PID"; \
	else \
		echo "PID $$PID is not running"; \
	fi; \
	rm -f "$$PID_FILE"

demo4-status:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector is healthy at $$BASE_URL"; \
	else \
		echo "Connector is not responding at $$BASE_URL"; \
	fi; \
	if [[ -f "$(DEMO4_PID_FILE)" ]]; then \
		echo "Demo4 PID: $$(cat "$(DEMO4_PID_FILE)") (make demo4-stop)"; \
	else \
		echo "No demo4-managed PID file"; \
	fi

demo-stop:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	PID_FILE="$(DEMO_PID_FILE)"; \
	if [[ ! -f "$$PID_FILE" ]]; then \
		echo "No demo-managed Connector PID file found"; \
		exit 0; \
	fi; \
	PID="$$(cat "$$PID_FILE")"; \
	if [[ -x "$$SERVER_DIR/.cargo-target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./.cargo-target/debug/connectorctl stop ) || true; \
	elif [[ -x "$$SERVER_DIR/target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./target/debug/connectorctl stop ) || true; \
	fi; \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill -- -"$$PID" 2>/dev/null || kill "$$PID" 2>/dev/null || true; \
		echo "Stopped Connector process group $$PID"; \
	else \
		echo "PID $$PID is not running"; \
	fi; \
	rm -f "$$PID_FILE"

demo-status:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector is healthy at $$BASE_URL"; \
		curl -fsS "$$BASE_URL/api/v1" 2>/dev/null | python -c 'import json,sys; \
try: data=json.load(sys.stdin); print("Mode:", data.get("mode", "unknown")) \
except Exception: print("Mode: unknown")'; \
	else \
		echo "Connector is not responding at $$BASE_URL"; \
	fi; \
	if [[ -f "$(DEMO_PID_FILE)" ]]; then \
		echo "Demo PID: $$(cat "$(DEMO_PID_FILE)")"; \
	else \
		echo "No demo-managed PID file"; \
	fi

demo5:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	DASHBOARD_URL="$(CONNECTOR_URL)/"; \
	PORT="$(CONNECTOR_PORT)"; \
	SERVER_DIR="$(SERVER_DIR)"; \
	DEV_MODE="$(CONNECTOR_DEV_MODE)"; \
	DEV_ENV="$(CONNECTOR_ENV)"; \
	LOG_FILE="$(DEMO5_LOG)"; \
	PID_FILE="$(DEMO5_PID_FILE)"; \
	LLM_PROVIDER="deepseek"; \
	LLM_MODEL="deepseek-chat"; \
	USE_EXISTING_SERVER=0; \
	if [[ -z "$${DEEPSEEK_API_KEY:-}" && -z "$${CONNECTOR_LLM_API_KEY:-}" ]]; then \
		if [[ -n "$${CONNECTOR_DEV_MODE:-}" ]]; then \
			echo "Note: Using dev mode - demo5 will work with limited functionality"; \
			ENTERED_LLM_KEY="dev-stub"; \
		else \
			echo "demo5 requires an LLM key for full functionality."; \
			echo "Options:"; \
			echo "  1. Set DEEPSEEK_API_KEY environment variable"; \
			echo "  2. Use demo handler: CONNECTOR_DEV_MODE=1 python demos/demo_handler.py run demo5"; \
			echo "  3. Enter DeepSeek API key now:"; \
			read -rsp "Enter DEEPSEEK_API_KEY for demo5 (or press Ctrl+C to cancel): " ENTERED_LLM_KEY; \
			echo; \
		fi; \
	else \
		ENTERED_LLM_KEY="$${DEEPSEEK_API_KEY:-$${CONNECTOR_LLM_API_KEY:-}}"; \
	fi; \
	if [[ -z "$$ENTERED_LLM_KEY" && -z "$${CONNECTOR_DEV_MODE:-}" ]]; then \
		echo "No LLM key provided. Use 'make demo-handler' for alternative options."; \
		exit 1; \
	fi; \
	export CONNECTOR_PORT="$$PORT"; \
	export CONNECTOR_URL="$$BASE_URL"; \
	export CONNECTOR_DEV_MODE="$$DEV_MODE"; \
	export CONNECTOR_ENV="$$DEV_ENV"; \
	export SERVER_DIR="$$SERVER_DIR"; \
	export CONNECTOR_API_KEY="$${CONNECTOR_API_KEY:-dev-token}"; \
	export CONNECTOR_AGENT_TOKEN_BUDGET="$${CONNECTOR_AGENT_TOKEN_BUDGET:-64000}"; \
	export CONNECTOR_LLM_FALLBACK="$${CONNECTOR_LLM_FALLBACK:-deepseek:deepseek-chat}"; \
	export CONNECTOR_LLM_FALLBACK_KEY="$${CONNECTOR_LLM_FALLBACK_KEY:-$$ENTERED_LLM_KEY}"; \
	export DEEPSEEK_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_PROVIDER="$$LLM_PROVIDER"; \
	export CONNECTOR_LLM_MODEL="$$LLM_MODEL"; \
	export DEMO5_PROVIDER="deepseek"; \
	export DEMO5_MODEL="deepseek-chat"; \
	unset CONNECTOR_LLM_STUB; \
	if [[ -f "$$PID_FILE" ]]; then \
		OLDPID="$$(cat "$$PID_FILE")"; \
		echo "Restarting demo5-managed Connector process $$OLDPID to load latest code ..."; \
		kill -- -"$$OLDPID" 2>/dev/null || kill "$$OLDPID" 2>/dev/null || true; \
		rm -f "$$PID_FILE"; \
		sleep 1; \
	elif curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Reusing existing Connector instance at $$BASE_URL for demo5 ..."; \
		USE_EXISTING_SERVER=1; \
	fi; \
	if [[ "$$USE_EXISTING_SERVER" -ne 1 ]]; then \
		echo "Building real infra binaries in $$SERVER_DIR ..."; \
		CARGO_TARGET_DIR="$$SERVER_DIR/.cargo-target" cargo build --manifest-path "$$SERVER_DIR/Cargo.toml" --bin connector-platform --bin connectorctl; \
		$(MAKE) install-local SERVER_DIR="$$SERVER_DIR"; \
		echo "Starting Connector Node through connectorctl on $$BASE_URL ..."; \
		setsid bash -lc 'cd "$$SERVER_DIR" && exec ./.cargo-target/debug/connectorctl start --foreground 2>/dev/null || exec ./target/debug/connectorctl start --foreground' >"$$LOG_FILE" 2>&1 & \
		echo $$! > "$$PID_FILE"; \
		echo "Boot log: $$LOG_FILE"; \
		echo "PID file: $$PID_FILE"; \
	fi; \
	READY=0; \
	for _ in $$(seq 1 120); do \
		if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1 && curl -fsS "$$BASE_URL/api/v1" >/dev/null 2>&1; then \
			READY=1; \
			break; \
		fi; \
		if [[ -f "$$PID_FILE" ]] && ! kill -0 "$$(cat "$$PID_FILE")" 2>/dev/null; then \
			echo "Connector exited during boot. Check $$LOG_FILE"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	if [[ "$$READY" -ne 1 ]]; then \
		echo "Connector did not become API-ready at $$BASE_URL"; \
		if [[ -f "$$LOG_FILE" ]]; then tail -n 40 "$$LOG_FILE"; fi; \
		exit 1; \
	fi; \
	if command -v firefox >/dev/null 2>&1; then \
		(firefox --new-tab "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard in Firefox: $$DASHBOARD_URL"; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		(xdg-open "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard: $$DASHBOARD_URL"; \
	else \
		echo "Dashboard ready at $$DASHBOARD_URL"; \
	fi; \
	echo "Running demo5 preflight ..."; \
	python demos/demo5/selective_context_demo.py preflight; \
	echo "Bootstrapping demo5 state ..."; \
	python demos/demo5/selective_context_demo.py bootstrap || true; \
	echo "Launching demo5: Selective Context + Identity-Aware Execution ..."; \
	python demos/demo5/selective_context_demo.py

demo5-stop:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	PID_FILE="$(DEMO5_PID_FILE)"; \
	if [[ ! -f "$$PID_FILE" ]]; then \
		echo "No demo5-managed Connector PID file found"; \
		exit 0; \
	fi; \
	PID="$$(cat "$$PID_FILE")"; \
	if [[ -x "$$SERVER_DIR/.cargo-target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./.cargo-target/debug/connectorctl stop ) || true; \
	elif [[ -x "$$SERVER_DIR/target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./target/debug/connectorctl stop ) || true; \
	fi; \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill -- -"$$PID" 2>/dev/null || kill "$$PID" 2>/dev/null || true; \
		echo "Stopped demo5 Connector process group $$PID"; \
	else \
		echo "PID $$PID is not running"; \
	fi; \
	rm -f "$$PID_FILE"

demo5-status:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector is healthy at $$BASE_URL"; \
	else \
		echo "Connector is not responding at $$BASE_URL"; \
	fi; \
	if [[ -f "$(DEMO5_PID_FILE)" ]]; then \
		echo "Demo5 PID: $$(cat "$(DEMO5_PID_FILE)") (make demo5-stop)"; \
	else \
		echo "No demo5-managed PID file"; \
	fi

demo6:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	DASHBOARD_URL="$(CONNECTOR_URL)/"; \
	PORT="$(CONNECTOR_PORT)"; \
	SERVER_DIR="$(SERVER_DIR)"; \
	DEV_MODE="$(CONNECTOR_DEV_MODE)"; \
	DEV_ENV="$(CONNECTOR_ENV)"; \
	LOG_FILE="$(DEMO6_LOG)"; \
	PID_FILE="$(DEMO6_PID_FILE)"; \
	LLM_PROVIDER="deepseek"; \
	LLM_MODEL="deepseek-chat"; \
	USE_EXISTING_SERVER=0; \
	if [[ -z "$${DEEPSEEK_API_KEY:-}" && -z "$${CONNECTOR_LLM_API_KEY:-}" ]]; then \
		if [[ -n "$${CONNECTOR_DEV_MODE:-}" ]]; then \
			echo "Note: Using dev mode - demo6 will work with limited functionality"; \
			ENTERED_LLM_KEY="dev-stub"; \
		else \
			echo "demo6 requires an LLM key for full functionality."; \
			echo "Options:"; \
			echo "  1. Set DEEPSEEK_API_KEY environment variable"; \
			echo "  2. Use demo handler: CONNECTOR_DEV_MODE=1 python demos/demo_handler.py run demo6"; \
			echo "  3. Enter DeepSeek API key now:"; \
			read -rsp "Enter DEEPSEEK_API_KEY for demo6 (or press Ctrl+C to cancel): " ENTERED_LLM_KEY; \
			echo; \
		fi; \
	else \
		ENTERED_LLM_KEY="$${DEEPSEEK_API_KEY:-$${CONNECTOR_LLM_API_KEY:-}}"; \
	fi; \
	if [[ -z "$$ENTERED_LLM_KEY" && -z "$${CONNECTOR_DEV_MODE:-}" ]]; then \
		echo "No LLM key provided. Use 'make demo-handler' for alternative options."; \
		exit 1; \
	fi; \
	export CONNECTOR_PORT="$$PORT"; \
	export CONNECTOR_URL="$$BASE_URL"; \
	export CONNECTOR_DEV_MODE="$$DEV_MODE"; \
	export CONNECTOR_ENV="$$DEV_ENV"; \
	export SERVER_DIR="$$SERVER_DIR"; \
	export CONNECTOR_API_KEY="$${CONNECTOR_API_KEY:-dev-token}"; \
	export CONNECTOR_AGENT_TOKEN_BUDGET="$${CONNECTOR_AGENT_TOKEN_BUDGET:-64000}"; \
	export CONNECTOR_LLM_FALLBACK="$${CONNECTOR_LLM_FALLBACK:-deepseek:deepseek-chat}"; \
	export CONNECTOR_LLM_FALLBACK_KEY="$${CONNECTOR_LLM_FALLBACK_KEY:-$$ENTERED_LLM_KEY}"; \
	export DEEPSEEK_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_API_KEY="$$ENTERED_LLM_KEY"; \
	export CONNECTOR_LLM_PROVIDER="$$LLM_PROVIDER"; \
	export CONNECTOR_LLM_MODEL="$$LLM_MODEL"; \
	export DEMO6_PROVIDER="deepseek"; \
	export DEMO6_MODEL="deepseek-chat"; \
	unset CONNECTOR_LLM_STUB; \
	if [[ -f "$$PID_FILE" ]]; then \
		OLDPID="$$(cat "$$PID_FILE")"; \
		echo "Restarting demo6-managed Connector process $$OLDPID to load latest code ..."; \
		kill -- -"$$OLDPID" 2>/dev/null || kill "$$OLDPID" 2>/dev/null || true; \
		rm -f "$$PID_FILE"; \
		sleep 1; \
	elif curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Reusing existing Connector instance at $$BASE_URL for demo6 ..."; \
		USE_EXISTING_SERVER=1; \
	fi; \
	if [[ "$$USE_EXISTING_SERVER" -ne 1 ]]; then \
		echo "Building real infra binaries in $$SERVER_DIR ..."; \
		CARGO_TARGET_DIR="$$SERVER_DIR/.cargo-target" cargo build --manifest-path "$$SERVER_DIR/Cargo.toml" --bin connector-platform --bin connectorctl; \
		$(MAKE) install-local SERVER_DIR="$$SERVER_DIR"; \
		echo "Starting Connector Node through connectorctl on $$BASE_URL ..."; \
		setsid bash -lc 'cd "$$SERVER_DIR" && exec ./.cargo-target/debug/connectorctl start --foreground 2>/dev/null || exec ./target/debug/connectorctl start --foreground' >"$$LOG_FILE" 2>&1 & \
		echo $$! > "$$PID_FILE"; \
		echo "Boot log: $$LOG_FILE"; \
		echo "PID file: $$PID_FILE"; \
	fi; \
	READY=0; \
	for _ in $$(seq 1 120); do \
		if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1 && curl -fsS "$$BASE_URL/api/v1" >/dev/null 2>&1; then \
			READY=1; \
			break; \
		fi; \
		if [[ -f "$$PID_FILE" ]] && ! kill -0 "$$(cat "$$PID_FILE")" 2>/dev/null; then \
			echo "Connector exited during boot. Check $$LOG_FILE"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	if [[ "$$READY" -ne 1 ]]; then \
		echo "Connector did not become API-ready at $$BASE_URL"; \
		if [[ -f "$$LOG_FILE" ]]; then tail -n 40 "$$LOG_FILE"; fi; \
		exit 1; \
	fi; \
	if command -v firefox >/dev/null 2>&1; then \
		(firefox --new-tab "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard in Firefox: $$DASHBOARD_URL"; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		(xdg-open "$$DASHBOARD_URL" >/dev/null 2>&1 &); \
		echo "Opened dashboard: $$DASHBOARD_URL"; \
	else \
		echo "Dashboard ready at $$DASHBOARD_URL"; \
	fi; \
	echo "Running demo6 preflight ..."; \
	python demos/demo6/deterministic_execution_demo.py preflight; \
	echo "Bootstrapping demo6 state ..."; \
	python demos/demo6/deterministic_execution_demo.py bootstrap || true; \
	echo "Launching demo6: Deterministic Tool Execution ..."; \
	python demos/demo6/deterministic_execution_demo.py

demo6-stop:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	PID_FILE="$(DEMO6_PID_FILE)"; \
	if [[ ! -f "$$PID_FILE" ]]; then \
		echo "No demo6-managed Connector PID file found"; \
		exit 0; \
	fi; \
	PID="$$(cat "$$PID_FILE")"; \
	if [[ -x "$$SERVER_DIR/.cargo-target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./.cargo-target/debug/connectorctl stop ) || true; \
	elif [[ -x "$$SERVER_DIR/target/debug/connectorctl" ]]; then \
		( cd "$$SERVER_DIR" && ./target/debug/connectorctl stop ) || true; \
	fi; \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill -- -"$$PID" 2>/dev/null || kill "$$PID" 2>/dev/null || true; \
		echo "Stopped demo6 Connector process group $$PID"; \
	else \
		echo "PID $$PID is not running"; \
	fi; \
	rm -f "$$PID_FILE"

# Demo Handler - unified demo management
demo-handler:
	@echo "Connector Demo Handler"
	@echo "===================="
	@echo "Available commands:"
	@echo "  python demos/demo_handler.py list                    # List all demos"
	@echo "  python demos/demo_handler.py status                  # Check demo status"
	@echo "  python demos/demo_handler.py run <demo>              # Run specific demo"
	@echo "  python demos/demo_handler.py bootstrap <demo>        # Bootstrap specific demo"
	@echo "  python demos/demo_handler.py preflight <demo>        # Run preflight checks"
	@echo "  python demos/demo_handler.py bootstrap-all           # Bootstrap all demos"
	@echo "  python demos/demo_handler.py run-all                 # Run all demos"

demo-list:
	@python demos/demo_handler.py list

demo-status:
	@python demos/demo_handler.py status

demo-bootstrap-all:
	@python demos/demo_handler.py bootstrap-all

demo-run-all:
	@python demos/demo_handler.py run-all

demo6-status:
	@set -euo pipefail; \
	BASE_URL="$(CONNECTOR_URL)"; \
	if curl -fsS "$$BASE_URL/health" >/dev/null 2>&1; then \
		echo "Connector is healthy at $$BASE_URL"; \
	else \
		echo "Connector is not responding at $$BASE_URL"; \
	fi; \
	if [[ -f "$(DEMO6_PID_FILE)" ]]; then \
		echo "Demo6 PID: $$(cat "$(DEMO6_PID_FILE)") (make demo6-stop)"; \
	else \
		echo "No demo6-managed PID file"; \
	fi

install-local:
	@set -euo pipefail; \
	SERVER_DIR="$(SERVER_DIR)"; \
	BIN_DIR="$(LOCAL_BIN_DIR)"; \
	UI_DIR="$(LOCAL_UI_DIR)"; \
	mkdir -p "$$BIN_DIR"; \
	install -m 755 "$$SERVER_DIR/.cargo-target/debug/connectorctl" "$$BIN_DIR/connectorctl" 2>/dev/null \
		|| install -m 755 "$$SERVER_DIR/target/debug/connectorctl" "$$BIN_DIR/connectorctl"; \
	install -m 755 "$$SERVER_DIR/.cargo-target/debug/connector-platform" "$$BIN_DIR/connector-platform" 2>/dev/null \
		|| install -m 755 "$$SERVER_DIR/target/debug/connector-platform" "$$BIN_DIR/connector-platform"; \
	if [[ -x "platform/connector-vm-agent/target/debug/connector-vm-agent" ]]; then \
		install -m 755 "platform/connector-vm-agent/target/debug/connector-vm-agent" "$$BIN_DIR/connector-vm-agent"; \
	fi; \
	mkdir -p "$$UI_DIR"; \
	if compgen -G "platform/ui-leptos/dashboard/dist/*" > /dev/null; then \
		cp -r platform/ui-leptos/dashboard/dist/* "$$UI_DIR/"; \
	fi; \
	echo "Installed connectorctl + connector-platform to $$BIN_DIR"; \
	echo "Installed dashboard assets to $$UI_DIR"; \
	if [[ ":$$PATH:" != *":$$BIN_DIR:"* ]]; then \
		echo "Add $$BIN_DIR to PATH to run connectorctl from anywhere."; \
	fi

# ═════════════════════════════════════════════════════════════════════════════
# Playground Deploy - Single Binary System (auto-deletes old binaries)
# ═════════════════════════════════════════════════════════════════════════════

# Build and deploy playground with only 1 binary (old gets deleted)
playground-deploy:
	@bash scripts/build-and-deploy.sh

# Clean build - delete ALL old binaries, build fresh, deploy
playground-clean-deploy:
	@echo "🧹 Deep clean..."
	@rm -rf platform/deploy/artifacts/*
	@docker builder prune -f 2>/dev/null || true
	@rm -rf platform/server/target/release plugins/*/target/release
	@bash scripts/build-and-deploy.sh

# Just clean artifacts (no build)
playground-clean:
	@echo "🧹 Cleaning playground artifacts..."
	@rm -rf platform/deploy/artifacts/*
	@docker builder prune -f 2>/dev/null || true
	@echo "✅ Clean. Only 1 binary will exist after next build."

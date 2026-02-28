# Changelog

All notable changes to Connector-OSS will be documented in this file.

## [0.2.0] — 2026-02-27

### Added

#### Packaging & Distribution
- **PyPI**: `pip install connector-oss` — prebuilt wheels for Linux/macOS/Windows (5 platforms)
- **npm**: `npm install @connector-oss/connector` — prebuilt NAPI-RS native addons (7 platforms)
- **Docker**: `docker run globalsushrut/connector-oss` — scratch image (~8MB, 0 CVEs)
- **Docker Compose**: `docker compose up` — server + SQLite persistence + optional Prometheus/Grafana
- **GitHub Actions CI**: test (1,857 tests), publish-pypi, publish-npm, publish-docker workflows
- **QUICKSTART.md**: 5-minute copy-paste guide for Python, TypeScript, Docker, and curl

#### NAPI-RS Native TypeScript SDK
- `connector-napi` Rust crate — 26 `#[napi]` methods calling Rust engine directly
- Native-first + HTTP fallback per method in TypeScript SDK
- `isNativeAvailable()` export, `c.isNative` property
- Prebuilt binaries as optional npm dependencies per platform

#### Connector Protocol (CP/1.0) — Server Routes
- 10 new REST routes under `/protocol/*` (info, identity, capabilities, safety, intent, consensus, attestation, telemetry, routing)
- Server now has **38 routes** total (was 28)

#### Architecture Documentation
- Full 61-module engine component table with scalability roles
- Distributed architecture section: cell topology diagram, interlink table, dependency chain
- 21-phase config-to-runtime wiring reference (A–U)
- CP/1.0 protocol layer table (7 layers + safety/telemetry/envelope)
- Technical positioning: Docker vs Kubernetes vs Istio vs Vault vs OPA vs Connector comparison
- Maturity stage assessment

### Changed
- Dockerfile: upgraded to Rust 1.82, added health check, documented all env vars
- docker-compose.yml: added SQLite persistence, health checks, observability profile, env defaults
- pyproject.toml: version 0.2.0, expanded keywords/classifiers, maturin 1.4+, strip=true
- package.json: scoped to `@connector-oss/connector`, dual CJS/ESM exports, optional platform deps
- Python SDK README: expanded with memory/knowledge/folders/observability examples + comparison table
- TypeScript SDK README: expanded with NAPI-RS docs, protocol examples, comparison table

## [0.1.0] — 2026-02-01

### Added
- Initial release
- **28 crates** across 3 workspaces (connector, vac, aapi)
- **connector-engine**: 61 modules, Ring 1-4 architecture
- **vac-core**: MemoryKernel, KnotEngine, syscall API, audit
- **vac-ffi**: Python FFI (~140 methods via PyO3)
- **connector-server**: REST API (28 routes initially)
- **connector-protocol**: CP/1.0 (11 modules, 120 capabilities)
- **connector-protocols**: ANP, A2A, ACP, MCP, SCITT bridges
- **aapi**: Action authorization, federation, gateway, pipeline
- **1,857 tests**, 0 failures
- YAML config system: 7 progressive levels (level0–level7)
- 3-tier config: Required / Defaults / Optional-Revoke

# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.0] - 2026-02-01

### Added
- Gateway execution via adapters (file + HTTP) with effect capture and receipts
- MetaRules policy enforcement (allow/deny/pending approval) in the gateway request path
- Production mode security posture (signature required, default-deny switch)
- GitHub Actions CI workflows (build, lint, tests, release)
- Open source hygiene files (LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT)

### Notes
- Capability-token enforcement is planned but not yet fully wired into the gateway request schema.

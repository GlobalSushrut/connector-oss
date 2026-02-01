# Contributing to Connector

Thank you for your interest in contributing to Connector! This monorepo contains two projects:

- **AAPI** — Agentic Action Protocol Interface
- **VAC** — Vault Attestation Chain

## Getting Started

### Prerequisites

- **Rust** 1.75+ (for both projects)
- **Node.js** 18+ (for VAC TypeScript SDK)
- **SQLite** (for AAPI development)

### Repository Structure

```
connector-oss/
├── aapi/               # AAPI - Action accountability
│   ├── crates/         # Rust crates
│   └── sdks/           # Python SDK
│
└── vac/                # VAC - Verifiable memory
    ├── crates/         # Rust crates
    ├── packages/       # TypeScript SDK
    └── demo/           # Interactive demo
```

### Building

```bash
# Build AAPI
cd aapi && cargo build

# Build VAC
cd vac && cargo build

# Build VAC TypeScript SDK
cd vac/packages/vac-sdk && npm install && npm run build
```

## Project-Specific Guidelines

Each project has its own detailed contributing guide:

- [AAPI Contributing Guide](aapi/CONTRIBUTING.md)
- [VAC Contributing Guide](vac/CONTRIBUTING.md)

## General Guidelines

### Code Style

- **Rust**: Use `rustfmt` and `clippy`
- **TypeScript**: Use ESLint and Prettier
- Document public APIs

### Commits

- Use clear, descriptive commit messages
- Reference issues when applicable
- Keep commits focused and atomic

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a PR with clear description

### Testing

```bash
# Test AAPI
cd aapi && cargo test

# Test VAC
cd vac && cargo test

# Test VAC TypeScript SDK
cd vac/packages/vac-sdk && npm test
```

## Code of Conduct

Be respectful and constructive in all interactions.

## License

By contributing, you agree that your contributions will be licensed under Apache License 2.0.

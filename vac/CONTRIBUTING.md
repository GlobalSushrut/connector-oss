# Contributing to VAC

Thank you for your interest in contributing to VAC (Vault Attestation Chain)! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Contributions](#making-contributions)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- **Rust** 1.70+ (for core crates)
- **Node.js** 18+ (for TypeScript SDK)
- **npm** or **pnpm**

### Repository Structure

```
vac/
├── crates/              # Rust crates
│   ├── vac-core/        # Core types, CID, codec
│   ├── vac-store/       # Content-addressable storage
│   ├── vac-prolly/      # Prolly tree implementation
│   ├── vac-red/         # RED engine (non-ML learning)
│   ├── vac-crypto/      # Ed25519 signatures
│   ├── vac-sync/        # DAG sync protocol
│   └── vac-wasm/        # WASM bindings
├── packages/
│   └── vac-sdk/         # TypeScript SDK
├── demo/                # Demo application
└── docs/                # Documentation
```

## Development Setup

### Rust Crates

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/vac.git
cd vac

# Build all crates
cargo build

# Run tests
cargo test

# Run with release optimizations
cargo build --release
```

### TypeScript SDK

```bash
cd packages/vac-sdk

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

### Demo Application

```bash
cd demo

# Install dependencies
npm install

# Start development server
npm run dev
```

## Making Contributions

### Types of Contributions

We welcome:

- **Bug fixes** - Fix issues and improve stability
- **Features** - New functionality aligned with the roadmap
- **Documentation** - Improve docs, examples, tutorials
- **Tests** - Increase test coverage
- **Performance** - Optimize critical paths

### Before You Start

1. **Check existing issues** - Someone may already be working on it
2. **Open an issue first** - For significant changes, discuss before coding
3. **Read the architecture docs** - Understand how VAC works

### Branch Naming

```
feature/short-description
fix/issue-number-description
docs/what-you-documented
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`
3. **Make your changes** with clear commits
4. **Write/update tests** for your changes
5. **Update documentation** if needed
6. **Run all tests** locally
7. **Submit a PR** with a clear description

### PR Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (for user-facing changes)
- [ ] Commit messages are clear

### PR Description Template

```markdown
## Summary
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation

## Testing
How did you test these changes?

## Related Issues
Fixes #123
```

## Coding Standards

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Document public APIs with doc comments

```rust
/// Computes the CID for a serializable object.
///
/// # Arguments
/// * `obj` - Any object implementing `Serialize`
///
/// # Returns
/// * `VacResult<Cid>` - The computed CID or an error
pub fn compute_cid<T: Serialize>(obj: &T) -> VacResult<Cid> {
    // ...
}
```

### TypeScript

- Use TypeScript strict mode
- Follow existing code style
- Use ESLint and Prettier
- Document exports with JSDoc

```typescript
/**
 * Creates a new VAC vault instance.
 * @param config - Vault configuration options
 * @returns A new Vault instance
 */
export function createVault(config: VaultConfig): Vault {
  // ...
}
```

## Testing

### Rust Tests

```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p vac-core

# Run with output
cargo test -- --nocapture
```

### TypeScript Tests

```bash
cd packages/vac-sdk
npm test
```

### Test Guidelines

- Write unit tests for new functions
- Write integration tests for workflows
- Test edge cases and error conditions
- Aim for >80% coverage on new code

## Documentation

### Where to Document

- **Code comments** - For implementation details
- **Doc comments** - For public API (Rust: `///`, TS: `/** */`)
- **README.md** - For getting started
- **docs/** - For detailed guides

### Documentation Style

- Be concise but complete
- Include code examples
- Explain the "why", not just the "what"
- Keep docs up to date with code changes

## Questions?

- **GitHub Issues** - For bugs and feature requests
- **Discussions** - For questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to VAC! 🚀

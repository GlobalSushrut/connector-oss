# Contributing to AAPI

Thank you for your interest in contributing to AAPI! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/AAPI.git
   cd AAPI
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/AAPI.git
   ```

## Development Setup

### Prerequisites

- **Rust**: 1.75+ (install via [rustup](https://rustup.rs/))
- **Python**: 3.9+ (for SDK development)
- **SQLite**: 3.x (for local database)

### Building the Project

```bash
# Build all Rust crates
cargo build

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy --all-targets
```

### Python SDK Development

```bash
cd sdks/python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## Making Changes

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring
- `test/description` - Test additions/changes

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```
feat(gateway): add MetaRules policy enforcement
fix(adapters): handle file path traversal correctly
docs(readme): update installation instructions
```

## Pull Request Process

1. **Update your fork** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature
   ```

3. **Make your changes** and commit them

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature
   ```

5. **Open a Pull Request** on GitHub

### PR Requirements

- [ ] All CI checks pass
- [ ] Code follows project style guidelines
- [ ] Tests added/updated for new functionality
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventions
- [ ] PR description explains the changes

## Coding Standards

### Rust

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Document public APIs with doc comments
- Write unit tests for new functionality

```rust
/// Brief description of the function.
///
/// # Arguments
///
/// * `arg1` - Description of arg1
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// Description of possible errors
///
/// # Examples
///
/// ```
/// let result = my_function(arg);
/// ```
pub fn my_function(arg1: Type) -> Result<ReturnType, Error> {
    // implementation
}
```

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use type hints
- Use docstrings for public functions/classes
- Format with `ruff format`
- Lint with `ruff check`

```python
def my_function(arg1: str) -> Result:
    """Brief description of the function.

    Args:
        arg1: Description of arg1

    Returns:
        Description of return value

    Raises:
        ValueError: When arg1 is invalid
    """
    pass
```

## Testing

### Rust Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture
```

### Python Tests

```bash
cd sdks/python
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=aapi
```

### Integration Tests

```bash
# Start the gateway
cargo run -p aapi-gateway &

# Run integration tests
cd sdks/python
python examples/basic_usage.py
```

## Documentation

- Update README.md for user-facing changes
- Update API documentation for interface changes
- Add examples for new features
- Keep CHANGELOG.md updated

### Building Docs

```bash
# Rust documentation
cargo doc --open

# Python documentation
cd sdks/python
# (documentation build command)
```

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Join our community channels (if available)

Thank you for contributing to AAPI! 🙏

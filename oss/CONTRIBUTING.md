# Contributing

This repository is Apache-2.0. By submitting a change you agree that your contribution is licensed under Apache-2.0.

## Checks

From the repository root:

```bash
make rust
```

Format Rust changes with `cargo fmt` in the workspace you touched.

## What does not belong here

- Private design notes, launch checklists, and discussion writeups
- Billing, license-server, or hosted-control-plane code
- Secrets, `.env` files, and local databases

Open a bug report with the crate, the command, and the error. Feature requests should name the user-visible behavior.

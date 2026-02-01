# AAPI Quickstart (Local)

This quickstart starts the AAPI Gateway locally and runs a small end-to-end action using the Python SDK.

## Prerequisites

- Rust 1.75+
- Python 3.9+

## One-command quickstart

From the repo root:

```bash
./scripts/quickstart.sh
```

## What this does

- Builds the workspace
- Starts the gateway on `http://127.0.0.1:8080`
- Uses the file adapter sandbox at `/tmp/aapi`
- Runs the Python example (`sdks/python/examples/basic_usage.py`) to:
  - write a file under `/tmp/aapi`
  - read it back
  - print receipts

## Manual steps (if you prefer)

Terminal 1:

```bash
mkdir -p /tmp/aapi
cargo run --bin aapi -- serve --host 127.0.0.1 --port 8080
```

Terminal 2:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e sdks/python
python sdks/python/examples/basic_usage.py
```

## Notes

- If you run the gateway in production mode, signatures are required.
- Capability-token enforcement is planned; approval and policy enforcement are already wired.

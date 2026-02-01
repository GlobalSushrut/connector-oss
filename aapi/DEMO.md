# AAPI Demo (Copy/Paste)

This is a short demo you can run live in under a minute.

## 1) Start the gateway

```bash
mkdir -p /tmp/aapi
cargo run --bin aapi -- serve --host 127.0.0.1 --port 8080
```

Health check:

```bash
curl -s http://127.0.0.1:8080/health | jq
```

## 2) Run the Python SDK example

In a second terminal:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e sdks/python
python sdks/python/examples/basic_usage.py
```

Expected behavior:

- A file is written under `/tmp/aapi` and then read back.
- The gateway returns receipts.
- The effect log records before/after state.

## 3) Trigger a policy decision

### Deny example

The gateway ships with a default policy that denies `file.delete` (safety). Submit a `file.delete` and observe the `denied` response.

If you prefer, you can use the gateway API directly with `curl` by adapting the payload example in `README.md`.

### Pending approval example

The default policies mark `http.post` as `pending_approval`. Submit `http.post` and observe:

- `status: pending_approval`
- a generated `approval_id`

## 4) Rollback demo

The adapters produce reversible effects for `file.write` and `file.delete`. There is a Rust integration test covering rollback:

```bash
cargo test -p aapi-adapters --test rollback_replay
```

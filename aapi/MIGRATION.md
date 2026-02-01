# Migration Notes

This document captures early migration guidance as AAPI approaches its Beta release.

## API stability

- The gateway HTTP endpoint for submission is:
  - `POST /v1/vakya`
- Response status can be:
  - `accepted`
  - `failed`
  - `denied`
  - `pending_approval`

If you previously treated every non-2xx as a denial, update clients to handle `denied` and `pending_approval` as successful HTTP responses with policy metadata.

## Sandbox behavior (file adapter)

- The gateway initializes the file adapter sandbox at:
  - `/tmp/aapi`

If your older demos used arbitrary filesystem paths, update them to use `/tmp/aapi/...`.

## Python SDK packaging

- Python package name:
  - `aapi-sdk`
- Optional extras:
  - `aapi-sdk[crypto]` enables Ed25519 signing helpers

If you import `aapi.crypto`, ensure you have installed the `crypto` extra.

## Production mode security posture

When running the gateway in production mode:

- Request signatures are required
- Default-deny posture is enabled

Capability-token verification is present at the library level and will be wired more strictly into the gateway request schema as part of the next iteration.

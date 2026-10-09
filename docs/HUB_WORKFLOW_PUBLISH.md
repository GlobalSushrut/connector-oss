# Hub workflow `.cpkg` publish (P4.2)

Honest contract for publishing a workflow package to Hub. **Not a shipping install path yet.**

## Status

| Field | Value |
|-------|--------|
| Product claim | Deferred / partial |
| CLI preview | `connectorctl workflow publish <workflow_id>` → `*.workflow.cpkg.json` (`format: workflow.cpkg.preview`) |
| Hub API | `POST /api/v1/hub/workflows/publish` — honesty stub (`implemented: false` today) |
| Install / yank | Future — same schema, not wired |

## Manifest schema (future `.cpkg`)

```json
{
  "schema": "workflow.cpkg.v1",
  "package_id": "string",
  "workflow_id": "string",
  "version": "semver or vN",
  "cls_source": "string",
  "requires": ["plugin-slug", "..."],
  "digest": "sha256 hex of canonical bytes (future)",
  "signature": "optional detached sig (future)",
  "published_at": "RFC3339"
}
```

Preview packages written by `connectorctl` use `format: "workflow.cpkg.preview"` and omit digest/signature.

## API — `POST /api/v1/hub/workflows/publish`

### Request (accepted shape for future)

```json
{
  "workflow_id": "string",
  "package_id": "optional string",
  "version": "optional string",
  "requires": ["optional plugin slugs"],
  "cls_source": "optional — server may load from catalog when omitted"
}
```

### Response (honesty)

```json
{
  "ok": true,
  "schema": "hub.workflow.publish.v1",
  "implemented": false,
  "status": "partial",
  "honesty": "Hub workflow .cpkg publish is not a shipping install path; CLI preview only until Hub registry lands.",
  "future": {
    "verify_on_install": true,
    "yank": "DELETE /api/v1/hub/workflows/:package_id/:version",
    "install": "POST /api/v1/hub/workflows/install"
  },
  "accepted_request_shape": { "...": "echo of validated fields when present" }
}
```

When a real registry lands, `implemented` flips to `true` only after verify-on-install + yank are exercised in lab.

## Related

- [FINAL_REACH.md](../FINAL_REACH.md) P4.2
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — Hub workflow publish row
- CLI: `connectorctl workflow publish`

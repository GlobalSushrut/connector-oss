from __future__ import annotations

import hashlib
import json
from typing import Any


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def canonical_asset_address(app_id: str, bucket: str, path: str) -> str:
    bucket_name = bucket.removesuffix("_assets")
    return f"gloo://{app_id}/{bucket_name}/{path.lstrip('/')}"


def receipt_hash(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def asset_receipt(
    *,
    app_id: str,
    bucket: str,
    path: str,
    content: str,
    previous_receipt_hash: str,
    node: str = "local",
) -> dict[str, Any]:
    address = canonical_asset_address(app_id, bucket, path)
    payload = {
        "app_id": app_id,
        "bucket": bucket.removesuffix("_assets"),
        "path": path,
        "address": address,
        "content_sha256": content_hash(content),
        "previous_receipt_hash": previous_receipt_hash,
        "node": node,
    }
    payload["receipt_hash"] = receipt_hash(payload)
    return payload


def build_receipt_ledger(
    manifest: dict[str, Any],
    assets: dict[str, list[dict[str, str]]],
    *,
    node: str = "local",
) -> dict[str, Any]:
    app_id = manifest.get("app_id", "unknown")
    receipt_head = "genesis"
    receipts: list[dict[str, Any]] = []

    for contract in assets.get("contracts", []):
        receipt = asset_receipt(
            app_id=app_id,
            bucket="contracts",
            path=contract["path"],
            content=contract["content"],
            previous_receipt_hash=receipt_head,
            node=node,
        )
        receipt_head = receipt["receipt_hash"]
        receipts.append(receipt)

    for bucket in ["policies", "identity_rules", "address_rules", "business_rules"]:
        for asset in assets.get(bucket, []):
            receipt = asset_receipt(
                app_id=app_id,
                bucket=bucket,
                path=asset["path"],
                content=asset["content"],
                previous_receipt_hash=receipt_head,
                node=node,
            )
            receipt_head = receipt["receipt_hash"]
            receipts.append(receipt)

    for workflow in manifest.get("workflows", []):
        cls_source = workflow.get("cls_source", "")
        if not cls_source:
            continue
        receipt = asset_receipt(
            app_id=app_id,
            bucket="workflows",
            path=f"workflows/{workflow.get('id', 'unknown')}.ccl",
            content=cls_source,
            previous_receipt_hash=receipt_head,
            node=node,
        )
        receipt_head = receipt["receipt_hash"]
        receipts.append(receipt)

    return {
        "schema": "gloo.receipt_ledger.v1",
        "app_id": app_id,
        "system_tier": manifest.get("system_tier", "installed"),
        "node": node,
        "receipt_head": receipt_head,
        "receipts": receipts,
    }


def verify_receipt_ledger(ledger: dict[str, Any], manifest: dict[str, Any], assets: dict[str, list[dict[str, str]]]) -> dict[str, Any]:
    expected = build_receipt_ledger(manifest, assets, node=ledger.get("node", "local"))
    errors: list[str] = []

    if ledger.get("schema") != "gloo.receipt_ledger.v1":
        errors.append("unsupported receipt ledger schema")
    if ledger.get("app_id") != manifest.get("app_id"):
        errors.append("receipt ledger app_id mismatch")
    if ledger.get("receipt_head") != expected["receipt_head"]:
        errors.append("receipt_head mismatch (package contents changed after build)")

    expected_by_path = {(r["bucket"], r["path"]): r for r in expected["receipts"]}
    for receipt in ledger.get("receipts", []):
        key = (receipt.get("bucket"), receipt.get("path"))
        match = expected_by_path.get(key)
        if not match:
            errors.append(f"unexpected receipt for {key}")
            continue
        if receipt.get("content_sha256") != match["content_sha256"]:
            errors.append(f"content hash mismatch for {key}")

    prev = "genesis"
    for receipt in ledger.get("receipts", []):
        if receipt.get("previous_receipt_hash") != prev:
            errors.append(f"broken receipt chain at {receipt.get('path')}")
            break
        recomputed = dict(receipt)
        recomputed.pop("receipt_hash", None)
        recomputed["receipt_hash"] = receipt_hash(recomputed)
        if recomputed["receipt_hash"] != receipt.get("receipt_hash"):
            errors.append(f"invalid receipt hash at {receipt.get('path')}")
        prev = receipt.get("receipt_hash", "")

    return {"ok": not errors, "errors": errors, "expected_head": expected["receipt_head"]}

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from .receipts import asset_receipt, content_hash, receipt_hash


class GlooNode:
    """
    Thin Python-first developer client for a Connector node.

    This is intentionally honest:
    - it can bootstrap workflows through the real backend
    - it can install an existing `.cpkg`
    - `gloo build` / `GlooProject.build_cpkg` emit a real `.cpkg` + pin; this client does not invent a second package format
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 60,
    ):
        env_url = os.getenv("CONNECTOR_BASE_URL") or os.getenv("CONNECTOR_URL")
        self._base_url_source = "arg" if base_url else ("env" if env_url else "implicit-default")
        self.base_url = (base_url or env_url or "http://127.0.0.1:9091").rstrip("/")
        self.token = token or os.getenv("CONNECTOR_API_KEY") or "dev-token"
        self.timeout = timeout

    def ensure_explicit_target(self) -> None:
        if self._base_url_source == "implicit-default":
            raise RuntimeError(
                "No Connector node target specified. Pass --base-url or set CONNECTOR_BASE_URL/CONNECTOR_URL "
                "to the real node address (localhost, k8s, cloud instance, or other reachable Connector node)."
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = requests.get(
            f"{self.base_url}/api/v1{path}",
            headers=self._headers(),
            params=params,
            timeout=self.timeout,
        )
        data = resp.json()
        if resp.status_code >= 400:
            raise RuntimeError(f"{path} failed: status={resp.status_code} body={data}")
        return data

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        resp = requests.post(
            f"{self.base_url}/api/v1{path}",
            headers=self._headers(),
            json=body,
            timeout=self.timeout,
        )
        data = resp.json()
        if resp.status_code >= 400:
            raise RuntimeError(f"{path} failed: status={resp.status_code} body={data}")
        if isinstance(data, dict) and data.get("ok") is False:
            raise RuntimeError(f"{path} returned ok=false: {data}")
        return data

    def health(self) -> Dict[str, Any]:
        resp = requests.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def doctor(self) -> Dict[str, Any]:
        health = self.health()
        api_root = self._get("")
        lab_mode = self._get("/runtime/lab-mode")
        llm_status = self._get("/settings/llms/status")
        return {
            "ok": True,
            "health": health,
            "api": api_root,
            "lab_mode": lab_mode,
            "llm_status": llm_status,
        }

    def logs(self, agent: Optional[str] = None, tail: int = 100) -> Dict[str, Any]:
        if agent:
            return self._get(f"/agents/{agent}/logs", {"tail": tail})
        return self._get("/monitor/logs", {"tail": tail})

    def trace(self, agent: str, last: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit}
        if last:
            params["last"] = last
        return self._get(f"/agents/{agent}/trace", params)

    def receipts(
        self,
        agent: str,
        *,
        from_ms: Optional[int] = None,
        to_ms: Optional[int] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit}
        if from_ms is not None:
            params["from_ms"] = from_ms
        if to_ms is not None:
            params["to_ms"] = to_ms
        return self._get(f"/agents/{agent}/audit/receipts", params)

    def bootstrap_reference_workflow(
        self,
        reference_id: str,
        *,
        enable: bool = True,
        dry_run: bool = True,
        run: bool = True,
    ) -> Dict[str, Any]:
        return self._post(
            "/workflows/bootstrap",
            {
                "source": f"reference:{reference_id}",
                "reference_id": reference_id,
                "enable": enable,
                "dry_run": dry_run,
                "run": run,
            },
        )

    def compile_cls(self, cls_source: str) -> Dict[str, Any]:
        return self._post("/cls/compile", {"source": cls_source})

    @staticmethod
    def _asset_bucket_name(bucket: str) -> str:
        return bucket.removesuffix("_assets")

    @staticmethod
    def _canonical_asset_address(app_id: str, bucket: str, path: str) -> str:
        return f"gloo://{app_id}/{GlooNode._asset_bucket_name(bucket)}/{path.lstrip('/')}"

    @staticmethod
    def _content_hash(content: str) -> str:
        return content_hash(content)

    @staticmethod
    def _receipt_hash(payload: Dict[str, Any]) -> str:
        return receipt_hash(payload)

    def _asset_receipt(
        self,
        *,
        app_id: str,
        bucket: str,
        path: str,
        content: str,
        previous_receipt_hash: str,
    ) -> Dict[str, Any]:
        return asset_receipt(
            app_id=app_id,
            bucket=bucket,
            path=path,
            content=content,
            previous_receipt_hash=previous_receipt_hash,
            node=self.base_url,
        )

    def publish_knowledge_text(
        self,
        *,
        app_id: str,
        bucket: str,
        path: str,
        content: str,
        previous_receipt_hash: str = "genesis",
    ) -> Dict[str, Any]:
        namespace = f"k/gloo/{app_id}/{self._asset_bucket_name(bucket)}"
        receipt = self._asset_receipt(
            app_id=app_id,
            bucket=bucket,
            path=path,
            content=content,
            previous_receipt_hash=previous_receipt_hash,
        )
        return self._post(
            "/memory/write",
            {
                "agent_pid": f"gloo:{app_id}",
                "content": json.dumps(
                    {
                        "kind": "gloo_customization_asset",
                        "address": receipt["address"],
                        "path": path,
                        "bucket": receipt["bucket"],
                        "content_sha256": receipt["content_sha256"],
                        "body": content,
                    },
                    indent=2,
                ),
                "pipeline": "gloo_apply",
                "packet_type": "extraction",
                "type": "semantic",
                "tags": [
                    "gloo",
                    receipt["bucket"],
                    path,
                    receipt["content_sha256"],
                    receipt["receipt_hash"],
                ],
                "user": receipt["address"],
            },
        )

    def register_workflow(self, workflow_payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/workflows", workflow_payload)

    def apply_intelligence(self, intelligence_spec: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/intelligence/apply", intelligence_spec)

    def bootstrap_workflow(self, workflow_payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(workflow_payload)
        body.setdefault("enable", True)
        body.setdefault("dry_run", True)
        body.setdefault("run", True)
        return self._post("/workflows/bootstrap", body)

    def apply_manifest(self, manifest: Dict[str, Any], *, skip_workflows: bool = False) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "ok": True,
            "app_id": manifest.get("app_id"),
            "node": self.base_url,
            "agents": [],
            "workflows": [],
            "contracts": [],
            "knowledge_assets": [],
            "receipts": [],
        }
        receipt_head = "genesis"
        if not skip_workflows:
            for workflow in manifest.get("workflows", []):
                results["workflows"].append(
                    self.bootstrap_workflow(
                        {
                            "workflow_id": workflow.get("id"),
                            "package_id": workflow.get("package_id") or f"pkg-{workflow.get('id')}",
                            "version": workflow.get("version", "v1"),
                            "cls_source": workflow.get("cls_source", ""),
                            "accounting_mode": workflow.get("accounting_mode", "action"),
                            "enable": True,
                            "dry_run": True,
                            "run": True,
                        }
                    )
                )
        for contract in manifest.get("contracts_assets", []):
            receipt = self._asset_receipt(
                app_id=manifest.get("app_id", "unknown"),
                bucket="contracts_assets",
                path=contract.get("path", ""),
                content=contract.get("content", ""),
                previous_receipt_hash=receipt_head,
            )
            receipt_head = receipt["receipt_hash"]
            results["contracts"].append(
                {
                    "path": contract.get("path"),
                    "address": receipt["address"],
                    "content_sha256": receipt["content_sha256"],
                    "receipt_hash": receipt["receipt_hash"],
                    "previous_receipt_hash": receipt["previous_receipt_hash"],
                    "compile": self.compile_cls(contract.get("content", "")),
                }
            )
            results["receipts"].append(receipt)
        for bucket in ["policies_assets", "identity_rules_assets", "address_rules_assets", "business_rules_assets"]:
            for asset in manifest.get(bucket, []):
                receipt = self._asset_receipt(
                    app_id=manifest.get("app_id", "unknown"),
                    bucket=bucket,
                    path=asset.get("path", ""),
                    content=asset.get("content", ""),
                    previous_receipt_hash=receipt_head,
                )
                receipt_head = receipt["receipt_hash"]
                results["knowledge_assets"].append(
                    {
                        "bucket": bucket,
                        "path": asset.get("path"),
                        "address": receipt["address"],
                        "content_sha256": receipt["content_sha256"],
                        "receipt_hash": receipt["receipt_hash"],
                        "previous_receipt_hash": receipt["previous_receipt_hash"],
                        "publish": self.publish_knowledge_text(
                            app_id=manifest.get("app_id", "unknown"),
                            bucket=bucket,
                            path=asset.get("path", ""),
                            content=asset.get("content", ""),
                            previous_receipt_hash=receipt["previous_receipt_hash"],
                        ),
                    }
                )
                results["receipts"].append(receipt)
        for agent in manifest.get("agents", []):
            results["agents"].append(
                self.apply_intelligence(
                    {
                        "apiVersion": "connector.ai/v1",
                        "kind": "Intelligence",
                        "metadata": {"name": agent.get("name")},
                        "spec": {
                            "purpose": agent.get("purpose"),
                            "class": agent.get("class_name", "app"),
                            "parameters": {
                                "model": agent.get("model"),
                                "namespace": agent.get("namespace", "default"),
                                "role": "reader",
                            },
                            "skills": agent.get("skills", []),
                            "knowledge": agent.get("knowledge", []),
                            "portals": agent.get("portals", []),
                            "harden": agent.get("harden", True),
                            "activate": True,
                        },
                    }
                )
            )
        results["receipt_head"] = receipt_head
        return results

    def install_cpkg_verified(
        self,
        path: str | Path,
        *,
        apply_assets: bool = True,
        require_receipts: bool = True,
    ) -> Dict[str, Any]:
        path = Path(path)
        local_verify: Dict[str, Any]
        if require_receipts:
            from .project import GlooProject

            local_verify = GlooProject.verify_cpkg_receipts(path)
            if not local_verify.get("ok"):
                raise RuntimeError(f"cpkg receipt verification failed: {local_verify.get('errors')}")
        else:
            local_verify = {"ok": True, "skipped": True}

        preflight = self.preflight_cpkg_file(path)
        install = self.install_cpkg_file(path)

        assets_apply = None
        if apply_assets and install.get("ok"):
            from .project import GlooProject

            manifest = GlooProject.manifest_from_cpkg(path)
            assets = GlooProject.customization_assets_from_cpkg(path)
            manifest["contracts_assets"] = assets["contracts"]
            manifest["policies_assets"] = assets["policies"]
            manifest["identity_rules_assets"] = assets["identity_rules"]
            manifest["address_rules_assets"] = assets["address_rules"]
            manifest["business_rules_assets"] = assets["business_rules"]
            server_burn_in = install.get("burn_in") or install.get("data", {}).get("burn_in")
            skip_workflows = bool(server_burn_in and server_burn_in.get("ok"))
            assets_apply = self.apply_manifest(manifest, skip_workflows=skip_workflows)

        return {
            "ok": True,
            "node": self.base_url,
            "local_verify": local_verify,
            "preflight": preflight,
            "install": install,
            "assets_apply": assets_apply,
        }

    def install_cpkg_file(self, path: str | Path) -> Dict[str, Any]:
        raw = Path(path).read_bytes()
        return self._post(
            "/plugins/cpkg/install",
            {"cpkg_base64": base64.b64encode(raw).decode("ascii")},
        )

    def preflight_cpkg_file(self, path: str | Path) -> Dict[str, Any]:
        raw = Path(path).read_bytes()
        return self._post(
            "/plugins/cpkg/preflight",
            {"cpkg_base64": base64.b64encode(raw).decode("ascii")},
        )

    def install_cpkg_url(self, url: str) -> Dict[str, Any]:
        return self._post("/plugins/cpkg/install", {"url": url})

    def preflight_cpkg_url(self, url: str) -> Dict[str, Any]:
        return self._post("/plugins/cpkg/preflight", {"url": url})

    def install_cpkg_hub(self, plugin_id: str, version: str) -> Dict[str, Any]:
        return self._post(
            "/plugins/cpkg/install",
            {"hub_fetch": {"plugin_id": plugin_id, "version": version}},
        )

    def preflight_cpkg_hub(self, plugin_id: str, version: str) -> Dict[str, Any]:
        return self._post(
            "/plugins/cpkg/preflight",
            {"hub_fetch": {"plugin_id": plugin_id, "version": version}},
        )

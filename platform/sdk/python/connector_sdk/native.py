"""Native control-plane client — mirrors connector-client / cnktros invoke path.

Defaults to http://127.0.0.1:9091 (platform listener). Refuses silent
``dev-token`` outside lab. Mutating invoke requires a package pin unless
``CONNECTOR_RUNTIME_PROFILE=lab``.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "connector_sdk.native requires 'requests'. Install with: pip install requests"
    ) from exc


class NativeClientError(RuntimeError):
    """Fail-closed native API / package-gate error (never empty success)."""

    def __init__(self, message: str, *, status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


def _runtime_profile() -> str:
    return os.getenv("CONNECTOR_RUNTIME_PROFILE", "development").strip().lower()


def _is_lab_profile(profile: Optional[str] = None) -> bool:
    p = (profile or _runtime_profile()).lower()
    return p in ("lab", "dev", "development", "test")


def admit_package_for_effect(
    package: Optional[Mapping[str, Any]],
    *,
    mutates: bool,
    profile: Optional[str] = None,
) -> None:
    """Client-side package gate matching connector_native_contract semantics."""
    if not mutates:
        return
    prof = (profile or _runtime_profile()).lower()
    if _is_lab_profile(prof) and package is None:
        return
    if package is None:
        raise NativeClientError(
            "package_required: mutating native invoke needs signed AppPackageV2 pin outside lab"
        )
    digest = str(package.get("package_digest") or "").strip()
    pkg_id = str(package.get("package_id") or "").strip()
    if not pkg_id or len(digest) < 16:
        raise NativeClientError("package_invalid_pin: package_id and package_digest required")
    if not _is_lab_profile(prof):
        sig = package.get("signature_present")
        if sig is False or sig is None:
            # production/hardened: require explicit signature_present=true
            if prof in ("production", "hardened", "defense", "defense-strict", "defense_strict"):
                raise NativeClientError(
                    "package_unsigned: signature_present required under production profile"
                )


@dataclass
class PackagePin:
    package_id: str
    package_digest: str
    kind: str = "app"
    ir_digest: Optional[str] = None
    signature_present: Optional[bool] = True

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": "connector.package_pin.v1",
            "package_id": self.package_id,
            "package_digest": self.package_digest,
            "kind": self.kind,
        }
        if self.ir_digest:
            out["ir_digest"] = self.ir_digest
        if self.signature_present is not None:
            out["signature_present"] = self.signature_present
        return out

    @staticmethod
    def from_cpkg_bytes(package_id: str, data: bytes, *, kind: str = "app") -> "PackagePin":
        digest = "cpkg-sha256-" + hashlib.sha256(data).hexdigest()
        return PackagePin(package_id=package_id, package_digest=digest, kind=kind)


class NativeClient:
    """Thin HTTP client for `/api/v1/native/*` surfaces."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        timeout: float = 30.0,
        runtime_profile: Optional[str] = None,
        enforce_package_gate: bool = True,
    ):
        env_url = os.getenv("CONNECTOR_BASE_URL") or os.getenv("CONNECTOR_NATIVE_URL")
        self.base_url = (base_url or env_url or "http://127.0.0.1:9091").rstrip("/")
        self.runtime_profile = (runtime_profile or _runtime_profile()).lower()
        self.enforce_package_gate = enforce_package_gate
        env_token = os.getenv("CONNECTOR_TOKEN") or os.getenv("CONNECTOR_API_TOKEN")
        if token is None:
            token = env_token
        if not token:
            if _is_lab_profile(self.runtime_profile):
                token = os.getenv("CONNECTOR_LAB_TOKEN", "")
            else:
                raise NativeClientError(
                    "token_required: set CONNECTOR_TOKEN or pass token= (no silent dev-token outside lab)"
                )
        if token == "dev-token" and not _is_lab_profile(self.runtime_profile):
            raise NativeClientError(
                "token_refused: silent/default dev-token is not allowed outside lab profile"
            )
        self.token = token or ""
        self.timeout = timeout
        self._session = requests.Session()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._session.headers.update(headers)

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}"

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        resp = self._session.request(
            method, self._url(path), json=body, timeout=self.timeout
        )
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        if resp.status_code >= 400:
            err = None
            if isinstance(data, dict):
                err = data.get("error") or data.get("message") or data.get("honesty")
            raise NativeClientError(
                str(err or f"http_{resp.status_code}"),
                status=resp.status_code,
                body=data,
            )
        if isinstance(data, dict) and data.get("ok") is False:
            raise NativeClientError(
                str(data.get("error") or data.get("honesty") or "request_denied"),
                status=resp.status_code,
                body=data,
            )
        return data

    def list_surfaces(self) -> Any:
        return self._request("GET", "/api/v1/native/surfaces")

    def list_channels(self) -> Any:
        return self._request("GET", "/api/v1/native/channels")

    def get_receipt(self, operation_id: str) -> Any:
        return self._request("GET", f"/api/v1/native/receipts/{operation_id}")

    def evidence_graph(self, *, limit: int = 64, intelligence: Optional[str] = None) -> Any:
        q = f"/api/v1/native/evidence/graph?limit={int(limit)}"
        if intelligence:
            q += f"&intelligence={intelligence}"
        return self._request("GET", q)

    def invoke(
        self,
        body: Dict[str, Any],
        package: Optional[PackagePin | Mapping[str, Any]] = None,
    ) -> Any:
        effect = body.get("effect") or {}
        mutates = bool(effect.get("mutates", False))
        pin_dict: Optional[Dict[str, Any]] = None
        if package is not None:
            pin_dict = package.to_dict() if isinstance(package, PackagePin) else dict(package)
        if self.enforce_package_gate:
            admit_package_for_effect(
                pin_dict, mutates=mutates, profile=self.runtime_profile
            )
        payload = dict(body)
        if pin_dict is not None:
            payload["package"] = pin_dict
        return self._request("POST", "/api/v1/native/invocations", payload)


def package_digest_file(path: str) -> str:
    """Compute ``cpkg-sha256-…`` digest for a local .cpkg file."""
    with open(path, "rb") as f:
        return "cpkg-sha256-" + hashlib.sha256(f.read()).hexdigest()

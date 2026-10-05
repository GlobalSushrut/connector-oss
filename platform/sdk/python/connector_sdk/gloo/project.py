from __future__ import annotations

import hashlib
import json
import os
import runpy
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

from .app import GlooAgentSpec, GlooAppManifest, GlooWorkflowSpec
from .receipts import build_receipt_ledger, verify_receipt_ledger


APP_TEMPLATE = """from connector_sdk import glue


def main() -> None:
    result = glue.health()
    print("Connector node healthy:", result.ok)


if __name__ == "__main__":
    main()
"""


CLS_TEMPLATE = """workflow sample_workflow {
  metadata {
    title: "Sample workflow"
  }

  step start {
    action: "memory.write"
  }
}
"""

CONTRACT_TEMPLATE = """contract sample_business_contract {
  interface {
    input request_id: string required
    output approved: bool
  }
}
"""

POLICY_TEMPLATE = """# Policy placeholders for future Connector/Gloo policy binding.
allow audit.write
allow memory.read
"""

IDENTITY_RULE_TEMPLATE = """# Identity mapping rules
# Example: principal -> business role / trust level / tenant mapping
"""

ADDRESS_RULE_TEMPLATE = """# Address routing rules
# Example: address -> connector node / workload / tenant mapping
"""

BUSINESS_RULE_TEMPLATE = """# Business rule placeholders
# Example: contract enforcement, workflow preconditions, HITL requirements
"""


LAUNCHER_TEMPLATE = """#!/usr/bin/env python3
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
VENDOR = ROOT / "vendor" / "site-packages"
if VENDOR.exists():
    sys.path.insert(0, str(VENDOR))
os.environ.setdefault("CONNECTOR_BASE_URL", os.getenv("CONNECTOR_URL", "http://127.0.0.1:9091"))
runpy.run_module("{entry_module}", run_name="__main__")
"""


class GlooProject:
    @staticmethod
    def entry_module_path(root: str | Path, entry_module: str) -> Path:
        root = Path(root)
        return root.joinpath(*entry_module.split(".")).with_suffix(".py")

    @staticmethod
    def _list_files_under(root: Path, rel_paths: list[str]) -> list[str]:
        files: list[str] = []
        for rel in rel_paths:
            target = root / rel
            if target.is_file():
                files.append(rel)
            elif target.is_dir():
                for child in sorted(target.rglob("*")):
                    if child.is_file():
                        files.append(child.relative_to(root).as_posix())
        return files

    @staticmethod
    def _read_text_assets(root: Path, rel_paths: list[str]) -> list[dict]:
        assets: list[dict] = []
        for rel in GlooProject._list_files_under(root, rel_paths):
            path = root / rel
            assets.append({"path": rel, "content": path.read_text()})
        return assets

    @staticmethod
    def run_build_hook(root: str | Path) -> bool:
        root = Path(root)
        hook = root / ".build.py"
        if not hook.exists():
            return False
        subprocess.run([sys.executable, str(hook)], cwd=str(root), check=True)
        return True

    @staticmethod
    def validate_manifest_data(manifest: dict) -> dict:
        errors: list[str] = []
        warnings: list[str] = []

        app_id = str(manifest.get("app_id", "")).strip()
        if not app_id:
            errors.append("app_id is required")
        name = str(manifest.get("name", "")).strip()
        if not name:
            errors.append("name is required")

        entry_module = str(manifest.get("entry_module", "")).strip()
        if not entry_module:
            errors.append("entry_module is required")

        workflows = manifest.get("workflows", [])
        for i, wf in enumerate(workflows):
            wid = str(wf.get("id", "")).strip()
            if not wid:
                errors.append(f"workflows[{i}].id is required")
            if not str(wf.get("package_id", "")).strip():
                errors.append(f"workflows[{i}].package_id is required")
            if not str(wf.get("cls_source", "")).strip():
                warnings.append(f"workflows[{i}] has empty cls_source; local .ccl source or explicit cls_source is expected")

        agents = manifest.get("agents", [])
        for i, agent in enumerate(agents):
            if not str(agent.get("id", "")).strip():
                errors.append(f"agents[{i}].id is required")
            if not str(agent.get("name", "")).strip():
                errors.append(f"agents[{i}].name is required")
            if not str(agent.get("purpose", "")).strip():
                errors.append(f"agents[{i}].purpose is required")

        for key in ["contracts", "policies", "identity_rules", "address_rules", "business_rules"]:
            value = manifest.get(key, [])
            if not isinstance(value, list):
                errors.append(f"{key} must be a list of relative paths")

        return {
            "ok": not errors,
            "errors": errors,
            "warnings": warnings,
            "app_id": app_id,
            "name": name,
            "entry_module": entry_module,
        }

    @staticmethod
    def validate_manifest(root: str | Path) -> dict:
        manifest = GlooProject.manifest_with_local_sources(root)
        out = GlooProject.validate_manifest_data(manifest)
        out["manifest"] = manifest
        return out

    @staticmethod
    def audit_project(root: str | Path) -> dict:
        root = Path(root)
        manifest = GlooProject.manifest_with_local_sources(root)
        validation = GlooProject.validate_manifest_data(manifest)
        entry_module = manifest.get("entry_module", "app.main")
        entry_path = GlooProject.entry_module_path(root, entry_module)
        if not entry_path.exists():
            validation["errors"].append(f"entry_module file not found: {entry_path.relative_to(root)}")
            validation["ok"] = False

        asset_groups = {
            "workflows": GlooProject._list_files_under(root, ["workflows"]),
            "contracts": GlooProject._list_files_under(root, manifest.get("contracts", [])),
            "policies": GlooProject._list_files_under(root, manifest.get("policies", [])),
            "identity_rules": GlooProject._list_files_under(root, manifest.get("identity_rules", [])),
            "address_rules": GlooProject._list_files_under(root, manifest.get("address_rules", [])),
            "business_rules": GlooProject._list_files_under(root, manifest.get("business_rules", [])),
        }

        for key, files in asset_groups.items():
            if not files:
                validation["warnings"].append(f"{key} has no files")

        return {
            "ok": validation["ok"],
            "errors": validation["errors"],
            "warnings": validation["warnings"],
            "entry_module": entry_module,
            "entry_module_file": entry_path.relative_to(root).as_posix() if entry_path.exists() else entry_path.as_posix(),
            "build_hook": (root / ".build.py").exists(),
            "requirements": (root / "requirements.txt").exists(),
            "asset_groups": asset_groups,
            "counts": {key: len(files) for key, files in asset_groups.items()},
            "manifest": manifest,
        }

    @staticmethod
    def customization_assets(root: str | Path) -> dict[str, list[dict]]:
        root = Path(root)
        manifest = GlooProject.manifest_with_local_sources(root)
        return {
            "contracts": GlooProject._read_text_assets(root, manifest.get("contracts", [])),
            "policies": GlooProject._read_text_assets(root, manifest.get("policies", [])),
            "identity_rules": GlooProject._read_text_assets(root, manifest.get("identity_rules", [])),
            "address_rules": GlooProject._read_text_assets(root, manifest.get("address_rules", [])),
            "business_rules": GlooProject._read_text_assets(root, manifest.get("business_rules", [])),
        }

    @staticmethod
    def plugin_id_from_app_id(app_id: str) -> str:
        cleaned = "".join(ch if ch.isalnum() else "-" for ch in app_id.lower()).strip("-")
        cleaned = "-".join(part for part in cleaned.split("-") if part)
        if "/" in app_id:
            return app_id
        return f"local/{cleaned or 'gloo-app'}"

    @staticmethod
    def render_plugin_toml(manifest: dict) -> str:
        plugin_id = GlooProject.plugin_id_from_app_id(manifest["app_id"])
        slug = plugin_id.split("/", 1)[1]
        name = manifest.get("name", slug)
        version = manifest.get("version", "0.1.0")
        description = manifest.get("description", "")
        permissions = manifest.get("permissions", [])
        required_lines = "\n".join(f'  "{p}",' for p in permissions)
        contracts = manifest.get("contracts", [])
        policies = manifest.get("policies", [])
        identity_rules = manifest.get("identity_rules", [])
        address_rules = manifest.get("address_rules", [])
        business_rules = manifest.get("business_rules", [])
        fmt = lambda items: ", ".join(f'"{x}"' for x in items)
        receipt_head = manifest.get("receipt_head", "genesis")
        system_tier = manifest.get("system_tier", "installed")
        return (
            "[plugin]\n"
            f'id = "{plugin_id}"\n'
            f'name = "{name}"\n'
            f'version = "{version}"\n'
            'author = "gloo"\n'
            'license = "MIT"\n'
            'min_kernel = "0.1.0"\n'
            'agos_abi = "agos.v1"\n'
            "\n"
            "[runtime]\n"
            'type = "subprocess"\n'
            'entrypoint = "bin/gloo-app"\n'
            "memory_mb = 256\n"
            "vcpus = 1\n"
            "shared = false\n"
            "max_concurrency = 4\n"
            'idle_window = "30s"\n'
            "cold_start_budget_ms = 1500\n"
            "\n"
            "[routes]\n"
            f'prefix = "/plugins/{slug}"\n'
            f'admin = "/plugins/{slug}/admin/*"\n'
            "\n"
            "[capabilities]\n"
            "required = [\n"
            f"{required_lines}\n"
            "]\n"
            "\n"
            "[ui]\n"
            "pages = []\n"
            "\n"
            "[gloo]\n"
            f'description = "{description}"\n'
            f'system_tier = "{system_tier}"\n'
            f'receipt_head = "{receipt_head}"\n'
            f"contracts = [{fmt(contracts)}]\n"
            f"policies = [{fmt(policies)}]\n"
            f"identity_rules = [{fmt(identity_rules)}]\n"
            f"address_rules = [{fmt(address_rules)}]\n"
            f"business_rules = [{fmt(business_rules)}]\n"
        )

    @staticmethod
    def vendor_dependencies(root: str | Path, target_dir: str | Path | None = None) -> Path:
        root = Path(root)
        req = root / "requirements.txt"
        target = Path(target_dir) if target_dir else root / ".gloo" / "site-packages"
        target.mkdir(parents=True, exist_ok=True)
        if not req.exists() or not req.read_text().strip():
            return target
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-r",
                str(req),
                "--target",
                str(target),
            ],
            check=True,
        )
        return target

    @staticmethod
    def build_cpkg(
        root: str | Path,
        output_path: str | Path | None = None,
        *,
        bundle_deps: bool = False,
    ) -> Path:
        root = Path(root)
        GlooProject.run_build_hook(root)
        manifest = GlooProject.manifest_with_local_sources(root)
        validation = GlooProject.validate_manifest_data(manifest)
        if not validation["ok"]:
            raise ValueError(f"invalid gloo manifest: {validation['errors']}")
        manifest.setdefault("system_tier", "installed")
        assets = GlooProject.customization_assets(root)
        ledger = build_receipt_ledger(manifest, assets)
        manifest["receipt_head"] = ledger["receipt_head"]
        plugin_toml = GlooProject.render_plugin_toml(manifest)
        entry_module = manifest.get("entry_module", "app.main")
        output = Path(output_path) if output_path else root / "dist" / f"{manifest['app_id'].replace('/', '-').replace('.', '-')}.cpkg"
        output.parent.mkdir(parents=True, exist_ok=True)
        vendor_dir = GlooProject.vendor_dependencies(root) if bundle_deps else None

        launcher = LAUNCHER_TEMPLATE.format(entry_module=entry_module)
        package_meta = {
            "schema": "connector.app_package.v2",
            "package_id": manifest["app_id"],
            "kind": "app",
            "mode": "managed",
            "version": str(manifest.get("version", "0.1.0")),
            "adapters": [],
        }
        cnktr = (
            f"app:\n  id: {manifest['app_id']}\n  mode: managed\n"
            "intelligence:\n  contract: contracts/main.cls\n"
            "authority:\n  default: deny\n"
            "adapters: []\n"
        )
        cnktr_path = root / "cnktr.yaml"
        if cnktr_path.exists():
            cnktr = cnktr_path.read_text()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            GlooProject._writestr(zf, "plugin.toml", plugin_toml, mode=0o644)
            GlooProject._writestr(zf, "META/package.json", json.dumps(package_meta, indent=2) + "\n", mode=0o644)
            GlooProject._writestr(zf, "cnktr.yaml", cnktr, mode=0o644)
            GlooProject._writestr(zf, "bin/gloo-app", launcher, mode=0o755)
            GlooProject._writestr(zf, "META/gloo-receipts.json", json.dumps(ledger, indent=2) + "\n", mode=0o644)
            GlooProject._writestr(zf, "gloo.json", json.dumps(manifest, indent=2) + "\n", mode=0o644)
            for rel in ["requirements.txt", "README.md"]:
                path = root / rel
                if path.exists():
                    GlooProject._writefile(zf, path, rel)
            for folder in ["app", "workflows", "contracts", "policies", "identity", "addressing", "business"]:
                base = root / folder
                if not base.exists():
                    continue
                for path in base.rglob("*"):
                    if path.is_file():
                        GlooProject._writefile(zf, path, path.relative_to(root).as_posix())
            if vendor_dir and vendor_dir.exists():
                for path in vendor_dir.rglob("*"):
                    if path.is_file():
                        rel = path.relative_to(vendor_dir).as_posix()
                        GlooProject._writefile(zf, path, f"vendor/site-packages/{rel}")
        pin = GlooProject.write_package_pin(output, package_id=manifest["app_id"], kind="app")
        assert pin.exists()
        return output

    @staticmethod
    def package_digest(path: str | Path) -> str:
        data = Path(path).read_bytes()
        return f"cpkg-sha256-{hashlib.sha256(data).hexdigest()}"

    @staticmethod
    def write_package_pin(
        cpkg_path: str | Path,
        *,
        package_id: str,
        kind: str = "app",
        signed: bool = False,
    ) -> Path:
        cpkg_path = Path(cpkg_path)
        pin = {
            "schema": "connector.package_gate.v1",
            "package_id": package_id,
            "package_digest": GlooProject.package_digest(cpkg_path),
            "signature_present": signed,
            "kind": kind,
        }
        pin_path = cpkg_path.parent / f"{cpkg_path.stem}.package.pin.json"
        pin_path.write_text(json.dumps(pin, indent=2) + "\n")
        return pin_path

    @staticmethod
    def load_package_pin(path: str | Path) -> dict:
        return json.loads(Path(path).read_text())

    @staticmethod
    def resolve_cpkg_for_apply(
        root: str | Path,
        *,
        cpkg: str | Path | None = None,
        package_pin: str | Path | None = None,
        lab: bool = False,
    ) -> dict:
        """Require a built `.cpkg` digest for apply outside lab."""
        root = Path(root)
        if lab or os.getenv("CONNECTOR_RUNTIME_PROFILE", "").lower() in {"lab", "playground", "development", "dev"}:
            return {
                "ok": True,
                "lab": True,
                "package": None,
                "honesty": "lab/dev unpackaged apply allowed — labeled non-production",
            }
        pin_path = Path(package_pin) if package_pin else None
        cpkg_path = Path(cpkg) if cpkg else None
        if pin_path is None and cpkg_path is not None:
            candidate = cpkg_path.parent / f"{cpkg_path.stem}.package.pin.json"
            if candidate.exists():
                pin_path = candidate
        if pin_path is None:
            dist = root / "dist"
            if dist.is_dir():
                pins = sorted(dist.glob("*.package.pin.json"))
                if len(pins) == 1:
                    pin_path = pins[0]
                elif not pins:
                    packages = sorted(dist.glob("*.cpkg"))
                    if len(packages) == 1:
                        cpkg_path = packages[0]
                        pin_path = GlooProject.write_package_pin(
                            cpkg_path,
                            package_id=GlooProject.load_manifest(root).get("app_id", cpkg_path.stem),
                        )
        if pin_path is None:
            raise ValueError(
                "production apply requires a built .cpkg pin — run `gloo build .` then "
                "`gloo apply . --cpkg dist/<app>.cpkg`, or pass --lab for labeled lab apply"
            )
        pin = GlooProject.load_package_pin(pin_path)
        digest = pin.get("package_digest", "")
        if not digest or len(digest) < 16:
            raise ValueError(f"invalid package pin at {pin_path}")
        if cpkg_path and cpkg_path.exists():
            actual = GlooProject.package_digest(cpkg_path)
            if actual != digest:
                raise ValueError(f"package digest mismatch: pin={digest} file={actual}")
        return {"ok": True, "lab": False, "package": pin, "pin_path": str(pin_path), "honesty": "packaged apply"}

    @staticmethod
    def manifest_from_cpkg(path: str | Path) -> dict:
        path = Path(path)
        with zipfile.ZipFile(path) as zf:
            return json.loads(zf.read("gloo.json").decode("utf-8"))

    @staticmethod
    def customization_assets_from_cpkg(path: str | Path) -> dict[str, list[dict]]:
        path = Path(path)
        manifest = GlooProject.manifest_from_cpkg(path)
        with zipfile.ZipFile(path) as zf:
            names = sorted(zf.namelist())

            def read_paths(keys: list[str]) -> list[dict]:
                out: list[dict] = []
                for key in keys:
                    if key.endswith("/"):
                        for rel in names:
                            if rel.startswith(key) and not rel.endswith("/"):
                                out.append({"path": rel, "content": zf.read(rel).decode("utf-8")})
                    elif key in names:
                        out.append({"path": key, "content": zf.read(key).decode("utf-8")})
                return out

            return {
                "contracts": read_paths(manifest.get("contracts", [])),
                "policies": read_paths(manifest.get("policies", [])),
                "identity_rules": read_paths(manifest.get("identity_rules", [])),
                "address_rules": read_paths(manifest.get("address_rules", [])),
                "business_rules": read_paths(manifest.get("business_rules", [])),
            }

    @staticmethod
    def verify_cpkg_receipts(path: str | Path) -> dict:
        path = Path(path)
        with zipfile.ZipFile(path) as zf:
            if "gloo.json" not in zf.namelist():
                return {"ok": True, "skipped": True, "reason": "not a gloo package"}
            manifest = json.loads(zf.read("gloo.json").decode("utf-8"))
            if "META/gloo-receipts.json" not in zf.namelist():
                return {
                    "ok": False,
                    "errors": ["missing META/gloo-receipts.json — rebuild with gloo build"],
                }
            ledger = json.loads(zf.read("META/gloo-receipts.json").decode("utf-8"))
        assets = GlooProject.customization_assets_from_cpkg(path)
        result = verify_receipt_ledger(ledger, manifest, assets)
        result["manifest"] = manifest
        result["ledger_head"] = ledger.get("receipt_head")
        return result

    @staticmethod
    def inspect_cpkg(path: str | Path) -> dict:
        path = Path(path)
        with zipfile.ZipFile(path) as zf:
            names = sorted(zf.namelist())
            plugin_toml = zf.read("plugin.toml").decode("utf-8")
            manifest = tomllib.loads(plugin_toml)
            return {
                "ok": True,
                "path": str(path),
                "plugin": manifest.get("plugin", {}),
                "runtime": manifest.get("runtime", {}),
                "routes": manifest.get("routes", {}),
                "capabilities": manifest.get("capabilities", {}),
                "files": names,
            }

    @staticmethod
    def _writestr(zf: zipfile.ZipFile, arcname: str, content: str, mode: int) -> None:
        info = zipfile.ZipInfo(arcname)
        info.external_attr = (mode & 0xFFFF) << 16
        zf.writestr(info, content)

    @staticmethod
    def _writefile(zf: zipfile.ZipFile, path: Path, arcname: str) -> None:
        mode = 0o755 if path.name.startswith("gloo-app") else 0o644
        info = zipfile.ZipInfo(arcname)
        info.external_attr = (mode & 0xFFFF) << 16
        zf.writestr(info, path.read_bytes())

    @staticmethod
    def load_manifest(root: str | Path) -> dict:
        root = Path(root)
        return json.loads((root / "gloo.json").read_text())

    @staticmethod
    def workflow_sources(root: str | Path) -> dict[str, str]:
        root = Path(root)
        out: dict[str, str] = {}
        wf_dir = root / "workflows"
        if not wf_dir.exists():
            return out
        for path in wf_dir.glob("*.ccl"):
            out[path.stem.replace("_", "-")] = path.read_text()
        return out

    @staticmethod
    def manifest_with_local_sources(root: str | Path) -> dict:
        root = Path(root)
        manifest = GlooProject.load_manifest(root)
        local_sources = GlooProject.workflow_sources(root)
        for wf in manifest.get("workflows", []):
            if not wf.get("cls_source"):
                wf["cls_source"] = local_sources.get(wf.get("id", ""), "")
        return manifest

    @staticmethod
    def run_entrypoint(root: str | Path) -> int:
        root = Path(root)
        manifest = GlooProject.load_manifest(root)
        entry_module = manifest.get("entry_module", "app.main")
        sys.path.insert(0, str(root))
        os.environ.setdefault("CONNECTOR_BASE_URL", os.getenv("CONNECTOR_URL", "http://127.0.0.1:9091"))
        runpy.run_module(entry_module, run_name="__main__")
        return 0

    @staticmethod
    def init_python_app(
        root: str | Path,
        *,
        app_id: str,
        name: str,
        description: str = "",
    ) -> Path:
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        (root / "app").mkdir(exist_ok=True)
        (root / "workflows").mkdir(exist_ok=True)
        (root / "contracts").mkdir(exist_ok=True)
        (root / "policies").mkdir(exist_ok=True)
        (root / "identity").mkdir(exist_ok=True)
        (root / "addressing").mkdir(exist_ok=True)
        (root / "business").mkdir(exist_ok=True)

        manifest = GlooAppManifest(
            app_id=app_id,
            name=name,
            description=description,
            agents=[
                GlooAgentSpec(
                    id="primary",
                    name=f"{name.lower().replace(' ', '-')}-agent",
                    purpose="Fill in the real job for this agent.",
                )
            ],
            workflows=[
                GlooWorkflowSpec(
                    id="sample-workflow",
                    package_id="pkg-sample-workflow",
                    cls_source=CLS_TEMPLATE,
                )
            ],
        )

        (root / "gloo.json").write_text(json.dumps(manifest.to_dict(), indent=2) + "\n")
        (root / "cnktr.yaml").write_text(
            f"app:\n  id: {app_id}\n  mode: managed\n"
            "intelligence:\n  contract: contracts/sample_contract.ccl\n"
            "authority:\n  default: deny\n"
            "adapters: []\n"
        )
        (root / ".build.py").write_text(
            "#!/usr/bin/env python3\n"
            "\"\"\"Optional pre-build hook for Gloo packaging.\"\"\"\n"
            "from pathlib import Path\n\n"
            "dist = Path('dist')\n"
            "dist.mkdir(exist_ok=True)\n"
            "print('gloo .build.py ran')\n"
        )
        (root / "app" / "__init__.py").write_text("")
        (root / "app" / "main.py").write_text(APP_TEMPLATE)
        (root / "workflows" / "sample_workflow.ccl").write_text(CLS_TEMPLATE)
        (root / "contracts" / "sample_contract.ccl").write_text(CONTRACT_TEMPLATE)
        (root / "policies" / "default.policy").write_text(POLICY_TEMPLATE)
        (root / "identity" / "default.rules").write_text(IDENTITY_RULE_TEMPLATE)
        (root / "addressing" / "default.rules").write_text(ADDRESS_RULE_TEMPLATE)
        (root / "business" / "default.rules").write_text(BUSINESS_RULE_TEMPLATE)
        (root / "requirements.txt").write_text("connector-sdk>=0.1.0\n")
        (root / "README.md").write_text(
            f"# {name}\n\n"
            "Python-first Connector/Gloo app scaffold.\n\n"
            "## Next steps\n"
            "- edit `gloo.json` / `cnktr.yaml`\n"
            "- edit `app/main.py`\n"
            "- edit `workflows/sample_workflow.ccl`\n"
            "- edit `contracts/`, `policies/`, `identity/`, `addressing/`, `business/`\n"
            "- use `gloo dev .`\n"
            "- use `gloo build .` (emits `.cpkg` + `.package.pin.json`)\n"
            "- use `gloo apply . --cpkg dist/<app>.cpkg --base-url http://127.0.0.1:9091`\n"
            "- production apply refuses unpackaged projects (pass `--lab` only for labeled lab)\n"
            "- use `gloo install-cpkg --file dist/<app>.cpkg`\n"
        )
        return root

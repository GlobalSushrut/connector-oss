import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from connector_sdk.gloo.app import GlooAgentSpec, GlooAppManifest, GlooWorkflowSpec
from connector_sdk.gloo.cli import build_parser
from connector_sdk.gloo.node import GlooNode
from connector_sdk.gloo.project import GlooProject


def test_manifest_to_dict():
    manifest = GlooAppManifest(
        app_id="com.connector.demo",
        name="Demo",
        agents=[GlooAgentSpec(id="primary", name="demo-agent", purpose="Help users")],
        workflows=[GlooWorkflowSpec(id="wf", package_id="pkg-wf", cls_source="workflow wf {}")],
    )
    data = manifest.to_dict()
    assert data["app_id"] == "com.connector.demo"
    assert data["agents"][0]["name"] == "demo-agent"
    assert data["workflows"][0]["package_id"] == "pkg-wf"
    assert data["contracts"] == ["contracts/"]
    assert data["system_tier"] == "installed"


def test_project_init_python_app():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        root = Path(root)
        assert (root / "gloo.json").exists()
        assert (root / "app" / "main.py").exists()
        assert (root / "workflows" / "sample_workflow.ccl").exists()
        assert (root / "contracts" / "sample_contract.ccl").exists()
        assert (root / "policies" / "default.policy").exists()
        assert (root / "identity" / "default.rules").exists()
        assert (root / "addressing" / "default.rules").exists()
        assert (root / "business" / "default.rules").exists()

        manifest = json.loads((root / "gloo.json").read_text())
        assert manifest["app_id"] == "com.connector.demo"
        assert manifest["name"] == "Demo App"


def test_cli_parser_init():
    parser = build_parser()
    args = parser.parse_args(["init", "/tmp/demo", "--app-id", "com.demo", "--name", "Demo"])
    assert args.command == "init"
    assert args.app_id == "com.demo"


def test_manifest_with_local_sources_fills_workflow():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        manifest = GlooProject.manifest_with_local_sources(root)
        assert manifest["workflows"][0]["cls_source"]


def test_cli_parser_apply():
    parser = build_parser()
    args = parser.parse_args(["apply", "/tmp/demo"])
    assert args.command == "apply"
    assert args.path == "/tmp/demo"


def test_run_entrypoint_executes_scaffold():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        with patch("connector_sdk.glue.runtime.execute_health") as mock_health:
            from connector_sdk.glue.result import GlueResult

            mock_health.return_value = GlueResult.success("health", "node", "local")
            assert GlooProject.run_entrypoint(root) == 0


def test_build_cpkg_outputs_real_archive():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        out = GlooProject.build_cpkg(root)
        assert out.exists()
        assert out.suffix == ".cpkg"
        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
            assert "plugin.toml" in names
            assert "bin/gloo-app" in names
            assert "gloo.json" in names
            assert "META/gloo-receipts.json" in names
            assert "app/main.py" in names
            assert "contracts/sample_contract.ccl" in names
            assert "policies/default.policy" in names
            assert "identity/default.rules" in names
            assert "addressing/default.rules" in names
            assert "business/default.rules" in names
            manifest = zf.read("plugin.toml").decode("utf-8")
            assert 'entrypoint = "bin/gloo-app"' in manifest


def test_inspect_cpkg_reads_manifest():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        out = GlooProject.build_cpkg(root)
        info = GlooProject.inspect_cpkg(out)
        assert info["plugin"]["id"] == "local/com-connector-demo"
        assert info["runtime"]["entrypoint"] == "bin/gloo-app"
        assert "app/main.py" in info["files"]


def test_cli_parser_preflight_and_doctor():
    parser = build_parser()
    preflight = parser.parse_args(["preflight-cpkg", "--file", "plugin.cpkg"])
    assert preflight.command == "preflight-cpkg"
    doctor = parser.parse_args(["doctor"])
    assert doctor.command == "doctor"
    logs = parser.parse_args(["logs", "--agent", "demo", "--tail", "50"])
    assert logs.command == "logs"
    trace = parser.parse_args(["trace", "demo-agent", "--limit", "10"])
    assert trace.command == "trace"
    receipts = parser.parse_args(["receipts", "demo-agent", "--limit", "25"])
    assert receipts.command == "receipts"
    deps = parser.parse_args(["bundle-deps", "/tmp/demo"])
    assert deps.command == "bundle-deps"
    validate = parser.parse_args(["validate", "/tmp/demo"])
    assert validate.command == "validate"
    audit = parser.parse_args(["audit-project", "/tmp/demo"])
    assert audit.command == "audit-project"
    verify = parser.parse_args(["verify-package", "plugin.cpkg", "--skip-server"])
    assert verify.command == "verify-package"


def test_build_cpkg_can_include_vendored_dependencies():
    with tempfile.TemporaryDirectory() as td:
        root = Path(GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App"))
        (root / "requirements.txt").write_text("")
        vendor = root / ".gloo" / "site-packages"
        vendor.mkdir(parents=True, exist_ok=True)
        (vendor / "demo_dep.py").write_text("VALUE = 1\n")
        out = GlooProject.build_cpkg(root, bundle_deps=True)
        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
            assert "vendor/site-packages/demo_dep.py" in names


def test_validate_manifest_success():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        result = GlooProject.validate_manifest(root)
        assert result["ok"] is True
        assert result["errors"] == []


def test_audit_project_reports_asset_groups():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        result = GlooProject.audit_project(root)
        assert result["ok"] is True
        assert result["counts"]["workflows"] >= 1
        assert result["counts"]["contracts"] >= 1
        assert result["build_hook"] is True
        assert result["entry_module_file"] == "app/main.py"


def test_customization_assets_reads_rule_files():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        assets = GlooProject.customization_assets(root)
        assert assets["contracts"][0]["path"] == "contracts/sample_contract.ccl"
        assert assets["policies"][0]["path"] == "policies/default.policy"
        assert assets["identity_rules"][0]["path"] == "identity/default.rules"


def test_verify_cpkg_receipts_matches_build():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        out = GlooProject.build_cpkg(root)
        result = GlooProject.verify_cpkg_receipts(out)
        assert result["ok"] is True
        assert result["ledger_head"] != "genesis"


def test_build_cpkg_tamper_fails_receipt_verify():
    with tempfile.TemporaryDirectory() as td:
        root = GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App")
        out = GlooProject.build_cpkg(root)
        tampered = out.with_name("tampered.cpkg")
        with zipfile.ZipFile(out) as src, zipfile.ZipFile(tampered, "w") as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename == "policies/default.policy":
                    data = b"# tampered\n"
                dst.writestr(item, data)
        result = GlooProject.verify_cpkg_receipts(tampered)
        assert result["ok"] is False


def test_validate_manifest_failure():
    result = GlooProject.validate_manifest_data({"app_id": "", "name": "", "workflows": [{}], "agents": [{}]})
    assert result["ok"] is False
    assert any("app_id is required" == err for err in result["errors"])


def test_build_hook_runs_before_package():
    with tempfile.TemporaryDirectory() as td:
        root = Path(GlooProject.init_python_app(td, app_id="com.connector.demo", name="Demo App"))
        (root / ".build.py").write_text(
            "from pathlib import Path\n"
            "Path('hook-ran.txt').write_text('yes')\n"
        )
        GlooProject.build_cpkg(root)
        assert (root / "hook-ran.txt").read_text() == "yes"


def test_node_requires_explicit_target():
    old_base = os.environ.pop("CONNECTOR_BASE_URL", None)
    old_url = os.environ.pop("CONNECTOR_URL", None)
    try:
        node = GlooNode()
        try:
            node.ensure_explicit_target()
            assert False, "expected explicit target error"
        except RuntimeError as exc:
            assert "No Connector node target specified" in str(exc)
    finally:
        if old_base is not None:
            os.environ["CONNECTOR_BASE_URL"] = old_base
        if old_url is not None:
            os.environ["CONNECTOR_URL"] = old_url


def test_node_asset_receipt_is_deterministic():
    node = GlooNode(base_url="http://node.test:9091")
    receipt = node._asset_receipt(
        app_id="com.connector.demo",
        bucket="policies_assets",
        path="policies/default.policy",
        content="allow audit.write\n",
        previous_receipt_hash="genesis",
    )
    assert receipt["address"] == "gloo://com.connector.demo/policies/policies/default.policy"
    assert receipt["previous_receipt_hash"] == "genesis"
    assert len(receipt["content_sha256"]) == 64
    assert len(receipt["receipt_hash"]) == 64


def test_apply_manifest_emits_hash_chain_receipts():
    class FakeNode(GlooNode):
        def __init__(self):
            super().__init__(base_url="http://node.test:9091")

        def compile_cls(self, cls_source: str) -> dict:
            return {"ok": True, "compiled": bool(cls_source)}

        def publish_knowledge_text(self, **kwargs) -> dict:
            return {"ok": True, "published": kwargs["path"]}

        def bootstrap_workflow(self, workflow_payload: dict) -> dict:
            return {"ok": True, "workflow_id": workflow_payload["workflow_id"]}

        def apply_intelligence(self, intelligence_spec: dict) -> dict:
            return {"ok": True, "agent": intelligence_spec["metadata"]["name"]}

    node = FakeNode()
    result = node.apply_manifest(
        {
            "app_id": "com.connector.demo",
            "workflows": [{"id": "wf", "package_id": "pkg-wf", "cls_source": "workflow wf {}"}],
            "contracts_assets": [{"path": "contracts/sample_contract.ccl", "content": "contract c {}"}],
            "policies_assets": [{"path": "policies/default.policy", "content": "allow memory.read"}],
            "identity_rules_assets": [],
            "address_rules_assets": [],
            "business_rules_assets": [],
            "agents": [{"id": "a1", "name": "demo-agent", "purpose": "Help users", "model": "gpt"}],
        }
    )
    assert result["ok"] is True
    assert len(result["receipts"]) == 2
    assert result["receipts"][0]["previous_receipt_hash"] == "genesis"
    assert result["receipts"][1]["previous_receipt_hash"] == result["receipts"][0]["receipt_hash"]
    assert result["receipt_head"] == result["receipts"][-1]["receipt_hash"]

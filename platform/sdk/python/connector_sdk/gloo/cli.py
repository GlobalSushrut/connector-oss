from __future__ import annotations

import argparse
import json
from pathlib import Path

from .project import GlooProject
from .node import GlooNode


def _require_explicit_target(node: GlooNode) -> None:
    node.ensure_explicit_target()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gloo", description="Gloo developer CLI for Connector")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init", help="Create a Python-first Gloo app scaffold")
    init_cmd.add_argument("path")
    init_cmd.add_argument("--app-id", required=True)
    init_cmd.add_argument("--name", required=True)
    init_cmd.add_argument("--description", default="")

    validate_cmd = sub.add_parser("validate", help="Validate gloo.json and local workflow sources")
    validate_cmd.add_argument("path")

    audit_cmd = sub.add_parser("audit-project", help="Deep local audit of a Gloo project")
    audit_cmd.add_argument("path")

    build_cmd = sub.add_parser("build", help="Build a real .cpkg from a Gloo Python project")
    build_cmd.add_argument("path")
    build_cmd.add_argument("--output", default=None)
    build_cmd.add_argument("--bundle-deps", action="store_true", help="Vendor Python requirements into the package")

    deps_cmd = sub.add_parser("bundle-deps", help="Vendor Python requirements into .gloo/site-packages")
    deps_cmd.add_argument("path")
    deps_cmd.add_argument("--output", default=None)

    inspect_cmd = sub.add_parser("inspect-cpkg", help="Inspect a local .cpkg archive")
    inspect_cmd.add_argument("path")

    apply_cmd = sub.add_parser("apply", help="Apply a gloo.json project to a Connector node")
    apply_cmd.add_argument("path")
    apply_cmd.add_argument("--base-url", default=None)
    apply_cmd.add_argument("--token", default=None)
    apply_cmd.add_argument("--cpkg", default=None, help="Built .cpkg required outside lab")
    apply_cmd.add_argument("--package-pin", default=None, help="Path to *.package.pin.json")
    apply_cmd.add_argument(
        "--lab",
        action="store_true",
        help="Allow unpackaged apply in lab/dev (labeled non-production)",
    )

    dev_cmd = sub.add_parser("dev", help="Run the local Python app entrypoint")
    dev_cmd.add_argument("path")

    doctor_cmd = sub.add_parser("doctor", help="Connector node diagnostics for Gloo developers")
    doctor_cmd.add_argument("--base-url", default=None)
    doctor_cmd.add_argument("--token", default=None)

    logs_cmd = sub.add_parser("logs", help="Read node or agent logs")
    logs_cmd.add_argument("--agent", default=None)
    logs_cmd.add_argument("--tail", type=int, default=100)
    logs_cmd.add_argument("--base-url", default=None)
    logs_cmd.add_argument("--token", default=None)

    trace_cmd = sub.add_parser("trace", help="Read agent trace")
    trace_cmd.add_argument("agent")
    trace_cmd.add_argument("--last", default=None)
    trace_cmd.add_argument("--limit", type=int, default=50)
    trace_cmd.add_argument("--base-url", default=None)
    trace_cmd.add_argument("--token", default=None)

    receipts_cmd = sub.add_parser("receipts", help="Read signed audit receipts for an agent")
    receipts_cmd.add_argument("agent")
    receipts_cmd.add_argument("--from-ms", type=int, default=None)
    receipts_cmd.add_argument("--to-ms", type=int, default=None)
    receipts_cmd.add_argument("--limit", type=int, default=100)
    receipts_cmd.add_argument("--base-url", default=None)
    receipts_cmd.add_argument("--token", default=None)

    health_cmd = sub.add_parser("health", help="Check Connector node health")
    health_cmd.add_argument("--base-url", default=None)
    health_cmd.add_argument("--token", default=None)

    boot_cmd = sub.add_parser("bootstrap-workflow", help="Real workflow bootstrap through Connector")
    boot_cmd.add_argument("reference_id")
    boot_cmd.add_argument("--base-url", default=None)
    boot_cmd.add_argument("--token", default=None)
    boot_cmd.add_argument("--no-enable", action="store_true")
    boot_cmd.add_argument("--no-dry-run", action="store_true")
    boot_cmd.add_argument("--no-run", action="store_true")

    cpkg_cmd = sub.add_parser(
        "install-cpkg",
        help="Verify, preflight, install, and burn-in a .cpkg through Connector",
    )
    cpkg_cmd.add_argument("--file", dest="file_path")
    cpkg_cmd.add_argument("--url")
    cpkg_cmd.add_argument("--hub-plugin-id")
    cpkg_cmd.add_argument("--hub-version")
    cpkg_cmd.add_argument("--base-url", default=None)
    cpkg_cmd.add_argument("--token", default=None)
    cpkg_cmd.add_argument(
        "--no-apply-assets",
        action="store_true",
        help="Skip applying contracts/rules/agents after install (workflows are burned in by the node)",
    )
    cpkg_cmd.add_argument(
        "--skip-receipt-verify",
        action="store_true",
        help="Skip local receipt-chain verification (not recommended)",
    )

    preflight_cmd = sub.add_parser("preflight-cpkg", help="Ask Connector to verify a .cpkg before install")
    preflight_cmd.add_argument("--file", dest="file_path")
    preflight_cmd.add_argument("--url")
    preflight_cmd.add_argument("--hub-plugin-id")
    preflight_cmd.add_argument("--hub-version")
    preflight_cmd.add_argument("--base-url", default=None)
    preflight_cmd.add_argument("--token", default=None)

    verify_cmd = sub.add_parser("verify-package", help="Validate locally and optionally preflight a built .cpkg")
    verify_cmd.add_argument("path")
    verify_cmd.add_argument("--base-url", default=None)
    verify_cmd.add_argument("--token", default=None)
    verify_cmd.add_argument("--skip-server", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        root = GlooProject.init_python_app(
            args.path,
            app_id=args.app_id,
            name=args.name,
            description=args.description,
        )
        print(f"created {root}")
        return 0

    if args.command == "validate":
        result = GlooProject.validate_manifest(args.path)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if args.command == "audit-project":
        result = GlooProject.audit_project(args.path)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if args.command == "build":
        out = GlooProject.build_cpkg(args.path, args.output, bundle_deps=args.bundle_deps)
        pin = Path(out).parent / f"{Path(out).stem}.package.pin.json"
        print(json.dumps({"ok": True, "package": str(out), "pin": str(pin) if pin.exists() else None}, indent=2))
        return 0

    if args.command == "bundle-deps":
        out = GlooProject.vendor_dependencies(args.path, args.output)
        print(out)
        return 0

    if args.command == "inspect-cpkg":
        print(json.dumps(GlooProject.inspect_cpkg(args.path), indent=2))
        return 0

    if args.command == "dev":
        return GlooProject.run_entrypoint(args.path)

    node = GlooNode(base_url=getattr(args, "base_url", None), token=getattr(args, "token", None))

    if args.command == "apply":
        _require_explicit_target(node)
        gate = GlooProject.resolve_cpkg_for_apply(
            args.path,
            cpkg=args.cpkg,
            package_pin=args.package_pin,
            lab=args.lab,
        )
        manifest = GlooProject.manifest_with_local_sources(args.path)
        assets = GlooProject.customization_assets(args.path)
        manifest["contracts_assets"] = assets["contracts"]
        manifest["policies_assets"] = assets["policies"]
        manifest["identity_rules_assets"] = assets["identity_rules"]
        manifest["address_rules_assets"] = assets["address_rules"]
        manifest["business_rules_assets"] = assets["business_rules"]
        if gate.get("package"):
            manifest["package"] = gate["package"]
        print(
            json.dumps(
                {
                    "node": node.base_url,
                    "package_gate": gate,
                    "result": node.apply_manifest(manifest),
                },
                indent=2,
            )
        )
        return 0

    if args.command == "health":
        _require_explicit_target(node)
        print(json.dumps(node.health(), indent=2))
        return 0

    if args.command == "doctor":
        _require_explicit_target(node)
        print(json.dumps({"node": node.base_url, "result": node.doctor()}, indent=2))
        return 0

    if args.command == "logs":
        _require_explicit_target(node)
        print(json.dumps({"node": node.base_url, "result": node.logs(agent=args.agent, tail=args.tail)}, indent=2))
        return 0

    if args.command == "trace":
        _require_explicit_target(node)
        print(json.dumps({"node": node.base_url, "result": node.trace(args.agent, last=args.last, limit=args.limit)}, indent=2))
        return 0

    if args.command == "receipts":
        _require_explicit_target(node)
        print(
            json.dumps(
                {
                    "node": node.base_url,
                    "result": node.receipts(
                        args.agent,
                        from_ms=args.from_ms,
                        to_ms=args.to_ms,
                        limit=args.limit,
                    ),
                },
                indent=2,
            )
        )
        return 0

    if args.command == "bootstrap-workflow":
        _require_explicit_target(node)
        out = node.bootstrap_reference_workflow(
            args.reference_id,
            enable=not args.no_enable,
            dry_run=not args.no_dry_run,
            run=not args.no_run,
        )
        print(json.dumps({"node": node.base_url, "result": out}, indent=2))
        return 0

    if args.command == "preflight-cpkg":
        _require_explicit_target(node)
        if args.file_path:
            out = node.preflight_cpkg_file(Path(args.file_path))
        elif args.url:
            out = node.preflight_cpkg_url(args.url)
        elif args.hub_plugin_id and args.hub_version:
            out = node.preflight_cpkg_hub(args.hub_plugin_id, args.hub_version)
        else:
            parser.error("preflight-cpkg requires --file, --url, or both --hub-plugin-id and --hub-version")
        print(json.dumps({"node": node.base_url, "result": out}, indent=2))
        return 0

    if args.command == "verify-package":
        local = GlooProject.inspect_cpkg(args.path)
        receipt_verify = GlooProject.verify_cpkg_receipts(args.path)
        if args.skip_server:
            print(
                json.dumps(
                    {"ok": receipt_verify.get("ok", True), "local": local, "receipts": receipt_verify, "server": None},
                    indent=2,
                )
            )
            return 0 if receipt_verify.get("ok", True) else 1
        _require_explicit_target(node)
        server = node.preflight_cpkg_file(Path(args.path))
        ok = receipt_verify.get("ok", True) and server.get("ok", True)
        print(
            json.dumps(
                {
                    "ok": ok,
                    "node": node.base_url,
                    "local": local,
                    "receipts": receipt_verify,
                    "server": server,
                },
                indent=2,
            )
        )
        return 0 if ok else 1

    if args.command == "install-cpkg":
        _require_explicit_target(node)
        if args.file_path:
            out = node.install_cpkg_verified(
                Path(args.file_path),
                apply_assets=not args.no_apply_assets,
                require_receipts=not args.skip_receipt_verify,
            )
        elif args.url:
            preflight = node.preflight_cpkg_url(args.url)
            install = node.install_cpkg_url(args.url)
            out = {"node": node.base_url, "preflight": preflight, "install": install}
        elif args.hub_plugin_id and args.hub_version:
            preflight = node.preflight_cpkg_hub(args.hub_plugin_id, args.hub_version)
            install = node.install_cpkg_hub(args.hub_plugin_id, args.hub_version)
            out = {"node": node.base_url, "preflight": preflight, "install": install}
        else:
            parser.error("install-cpkg requires --file, --url, or both --hub-plugin-id and --hub-version")
        print(json.dumps(out, indent=2))
        return 0

    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

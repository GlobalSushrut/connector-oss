"""
connector.config — YAML/TOML config loader for connector-oss.

Loads a connector.yaml (or .toml) and returns a fully configured Connector.
Supports ${ENV_VAR} interpolation in all string values.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


# ── env-var interpolation ─────────────────────────────────────────────────────

_ENV_RE = re.compile(r"\$\{([^}]+)\}")


def _interpolate(value: Any) -> Any:
    """Recursively replace ${VAR} with os.environ[VAR] in strings."""
    if isinstance(value, str):
        def _replace(m: re.Match) -> str:
            var = m.group(1)
            val = os.environ.get(var)
            if val is None:
                raise EnvironmentError(
                    f"connector.yaml references ${{{var}}} but that environment variable is not set.\n"
                    f"  Fix: export {var}=<your-value>  or set it in your .env file."
                )
            return val
        return _ENV_RE.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


# ── loaders ───────────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        raise ImportError(
            "PyYAML is required to load connector.yaml.\n"
            "  pip install pyyaml"
        )
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _load_toml(path: str) -> dict:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            raise ImportError(
                "tomli is required to load connector.toml on Python < 3.11.\n"
                "  pip install tomli"
            )
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_file(path: str) -> dict:
    """Load a connector.yaml or connector.toml and return the raw dict."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"  Create one with: connector init  (or copy the example from docs/)"
        )
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        raw = _load_yaml(path)
    elif suffix == ".toml":
        raw = _load_toml(path)
    else:
        raise ValueError(
            f"Unsupported config format: {suffix}\n"
            f"  Supported: .yaml, .yml, .toml"
        )
    return _interpolate(raw)


# ── builder helpers ───────────────────────────────────────────────────────────

def _apply_security(builder: Any, sec: dict) -> Any:
    """Apply a security dict to a ConnectorBuilder."""
    if sec.get("signing"):
        builder = builder.security(signing=True)
    if sec.get("scitt"):
        builder = builder.security(scitt=True)
    if sec.get("require_mfa"):
        builder = builder.security(require_mfa=True)
    if "max_delegation_depth" in sec:
        builder = builder.security(max_delegation_depth=sec["max_delegation_depth"])
    if "data_classification" in sec:
        builder = builder.security(data_classification=sec["data_classification"])
    if "jurisdiction" in sec:
        builder = builder.security(jurisdiction=sec["jurisdiction"])
    if "retention_days" in sec:
        builder = builder.security(retention_days=sec["retention_days"])
    return builder


# ── main entry points ─────────────────────────────────────────────────────────

def connector_from_config(path: str) -> "Connector":  # noqa: F821
    """
    Load a connector.yaml / connector.toml and return a ready Connector.

    For .yaml/.yml files the native Rust loader is used (full env-var
    interpolation, all 3-tier config sections parsed by the kernel).
    For .toml files the Python fallback loader is used.

    Example connector.yaml:
        connector:
          provider: openai
          model: gpt-4o
          api_key: ${OPENAI_API_KEY}
          storage: sqlite:./app.db
          comply: [hipaa]

        agents:
          doctor:
            instructions: "You are a medical assistant"
            tools: [search_ehr, write_notes]
            deny_data: [financial]

        cluster:
          mode: cluster
          peers: ["node2:7000"]

        streaming:
          protocol: sse

    Usage:
        from connector import Connector
        c = Connector.from_config("connector.yaml")
        result = c.agent("doctor", "You are a medical assistant").run(
            "Patient has fever", "user:dr_smith"
        )
    """
    from vac_ffi import Connector  # native Rust loader

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"  Create one with: connector init  (or copy the example from docs/)"
        )

    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        # Delegate entirely to the Rust config loader — handles env-var
        # interpolation, all 3 tiers, and full struct validation.
        return Connector.from_config(path)

    # TOML fallback — Python-side loader (Rust loader only supports YAML)
    cfg = _interpolate(_load_toml(path))
    return _connector_from_dict(cfg)


def connector_from_config_str(yaml: str) -> "Connector":  # noqa: F821
    """
    Load a Connector from a YAML string.
    Useful for testing or embedding config inline.

    Usage:
        from connector.config import connector_from_config_str
        c = connector_from_config_str('''
        connector:
          provider: openai
          model: gpt-4o
          api_key: sk-test
        ''')
    """
    from vac_ffi import Connector  # native Rust loader
    return Connector.from_config_str(yaml)


def _connector_from_dict(cfg: dict) -> "Connector":  # noqa: F821
    """Build a Connector from a pre-parsed and interpolated config dict (TOML path)."""
    from vac_ffi import Connector

    conn_cfg = cfg.get("connector", {})
    provider  = conn_cfg.get("provider", "openai")
    model     = conn_cfg.get("model", "gpt-4o")
    api_key   = conn_cfg.get("api_key", "")
    endpoint  = conn_cfg.get("endpoint")

    if endpoint:
        c = Connector.custom(endpoint, model, api_key)
    elif api_key:
        c = Connector(provider, model, api_key)
    else:
        c = Connector.from_env()

    if "comply" in conn_cfg:
        frameworks = conn_cfg["comply"]
        if isinstance(frameworks, str):
            frameworks = [frameworks]
        c = c.comply(*frameworks)

    if "security" in conn_cfg:
        c = _apply_security(c, conn_cfg["security"])

    c._config_agents    = cfg.get("agents", {})
    c._config_pipelines = cfg.get("pipelines", {})
    return c

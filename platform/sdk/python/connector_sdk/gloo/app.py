from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GlooAgentSpec:
    id: str
    name: str
    purpose: str
    model: Optional[str] = None
    class_name: str = "app"
    namespace: str = "default"
    harden: bool = True
    knowledge: List[Dict[str, Any]] = field(default_factory=list)
    skills: List[Dict[str, Any]] = field(default_factory=list)
    portals: List[Dict[str, Any]] = field(default_factory=list)

    def to_intelligence_spec(self) -> Dict[str, Any]:
        return {
            "apiVersion": "connector.ai/v1",
            "kind": "Intelligence",
            "metadata": {"name": self.name},
            "spec": {
                "purpose": self.purpose,
                "class": self.class_name,
                "parameters": {
                    "model": self.model,
                    "namespace": self.namespace,
                    "role": "reader",
                },
                "skills": self.skills,
                "knowledge": self.knowledge,
                "portals": self.portals,
                "harden": self.harden,
                "activate": True,
            },
        }


@dataclass
class GlooWorkflowSpec:
    id: str
    package_id: str
    cls_source: str
    accounting_mode: str = "action"
    version: str = "v1"

    def to_workflow_payload(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.id,
            "package_id": self.package_id,
            "version": self.version,
            "cls_source": self.cls_source,
            "accounting_mode": self.accounting_mode,
        }


@dataclass
class GlooAppManifest:
    app_id: str
    name: str
    version: str = "0.1.0"
    runtime: str = "python3.11"
    description: str = ""
    entry_module: str = "app.main"
    agents: List[GlooAgentSpec] = field(default_factory=list)
    workflows: List[GlooWorkflowSpec] = field(default_factory=list)
    contracts: List[str] = field(default_factory=lambda: ["contracts/"])
    policies: List[str] = field(default_factory=lambda: ["policies/"])
    identity_rules: List[str] = field(default_factory=lambda: ["identity/"])
    address_rules: List[str] = field(default_factory=lambda: ["addressing/"])
    business_rules: List[str] = field(default_factory=lambda: ["business/"])
    permissions: List[str] = field(default_factory=lambda: ["memory.read", "memory.write", "tools.invoke"])
    env: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    system_tier: str = "installed"
    receipt_head: str = "genesis"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_id": self.app_id,
            "name": self.name,
            "version": self.version,
            "runtime": self.runtime,
            "description": self.description,
            "entry_module": self.entry_module,
            "agents": [asdict(agent) for agent in self.agents],
            "workflows": [asdict(workflow) for workflow in self.workflows],
            "contracts": self.contracts,
            "policies": self.policies,
            "identity_rules": self.identity_rules,
            "address_rules": self.address_rules,
            "business_rules": self.business_rules,
            "permissions": self.permissions,
            "env": self.env,
            "metadata": self.metadata,
            "system_tier": self.system_tier,
            "receipt_head": self.receipt_head,
        }


@dataclass
class GlooApp:
    manifest: GlooAppManifest
    source_root: Optional[str] = None

    def to_manifest_dict(self) -> Dict[str, Any]:
        return self.manifest.to_dict()

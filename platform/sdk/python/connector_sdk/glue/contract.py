"""
CompiledContract - CLS contract representation
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ParamDef:
    """Parameter definition"""
    name: str
    type_name: str
    required: bool = False
    description: Optional[str] = None


@dataclass
class CompiledContract:
    """
    A compiled CLS contract ready for execution.
    
    Created by cls.compile() from CLS source code.
    """
    cid: str
    name: str
    version: Optional[str] = None
    source: Optional[str] = None
    inputs: List[ParamDef] = field(default_factory=list)
    outputs: List[ParamDef] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    policies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CompiledContract":
        """Create from API response"""
        inputs = [
            ParamDef(
                name=p.get("name", ""),
                type_name=p.get("type_name", ""),
                required=p.get("required", False),
                description=p.get("description")
            )
            for p in d.get("inputs", [])
        ]
        outputs = [
            ParamDef(
                name=p.get("name", ""),
                type_name=p.get("type_name", ""),
                required=True,
                description=p.get("description")
            )
            for p in d.get("outputs", [])
        ]
        
        return cls(
            cid=d.get("cid", d.get("contract_cid", "")),
            name=d.get("name", ""),
            version=d.get("version"),
            source=d.get("source"),
            inputs=inputs,
            outputs=outputs,
            tools=d.get("tools", []),
            capabilities=d.get("capabilities", []),
            policies=d.get("policies", []),
            metadata=d.get("metadata", {})
        )

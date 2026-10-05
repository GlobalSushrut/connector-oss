"""
CLS - Connector Logic System embedding for Python

Allows CLS contracts to be written directly in Python code.
"""

from typing import Any, Dict, Optional
import hashlib
import requests
import os

from .contract import CompiledContract, ParamDef
from .error import GlueError, ErrorCode


class CLSCompiler:
    """
    CLS compiler interface.
    
    Usage:
        from connector.glue import cls
        
        # Compile CLS source
        contract = cls.compile('''
            contract hello {
                interface {
                    input name: string required
                    output greeting: string
                }
            }
        ''')
        
        # Or use as a context manager for builder pattern
        with cls.contract("hello") as c:
            c.input("name", "string", required=True)
            c.output("greeting", "string")
    """
    
    def __init__(self):
        self._base_url = os.environ.get("CONNECTOR_URL", "http://localhost:8080")
        self._api_key = os.environ.get("CONNECTOR_API_KEY")
        self._cache: Dict[str, CompiledContract] = {}
    
    def compile(self, source: str) -> CompiledContract:
        """
        Compile CLS source code into a CompiledContract.
        
        Args:
            source: CLS source code
            
        Returns:
            CompiledContract ready for execution
            
        Raises:
            GlueError: If compilation fails
        """
        # Check cache first
        source_hash = hashlib.sha256(source.encode()).hexdigest()[:32]
        if source_hash in self._cache:
            return self._cache[source_hash]
        
        # Try remote compilation first
        try:
            contract = self._compile_remote(source)
            self._cache[source_hash] = contract
            return contract
        except Exception:
            # Fall back to local parsing
            contract = self._compile_local(source)
            self._cache[source_hash] = contract
            return contract
    
    def _compile_remote(self, source: str) -> CompiledContract:
        """Compile via remote API"""
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        
        response = requests.post(
            f"{self._base_url}/api/v1/cls/compile",
            json={"source": source},
            headers=headers,
            timeout=30
        )
        
        data = response.json()
        if not data.get("ok", False):
            error = data.get("error", {})
            raise GlueError(
                ErrorCode.COMPILE_ERROR,
                error.get("message", "Compilation failed"),
                detail=error.get("detail"),
                hints=error.get("hints", [])
            )
        
        return CompiledContract.from_dict(data.get("data", {}))
    
    def _compile_local(self, source: str) -> CompiledContract:
        """Local parsing fallback"""
        # Simple local parsing for basic contracts
        source_hash = hashlib.sha256(source.encode()).hexdigest()[:32]
        cid = f"cls1-sha256-{source_hash}"
        
        # Extract contract name
        name = "unknown"
        lines = source.strip().split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("contract "):
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[1].rstrip("{").strip()
                break
        
        return CompiledContract(
            cid=cid,
            name=name,
            source=source
        )
    
    def contract(self, name: str) -> "ContractBuilder":
        """
        Create a contract using the builder pattern.
        
        Usage:
            with cls.contract("hello") as c:
                c.version("1.0.0")
                c.input("name", "string", required=True)
                c.output("greeting", "string")
        """
        return ContractBuilder(name)
    
    def __call__(self, source: str) -> CompiledContract:
        """Allow cls("source") syntax"""
        return self.compile(source)


class ContractBuilder:
    """
    Builder for creating CLS contracts programmatically.
    
    Usage:
        with cls.contract("hello") as c:
            c.version("1.0.0")
            c.domain("general")
            c.input("name", "string", required=True)
            c.output("greeting", "string")
            c.tool("search", binding="advisory")
            c.require("safe_content")
    """
    
    def __init__(self, name: str):
        self._name = name
        self._version: Optional[str] = None
        self._domain: Optional[str] = None
        self._inputs: list = []
        self._outputs: list = []
        self._tools: list = []
        self._capabilities: list = []
        self._policies: list = []
        self._flow_stages: list = []
    
    def __enter__(self) -> "ContractBuilder":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def version(self, v: str) -> "ContractBuilder":
        """Set contract version"""
        self._version = v
        return self
    
    def domain(self, d: str) -> "ContractBuilder":
        """Set contract domain"""
        self._domain = d
        return self
    
    def input(self, name: str, type_name: str, required: bool = False,
              description: Optional[str] = None) -> "ContractBuilder":
        """Add an input parameter"""
        self._inputs.append({
            "name": name,
            "type": type_name,
            "required": required,
            "description": description
        })
        return self
    
    def output(self, name: str, type_name: str,
               description: Optional[str] = None) -> "ContractBuilder":
        """Add an output parameter"""
        self._outputs.append({
            "name": name,
            "type": type_name,
            "description": description
        })
        return self
    
    def tool(self, name: str, binding: str = "advisory") -> "ContractBuilder":
        """Add a tool capability"""
        self._tools.append({"name": name, "binding": binding})
        return self
    
    def memory(self, namespace: str, mode: str = "readonly") -> "ContractBuilder":
        """Add a memory capability"""
        self._capabilities.append({"type": "memory", "namespace": namespace, "mode": mode})
        return self
    
    def require(self, policy: str) -> "ContractBuilder":
        """Add a required policy"""
        self._policies.append({"kind": "require", "subject": policy})
        return self
    
    def deny(self, policy: str) -> "ContractBuilder":
        """Add a denied policy"""
        self._policies.append({"kind": "deny", "subject": policy})
        return self
    
    def flow(self) -> "FlowBuilder":
        """Start building a flow"""
        return FlowBuilder(self)
    
    def build(self) -> CompiledContract:
        """Build the contract"""
        source = self._generate_source()
        return cls.compile(source)
    
    def _generate_source(self) -> str:
        """Generate CLS source from builder state"""
        lines = [f"contract {self._name} {{"]
        
        # Solution block
        if self._version or self._domain:
            lines.append(f"    solution {self._name} {{")
            if self._version:
                lines.append(f'        version: "{self._version}"')
            if self._domain:
                lines.append(f'        domain: "{self._domain}"')
            lines.append("    }")
        
        # Interface block
        if self._inputs or self._outputs:
            lines.append("    interface {")
            for inp in self._inputs:
                req = " required" if inp.get("required") else ""
                desc = f' "{inp["description"]}"' if inp.get("description") else ""
                lines.append(f'        input {inp["name"]}: {inp["type"]}{req}{desc}')
            for out in self._outputs:
                desc = f' "{out["description"]}"' if out.get("description") else ""
                lines.append(f'        output {out["name"]}: {out["type"]}{desc}')
            lines.append("    }")
        
        # Capabilities block
        if self._tools or self._capabilities:
            lines.append("    capabilities {")
            for tool in self._tools:
                lines.append(f'        tool {tool["name"]} {tool["binding"]}')
            for cap in self._capabilities:
                if cap["type"] == "memory":
                    lines.append(f'        memory {cap["namespace"]} {cap["mode"]}')
            lines.append("    }")
        
        # Policy block
        if self._policies:
            lines.append("    policy {")
            for pol in self._policies:
                lines.append(f'        {pol["kind"]} {pol["subject"]}')
            lines.append("    }")
        
        lines.append("}")
        return "\n".join(lines)


class FlowBuilder:
    """Builder for flow blocks"""
    
    def __init__(self, contract: ContractBuilder):
        self._contract = contract
        self._stages: list = []
    
    def __enter__(self) -> "FlowBuilder":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def stage(self, name: str) -> "StageBuilder":
        """Add a stage to the flow"""
        stage = StageBuilder(self, name)
        self._stages.append(stage)
        return stage


class StageBuilder:
    """Builder for flow stages"""
    
    def __init__(self, flow: FlowBuilder, name: str):
        self._flow = flow
        self._name = name
        self._ops: list = []
    
    def __enter__(self) -> "StageBuilder":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def require(self, field: str, op: str, value: str) -> "StageBuilder":
        """Add a require operation"""
        self._ops.append({"type": "require", "field": field, "op": op, "value": value})
        return self
    
    def call(self, tool: str, params: Dict[str, Any], bind: Optional[str] = None) -> "StageBuilder":
        """Add a tool call"""
        self._ops.append({"type": "call", "tool": tool, "params": params, "bind": bind})
        return self
    
    def when(self, condition: str) -> "WhenBuilder":
        """Add a conditional"""
        return WhenBuilder(self, condition)
    
    def otherwise(self) -> "OtherwiseBuilder":
        """Add an otherwise clause"""
        return OtherwiseBuilder(self)


class WhenBuilder:
    """Builder for when clauses"""
    
    def __init__(self, stage: StageBuilder, condition: str):
        self._stage = stage
        self._condition = condition
    
    def emit(self, event: str, data: Dict[str, Any]) -> StageBuilder:
        """Emit an event"""
        self._stage._ops.append({
            "type": "when",
            "condition": self._condition,
            "action": {"type": "emit", "event": event, "data": data}
        })
        return self._stage


class OtherwiseBuilder:
    """Builder for otherwise clauses"""
    
    def __init__(self, stage: StageBuilder):
        self._stage = stage
    
    def emit(self, event: str, data: Dict[str, Any]) -> StageBuilder:
        """Emit an event"""
        self._stage._ops.append({
            "type": "otherwise",
            "action": {"type": "emit", "event": event, "data": data}
        })
        return self._stage


# Global CLS compiler instance
cls = CLSCompiler()

# Convenience function
def compile(source: str) -> CompiledContract:
    """Compile CLS source code"""
    return cls.compile(source)

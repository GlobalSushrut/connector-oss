from typing import Optional, Type, Dict, Any
from pydantic import BaseModel, Field

# Conditional import to handle optional dependency
try:
    from langchain_core.tools import BaseTool
except ImportError:
    try:
        from langchain.tools import BaseTool
    except ImportError:
        # Fallback for type hinting if langchain is not installed
        class BaseTool:
            pass

from .client import AapiClient
from .builder import VakyaBuilder

class AapiActionSchema(BaseModel):
    """Schema for AAPI actions"""
    action: str = Field(..., description="The action to perform (e.g. 'file.read', 'http.post')")
    resource: str = Field(..., description="The target resource URI (e.g. 'file:/path/to/file')")
    body: Dict[str, Any] = Field(default_factory=dict, description="Parameters/payload for the action")
    reason: str = Field(..., description="Justification for why this action is being taken (for audit)")

class AapiTool(BaseTool):
    """
    LangChain tool for executing actions via AAPI.
    
    This tool allows an agent to perform side effects (file IO, API calls, etc.)
    safely through the AAPI Gateway, which ensures:
    1. Authentication & Authorization (MetaRules)
    2. Audit Logging (IndexDB)
    3. Recoverability (Effect Capture)
    """
    name: str = "aapi_execute"
    description: str = "Execute a secure system action. Use this tool for ALL side effects (reading/writing files, API calls, etc.)."
    args_schema: Type[BaseModel] = AapiActionSchema
    
    # Exclude client from serialization
    client: Any = Field(exclude=True)
    actor_id: str
    
    model_config = {
        "arbitrary_types_allowed": True
    }

    def _run(self, action: str, resource: str, reason: str, body: Dict[str, Any] = {}) -> str:
        """Execute the action synchronously."""
        if not hasattr(self.client, 'submit'):
            return "Error: AAPI Client not initialized"

        try:
            # Build VĀKYA
            builder = VakyaBuilder()\
                .actor(self.actor_id)\
                .as_agent()\
                .resource(resource)\
                .action(action)\
                .body(body)\
                .reason(reason)
                
            vakya = builder.build()
            
            # Submit to Gateway
            response = self.client.submit(vakya)
            
            status = response.get('status', 'unknown')
            vakya_id = response.get('vakya_id')
            
            if status == 'accepted' or status == 'success':
                receipt = response.get('receipt', {})
                return f"Action Succeeded. ID: {vakya_id}. Receipt: {receipt}"
            else:
                return f"Action Status: {status}. ID: {vakya_id}"
                
        except Exception as e:
            return f"Action Failed: {str(e)}"

    async def _arun(self, action: str, resource: str, reason: str, body: Dict[str, Any] = {}) -> str:
        """Execute the action asynchronously."""
        # Currently delegates to sync implementation as SDK is sync-first
        # In a production environment, you would use an async client
        return self._run(action, resource, reason, body)

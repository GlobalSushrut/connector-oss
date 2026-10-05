"""
LangChain + Connector Integration Example

This example demonstrates how to use Connector as a memory backend for LangChain agents.
Connector provides:
- Persistent, auditable memory with CID-based addressing
- Multi-agent memory isolation via namespaces
- HIPAA/SOC2 compliant audit trails
- Built-in vector search for semantic retrieval

Requirements:
    pip install langchain langchain-openai requests

Usage:
    export OPENAI_API_KEY=sk-...
    export CONNECTOR_URL=http://localhost:8080
    python langchain_connector.py
"""

import os
import json
import requests
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

# LangChain imports
from langchain.memory import BaseMemory
from langchain.schema import BaseMessage, HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.tools import Tool


@dataclass
class ConnectorConfig:
    """Configuration for Connector connection."""
    base_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    agent_id: Optional[str] = None
    namespace: str = "/m/langchain"
    
    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        return cls(
            base_url=os.getenv("CONNECTOR_URL", "http://localhost:8080"),
            api_key=os.getenv("CONNECTOR_API_KEY"),
            agent_id=os.getenv("CONNECTOR_AGENT_ID"),
            namespace=os.getenv("CONNECTOR_NAMESPACE", "/m/langchain"),
        )


class ConnectorMemory(BaseMemory):
    """
    LangChain Memory backed by Connector Platform.
    
    Features:
    - Persistent memory across sessions
    - Audit trail for all memory operations
    - Namespace isolation for multi-agent setups
    - CID-based content addressing
    """
    
    config: ConnectorConfig
    session_id: Optional[str] = None
    memory_key: str = "history"
    return_messages: bool = True
    
    def __init__(self, config: Optional[ConnectorConfig] = None, **kwargs):
        super().__init__(**kwargs)
        self.config = config or ConnectorConfig.from_env()
        self._messages: List[BaseMessage] = []
        self._ensure_agent()
    
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
    
    def _ensure_agent(self):
        """Ensure the agent exists in Connector."""
        if self.config.agent_id:
            return
        
        # Create agent via V2 API
        resp = requests.post(
            f"{self.config.base_url}/api/v2/agents",
            headers=self._headers(),
            json={
                "name": "langchain-agent",
                "namespace": self.config.namespace,
                "description": "LangChain integration agent",
            }
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok") and data.get("data"):
                self.config.agent_id = data["data"]["id"]
                print(f"Created Connector agent: {self.config.agent_id}")
    
    @property
    def memory_variables(self) -> List[str]:
        return [self.memory_key]
    
    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Load memory from Connector."""
        if self.return_messages:
            return {self.memory_key: self._messages}
        
        # Convert to string format
        buffer = ""
        for msg in self._messages:
            if isinstance(msg, HumanMessage):
                buffer += f"Human: {msg.content}\n"
            elif isinstance(msg, AIMessage):
                buffer += f"AI: {msg.content}\n"
        return {self.memory_key: buffer}
    
    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, str]) -> None:
        """Save context to Connector memory."""
        # Extract input/output
        input_str = inputs.get("input", str(inputs))
        output_str = outputs.get("output", str(outputs))
        
        # Add to local cache
        self._messages.append(HumanMessage(content=input_str))
        self._messages.append(AIMessage(content=output_str))
        
        # Persist to Connector
        self._write_memory({
            "type": "conversation_turn",
            "input": input_str,
            "output": output_str,
            "turn_number": len(self._messages) // 2,
        })
    
    def _write_memory(self, content: Dict[str, Any]) -> Optional[str]:
        """Write memory to Connector and return CID."""
        if not self.config.agent_id:
            return None
        
        resp = requests.post(
            f"{self.config.base_url}/api/v2/memory",
            headers=self._headers(),
            json={
                "agent_id": self.config.agent_id,
                "content": content,
                "tags": ["langchain", "conversation"],
            }
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok") and data.get("data"):
                return data["data"]["cid"]
        return None
    
    def clear(self) -> None:
        """Clear memory."""
        self._messages = []


class ConnectorTools:
    """
    LangChain Tools backed by Connector Platform.
    
    Provides tools for:
    - Memory read/write
    - Agent communication
    - Audit log access
    """
    
    def __init__(self, config: Optional[ConnectorConfig] = None):
        self.config = config or ConnectorConfig.from_env()
    
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
    
    def write_memory(self, content: str) -> str:
        """Write content to persistent memory."""
        resp = requests.post(
            f"{self.config.base_url}/api/v2/memory",
            headers=self._headers(),
            json={
                "agent_id": self.config.agent_id or "langchain",
                "content": {"text": content, "type": "note"},
                "tags": ["langchain", "tool-write"],
            }
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok"):
                cid = data["data"]["cid"]
                return f"Memory saved with CID: {cid}"
        return "Failed to save memory"
    
    def read_memory(self, cid: str) -> str:
        """Read memory by CID."""
        resp = requests.get(
            f"{self.config.base_url}/api/v2/memory/{cid}",
            headers=self._headers(),
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok"):
                return json.dumps(data["data"]["content"])
        return f"Memory not found: {cid}"
    
    def search_memory(self, query: str) -> str:
        """Search memory by query."""
        resp = requests.get(
            f"{self.config.base_url}/api/v2/memory",
            headers=self._headers(),
            params={"q": query, "limit": 5},
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok"):
                results = data["data"]
                if not results:
                    return "No memories found"
                return json.dumps([{"cid": m["cid"], "summary": m.get("summary")} for m in results])
        return "Search failed"
    
    def get_tools(self) -> List[Tool]:
        """Get LangChain tools for Connector operations."""
        return [
            Tool(
                name="write_memory",
                description="Write important information to persistent memory. Use this to remember facts, decisions, or context for later.",
                func=self.write_memory,
            ),
            Tool(
                name="read_memory",
                description="Read a specific memory by its CID (content identifier).",
                func=self.read_memory,
            ),
            Tool(
                name="search_memory",
                description="Search memories by keyword or semantic query.",
                func=self.search_memory,
            ),
        ]


def create_connector_agent(
    model: str = "gpt-4o",
    config: Optional[ConnectorConfig] = None,
) -> AgentExecutor:
    """
    Create a LangChain agent with Connector memory and tools.
    
    Args:
        model: OpenAI model to use
        config: Connector configuration
    
    Returns:
        AgentExecutor ready to use
    """
    config = config or ConnectorConfig.from_env()
    
    # Initialize LLM
    llm = ChatOpenAI(model=model, temperature=0)
    
    # Initialize Connector memory and tools
    memory = ConnectorMemory(config=config)
    tools = ConnectorTools(config=config).get_tools()
    
    # Create prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a helpful AI assistant with persistent memory.
        
You have access to Connector Platform for:
- Storing important information (write_memory)
- Retrieving past memories (read_memory, search_memory)

Use these tools to maintain context across conversations and remember important facts."""),
        MessagesPlaceholder(variable_name="history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    
    # Create agent
    agent = create_openai_functions_agent(llm, tools, prompt)
    
    return AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        verbose=True,
    )


# Example usage
if __name__ == "__main__":
    print("=" * 60)
    print("LangChain + Connector Integration Demo")
    print("=" * 60)
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("\nNote: Set OPENAI_API_KEY to run the full demo")
        print("For now, showing the integration structure...\n")
        
        # Show configuration
        config = ConnectorConfig.from_env()
        print(f"Connector URL: {config.base_url}")
        print(f"Namespace: {config.namespace}")
        
        # Show available tools
        tools = ConnectorTools(config=config)
        print("\nAvailable Tools:")
        for tool in tools.get_tools():
            print(f"  - {tool.name}: {tool.description[:50]}...")
        
        print("\nTo run the full demo:")
        print("  export OPENAI_API_KEY=sk-...")
        print("  python langchain_connector.py")
    else:
        # Run full demo
        agent = create_connector_agent()
        
        # Example conversation
        print("\n--- Conversation Start ---\n")
        
        result = agent.invoke({"input": "Remember that my favorite color is blue."})
        print(f"Agent: {result['output']}\n")
        
        result = agent.invoke({"input": "What is my favorite color?"})
        print(f"Agent: {result['output']}\n")
        
        print("--- Conversation End ---")

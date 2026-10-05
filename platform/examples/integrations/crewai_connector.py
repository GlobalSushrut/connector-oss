"""
CrewAI + Connector Integration Example

This example demonstrates how to use Connector as a memory and coordination
backend for CrewAI multi-agent workflows.

Connector provides:
- Shared memory across crew members with namespace isolation
- Agent-to-agent communication via the A2A protocol
- Audit trails for all agent actions
- KECS (maturity) scoring for agent reliability

Requirements:
    pip install crewai requests

Usage:
    export OPENAI_API_KEY=sk-...
    export CONNECTOR_URL=http://localhost:8080
    python crewai_connector.py
"""

import os
import json
import requests
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

# CrewAI imports (optional - graceful fallback if not installed)
try:
    from crewai import Agent, Task, Crew, Process
    from crewai.tools import BaseTool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    print("CrewAI not installed. Run: pip install crewai")


@dataclass
class ConnectorConfig:
    """Configuration for Connector connection."""
    base_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    namespace: str = "/m/crewai"
    
    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        return cls(
            base_url=os.getenv("CONNECTOR_URL", "http://localhost:8080"),
            api_key=os.getenv("CONNECTOR_API_KEY"),
            namespace=os.getenv("CONNECTOR_NAMESPACE", "/m/crewai"),
        )


class ConnectorClient:
    """Client for Connector Platform API."""
    
    def __init__(self, config: Optional[ConnectorConfig] = None):
        self.config = config or ConnectorConfig.from_env()
        self._agent_ids: Dict[str, str] = {}
    
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
    
    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"
    
    def register_agent(self, name: str, role: str) -> str:
        """Register a CrewAI agent with Connector."""
        resp = requests.post(
            self._url("/api/v2/agents"),
            headers=self._headers(),
            json={
                "name": name,
                "namespace": f"{self.config.namespace}/{name}",
                "description": f"CrewAI agent: {role}",
            }
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok") and data.get("data"):
                agent_id = data["data"]["id"]
                self._agent_ids[name] = agent_id
                return agent_id
        return f"agent_{name}"
    
    def write_memory(self, agent_name: str, content: Dict[str, Any], tags: List[str] = None) -> Optional[str]:
        """Write memory for an agent."""
        agent_id = self._agent_ids.get(agent_name, agent_name)
        resp = requests.post(
            self._url("/api/v2/memory"),
            headers=self._headers(),
            json={
                "agent_id": agent_id,
                "content": content,
                "tags": tags or ["crewai"],
            }
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok") and data.get("data"):
                return data["data"]["cid"]
        return None
    
    def read_memory(self, cid: str) -> Optional[Dict[str, Any]]:
        """Read memory by CID."""
        resp = requests.get(
            self._url(f"/api/v2/memory/{cid}"),
            headers=self._headers(),
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok") and data.get("data"):
                return data["data"]["content"]
        return None
    
    def list_memory(self, agent_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """List memories for an agent."""
        agent_id = self._agent_ids.get(agent_name, agent_name)
        resp = requests.get(
            self._url("/api/v2/memory"),
            headers=self._headers(),
            params={"agent_id": agent_id, "limit": limit},
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok"):
                return data.get("data", [])
        return []
    
    def get_agent_health(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get agent health/maturity score."""
        agent_id = self._agent_ids.get(agent_name, agent_name)
        resp = requests.get(
            self._url(f"/api/v2/agents/{agent_id}/health"),
            headers=self._headers(),
        )
        if resp.ok:
            data = resp.json()
            if data.get("ok"):
                return data.get("data")
        return None
    
    def send_message(self, from_agent: str, to_agent: str, message: Dict[str, Any]) -> bool:
        """Send message between agents."""
        from_id = self._agent_ids.get(from_agent, from_agent)
        to_id = self._agent_ids.get(to_agent, to_agent)
        
        resp = requests.post(
            self._url("/api/v2/tools/agent.message/invoke"),
            headers=self._headers(),
            json={
                "agent_id": from_id,
                "parameters": {
                    "to_agent": to_id,
                    "message": message,
                }
            }
        )
        return resp.ok


if CREWAI_AVAILABLE:
    class ConnectorMemoryTool(BaseTool):
        """CrewAI tool for writing to Connector memory."""
        name: str = "write_memory"
        description: str = "Write important information to persistent memory for later retrieval"
        client: ConnectorClient = field(default_factory=ConnectorClient)
        agent_name: str = "default"
        
        def _run(self, content: str) -> str:
            cid = self.client.write_memory(
                self.agent_name,
                {"text": content, "type": "note"},
                tags=["crewai", "tool-write"]
            )
            if cid:
                return f"Memory saved with CID: {cid}"
            return "Failed to save memory"
    
    class ConnectorSearchTool(BaseTool):
        """CrewAI tool for searching Connector memory."""
        name: str = "search_memory"
        description: str = "Search past memories and findings"
        client: ConnectorClient = field(default_factory=ConnectorClient)
        agent_name: str = "default"
        
        def _run(self, query: str) -> str:
            memories = self.client.list_memory(self.agent_name, limit=5)
            if not memories:
                return "No memories found"
            return json.dumps([{
                "cid": m.get("cid"),
                "summary": m.get("summary", "No summary"),
            } for m in memories])


def create_connector_crew(config: Optional[ConnectorConfig] = None) -> Optional["Crew"]:
    """
    Create a CrewAI crew with Connector integration.
    
    Returns:
        Crew instance with Connector-backed memory and tools
    """
    if not CREWAI_AVAILABLE:
        print("CrewAI not available")
        return None
    
    config = config or ConnectorConfig.from_env()
    client = ConnectorClient(config)
    
    # Register agents with Connector
    client.register_agent("researcher", "Research Specialist")
    client.register_agent("writer", "Content Writer")
    client.register_agent("reviewer", "Quality Reviewer")
    
    # Create tools
    researcher_memory = ConnectorMemoryTool(client=client, agent_name="researcher")
    researcher_search = ConnectorSearchTool(client=client, agent_name="researcher")
    
    writer_memory = ConnectorMemoryTool(client=client, agent_name="writer")
    
    # Create agents
    researcher = Agent(
        role="Research Specialist",
        goal="Find accurate and relevant information",
        backstory="Expert researcher with access to persistent memory",
        tools=[researcher_memory, researcher_search],
        verbose=True,
    )
    
    writer = Agent(
        role="Content Writer",
        goal="Create clear and engaging content",
        backstory="Skilled writer who builds on research findings",
        tools=[writer_memory],
        verbose=True,
    )
    
    reviewer = Agent(
        role="Quality Reviewer",
        goal="Ensure accuracy and quality",
        backstory="Meticulous reviewer who checks all work",
        verbose=True,
    )
    
    # Create tasks
    research_task = Task(
        description="Research the topic: {topic}. Save key findings to memory.",
        expected_output="A summary of research findings",
        agent=researcher,
    )
    
    writing_task = Task(
        description="Write content based on the research findings",
        expected_output="A well-written article or report",
        agent=writer,
    )
    
    review_task = Task(
        description="Review the content for accuracy and quality",
        expected_output="Final reviewed content with any corrections",
        agent=reviewer,
    )
    
    # Create crew
    crew = Crew(
        agents=[researcher, writer, reviewer],
        tasks=[research_task, writing_task, review_task],
        process=Process.sequential,
        verbose=True,
    )
    
    return crew


# Example usage
if __name__ == "__main__":
    print("=" * 60)
    print("CrewAI + Connector Integration Demo")
    print("=" * 60)
    
    config = ConnectorConfig.from_env()
    print(f"\nConnector URL: {config.base_url}")
    print(f"Namespace: {config.namespace}")
    
    # Initialize client
    client = ConnectorClient(config)
    
    # Show API capabilities
    print("\n--- Connector API Capabilities ---")
    print("1. Agent Registration: Register CrewAI agents with Connector")
    print("2. Persistent Memory: Store findings across crew runs")
    print("3. Agent Communication: A2A protocol for agent messaging")
    print("4. Health Monitoring: KECS scores for agent reliability")
    print("5. Audit Trails: Full audit log of all agent actions")
    
    if not CREWAI_AVAILABLE:
        print("\n--- CrewAI Not Installed ---")
        print("To run the full demo:")
        print("  pip install crewai")
        print("  export OPENAI_API_KEY=sk-...")
        print("  python crewai_connector.py")
    elif not os.getenv("OPENAI_API_KEY"):
        print("\n--- OpenAI API Key Required ---")
        print("To run the full demo:")
        print("  export OPENAI_API_KEY=sk-...")
        print("  python crewai_connector.py")
    else:
        print("\n--- Running Full Demo ---")
        crew = create_connector_crew(config)
        if crew:
            result = crew.kickoff(inputs={"topic": "AI Agent Memory Systems"})
            print(f"\n--- Final Result ---\n{result}")

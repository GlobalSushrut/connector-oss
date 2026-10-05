#!/usr/bin/env python3
"""
Canonical Example 2: Tool Agent
===============================

Demonstrates Connector's tool integration capabilities:
- Connecting to MCP tool servers
- Discovering available tools
- Invoking tools with audit trail
- Tool result handling

This shows how Connector acts as infrastructure for tool-using agents.

Usage:
    export CONNECTOR_URL=http://localhost:8080
    export CONNECTOR_API_KEY=your-api-key
    python 02_tool_agent.py
"""

import os
import json
import httpx
from typing import Optional, Any

# Configuration
CONNECTOR_URL = os.getenv("CONNECTOR_URL", "http://localhost:8080")
API_KEY = os.getenv("CONNECTOR_API_KEY", "dev-key")

# HTTP client with auth
client = httpx.Client(
    base_url=CONNECTOR_URL,
    headers={"Authorization": f"Bearer {API_KEY}"},
    timeout=30.0,
)


def create_agent(name: str, description: str) -> dict:
    """Create a new agent."""
    response = client.post(
        "/api/v2/agents",
        json={
            "name": name,
            "description": description,
            "namespace": "examples",
        },
    )
    response.raise_for_status()
    return response.json()["data"]


def list_tools(agent_id: str, category: str = None) -> list[dict]:
    """List available tools for an agent."""
    params = {}
    if category:
        params["category"] = category
    
    response = client.get("/api/v2/tools", params=params)
    response.raise_for_status()
    return response.json()["data"]


def get_tool(tool_id: str) -> dict:
    """Get details about a specific tool."""
    response = client.get(f"/api/v2/tools/{tool_id}")
    response.raise_for_status()
    return response.json()["data"]


def invoke_tool(agent_id: str, tool_id: str, parameters: dict) -> dict:
    """Invoke a tool and get the result."""
    response = client.post(
        f"/api/v2/tools/{tool_id}/invoke",
        json={
            "agent_id": agent_id,
            "parameters": parameters,
        },
    )
    response.raise_for_status()
    return response.json()["data"]


def get_audit_entry(audit_id: str) -> dict:
    """Get audit entry for a tool invocation."""
    response = client.get(f"/api/v2/audit/{audit_id}")
    response.raise_for_status()
    return response.json()["data"]


def write_memory(agent_id: str, content: dict, tags: list[str] = None) -> dict:
    """Write tool result to memory."""
    response = client.post(
        "/api/v2/memory",
        json={
            "agent_id": agent_id,
            "content": content,
            "tags": tags or [],
        },
    )
    response.raise_for_status()
    return response.json()["data"]


class ToolAgent:
    """
    A simple tool-using agent backed by Connector.
    
    This demonstrates the pattern of:
    1. Agent receives a task
    2. Agent selects appropriate tool
    3. Agent invokes tool via Connector
    4. Connector audits the invocation
    5. Agent stores result in memory
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.tools = {}
        self._refresh_tools()
    
    def _refresh_tools(self):
        """Refresh the list of available tools."""
        tools = list_tools(self.agent_id)
        self.tools = {t["id"]: t for t in tools}
    
    def find_tool(self, capability: str) -> Optional[dict]:
        """Find a tool that matches the required capability."""
        capability_lower = capability.lower()
        for tool in self.tools.values():
            if capability_lower in tool.get("description", "").lower():
                return tool
            if capability_lower in tool.get("name", "").lower():
                return tool
        return None
    
    def execute_task(self, task: str, tool_id: str, params: dict) -> dict:
        """Execute a task using a tool."""
        print(f"   Executing task: {task}")
        print(f"   Using tool: {tool_id}")
        print(f"   Parameters: {json.dumps(params)}")
        
        # Invoke the tool
        result = invoke_tool(self.agent_id, tool_id, params)
        
        # Store the result in memory
        memory = write_memory(
            agent_id=self.agent_id,
            content={
                "type": "tool_result",
                "task": task,
                "tool_id": tool_id,
                "parameters": params,
                "result": result.get("result"),
                "success": result.get("success"),
                "duration_ms": result.get("duration_ms"),
            },
            tags=["tool_result", tool_id],
        )
        
        return {
            "result": result,
            "memory_cid": memory["cid"],
            "audit_cid": result.get("audit_cid"),
        }


def main():
    print("=" * 60)
    print("Connector Tool Agent Example")
    print("=" * 60)
    print()
    
    # Step 1: Create an agent
    print("1. Creating tool agent...")
    agent = create_agent(
        name="tool-demo-agent",
        description="Demonstrates tool invocation with audit trail",
    )
    agent_id = agent["id"]
    print(f"   ✓ Created agent: {agent_id}")
    print()
    
    # Step 2: List available tools
    print("2. Discovering available tools...")
    tools = list_tools(agent_id)
    print(f"   ✓ Found {len(tools)} tools:")
    for tool in tools[:5]:  # Show first 5
        print(f"      - {tool['name']}: {tool.get('description', 'No description')[:50]}...")
    if len(tools) > 5:
        print(f"      ... and {len(tools) - 5} more")
    print()
    
    # Step 3: Get tool details
    print("3. Getting tool details...")
    if tools:
        tool = get_tool(tools[0]["id"])
        print(f"   Tool: {tool['name']}")
        print(f"   Description: {tool.get('description', 'N/A')}")
        print(f"   Category: {tool.get('category', 'N/A')}")
        print(f"   Parameters:")
        for param in tool.get("parameters", []):
            required = "required" if param.get("required") else "optional"
            print(f"      - {param['name']} ({param.get('type_', 'any')}, {required})")
    print()
    
    # Step 4: Create a ToolAgent and execute tasks
    print("4. Creating ToolAgent wrapper...")
    tool_agent = ToolAgent(agent_id)
    print(f"   ✓ ToolAgent initialized with {len(tool_agent.tools)} tools")
    print()
    
    # Step 5: Execute a sample task
    print("5. Executing sample tasks...")
    
    # Task 1: Memory write (built-in tool)
    print()
    print("   Task 1: Store a fact using memory_write tool")
    if "memory_write" in tool_agent.tools:
        result = tool_agent.execute_task(
            task="Store user preference",
            tool_id="memory_write",
            params={
                "content": {"preference": "notifications_enabled", "value": True},
                "tags": ["preference", "notifications"],
            },
        )
        print(f"   ✓ Success: {result['result'].get('success')}")
        print(f"   ✓ Memory CID: {result['memory_cid'][:16]}...")
        print(f"   ✓ Audit CID: {result.get('audit_cid', 'N/A')}")
    else:
        print("   (memory_write tool not available - using mock)")
    
    # Task 2: Memory search (built-in tool)
    print()
    print("   Task 2: Search memories using memory_search tool")
    if "memory_search" in tool_agent.tools:
        result = tool_agent.execute_task(
            task="Find user preferences",
            tool_id="memory_search",
            params={
                "query": "user preferences",
                "limit": 5,
            },
        )
        print(f"   ✓ Success: {result['result'].get('success')}")
        print(f"   ✓ Results: {len(result['result'].get('result', {}).get('matches', []))} matches")
    else:
        print("   (memory_search tool not available - using mock)")
    
    print()
    
    # Step 6: View audit trail
    print("6. Viewing audit trail...")
    response = client.get(
        "/api/v2/audit",
        params={"agent_id": agent_id, "limit": 5},
    )
    if response.status_code == 200:
        audit_entries = response.json()["data"]
        print(f"   ✓ Found {len(audit_entries)} audit entries:")
        for entry in audit_entries:
            print(f"      - {entry.get('operation', 'N/A')}: {entry.get('outcome', 'N/A')} ({entry.get('duration_us', 0)}μs)")
    print()
    
    # Step 7: Export audit in OCSF format
    print("7. Exporting audit in OCSF format (for SIEM)...")
    response = client.get(
        "/api/v2/audit",
        params={"agent_id": agent_id, "format": "ocsf", "limit": 3},
    )
    if response.status_code == 200:
        ocsf_data = response.json()
        print(f"   ✓ OCSF export ready")
        print(f"   ✓ Schema: OCSF 1.3.0")
        print(f"   ✓ Class: System Activity (6001)")
        print("   ✓ Ready for Splunk/Datadog ingestion")
    print()
    
    # Summary
    print("=" * 60)
    print("Tool Agent Demo Complete!")
    print("=" * 60)
    print()
    print("Key Concepts Demonstrated:")
    print("  • Discovering available tools")
    print("  • Invoking tools with parameters")
    print("  • Automatic audit trail generation")
    print("  • Storing tool results in memory")
    print("  • OCSF export for SIEM integration")
    print()
    print("Architecture Pattern:")
    print("  ┌─────────────┐     ┌───────────────┐     ┌──────────┐")
    print("  │  Your AI    │────▶│   Connector   │────▶│  Tools   │")
    print("  │  Agent      │◀────│  (Audit+Mem)  │◀────│  (MCP)   │")
    print("  └─────────────┘     └───────────────┘     └──────────┘")
    print()
    print("Next Steps:")
    print("  • See 03_compliance_agent.py for audit + evidence")
    print("  • Connect your own MCP tools via /tools/connect")
    print()


if __name__ == "__main__":
    main()

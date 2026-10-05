#!/usr/bin/env python3
"""
Canonical Example 1: Memory Agent
=================================

Demonstrates Connector's core memory capabilities:
- Writing memories with metadata and tags
- Recalling memories with semantic search
- Memory consolidation and lifecycle

This is the simplest Connector integration - just memory storage and retrieval.

Usage:
    export CONNECTOR_URL=http://localhost:8080
    export CONNECTOR_API_KEY=your-api-key
    python 01_memory_agent.py
"""

import os
import json
import httpx
from datetime import datetime
from typing import Optional

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


def write_memory(agent_id: str, content: dict, tags: list[str] = None, summary: str = None) -> dict:
    """Write a memory packet to the agent's memory store."""
    response = client.post(
        "/api/v2/memory",
        json={
            "agent_id": agent_id,
            "content": content,
            "tags": tags or [],
            "summary": summary,
        },
    )
    response.raise_for_status()
    return response.json()["data"]


def recall_memories(agent_id: str, limit: int = 10, tag: str = None) -> list[dict]:
    """Recall memories from the agent's memory store."""
    params = {"agent_id": agent_id, "limit": limit}
    if tag:
        params["tag"] = tag
    
    response = client.get("/api/v2/memory", params=params)
    response.raise_for_status()
    return response.json()["data"]


def search_memories(agent_id: str, query: str, limit: int = 5) -> list[dict]:
    """Semantic search across agent memories."""
    response = client.get(
        f"/api/v2/memory/search",
        params={"agent_id": agent_id, "q": query, "limit": limit},
    )
    response.raise_for_status()
    return response.json()["data"]


def get_memory(cid: str) -> dict:
    """Get a specific memory by CID."""
    response = client.get(f"/api/v2/memory/{cid}")
    response.raise_for_status()
    return response.json()["data"]


def delete_memory(cid: str) -> dict:
    """Delete a memory by CID."""
    response = client.delete(f"/api/v2/memory/{cid}")
    response.raise_for_status()
    return response.json()["data"]


def main():
    print("=" * 60)
    print("Connector Memory Agent Example")
    print("=" * 60)
    print()
    
    # Step 1: Create an agent
    print("1. Creating memory agent...")
    agent = create_agent(
        name="memory-demo-agent",
        description="Demonstrates memory storage and retrieval",
    )
    agent_id = agent["id"]
    print(f"   ✓ Created agent: {agent_id}")
    print()
    
    # Step 2: Write some memories
    print("2. Writing memories...")
    
    memories = [
        {
            "content": {
                "type": "fact",
                "subject": "user_preference",
                "value": "User prefers dark mode interfaces",
            },
            "tags": ["preference", "ui"],
            "summary": "User UI preference: dark mode",
        },
        {
            "content": {
                "type": "conversation",
                "user_message": "What's the weather like?",
                "assistant_response": "It's sunny and 72°F today.",
                "timestamp": datetime.now().isoformat(),
            },
            "tags": ["conversation", "weather"],
            "summary": "Weather inquiry - sunny 72°F",
        },
        {
            "content": {
                "type": "task",
                "description": "Schedule meeting with team",
                "status": "completed",
                "completed_at": datetime.now().isoformat(),
            },
            "tags": ["task", "completed"],
            "summary": "Completed: Schedule team meeting",
        },
        {
            "content": {
                "type": "fact",
                "subject": "user_location",
                "value": "User is based in San Francisco",
            },
            "tags": ["fact", "location"],
            "summary": "User location: San Francisco",
        },
        {
            "content": {
                "type": "insight",
                "observation": "User typically asks about weather in the morning",
                "confidence": 0.85,
            },
            "tags": ["insight", "pattern"],
            "summary": "Pattern: morning weather inquiries",
        },
    ]
    
    written_cids = []
    for mem in memories:
        result = write_memory(
            agent_id=agent_id,
            content=mem["content"],
            tags=mem["tags"],
            summary=mem["summary"],
        )
        written_cids.append(result["cid"])
        print(f"   ✓ Wrote memory: {result['cid'][:16]}... ({mem['summary']})")
    
    print(f"   Total: {len(written_cids)} memories written")
    print()
    
    # Step 3: Recall all memories
    print("3. Recalling all memories...")
    all_memories = recall_memories(agent_id, limit=10)
    print(f"   ✓ Retrieved {len(all_memories)} memories")
    for mem in all_memories:
        print(f"      - {mem.get('summary', 'No summary')} [{', '.join(mem.get('tags', []))}]")
    print()
    
    # Step 4: Filter by tag
    print("4. Filtering memories by tag 'preference'...")
    preference_memories = recall_memories(agent_id, tag="preference")
    print(f"   ✓ Found {len(preference_memories)} memories with tag 'preference'")
    for mem in preference_memories:
        print(f"      - {mem.get('summary', 'No summary')}")
    print()
    
    # Step 5: Semantic search
    print("5. Semantic search: 'where is the user located?'...")
    search_results = search_memories(agent_id, query="where is the user located?")
    print(f"   ✓ Found {len(search_results)} relevant memories")
    for mem in search_results:
        print(f"      - {mem.get('summary', 'No summary')} (score: {mem.get('score', 'N/A')})")
    print()
    
    # Step 6: Get specific memory
    print("6. Getting specific memory by CID...")
    if written_cids:
        specific_memory = get_memory(written_cids[0])
        print(f"   ✓ Retrieved memory: {specific_memory['cid'][:16]}...")
        print(f"      Content: {json.dumps(specific_memory.get('content', {}), indent=2)[:100]}...")
    print()
    
    # Step 7: Delete a memory
    print("7. Deleting a memory...")
    if len(written_cids) > 1:
        deleted = delete_memory(written_cids[-1])
        print(f"   ✓ Deleted memory: {deleted['cid'][:16]}...")
    print()
    
    # Summary
    print("=" * 60)
    print("Memory Agent Demo Complete!")
    print("=" * 60)
    print()
    print("Key Concepts Demonstrated:")
    print("  • Creating an agent with Connector")
    print("  • Writing structured memories with tags")
    print("  • Recalling memories with filters")
    print("  • Semantic search across memories")
    print("  • Memory lifecycle (create, read, delete)")
    print()
    print("Next Steps:")
    print("  • See 02_tool_agent.py for MCP tool integration")
    print("  • See 03_compliance_agent.py for audit + evidence")
    print()


if __name__ == "__main__":
    main()

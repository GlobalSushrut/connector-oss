#!/usr/bin/env python3
"""
Connector Platform — Python SDK Quickstart Example

This example demonstrates:
1. Connecting to the platform
2. Registering and managing agents
3. Memory operations (write, read, search)
4. Knowledge pipeline (assets → knowledge)
5. Tool integration
"""

import os
from connector_sdk import ConnectorClient

# ═══════════════════════════════════════════════════════════════
# 1. Connect to Platform
# ═══════════════════════════════════════════════════════════════

# Default: localhost:3000 in dev mode
client = ConnectorClient(
    base_url=os.getenv("CONNECTOR_URL", "http://localhost:3000"),
    api_key=os.getenv("CONNECTOR_API_KEY"),  # Optional in dev mode
)

print("✓ Connected to Connector Platform")

# ═══════════════════════════════════════════════════════════════
# 2. Agent Lifecycle
# ═══════════════════════════════════════════════════════════════

# Register a new agent
agent = client.agents.register(
    name="demo_agent",
    description="Quickstart demo agent",
    clearance=2,  # Security clearance level
    token_budget=10000,
)
print(f"✓ Registered agent: {agent['pid']}")

# Start the agent (registered → running)
client.agents.start(agent["pid"])
print(f"✓ Started agent: {agent['pid']}")

# Check agent status
status = client.agents.get(agent["pid"])
print(f"  Status: {status['phase']}")

# ═══════════════════════════════════════════════════════════════
# 3. Memory Operations
# ═══════════════════════════════════════════════════════════════

# Write to agent's private memory (/m/ namespace)
namespace = f"m/{agent['pid']}/scratch"

client.memory.write(
    namespace=namespace,
    packet_type="observation",
    payload={
        "text": "The user asked about climate change",
        "intent": "question",
        "entities": ["climate", "environment"],
    },
)
print(f"✓ Wrote to memory: {namespace}")

# Write more data
client.memory.write(
    namespace=namespace,
    packet_type="inference",
    payload={
        "conclusion": "User is interested in environmental topics",
        "confidence": 0.85,
    },
)

# Read memory
packets = client.memory.read(namespace=namespace, limit=10)
print(f"✓ Read {len(packets)} packets from memory")

for p in packets:
    print(f"  - [{p['packet_type']}] {p['payload']}")

# Semantic search
results = client.memory.search(
    namespace=f"m/{agent['pid']}",
    query="environmental topics",
    top_k=5,
)
print(f"✓ Search found {len(results)} results")

# ═══════════════════════════════════════════════════════════════
# 4. Knowledge Pipeline
# ═══════════════════════════════════════════════════════════════

# Create an asset container (staging area for raw files)
container = client.assets.create_container(
    name="demo_docs",
    allowed_types=["txt", "md", "json"],
    quota_bytes=10 * 1024 * 1024,  # 10MB
)
print(f"✓ Created asset container: {container['id']}")

# Upload raw content
client.assets.upload(
    container_id=container["id"],
    filename="facts.txt",
    content="""
    Climate change is causing global temperatures to rise.
    The Paris Agreement aims to limit warming to 1.5°C.
    Renewable energy adoption is accelerating worldwide.
    """,
)
print("✓ Uploaded asset: facts.txt")

# Ingest assets into knowledge (/k/ namespace)
result = client.assets.ingest(
    container_id=container["id"],
    target_ns="k/demo/facts",
)
print(f"✓ Ingested {result['processed']} assets to knowledge")

# Query knowledge
knowledge = client.memory.search(
    namespace="k/demo/facts",
    query="Paris Agreement temperature",
    top_k=3,
)
print(f"✓ Knowledge search: {len(knowledge)} results")

# ═══════════════════════════════════════════════════════════════
# 5. Tool Integration (if tools configured)
# ═══════════════════════════════════════════════════════════════

# List available tools
tools = client.tools.list()
print(f"✓ Available tools: {len(tools)}")

# Example tool call (if web_search is configured)
# result = client.tools.call(
#     tool="web_search",
#     params={"query": "latest climate news"},
# )

# ═══════════════════════════════════════════════════════════════
# 6. Books (Accounting)
# ═══════════════════════════════════════════════════════════════

# Get system position (like a balance sheet)
position = client.books.position()
print(f"✓ System position:")
print(f"  - Total operations: {position.get('total_ops', 0)}")
print(f"  - Active agents: {position.get('active_agents', 0)}")

# Get agent's ledger
ledger = client.books.ledger(agent["pid"])
print(f"✓ Agent ledger: {len(ledger)} entries")

# ═══════════════════════════════════════════════════════════════
# 7. Cleanup
# ═══════════════════════════════════════════════════════════════

# Freeze agent (suspend with snapshot)
# client.agents.freeze(agent["pid"])

# Or kill agent (terminate)
client.agents.kill(agent["pid"])
print(f"✓ Killed agent: {agent['pid']}")

print("\n✅ Quickstart complete!")

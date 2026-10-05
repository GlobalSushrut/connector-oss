#!/usr/bin/env python3
"""
Connector Platform — Knowledge Pipeline Example

Demonstrates the Kafka-style ingestion pipeline:
  /v/assets/ → Validation → Cleaning → Structuring → /k/knowledge/

This example shows:
1. Creating asset containers
2. Uploading various file types
3. Ingesting assets into knowledge
4. Querying the knowledge graph
"""

from connector_sdk import ConnectorClient

client = ConnectorClient("http://localhost:3000")

# ═══════════════════════════════════════════════════════════════
# 1. Create Asset Container
# ═══════════════════════════════════════════════════════════════

print("Creating asset container...")
container = client.assets.create_container(
    name="company_docs",
    allowed_types=["txt", "md", "json", "csv"],
    quota_bytes=100 * 1024 * 1024,  # 100MB
)
print(f"✓ Container: {container['id']}")
print(f"  Namespace: {container['namespace']}")  # /v/{id}

# ═══════════════════════════════════════════════════════════════
# 2. Upload Assets
# ═══════════════════════════════════════════════════════════════

# Plain text document
client.assets.upload(
    container_id=container["id"],
    filename="policies.txt",
    content="""
    Company Policy Document
    
    1. Remote Work Policy
    Employees may work remotely up to 3 days per week.
    Core hours are 10am-3pm in local timezone.
    
    2. Expense Policy
    Travel expenses require manager approval over $500.
    Meals are reimbursed up to $50/day during travel.
    """,
)
print("✓ Uploaded: policies.txt")

# Markdown document
client.assets.upload(
    container_id=container["id"],
    filename="onboarding.md",
    content="""
    # New Employee Onboarding
    
    ## Week 1
    - Complete HR paperwork
    - Set up development environment
    - Meet with team lead
    
    ## Week 2
    - Shadow senior developer
    - Complete security training
    - First code review
    """,
)
print("✓ Uploaded: onboarding.md")

# JSON data
client.assets.upload(
    container_id=container["id"],
    filename="team.json",
    content="""
    {
        "team": "Engineering",
        "members": [
            {"name": "Alice", "role": "Tech Lead", "expertise": ["Python", "ML"]},
            {"name": "Bob", "role": "Senior Dev", "expertise": ["Rust", "Systems"]},
            {"name": "Carol", "role": "DevOps", "expertise": ["K8s", "AWS"]}
        ],
        "projects": ["Platform", "SDK", "Docs"]
    }
    """,
)
print("✓ Uploaded: team.json")

# CSV data
client.assets.upload(
    container_id=container["id"],
    filename="metrics.csv",
    content="""date,metric,value
2024-01-01,users,1000
2024-01-02,users,1050
2024-01-03,users,1100
2024-01-01,requests,50000
2024-01-02,requests,52000
2024-01-03,requests,55000
""",
)
print("✓ Uploaded: metrics.csv")

# ═══════════════════════════════════════════════════════════════
# 3. List Assets
# ═══════════════════════════════════════════════════════════════

containers = client.assets.list_containers()
print(f"\n✓ Total containers: {len(containers)}")

# ═══════════════════════════════════════════════════════════════
# 4. Ingest to Knowledge
# ═══════════════════════════════════════════════════════════════

print("\nIngesting assets to knowledge...")
result = client.assets.ingest(
    container_id=container["id"],
    target_ns="k/company/docs",
)
print(f"✓ Processed: {result['processed']}/{result['total']} assets")
print(f"  Target namespace: {result['target_namespace']}")

# ═══════════════════════════════════════════════════════════════
# 5. Query Knowledge
# ═══════════════════════════════════════════════════════════════

print("\nQuerying knowledge graph...")

# Search for remote work policy
results = client.memory.search(
    namespace="k/company/docs",
    query="remote work policy",
    top_k=3,
)
print(f"\n'remote work policy' → {len(results)} results")
for r in results:
    print(f"  - Score: {r.get('score', 0):.2f}")
    print(f"    {r.get('text', '')[:100]}...")

# Search for onboarding
results = client.memory.search(
    namespace="k/company/docs",
    query="new employee first week",
    top_k=3,
)
print(f"\n'new employee first week' → {len(results)} results")

# Search for team info
results = client.memory.search(
    namespace="k/company/docs",
    query="Python expertise",
    top_k=3,
)
print(f"\n'Python expertise' → {len(results)} results")

# ═══════════════════════════════════════════════════════════════
# 6. Knowledge Graph Stats
# ═══════════════════════════════════════════════════════════════

print("\n✅ Knowledge pipeline complete!")
print(f"  Assets uploaded: 4")
print(f"  Knowledge namespace: k/company/docs")

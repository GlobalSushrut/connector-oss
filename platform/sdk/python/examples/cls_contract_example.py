#!/usr/bin/env python3
"""
Connector Platform — CLS Contract Example

This example demonstrates:
1. Writing a CLS contract
2. Compiling and deploying it
3. Running the agent with the contract
"""

from connector_sdk import ConnectorClient

client = ConnectorClient("http://localhost:3000")

# ═══════════════════════════════════════════════════════════════
# 1. Define CLS Contract
# ═══════════════════════════════════════════════════════════════

CLS_CONTRACT = """
contract ResearchAssistant {
    version: "1.0.0"
    description: "Research assistant that searches and summarizes"
    
    memory {
        alias context = "m/{agent}/context"
        alias findings = "m/{agent}/findings"
        alias kb = "k/research/papers"
    }
    
    tools {
        bind search: "mcp://arxiv/search" {
            requires_approval: false
            rate_limit: 5/minute
        }
    }
    
    states {
        initial: idle
        terminal: [done]
        states: [idle, searching, analyzing, responding, done]
    }
    
    governance {
        pre: budget.tokens > 500
        invariant: clearance >= 2
        post: response.length < 2000
    }
    
    flow main {
        on user_message {
            recall context as prev_context
            
            transition idle -> searching
            
            call search(query: input.text, limit: 5) as papers
            
            transition searching -> analyzing
            
            think {
                goal: "Summarize relevant findings"
                constraints: ["Cite sources", "Be concise"]
                using: [papers, prev_context]
            }
            
            transition analyzing -> responding
            
            respond {
                template: "research_summary"
                cite: [papers]
            }
            
            remember findings: {
                query: input.text,
                papers: papers,
                timestamp: now()
            }
            
            transition responding -> done
        }
    }
}
"""

# ═══════════════════════════════════════════════════════════════
# 2. Compile Contract
# ═══════════════════════════════════════════════════════════════

print("Compiling CLS contract...")
result = client.contracts.compile(source=CLS_CONTRACT)

if result.get("ok"):
    contract = result["contract"]
    print(f"✓ Compiled: {contract['cid']}")
    print(f"  Version: {contract['version']}")
    print(f"  States: {contract['states']}")
else:
    print(f"✗ Compilation failed: {result.get('error')}")
    exit(1)

# ═══════════════════════════════════════════════════════════════
# 3. Deploy Agent with Contract
# ═══════════════════════════════════════════════════════════════

print("\nDeploying agent...")
agent = client.agents.register(
    name="research_assistant",
    description="Research assistant powered by CLS",
    contract_cid=contract["cid"],
    clearance=2,
    token_budget=50000,
)
print(f"✓ Deployed: {agent['pid']}")

# Start the agent
client.agents.start(agent["pid"])
print(f"✓ Agent running")

# ═══════════════════════════════════════════════════════════════
# 4. Interact with Agent
# ═══════════════════════════════════════════════════════════════

print("\nSending message to agent...")
response = client.agents.message(
    pid=agent["pid"],
    text="What are the latest advances in transformer architectures?",
)

print(f"Response: {response.get('text', 'No response')}")
print(f"Citations: {response.get('citations', [])}")

# ═══════════════════════════════════════════════════════════════
# 5. Check Agent State
# ═══════════════════════════════════════════════════════════════

status = client.agents.get(agent["pid"])
print(f"\nAgent state: {status['state']}")
print(f"Tokens used: {status.get('tokens_used', 0)}")

# Cleanup
client.agents.kill(agent["pid"])
print("✓ Agent terminated")

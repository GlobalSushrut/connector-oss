# 67 — LLM Frameworks and Memory Systems

> Extended coverage of memory frameworks and LLM application stacks that integrate with Connector. Includes MEM0, Zep, LangGraph, Vercel AI SDK, and memory system comparisons.

---

## Memory System Architecture

Connector's memory system (`/m/` namespace) is designed for governed AI operations. External memory frameworks can integrate to provide specialized capabilities while leveraging Connector's 9-ring enforcement.

```
┌─────────────────────────────────────────────────────────┐
│                    User Query                           │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │    Connector Layer    │
              │   9 Rings / 9 Chains    │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │   Memory Interface     │
              │   (Memory2 Service)    │
              └───────────┬───────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Native    │   │    MEM0     │   │     Zep     │
│   /m/ /k/   │   │  (Memory)   │   │  (Memory)   │
└─────────────┘   └─────────────┘   └─────────────┘
```

---

## MEM0 Integration

[MEM0](https://github.com/mem0ai/mem0) is an open-source memory layer for AI apps with user-specific memory.

### Connector + MEM0 Hybrid

```python
# connector_mem0_adapter.py
from mem0 import Memory
from connector import Agent

class ConnectorMEM0Adapter:
    """Use MEM0 for user memory, Connector for governance."""
    
    def __init__(self, mem0_config: dict, connector_platform: Platform):
        self.mem0 = Memory.from_config(mem0_config)
        self.platform = connector_platform
        
    async def chat(self, user_id: str, message: str) -> dict:
        """Chat with user-specific memory and governance."""
        
        # 1. Retrieve user memory from MEM0
        user_memories = self.mem0.search(
            query=message,
            user_id=user_id,
            limit=5
        )
        
        # 2. Create governed agent with context
        agent = self.platform.create_agent(
            name=f"user-{user_id}",
            contract_cid="cls1-sha256-chat-standard",
            context={
                "user_memories": user_memories,
                "user_id": user_id
            }
        )
        
        # 3. Execute with governance
        result = agent.run(
            intent=message,
            regulation_tags=["user-data-policy"]
        )
        
        # 4. Store important facts back to MEM0
        if result.contains_new_facts:
            self.mem0.add(
                result.extracted_facts,
                user_id=user_id,
                metadata={
                    "audit_cid": result.audit_cid,
                    "source": "governed_chat"
                }
            )
        
        return {
            'response': result.content,
            'audit_cid': result.audit_cid,
            'memories_used': len(user_memories)
        }
```

### MEM0 → Connector Memory Bridge

```python
# mem0_connector_bridge.py
from connector import MemoryKernel

class MEM0ConnectorBridge:
    """Sync MEM0 memories to Connector's /m/ namespace for audit."""
    
    def sync_to_connector(self, user_id: str):
        """Sync user memories to Connector for governed access."""
        
        memories = self.mem0.get_all(user_id=user_id)
        
        for mem in memories:
            # Write to Connector's /m/ namespace
            self.kernel.write(
                namespace=f"/m/mem0/users/{user_id}/",
                content=mem['text'],
                metadata={
                    "mem0_id": mem['id'],
                    "mem0_score": mem['score'],
                    "connector_tags": ["mem0-sync"]
                }
            )
```

---

## Zep Integration

[Zep](https://github.com/getzep/zep) is a long-term memory service for AI assistants.

### Zep + Connector Architecture

```python
# zep_connector_integration.py
from zep_python import ZepClient
from connector import Agent, Platform

class ZepConnectorIntegration:
    """Use Zep for conversation memory, Connector for governance."""
    
    def __init__(self, zep_url: str, zep_api_key: str, connector_platform: Platform):
        self.zep = ZepClient(zep_url, zep_api_key)
        self.platform = connector_platform
        
    async def governed_conversation(
        self,
        session_id: str,
        user_id: str,
        message: str
    ) -> dict:
        """Chat with Zep memory and Connector governance."""
        
        # 1. Get conversation history from Zep
        memory = await self.zep.memory.get(session_id)
        messages = memory.messages
        
        # 2. Create governed agent with full context
        agent = self.platform.create_agent(
            name=f"zep-{session_id}",
            contract_cid="cls1-sha256-conversational",
            context={
                "conversation_history": messages,
                "session_id": session_id,
                "user_id": user_id
            }
        )
        
        # 3. Execute with governance
        result = agent.run(
            intent=message,
            regulation_tags=["conversation-privacy"]
        )
        
        # 4. Add AI response to Zep
        await self.zep.memory.add(
            session_id,
            messages=[
                {"role": "user", "content": message},
                {"role": "assistant", "content": result.content}
            ]
        )
        
        return {
            'response': result.content,
            'audit_cid': result.audit_cid,
            'zep_session': session_id
        }
```

---

## LangGraph Integration

[LangGraph](https://github.com/langchain-ai/langgraph) is LangChain's framework for building stateful agent workflows.

### LangGraph → Connector Node

```python
# langgraph_connector.py
from langgraph.graph import StateGraph
from connector import Agent

class ConnectorLangGraphNode:
    """Connector-powered node for LangGraph workflows."""
    
    def __init__(self, agent_pid: str, node_url: str):
        self.agent_pid = agent_pid
        self.agent = Agent.from_pid(agent_pid, node_url)
        
    def invoke(self, state: dict) -> dict:
        """Called by LangGraph during workflow execution."""
        
        # Execute through Connector with full governance
        result = self.agent.run(
            intent=state['current_task'],
            context=state.get('context', {}),
            tools=state.get('tools', [])
        )
        
        return {
            **state,
            'last_result': result.content,
            'audit_cid': result.audit_cid,
            'grounded': result.grounded
        }

# Build LangGraph with Connector governance
builder = StateGraph()

# Add Connector-powered nodes
builder.add_node("research", ConnectorLangGraphNode("ag_research_01"))
builder.add_node("analyze", ConnectorLangGraphNode("ag_analyze_01"))
builder.add_node("decide", ConnectorLangGraphNode("ag_decide_01"))

# Define edges
builder.add_edge("research", "analyze")
builder.add_edge("analyze", "decide")

graph = builder.compile()

# Execute with full audit trail
result = graph.invoke({
    "current_task": "Research market trends",
    "context": {"industry": "healthcare"}
})

print(f"Result: {result['last_result']}")
print(f"Audit: {result['audit_cid']}")
```

---

## Vercel AI SDK Integration

[Vercel AI SDK](https://sdk.vercel.ai) is a TypeScript toolkit for AI apps.

### Connector as AI SDK Backend

```typescript
// connector-ai-sdk-adapter.ts
import { createConnectorAdapter } from 'ai-sdk-connector';

const connector = createConnectorAdapter({
  nodeUrl: 'https://connector.internal:8443',
  apiKey: process.env.CONNECTOR_API_KEY,
});

// Use with AI SDK
import { streamText } from 'ai';

const result = await streamText({
  model: connector('governed-gpt-4'),
  messages: [
    { role: 'user', content: 'Analyze this medical report' }
  ],
  // Connector handles governance, not the SDK
  onFinish: (response) => {
    console.log('Audit CID:', response.audit_cid);
    console.log('Grounded:', response.grounded);
  }
});
```

### Streaming with Governance

```typescript
// Next.js API route with Connector
import { StreamingTextResponse } from 'ai';

export async function POST(req: Request) {
  const { messages } = await req.json();
  
  // Route through Connector for governance
  const response = await fetch(
    'https://connector.internal:8443/api/v1/agents/ag_web_01/chat',
    {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${process.env.CONNECTOR_API_KEY}`,
        'Accept': 'text/event-stream'
      },
      body: JSON.stringify({
        messages,
        stream: true,
        regulations: ['hipaa']
      })
    }
  );
  
  return new StreamingTextResponse(response.body);
}
```

---

## AutoGen Integration

[AutoGen](https://github.com/microsoft/autogen) is Microsoft's multi-agent conversation framework.

### AutoGen + Connector

```python
# autogen_connector.py
from autogen import ConversableAgent
from connector import Platform

class ConnectorAutoGenAgent(ConversableAgent):
    """AutoGen agent powered by Connector governance."""
    
    def __init__(self, name: str, agent_pid: str, platform: Platform):
        super().__init__(name=name)
        self.agent_pid = agent_pid
        self.platform = platform
        self.agent = platform.get_agent(agent_pid)
        
    def generate_reply(self, messages, sender, config):
        """Override to use Connector for generation."""
        
        intent = messages[-1]['content']
        
        # Execute through Connector
        result = self.agent.run(
            intent=intent,
            context={'conversation': messages},
            regulation_tags=['multi-agent-policy']
        )
        
        return {
            'content': result.content,
            'audit_cid': result.audit_cid,
            'name': self.name
        }

# Create multi-agent team with governance
researcher = ConnectorAutoGenAgent("researcher", "ag_research_01", platform)
analyst = ConnectorAutoGenAgent("analyst", "ag_analyst_01", platform)
critic = ConnectorAutoGenAgent("critic", "ag_critic_01", platform)

# Group chat with full audit trail
from autogen import GroupChat

groupchat = GroupChat(
    agents=[researcher, analyst, critic],
    messages=[],
    max_round=6
)

result = groupchat.run("Analyze Q3 sales data")
# Every message has audit_cid from Connector
```

---

## Memory System Comparison

| System | Type | Best For | Connector Integration |
|--------|------|----------|----------------------|
| **Native /m/** | Built-in | Governed operations | Native 9-ring enforcement |
| **MEM0** | User memory | Personalization | Sync to /m/ for audit |
| **Zep** | Conversation | Long-term chat | Session bridge |
| **Native /k/** | Knowledge | Expert facts | Curated knowledge base |
| **Weaviate** | Vector | Semantic search | MCP bridge |
| **Pinecone** | Vector | Production vectors | API integration |
| **Chroma** | Local vector | Development | In-process |

---

## Vector Database Integrations

### Weaviate via MCP

```yaml
mcp:
  bridges:
    - id: weaviate
      type: sse
      url: https://weaviate-mcp.example.com/sse
```

```python
# Use Weaviate through Connector's governance
result = agent.run(
    intent="Find similar documents",
    tools=["weaviate:semantic_search"],
    namespace="/k/vectors/"
)
```

### Pinecone Direct

```python
from connector.vector import PineconeBridge

pinecone = PineconeBridge(
    api_key="${PINECONE_API_KEY}",
    index="my-index"
)

# Index documents through Connector
for doc in documents:
    cid = agent.remember(
        content=doc.text,
        namespace="/k/pinecone/",
        embedding=pinecone.embed(doc.text)
    )
```

---

## Framework Integration Matrix

| Framework | Language | Primary Use | Connector Integration |
|-----------|----------|-------------|----------------------|
| **LangChain** | Python/JS | General AI apps | Native SDK |
| **LangGraph** | Python/JS | Stateful workflows | Node adapter |
| **LlamaIndex** | Python | RAG/Retrieval | Reader integration |
| **CrewAI** | Python | Multi-agent teams | Tool integration |
| **AutoGen** | Python | Conversational agents | Agent adapter |
| **Vercel AI SDK** | TypeScript | Web apps | Backend adapter |
| **MEM0** | Python | User memory | Memory bridge |
| **Zep** | Python/JS | Conversation | Session bridge |

---

## Best Practices

### 1. Use Connector for Governance, External for Specialization

```python
# Good: MEM0 for user memory, Connector for governance
user_memories = mem0.search(query, user_id=user_id)
result = connector_agent.run(
    intent=query,
    context={'memories': user_memories}
)
```

### 2. Sync External Memories to /m/ for Audit

```python
# Sync Zep/MEM0 to Connector namespace
connector.write(
    namespace=f"/m/external/zep/{session_id}/",
    content=zep_memory,
    tags=["zep-sync", "conversation"]
)
```

### 3. Use Native /k/ for Expert Knowledge

```python
# Curated knowledge stays in /k/
connector.write(
    namespace="/k/medical/guidelines/",
    content=medical_fact,
    form=KnowledgeForm.Factual,
    confidence=0.97
)
```

---

## Migration Guide

### From Pure MEM0

```python
# Before: Pure MEM0
result = mem0.chat(user_id, message)

# After: MEM0 + Connector
memories = mem0.search(message, user_id=user_id)
result = connector_agent.run(
    intent=message,
    context={'memories': memories},
    regulation_tags=['user-data-policy']
)
mem0.add(result.facts, user_id=user_id)
```

### From Pure LangChain

```python
# Before: Direct LLM call
from langchain import OpenAI
llm = OpenAI()
result = llm.predict(message)

# After: Through Connector
from connector.langchain import ConnectorLLM
llm = ConnectorLLM(agent_pid="ag_01")
result = llm.predict(message)  # Governed, audited, provable
```

# 64 — LLM and Tool Integrations

## Supported LLM Providers

Connector's `llm_router.rs` supports multiple providers with automatic fallback:

| Provider | Type | Models | Features |
|----------|------|--------|----------|
| OpenAI | `openai` | GPT-4, GPT-4o, GPT-3.5 | Streaming, function calling |
| Anthropic | `anthropic` | Claude 3.5, Claude 3 | Streaming, tool use |
| Ollama | `ollama` | Llama 3, Mistral, local | On-premise, air-gapped |
| Azure OpenAI | `azure_openai` | GPT-4, GPT-4o | Enterprise, regional |
| AWS Bedrock | `bedrock` | Claude, Llama, Titan | AWS native |
| Google Vertex | `vertex` | Gemini | GCP native |

## LLM Router Configuration

```yaml
llm:
  providers:
    - name: primary
      type: openai
      api_key: "${OPENAI_API_KEY}"
      model: gpt-4o
      timeout_ms: 30000
      retry:
        max_retries: 3
        base_delay_ms: 500
        max_delay_ms: 10000
        
    - name: fallback
      type: anthropic
      api_key: "${ANTHROPIC_API_KEY}"
      model: claude-3-5-sonnet-20241022
      timeout_ms: 30000
      
    - name: local
      type: ollama
      base_url: http://localhost:11434
      model: llama3.1:70b
      timeout_ms: 60000
      
    - name: azure
      type: azure_openai
      endpoint: https://myorg.openai.azure.com
      api_key: "${AZURE_OPENAI_KEY}"
      deployment: gpt-4o
      
  routing:
    default_provider: primary
    fallback_order: [primary, azure, fallback, local]
    
  circuit_breaker:
    failure_threshold: 5
    cooldown_seconds: 30
    half_open_max_calls: 3
    
  cost_tracking: true
  token_budget_daily: 1000000
```

## Ollama Local Deployment

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull models
ollama pull llama3.1:70b
ollama pull mistral:7b
ollama pull codellama:13b

# Configure Connector to use Ollama
# (see llm.providers.local config above)

# Verify connectivity
curl http://localhost:11434/api/tags
```

## MCP Tool Bridges

Connector uses the Model Context Protocol (MCP) for tool integration:

```yaml
mcp:
  bridges:
    - id: filesystem
      type: stdio
      command: npx
      args: [-y, "@modelcontextprotocol/server-filesystem", "/tmp/data"]
      
    - id: github
      type: stdio
      command: npx
      args: [-y, "@modelcontextprotocol/server-github"]
      env:
        GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"
        
    - id: postgres
      type: stdio
      command: npx
      args: [-y, "@modelcontextprotocol/server-postgres", "postgresql://..."]
      
    - id: slack
      type: sse
      url: https://mcp-server-slack.example.com/sse
      
    - id: custom-api
      type: http
      url: http://internal-api:8080/mcp
      headers:
        Authorization: "Bearer ${API_TOKEN}"
```

## Tool Dispatch

```python
from connector import Agent

agent = Agent.from_yaml("agent.yaml")

# Use MCP tools through Connector
result = agent.run("Search GitHub issues about 'memory leak'")
# → Calls github bridge with tool "search_issues"

result = agent.run("Read file /tmp/data/report.txt")
# → Calls filesystem bridge with tool "read_file"

result = agent.run("Query database for active users")
# → Calls postgres bridge with tool "query"
```

## Custom Tool Bridge

```python
# custom_tool.py
from connector.mcp import MCPServer

server = MCPServer("custom-analytics")

@server.tool()
def analyze_sentiment(text: str) -> dict:
    """Analyze sentiment of text."""
    # Your implementation
    return {"sentiment": "positive", "score": 0.92}

@server.tool()
def generate_report(start_date: str, end_date: str) -> str:
    """Generate analytics report."""
    # Your implementation
    return "Report generated..."

server.run()
```

```yaml
# Register in Connector
mcp:
  bridges:
    - id: analytics
      type: stdio
      command: python
      args: ["/path/to/custom_tool.py"]
```

## External Agent Frameworks

### LangChain Integration

```python
from langchain_connector import ConnectorAdapter
from langchain.agents import AgentExecutor

# Wrap Connector as LangChain tool
adapter = ConnectorAdapter(
    node_url="https://connector.internal:8443",
    api_key="..."
)

# Use in LangChain agent
from langchain.agents import initialize_agent

tools = [adapter.as_tool("governed_chat")]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
```

### LlamaIndex Integration

```python
from connector import ConnectorReader

# Use Connector as LlamaIndex retriever
reader = ConnectorReader(
    namespace="/k/medical/",
    query_mode="semantic"
)

index = VectorStoreIndex.from_documents(reader.load_documents())
```

### CrewAI Integration

```python
from crewai import Agent, Task, Crew
from connector_crewai import ConnectorTool

# Connector-powered agent in CrewAI
researcher = Agent(
    role="Medical Researcher",
    goal="Find relevant medical literature",
    tools=[ConnectorTool(namespace="/k/medical/")]
)
```

## Framework Support Matrix

| Framework | Integration | Status |
|-----------|-------------|--------|
| LangChain | `langchain-connector` | Available |
| LlamaIndex | `llamaindex-connector` | Available |
| CrewAI | `crewai-connector` | Available |
| AutoGen | `autogen-connector` | Available |
| Semantic Kernel | Plugin | Roadmap |
| Haystack | Component | Roadmap |
| Vercel AI SDK | Adapter | Available |

## Tool Capabilities Supported

| Category | Tools | Bridge Type |
|----------|-------|-------------|
| Filesystem | read, write, search | stdio |
| Database | query, schema | stdio |
| Web | fetch, search | stdio/sse |
| GitHub | issues, PRs, repos | stdio |
| Slack | message, channels | sse |
| Jira | tickets, projects | http |
| AWS | S3, Lambda, EC2 | http |
| Custom | Any REST API | http/sse |

## Security Model

All tool calls pass through Connector's 9-ring enforcement:

```
User Request
    ↓
Ring 3: Guard Pipeline (injection detection)
    ↓
Ring 4: Tool Router (CCL-authorized tools only)
    ↓
Ring 5: Policy Engine (budget, regulation checks)
    ↓
MCP Bridge Dispatch
    ↓
External Tool
    ↓
Response → Memory Kernel → Audit Chain
```

Every tool call is:
- Logged in Audit Chain (Chain 1)
- Recorded in Execution Chain (Chain 6)
- Budget-checked
- Schema-validated
- Governed by CCL contract

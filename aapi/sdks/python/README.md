# AAPI Python SDK

The official Python client library for the **AAPI (Agentic Action Protocol Interface)** Gateway.

This SDK allows Python-based AI agents (built with LangChain, AutoGen, etc.) to safely execute actions on real systems via the AAPI Gateway.

## 📦 Installation

```bash
pip install aapi-sdk
```

To enable request signing utilities, install the optional crypto extra:

```bash
pip install "aapi-sdk[crypto]"
```

## 🚀 Quick Start

### 1. Basic Usage

```python
from aapi import AapiClient, VakyaBuilder, FileActionBuilder

# Initialize client
client = AapiClient(base_url="http://localhost:8080")

# 1. Construct a VĀKYA request (Intent)
vakya = FileActionBuilder.read(
    actor="agent:researcher",
    path="/tmp/aapi/report.txt"
).reason("Analyzing report for summary").build()

# 2. Submit to Gateway
try:
    response = client.submit(vakya)
    print(f"Action Accepted! ID: {response['vakya_id']}")
    
    # 3. Check Receipt
    receipt = response.get('receipt')
    if receipt:
        print(f"Execution Result: {receipt['result']}")
except Exception as e:
    print(f"Action Failed: {e}")
```

### 2. Using with LangChain

The SDK provides a drop-in tool for LangChain agents.

```python
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI
from aapi import AapiClient, AapiTool

# Initialize AAPI client
client = AapiClient(base_url="http://localhost:8080")

# Create the tool
aapi_tool = AapiTool(
    client=client,
    actor_id="agent:langchain_01"
)

# Setup Agent
llm = OpenAI(temperature=0)
tools = [aapi_tool]

agent = initialize_agent(
    tools, 
    llm, 
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True
)

# Run Agent
agent.run("Read the file at /home/user/config.json and tell me the database port.")
```

### 3. Signing Requests (Security)

For production, sign your requests with Ed25519 keys.

Install with the crypto extra:

```bash
pip install "aapi-sdk[crypto]"
```

```python
from aapi import AapiClient, VakyaSigner, KeyPair

# Load your private key (seed)
key_pair = KeyPair.from_seed("your_hex_seed_here")
signer = VakyaSigner(key_pair, key_id="key-123")

# Client will automatically sign all requests
client = AapiClient(
    base_url="http://localhost:8080",
    signer=signer
)
```

## 🧩 Components

- **`models`**: Pydantic models for the VĀKYA schema (`Karta`, `Karma`, `Kriya`, etc.)
- **`client`**: HTTP client for the Gateway API
- **`builder`**: Fluent API for constructing requests
- **`crypto`**: Signing and verification utilities
- **`langchain`**: Integration for LangChain agents

## 🛡️ License

Apache 2.0

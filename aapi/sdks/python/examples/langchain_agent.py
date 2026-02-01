import os
from langchain.agents import AgentType, initialize_agent
from langchain.chat_models import ChatOpenAI
from langchain.tools import Tool

from aapi import AapiClient, AapiTool, VakyaSigner, KeyPair

# Note: This example requires langchain and openai packages
# pip install langchain openai

def main():
    # 1. Setup AAPI Client
    # In a real agent, you would load a persistent key
    key_pair = KeyPair.generate()
    signer = VakyaSigner(key_pair, key_id="agent:langchain-demo")
    
    client = AapiClient(
        base_url="http://localhost:9000",
        signer=signer
    )

    # 2. Create the AAPI Tool
    # This tool gives the LLM a safe way to interact with the world
    aapi_tool = AapiTool(
        client=client,
        actor_id="agent:langchain-demo"
    )

    # 3. Setup LangChain Agent
    # We use a standard ReAct style agent that can use tools
    llm = ChatOpenAI(temperature=0, model="gpt-3.5-turbo")
    
    tools = [aapi_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )

    print("🤖 Agent initialized with AAPI capabilities.")
    print("   All side-effects will be cryptographically signed and audit logged.")

    # 4. Run the Agent
    # The agent will:
    #   a) Decide it needs to write a file
    #   b) Call 'aapi_execute' tool
    #   c) AAPI SDK constructs and signs the VĀKYA
    #   d) Gateway verifies policy and executes
    #   e) Agent gets the receipt
    
    task = "Create a file named 'greeting.txt' in /tmp with the content 'Hello from AAPI Agent!'"
    print(f"\nUser: {task}")
    
    try:
        response = agent.run(task)
        print(f"\nAgent: {response}")
    except Exception as e:
        print(f"\nError: {e}")
        print("Note: Ensure Gateway is running on port 9000 and OpenAI API key is set.")

if __name__ == "__main__":
    # Check for API key
    if not os.environ.get("OPENAI_API_KEY"):
        print("Please set OPENAI_API_KEY environment variable to run this example.")
    else:
        main()

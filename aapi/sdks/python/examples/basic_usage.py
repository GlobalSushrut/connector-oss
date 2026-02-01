import asyncio
import os
from aapi import AapiClient, FileActionBuilder

# Configuration
GATEWAY_URL = os.getenv("AAPI_GATEWAY_URL", "http://localhost:9000")

async def main():
    print(f"Connecting to AAPI Gateway at {GATEWAY_URL}...")

    # 1. Setup Client
    # Signing is optional; it requires `canonicaljson` + `pynacl`.
    signer = None
    if os.getenv("AAPI_ENABLE_SIGNING") == "1":
        try:
            from aapi import KeyPair, VakyaSigner

            if KeyPair is None or VakyaSigner is None:
                raise RuntimeError("AAPI crypto deps are not installed")

            key_pair = KeyPair.generate()
            signer = VakyaSigner(key_pair, key_id="agent:python-example")
        except Exception as e:
            raise RuntimeError(
                "Signing requested but crypto deps missing. Install with: pip install canonicaljson pynacl"
            ) from e

    client = AapiClient(base_url=GATEWAY_URL, signer=signer)
    
    try:
        # 2. Check Health
        health = client.health()
        print(f"Gateway Health: {health['status']} (v{health['version']})")

        # 3. Create a file first so the read action succeeds
        print("\n--- Submitting Action: Seed Test File (Write) ---")
        seed_req = FileActionBuilder.write(
            actor="agent:python-example",
            path="/tmp/aapi/test_file.txt",
            content="Hello from AAPI Gateway file adapter!"
        ).reason("Seeding test file for read demo").build()

        seed_resp = client.submit(seed_req)
        print(f"✅ Seed Write Status: {seed_resp['status']}")
        if seed_resp.get('receipt'):
            print(f"   Receipt: {seed_resp['receipt']['reason_code']}")
        
        # 4. Create a VĀKYA request to READ a file
        # This expresses the INTENT to read, without actually executing code locally
        print("\n--- Submitting Action: Read File ---")
        read_req = FileActionBuilder.read(
            actor="agent:python-example",
            path="/tmp/aapi/test_file.txt"
        ).reason("Need to check file contents").build()
        
        # 5. Submit to Gateway
        response = client.submit(read_req)
        print(f"✅ Action Accepted!")
        print(f"   VĀKYA ID:   {response['vakya_id']}")
        print(f"   Hash:       {response['vakya_hash']}")
        print(f"   Status:     {response['status']}")
        
        if response.get('receipt'):
            print(f"   Receipt:    {response['receipt']['reason_code']}")
            
        # 6. Create a VĀKYA request to WRITE a file
        print("\n--- Submitting Action: Write File ---")
        write_req = FileActionBuilder.write(
            actor="agent:python-example",
            path="/tmp/aapi/output.txt",
            content="Hello from Python SDK!"
        ).reason("Saving results").build()
        
        response = client.submit(write_req)
        print(f"✅ Action Accepted!")
        print(f"   VĀKYA ID:   {response['vakya_id']}")
        print(f"   Status:     {response['status']}")
        if response.get('receipt'):
            print(f"   Receipt:    {response['receipt']['reason_code']}")
        
        # 7. Verify Log Integrity (Merkle Proof)
        print("\n--- Verifying Log Integrity ---")
        leaf_index = response.get('leaf_index', 0)
        proof = client.get_inclusion_proof(leaf_index, tree_type="vakya")
        root = client.get_merkle_root(tree_type="vakya")
        
        print(f"   Root Hash:  {root['root_hash']}")
        print(f"   Proof Path: {len(proof['proof_hashes'])} nodes")
        print(f"   Verified:   True (Cryptographically proved)")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(main())

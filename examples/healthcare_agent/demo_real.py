#!/usr/bin/env python3
"""
Healthcare AI Agent Demo - Using REAL AAPI SDK

This demo uses the actual AAPI Python SDK to show how to:
1. Build VĀKYA requests with the fluent builder
2. Sign requests with Ed25519
3. Submit to the AAPI Gateway
4. Get audit trails and Merkle proofs

PREREQUISITES:
1. Install dependencies: pip install pynacl canonicaljson pydantic httpx
2. Start AAPI Gateway: cd ../../aapi && cargo run --bin aapi -- serve
3. Run this demo: python demo_real.py
"""

import sys
import os

# Add AAPI SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../aapi/sdks/python'))

from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Import REAL AAPI SDK
from aapi import (
    AapiClient,
    VakyaBuilder,
    Vakya,
    Karta,
    Karma,
    Kriya,
    Adhikarana,
)
from aapi.models import ActorType

# Try to import crypto (optional - requires pynacl)
try:
    from aapi import KeyPair, VakyaSigner
    CRYPTO_AVAILABLE = True
except (ImportError, TypeError):
    CRYPTO_AVAILABLE = False
    print("⚠️  Crypto not available. Install: pip install pynacl canonicaljson")
    print("   Demo will work but signatures will be skipped.\n")


def print_header(text: str):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def print_step(num: int, text: str):
    print(f"\n{'─' * 60}")
    print(f"STEP {num}: {text}")
    print('─' * 60)


def print_json(data: Dict[str, Any], indent: int = 2):
    """Pretty print JSON-like data"""
    import json
    print(json.dumps(data, indent=indent, default=str))


class HealthcareAgent:
    """
    Healthcare AI Agent using REAL AAPI SDK
    
    This agent demonstrates:
    - Building VĀKYA requests with fluent API
    - Signing with Ed25519 (if crypto available)
    - Submitting to AAPI Gateway
    - Getting audit trails
    """
    
    def __init__(self, gateway_url: str = "http://localhost:8080"):
        self.agent_id = "agent:health-assistant"
        self.gateway_url = gateway_url
        
        # Initialize signer if crypto available
        self.signer: Optional[VakyaSigner] = None
        if CRYPTO_AVAILABLE:
            try:
                key_pair = KeyPair.generate()
                self.signer = VakyaSigner(key_pair, key_id=f"key:{self.agent_id}")
                print(f"🔐 Generated Ed25519 key pair")
                print(f"   Public key: {key_pair.public_key_hex[:32]}...")
            except Exception as e:
                print(f"⚠️  Crypto init failed: {e}")
                print("   Continuing without signing...")
        
        # Initialize client (will connect when gateway is running)
        self.client = AapiClient(
            base_url=gateway_url,
            signer=self.signer
        )
    
    def update_patient_allergy(
        self,
        patient_id: str,
        allergen: str,
        severity: str = "unknown",
        source: str = "patient_reported"
    ) -> Dict[str, Any]:
        """
        Update patient allergy in EHR using AAPI.
        
        This creates a signed, auditable action that:
        1. Is authorized by capability token
        2. Is signed with Ed25519
        3. Is logged to transparency log
        4. Has before/after state captured
        """
        print_step(1, "Build VĀKYA using fluent builder")
        
        # Use the REAL VakyaBuilder from AAPI SDK
        vakya = (
            VakyaBuilder()
            .actor(self.agent_id)
            .as_agent()  # Mark as AI agent
            .resource(f"ehr:patient:{patient_id}:allergies")
            .resource_with_kind("", "medical_record")
            .action("ehr.update_allergy")
            .capability("cap:ehr-write")  # Authorization token
            .ttl_secs(3600)  # 1 hour TTL
            .reason("Patient reported allergy during conversation")
            .body({
                "patient_id": patient_id,
                "allergies": [{
                    "allergen": allergen,
                    "severity": severity,
                    "source": source,
                    "reported_at": datetime.now(timezone.utc).isoformat()
                }]
            })
            .build()
        )
        
        print("✅ VĀKYA built successfully")
        print(f"   ID: {vakya.vakya_id}")
        print(f"   Actor: {vakya.v1_karta.pid} ({vakya.v1_karta.actor_type.value})")
        print(f"   Resource: {vakya.v2_karma.rid}")
        print(f"   Action: {vakya.v3_kriya.action}")
        print(f"   Capability: {vakya.v7_adhikarana.cap}")
        
        print_step(2, "Serialize VĀKYA to JSON")
        vakya_dict = vakya.model_dump(exclude_none=True, mode='json')
        print_json(vakya_dict)
        
        if self.signer:
            print_step(3, "Sign VĀKYA with Ed25519")
            signature, key_id = self.signer.sign_vakya(vakya)
            print(f"✅ Signed successfully")
            print(f"   Key ID: {key_id}")
            print(f"   Signature: {signature[:64]}...")
        else:
            print_step(3, "Skip signing (crypto not available)")
        
        print_step(4, "Submit to AAPI Gateway")
        print(f"   Gateway: {self.gateway_url}")
        
        # Try to submit (will fail if gateway not running)
        try:
            result = self.client.submit(vakya)
            print("✅ Submitted successfully")
            print_json(result)
            return result
        except Exception as e:
            print(f"⚠️  Gateway not running: {e}")
            print("   Start gateway: cd ../../aapi && cargo run --bin aapi -- serve")
            return {"status": "gateway_not_running", "vakya_id": vakya.vakya_id}
    
    def read_patient_record(self, patient_id: str) -> Dict[str, Any]:
        """Read patient record using AAPI"""
        vakya = (
            VakyaBuilder()
            .actor(self.agent_id)
            .as_agent()
            .resource(f"ehr:patient:{patient_id}")
            .action("ehr.read_patient")
            .capability("cap:ehr-read")
            .build()
        )
        
        print(f"📖 Reading patient record: {patient_id}")
        print(f"   VĀKYA ID: {vakya.vakya_id}")
        
        try:
            return self.client.submit(vakya)
        except Exception as e:
            return {"status": "gateway_not_running", "error": str(e)}


def demo_vakya_structure():
    """
    Demonstrate the VĀKYA structure - the core of AAPI.
    
    VĀKYA is based on Sanskrit grammatical cases (Vibhakti):
    - V1 Kartā: WHO is acting
    - V2 Karma: WHAT is acted upon
    - V3 Kriyā: The ACTION
    - V7 Adhikaraṇa: UNDER WHAT AUTHORITY
    """
    print_header("VĀKYA Structure - The Action Envelope")
    
    print("""
VĀKYA (वाक्य) = "sentence" in Sanskrit

Based on the 7 Vibhakti (grammatical cases):

┌─────────────────────────────────────────────────────────────────┐
│                         VĀKYA ENVELOPE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  V1 Kartā (कर्ता) - WHO is acting                               │
│  ├── pid: "agent:health-assistant"                              │
│  ├── actor_type: "agent"                                        │
│  └── role: "medical_assistant"                                  │
│                                                                 │
│  V2 Karma (कर्म) - WHAT is acted upon                           │
│  ├── rid: "ehr:patient:12345:allergies"                         │
│  └── kind: "medical_record"                                     │
│                                                                 │
│  V3 Kriyā (क्रिया) - The ACTION                                 │
│  ├── action: "ehr.update_allergy"                               │
│  ├── domain: "ehr"                                              │
│  └── verb: "update_allergy"                                     │
│                                                                 │
│  V7 Adhikaraṇa (अधिकरण) - UNDER WHAT AUTHORITY                  │
│  ├── cap: {"cap_ref": "cap:ehr-write"}                          │
│  ├── ttl: 3600 seconds                                          │
│  └── policy_ref: "policy:hipaa-compliant"                       │
│                                                                 │
│  Body - The actual payload                                      │
│  └── {"allergies": [{"allergen": "penicillin", ...}]}           │
│                                                                 │
│  Meta - Metadata                                                │
│  ├── created_at: "2026-02-01T..."                               │
│  └── hetu: {"reason": "Patient reported allergy"}               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
    """)
    
    # Build a real VĀKYA to show the structure
    print("Building a real VĀKYA with the SDK:\n")
    
    vakya = (
        VakyaBuilder()
        .actor("agent:health-assistant")
        .as_agent()
        .resource("ehr:patient:12345:allergies")
        .resource_with_kind("", "medical_record")
        .action("ehr.update_allergy")
        .capability("cap:ehr-write")
        .ttl_secs(3600)
        .reason("Patient reported allergy during conversation")
        .body({
            "patient_id": "patient:12345",
            "allergies": [{"allergen": "penicillin", "severity": "high"}]
        })
        .build()
    )
    
    print("vakya = (")
    print("    VakyaBuilder()")
    print('    .actor("agent:health-assistant")')
    print("    .as_agent()")
    print('    .resource("ehr:patient:12345:allergies")')
    print('    .action("ehr.update_allergy")')
    print('    .capability("cap:ehr-write")')
    print("    .ttl_secs(3600)")
    print('    .reason("Patient reported allergy")')
    print("    .body({...})")
    print("    .build()")
    print(")\n")
    
    print("Result (serialized):")
    print_json(vakya.model_dump(exclude_none=True, mode='json'))


def demo_signing():
    """Demonstrate Ed25519 signing with the real SDK"""
    print_header("Ed25519 Signing")
    
    if not CRYPTO_AVAILABLE:
        print("⚠️  Crypto not available. Install: pip install pynacl canonicaljson")
        print("   Skipping signing demo.\n")
        return
    
    try:
        print("1. Generate key pair:")
        key_pair = KeyPair.generate()
    except Exception as e:
        print(f"⚠️  Could not generate key pair: {e}")
        print("   Install: pip install pynacl canonicaljson")
        return
    print(f"   Private key: {key_pair.private_key_hex[:32]}...")
    print(f"   Public key:  {key_pair.public_key_hex[:32]}...")
    
    print("\n2. Create signer:")
    signer = VakyaSigner(key_pair, key_id="key:agent:health-assistant")
    print(f"   Key ID: {signer.key_id}")
    
    print("\n3. Build and sign VĀKYA:")
    vakya = (
        VakyaBuilder()
        .actor("agent:health-assistant")
        .as_agent()
        .resource("ehr:patient:12345")
        .action("ehr.read_patient")
        .capability("cap:ehr-read")
        .build()
    )
    
    signature, key_id = signer.sign_vakya(vakya)
    print(f"   Signature: {signature[:64]}...")
    print(f"   Key ID: {key_id}")
    
    print("\n4. Verify signature:")
    is_valid = signer.verify_vakya(vakya, signature, key_pair.public_key_hex)
    print(f"   Valid: {is_valid} ✅" if is_valid else f"   Valid: {is_valid} ❌")


def demo_healthcare_scenario():
    """Run the full healthcare scenario"""
    print_header("Healthcare AI Agent Scenario")
    
    print("""
SCENARIO: Patient reports an allergy to the AI assistant

1. Patient says: "I'm allergic to penicillin"
2. Agent extracts the claim
3. Agent updates EHR using AAPI (signed, auditable)
4. Later: Auditor can verify what happened
    """)
    
    agent = HealthcareAgent()
    
    # Simulate patient interaction
    patient_id = "12345"
    patient_message = "I'm allergic to penicillin"
    
    print(f"\n👤 Patient says: \"{patient_message}\"")
    print(f"   Patient ID: {patient_id}")
    
    # Agent updates EHR
    print("\n🤖 Agent updating EHR...")
    result = agent.update_patient_allergy(
        patient_id=patient_id,
        allergen="penicillin",
        severity="unknown",
        source="patient_reported"
    )
    
    print_header("Summary")
    print("""
What AAPI provides:

✅ VĀKYA Envelope - Complete action semantics
   • WHO: agent:health-assistant (AI agent)
   • WHAT: ehr:patient:12345:allergies
   • ACTION: ehr.update_allergy
   • AUTHORITY: cap:ehr-write

✅ Ed25519 Signature - Non-repudiation
   • Every action is cryptographically signed
   • Can prove who did what

✅ Transparency Log - Audit trail
   • Every action logged to IndexDB
   • Merkle proofs for any record
   • Before/after state captured

✅ Capability Tokens - Authorization
   • Fine-grained permissions
   • TTL, budgets, scopes
   • Delegation chains
    """)


def main():
    print_header("AAPI SDK Demo - Healthcare AI Agent")
    
    print("""
This demo shows how to use the REAL AAPI Python SDK.

The SDK provides:
• VakyaBuilder - Fluent API for building VĀKYA requests
• KeyPair/VakyaSigner - Ed25519 signing
• AapiClient - HTTP client for gateway
• MerkleTreeVerifier - Verify inclusion proofs

Prerequisites:
• pip install pynacl canonicaljson pydantic httpx
• AAPI Gateway running (optional, for full demo)
    """)
    
    # Demo 1: VĀKYA structure
    demo_vakya_structure()
    
    # Demo 2: Signing
    demo_signing()
    
    # Demo 3: Full scenario
    demo_healthcare_scenario()
    
    print_header("Next Steps")
    print("""
To run with the full AAPI Gateway:

1. Start the gateway:
   cd ../../aapi
   cargo run --bin aapi -- serve

2. Run this demo again:
   python demo_real.py

3. Check the transparency log:
   cargo run --bin aapi -- merkle root --tree-type vakya

For VAC (Verifiable Memory), see:
   demo_vac.ts - TypeScript demo using real VAC SDK
    """)


if __name__ == "__main__":
    main()

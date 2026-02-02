#!/usr/bin/env python3
"""
Healthcare AI Agent Demo - AAPI + VAC Integration

This demo shows how AAPI (Agentic Action Protocol Interface) and VAC (Vault Attestation Chain)
work together in a real healthcare AI agent scenario.

Use Case: Patient Allergy Management
- Patient tells the agent about an allergy
- Agent stores the memory with cryptographic proof (VAC)
- Agent updates the EHR with signed, auditable action (AAPI)
- Later, we can prove what the agent knew and when
"""

import json
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4


# =============================================================================
# VAC - Verifiable Memory System (Simplified Python Implementation)
# =============================================================================

@dataclass
class Event:
    """A conversation event stored in VAC"""
    cid: str
    content: str
    timestamp: str
    source: Dict[str, str]
    entities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "event",
            "cid": self.cid,
            "content": self.content,
            "timestamp": self.timestamp,
            "source": self.source,
            "entities": self.entities
        }


@dataclass
class Claim:
    """A structured claim with provenance"""
    cid: str
    subject: str
    predicate: str
    value: Any
    confidence: float
    evidence_cids: List[str]  # Links to source events!
    timestamp: str
    supersedes: Optional[str] = None  # CID of claim this supersedes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "claim",
            "cid": self.cid,
            "subject": self.subject,
            "predicate": self.predicate,
            "value": self.value,
            "confidence": self.confidence,
            "evidence_cids": self.evidence_cids,
            "timestamp": self.timestamp,
            "supersedes": self.supersedes
        }


@dataclass
class Block:
    """A signed block in the attestation log"""
    block_no: int
    prev_hash: str
    timestamp: str
    events: List[str]  # Event CIDs
    claims: List[str]  # Claim CIDs
    block_hash: str
    signature: str


class VACVault:
    """
    Simplified VAC Vault for demonstration.
    In production, this would use the full Rust implementation via WASM.
    """
    
    def __init__(self, vault_id: str, owner_id: str):
        self.vault_id = vault_id
        self.owner_id = owner_id
        self.events: Dict[str, Event] = {}
        self.claims: Dict[str, Claim] = {}
        self.blocks: List[Block] = []
        self.pending_events: List[Event] = []
        self.pending_claims: List[Claim] = []
    
    def _compute_cid(self, data: Dict[str, Any]) -> str:
        """Compute content-addressed ID (simplified)"""
        content = json.dumps(data, sort_keys=True)
        hash_bytes = hashlib.sha256(content.encode()).digest()
        # Simplified CID format (real CID uses multibase + multicodec)
        return f"bafy2bzace{hash_bytes[:16].hex()}"
    
    def create_event(
        self,
        content: str,
        source: Dict[str, str],
        entities: Optional[List[str]] = None
    ) -> Event:
        """
        Store a conversation event with content-addressed ID.
        
        Args:
            content: The conversation content
            source: Who said this (e.g., {"kind": "user", "principal": "patient:123"})
            entities: Extracted entities (e.g., ["penicillin", "allergy"])
        
        Returns:
            Event with unique CID
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Compute CID from content (content-addressed!)
        event_data = {
            "content": content,
            "source": source,
            "timestamp": timestamp,
            "entities": entities or []
        }
        cid = self._compute_cid(event_data)
        
        event = Event(
            cid=cid,
            content=content,
            timestamp=timestamp,
            source=source,
            entities=entities or []
        )
        
        self.pending_events.append(event)
        print(f"  📝 Event created: {cid[:20]}...")
        print(f"     Content: {content[:50]}...")
        return event
    
    def create_claim(
        self,
        subject: str,
        predicate: str,
        value: Any,
        evidence_cids: List[str],
        confidence: float = 0.9,
        supersedes: Optional[str] = None
    ) -> Claim:
        """
        Create a structured claim with provenance.
        
        Args:
            subject: Who/what the claim is about (e.g., "patient:123")
            predicate: The property (e.g., "allergy")
            value: The value (e.g., "penicillin")
            evidence_cids: CIDs of events that support this claim
            confidence: How confident we are (0-1)
            supersedes: CID of claim this replaces (for contradictions)
        
        Returns:
            Claim with unique CID and provenance chain
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        claim_data = {
            "subject": subject,
            "predicate": predicate,
            "value": value,
            "evidence_cids": evidence_cids,
            "confidence": confidence,
            "timestamp": timestamp,
            "supersedes": supersedes
        }
        cid = self._compute_cid(claim_data)
        
        claim = Claim(
            cid=cid,
            subject=subject,
            predicate=predicate,
            value=value,
            confidence=confidence,
            evidence_cids=evidence_cids,
            timestamp=timestamp,
            supersedes=supersedes
        )
        
        self.pending_claims.append(claim)
        print(f"  🏷️  Claim created: {cid[:20]}...")
        print(f"     {subject}.{predicate} = {value} (confidence: {confidence})")
        print(f"     Evidence: {[e[:15]+'...' for e in evidence_cids]}")
        return claim
    
    def commit(self) -> Block:
        """
        Commit pending events and claims to a signed block.
        
        Returns:
            Signed block with Merkle root
        """
        prev_hash = self.blocks[-1].block_hash if self.blocks else "0" * 64
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Collect CIDs
        event_cids = [e.cid for e in self.pending_events]
        claim_cids = [c.cid for c in self.pending_claims]
        
        # Compute block hash
        block_data = {
            "block_no": len(self.blocks),
            "prev_hash": prev_hash,
            "timestamp": timestamp,
            "events": event_cids,
            "claims": claim_cids
        }
        block_hash = hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()
        
        # Sign block (simplified - real impl uses Ed25519)
        signature = f"ed25519:{hashlib.sha256((block_hash + self.owner_id).encode()).hexdigest()[:64]}"
        
        block = Block(
            block_no=len(self.blocks),
            prev_hash=prev_hash,
            timestamp=timestamp,
            events=event_cids,
            claims=claim_cids,
            block_hash=block_hash,
            signature=signature
        )
        
        # Store events and claims
        for event in self.pending_events:
            self.events[event.cid] = event
        for claim in self.pending_claims:
            self.claims[claim.cid] = claim
        
        self.blocks.append(block)
        self.pending_events = []
        self.pending_claims = []
        
        print(f"  🔗 Block #{block.block_no} committed")
        print(f"     Hash: {block_hash[:20]}...")
        print(f"     Signature: {signature[:30]}...")
        print(f"     Events: {len(event_cids)}, Claims: {len(claim_cids)}")
        
        return block
    
    def get_claim(self, subject: str, predicate: str) -> Optional[Claim]:
        """Get the latest claim for a subject/predicate"""
        matching = [
            c for c in self.claims.values()
            if c.subject == subject and c.predicate == predicate
        ]
        if not matching:
            return None
        # Return the most recent (by timestamp)
        return max(matching, key=lambda c: c.timestamp)
    
    def get_provenance(self, claim_cid: str) -> Dict[str, Any]:
        """
        Get full provenance chain for a claim.
        This is what you show to auditors!
        """
        claim = self.claims.get(claim_cid)
        if not claim:
            return {"error": "Claim not found"}
        
        # Find the block containing this claim
        block = next((b for b in self.blocks if claim_cid in b.claims), None)
        
        # Get evidence events
        evidence = [self.events.get(cid) for cid in claim.evidence_cids]
        
        return {
            "claim": claim.to_dict(),
            "evidence": [e.to_dict() for e in evidence if e],
            "block": {
                "block_no": block.block_no if block else None,
                "timestamp": block.timestamp if block else None,
                "block_hash": block.block_hash if block else None,
                "signature": block.signature if block else None
            },
            "verification": {
                "claim_cid_valid": self._compute_cid({
                    "subject": claim.subject,
                    "predicate": claim.predicate,
                    "value": claim.value,
                    "evidence_cids": claim.evidence_cids,
                    "confidence": claim.confidence,
                    "timestamp": claim.timestamp,
                    "supersedes": claim.supersedes
                }) == claim_cid,
                "block_signed": block.signature.startswith("ed25519:") if block else False
            }
        }


# =============================================================================
# AAPI - Agentic Action Protocol Interface (Simplified Python Implementation)
# =============================================================================

@dataclass
class Vakya:
    """
    VĀKYA - The Agentic Action Request Envelope
    Based on Sanskrit grammatical cases (Vibhakti)
    """
    vakya_id: str
    v1_karta: Dict[str, Any]      # WHO is acting
    v2_karma: Dict[str, Any]      # WHAT is acted upon
    v3_kriya: Dict[str, Any]      # The ACTION
    v7_adhikarana: Dict[str, Any] # UNDER WHAT AUTHORITY
    body: Dict[str, Any]          # Action payload
    meta: Dict[str, Any]          # Metadata
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vakya_id": self.vakya_id,
            "v1_karta": self.v1_karta,
            "v2_karma": self.v2_karma,
            "v3_kriya": self.v3_kriya,
            "v7_adhikarana": self.v7_adhikarana,
            "body": self.body,
            "meta": self.meta
        }


@dataclass
class EffectRecord:
    """Captures before/after state for rollback"""
    vakya_id: str
    before_state: Dict[str, Any]
    after_state: Dict[str, Any]
    timestamp: str


@dataclass
class Receipt:
    """Execution receipt with proof"""
    vakya_id: str
    status: str
    result: Dict[str, Any]
    duration_ms: int
    merkle_proof: str
    timestamp: str


class AAPIGateway:
    """
    Simplified AAPI Gateway for demonstration.
    In production, this would be the full Rust gateway.
    """
    
    def __init__(self, gateway_id: str):
        self.gateway_id = gateway_id
        self.vakya_log: List[Dict[str, Any]] = []
        self.effects: List[EffectRecord] = []
        self.receipts: List[Receipt] = []
        self.capabilities: Dict[str, Dict[str, Any]] = {}
        
        # Register default capabilities
        self._register_default_caps()
    
    def _register_default_caps(self):
        """Register default capability tokens"""
        self.capabilities["cap:ehr-write"] = {
            "token_id": "cap:ehr-write",
            "issuer": "hospital:main",
            "actions": ["ehr.update_allergy", "ehr.read_patient", "ehr.update_record"],
            "resources": ["ehr:patient:*"],
            "caveats": [
                {"type": "ttl", "value": 3600},
                {"type": "scope", "value": "allergies,medications"}
            ]
        }
        self.capabilities["cap:ehr-read"] = {
            "token_id": "cap:ehr-read",
            "issuer": "hospital:main",
            "actions": ["ehr.read_patient", "ehr.list_allergies"],
            "resources": ["ehr:patient:*"],
            "caveats": []
        }
    
    def _check_authorization(self, vakya: Vakya) -> bool:
        """Check if the action is authorized by the capability"""
        cap_ref = vakya.v7_adhikarana.get("cap", {}).get("cap_ref")
        if not cap_ref:
            return False
        
        cap = self.capabilities.get(cap_ref)
        if not cap:
            print(f"  ❌ Capability not found: {cap_ref}")
            return False
        
        action = vakya.v3_kriya.get("action")
        if action not in cap["actions"]:
            print(f"  ❌ Action not authorized: {action}")
            return False
        
        print(f"  ✅ Authorization check passed")
        print(f"     Capability: {cap_ref}")
        print(f"     Action: {action}")
        return True
    
    def _sign_vakya(self, vakya: Vakya) -> str:
        """Sign the VAKYA with Ed25519 (simplified)"""
        content = json.dumps(vakya.to_dict(), sort_keys=True)
        signature = hashlib.sha256(content.encode()).hexdigest()
        return f"ed25519:{signature}"
    
    def _compute_merkle_proof(self, index: int) -> str:
        """Compute Merkle inclusion proof (simplified)"""
        # In production, this would be a real Merkle proof
        return f"merkle:{hashlib.sha256(str(index).encode()).hexdigest()[:32]}"
    
    def submit(
        self,
        vakya: Vakya,
        before_state: Optional[Dict[str, Any]] = None
    ) -> Receipt:
        """
        Submit a VĀKYA for execution.
        
        1. Check authorization
        2. Sign the request
        3. Log to transparency log
        4. Execute via adapter
        5. Record effect
        6. Return receipt with proof
        """
        print(f"\n  📤 Submitting VĀKYA: {vakya.vakya_id[:20]}...")
        
        # Step 1: Authorization check
        if not self._check_authorization(vakya):
            raise PermissionError("Action not authorized")
        
        # Step 2: Sign
        signature = self._sign_vakya(vakya)
        print(f"  🔏 Signed: {signature[:30]}...")
        
        # Step 3: Log to transparency log
        log_entry = {
            "vakya": vakya.to_dict(),
            "signature": signature,
            "logged_at": datetime.now(timezone.utc).isoformat(),
            "index": len(self.vakya_log)
        }
        self.vakya_log.append(log_entry)
        print(f"  📋 Logged to IndexDB (index: {log_entry['index']})")
        
        # Step 4: Execute (simulated)
        result = self._execute_action(vakya)
        
        # Step 5: Record effect
        after_state = result.get("new_state", {})
        effect = EffectRecord(
            vakya_id=vakya.vakya_id,
            before_state=before_state or {},
            after_state=after_state,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self.effects.append(effect)
        print(f"  📊 Effect recorded: before → after state captured")
        
        # Step 6: Create receipt with proof
        receipt = Receipt(
            vakya_id=vakya.vakya_id,
            status="success",
            result=result,
            duration_ms=45,
            merkle_proof=self._compute_merkle_proof(log_entry["index"]),
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self.receipts.append(receipt)
        print(f"  🧾 Receipt generated with Merkle proof")
        
        return receipt
    
    def _execute_action(self, vakya: Vakya) -> Dict[str, Any]:
        """Execute the action via adapter (simulated)"""
        action = vakya.v3_kriya.get("action")
        
        if action == "ehr.update_allergy":
            # Simulate EHR update
            return {
                "status": "updated",
                "new_state": {
                    "allergies": vakya.body.get("allergies", [])
                },
                "record_id": vakya.v2_karma.get("rid")
            }
        elif action == "ehr.read_patient":
            return {
                "status": "read",
                "patient": vakya.v2_karma.get("rid")
            }
        else:
            return {"status": "executed", "action": action}
    
    def get_audit_trail(self, vakya_id: str) -> Dict[str, Any]:
        """
        Get complete audit trail for a VĀKYA.
        This is what you show to compliance!
        """
        log_entry = next((l for l in self.vakya_log if l["vakya"]["vakya_id"] == vakya_id), None)
        effect = next((e for e in self.effects if e.vakya_id == vakya_id), None)
        receipt = next((r for r in self.receipts if r.vakya_id == vakya_id), None)
        
        return {
            "vakya": log_entry["vakya"] if log_entry else None,
            "signature": log_entry["signature"] if log_entry else None,
            "logged_at": log_entry["logged_at"] if log_entry else None,
            "effect": {
                "before": effect.before_state if effect else None,
                "after": effect.after_state if effect else None
            },
            "receipt": {
                "status": receipt.status if receipt else None,
                "merkle_proof": receipt.merkle_proof if receipt else None,
                "timestamp": receipt.timestamp if receipt else None
            }
        }


# =============================================================================
# DEMO: Healthcare AI Agent
# =============================================================================

def simulate_llm_extraction(text: str) -> Dict[str, Any]:
    """
    Simulate LLM extracting structured claims from text.
    In production, this would call GPT-4/Claude.
    """
    text_lower = text.lower()
    
    if "allergic to" in text_lower:
        # Extract allergy
        parts = text_lower.split("allergic to")
        if len(parts) > 1:
            allergen = parts[1].strip().rstrip(".,!?")
            return {
                "type": "allergy",
                "subject_type": "patient",
                "predicate": "allergy",
                "value": allergen,
                "confidence": 0.95
            }
    
    if "taking" in text_lower or "medication" in text_lower:
        return {
            "type": "medication",
            "subject_type": "patient",
            "predicate": "current_medication",
            "value": "unknown",
            "confidence": 0.7
        }
    
    return {"type": "unknown", "confidence": 0.0}


def run_demo():
    """
    Run the complete healthcare AI agent demo.
    """
    print("=" * 70)
    print("  HEALTHCARE AI AGENT DEMO - AAPI + VAC Integration")
    print("=" * 70)
    print()
    
    # Initialize systems
    print("🚀 Initializing systems...")
    vault = VACVault(vault_id="vault:hospital:main", owner_id="agent:health-assistant")
    gateway = AAPIGateway(gateway_id="gateway:hospital:main")
    patient_id = "patient:12345"
    print()
    
    # ==========================================================================
    # SCENARIO 1: Patient reports an allergy
    # ==========================================================================
    print("-" * 70)
    print("📋 SCENARIO 1: Patient reports an allergy")
    print("-" * 70)
    print()
    
    user_message = "I'm allergic to penicillin. Please make sure that's in my records."
    print(f"👤 Patient says: \"{user_message}\"")
    print()
    
    # Step 1: Store conversation event in VAC
    print("STEP 1: Store conversation event (VAC)")
    event = vault.create_event(
        content=f"Patient stated: {user_message}",
        source={"kind": "user", "principal": patient_id},
        entities=["penicillin", "allergy"]
    )
    print()
    
    # Step 2: LLM extracts structured claim
    print("STEP 2: LLM extracts structured claim")
    extraction = simulate_llm_extraction(user_message)
    print(f"  🤖 LLM extracted: {extraction}")
    print()
    
    # Step 3: Store claim with provenance in VAC
    print("STEP 3: Store claim with provenance (VAC)")
    claim = vault.create_claim(
        subject=patient_id,
        predicate=extraction["predicate"],
        value=extraction["value"],
        evidence_cids=[event.cid],  # Links to source event!
        confidence=extraction["confidence"]
    )
    print()
    
    # Step 4: Create AAPI action to update EHR
    print("STEP 4: Create and authorize action (AAPI)")
    vakya = Vakya(
        vakya_id=str(uuid4()),
        v1_karta={
            "pid": "agent:health-assistant",
            "actor_type": "agent",
            "role": "medical_assistant"
        },
        v2_karma={
            "rid": f"ehr:{patient_id}:allergies",
            "kind": "medical_record"
        },
        v3_kriya={
            "action": "ehr.update_allergy",
            "domain": "ehr",
            "verb": "update_allergy",
            "expected_effect": "UPDATE"
        },
        v7_adhikarana={
            "cap": {"cap_ref": "cap:ehr-write"},
            "policy_ref": "policy:hipaa-compliant"
        },
        body={
            "patient_id": patient_id,
            "allergies": [{"allergen": "penicillin", "severity": "unknown", "source": "patient_reported"}]
        },
        meta={
            "created_at": datetime.now(timezone.utc).isoformat(),
            "vac_claim_cid": claim.cid,  # Link to VAC claim!
            "vac_event_cid": event.cid   # Link to VAC event!
        }
    )
    
    # Step 5: Submit action via AAPI
    print("STEP 5: Execute action via AAPI Gateway")
    before_state = {"allergies": []}  # Current EHR state
    receipt = gateway.submit(vakya, before_state=before_state)
    print()
    
    # Step 6: Store action result in VAC and commit block
    print("STEP 6: Store result and commit block (VAC)")
    result_event = vault.create_event(
        content=f"Updated EHR with allergy: penicillin. AAPI receipt: {receipt.vakya_id[:20]}...",
        source={"kind": "agent", "principal": "agent:health-assistant"},
        entities=["ehr_update", "allergy", "penicillin"]
    )
    block = vault.commit()
    print()
    
    # ==========================================================================
    # SCENARIO 2: Compliance Audit
    # ==========================================================================
    print("-" * 70)
    print("📋 SCENARIO 2: Compliance Audit - Prove what the agent knew")
    print("-" * 70)
    print()
    
    print("🔍 Auditor asks: 'Prove the agent knew about the penicillin allergy'")
    print()
    
    # Get VAC provenance
    print("VAC PROVENANCE CHAIN:")
    provenance = vault.get_provenance(claim.cid)
    print(json.dumps(provenance, indent=2, default=str))
    print()
    
    # Get AAPI audit trail
    print("AAPI AUDIT TRAIL:")
    audit = gateway.get_audit_trail(vakya.vakya_id)
    print(json.dumps(audit, indent=2, default=str))
    print()
    
    # ==========================================================================
    # SCENARIO 3: Contradiction Handling
    # ==========================================================================
    print("-" * 70)
    print("📋 SCENARIO 3: Contradiction - Patient updates allergy info")
    print("-" * 70)
    print()
    
    new_message = "Actually, I'm not allergic to penicillin anymore. I was tested recently."
    print(f"👤 Patient says: \"{new_message}\"")
    print()
    
    # Store new event
    print("STEP 1: Store new conversation event")
    new_event = vault.create_event(
        content=f"Patient stated: {new_message}",
        source={"kind": "user", "principal": patient_id},
        entities=["penicillin", "allergy", "update"]
    )
    print()
    
    # Create superseding claim
    print("STEP 2: Create superseding claim (old claim preserved for audit)")
    new_claim = vault.create_claim(
        subject=patient_id,
        predicate="allergy",
        value="none",  # Updated value
        evidence_cids=[new_event.cid],
        confidence=0.85,
        supersedes=claim.cid  # Links to old claim!
    )
    print(f"  ⚠️  This claim SUPERSEDES: {claim.cid[:20]}...")
    print(f"     Old value: penicillin → New value: none")
    print(f"     Both claims preserved in chain for audit trail!")
    print()
    
    # Commit
    print("STEP 3: Commit to new block")
    block2 = vault.commit()
    print()
    
    # ==========================================================================
    # Summary
    # ==========================================================================
    print("=" * 70)
    print("  DEMO COMPLETE - Summary")
    print("=" * 70)
    print()
    print("VAC (Verifiable Memory):")
    print(f"  • Events stored: {len(vault.events)}")
    print(f"  • Claims stored: {len(vault.claims)}")
    print(f"  • Blocks committed: {len(vault.blocks)}")
    print(f"  • All with CIDs and cryptographic proofs")
    print()
    print("AAPI (Auditable Actions):")
    print(f"  • Actions logged: {len(gateway.vakya_log)}")
    print(f"  • Effects recorded: {len(gateway.effects)}")
    print(f"  • Receipts generated: {len(gateway.receipts)}")
    print(f"  • All with signatures and Merkle proofs")
    print()
    print("KEY BENEFITS:")
    print("  ✅ Every memory has a CID (content-addressed, tamper-proof)")
    print("  ✅ Every claim links to evidence (provenance chain)")
    print("  ✅ Contradictions are superseded, not deleted (audit trail)")
    print("  ✅ Every action is authorized and signed (accountability)")
    print("  ✅ Every action has before/after state (reversibility)")
    print("  ✅ Everything has Merkle proofs (cryptographic verification)")
    print()


if __name__ == "__main__":
    run_demo()

# Healthcare AI Agent Demo

This demo shows how AAPI + VAC work together in a real-world healthcare AI agent scenario.

## Demo Files

| File | Description | Uses Real SDK? |
|------|-------------|----------------|
| `demo.py` | Simulation showing the flow | No (educational) |
| `demo_real.py` | **Uses REAL AAPI Python SDK** | ✅ Yes |
| `demo_vac.ts` | **Uses REAL VAC TypeScript SDK** | ✅ Yes |

## Use Case: Patient Allergy Management

An AI assistant helps doctors manage patient information. The agent must:
1. **Remember** patient allergies (VAC - verifiable memory)
2. **Execute** actions like updating records (AAPI - auditable actions)
3. **Prove** what it knew and when (compliance requirement)

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HEALTHCARE AI AGENT FLOW                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Patient: "I'm allergic to penicillin"                                      │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 1: VAC - Store Conversation Event                              │    │
│  │                                                                     │    │
│  │   event = vault.create_event(                                       │    │
│  │     payload="Patient stated: I'm allergic to penicillin",           │    │
│  │     source={"kind": "user", "principal": "patient:12345"}           │    │
│  │   )                                                                 │    │
│  │   # Returns: Event with CID bafy2bzace...                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 2: LLM - Extract Structured Claim                              │    │
│  │                                                                     │    │
│  │   # LLM extracts:                                                   │    │
│  │   subject = "patient:12345"                                         │    │
│  │   predicate = "allergy"                                             │    │
│  │   value = "penicillin"                                              │    │
│  │   confidence = 0.95                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 3: VAC - Store Claim with Provenance                           │    │
│  │                                                                     │    │
│  │   claim = vault.create_claim(                                       │    │
│  │     subject="patient:12345",                                        │    │
│  │     predicate="allergy",                                            │    │
│  │     value="penicillin",                                             │    │
│  │     evidence_refs=[event.cid]  # Links to source!                   │    │
│  │   )                                                                 │    │
│  │   # Returns: Claim with CID bafy2bzacew...                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 4: AAPI - Create & Authorize Action                            │    │
│  │                                                                     │    │
│  │   vakya = Vakya(                                                    │    │
│  │     v1_karta=Karta(pid="agent:health-assistant", type="agent"),     │    │
│  │     v2_karma=Karma(rid="ehr:patient:12345:allergies"),              │    │
│  │     v3_kriya=Kriya(action="ehr.update_allergy"),                    │    │
│  │     v7_adhikarana=Adhikarana(cap={"cap_ref": "cap:ehr-write"})      │    │
│  │   )                                                                 │    │
│  │   # Signed with Ed25519, logged to IndexDB                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 5: AAPI - Execute Action via Adapter                           │    │
│  │                                                                     │    │
│  │   result = aapi_client.submit(vakya)                                │    │
│  │   # Effect record: before={allergies: []}, after={allergies: [...]} │    │
│  │   # Receipt: status=success, merkle_proof=...                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 6: VAC - Commit Block                                          │    │
│  │                                                                     │    │
│  │   block = vault.commit()                                            │    │
│  │   # Block signed with Ed25519                                       │    │
│  │   # Contains: event CID, claim CID, action result                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                         LATER: COMPLIANCE AUDIT

  Regulator: "Prove the agent knew about the allergy before prescribing"
                     │
                     ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ PROOF CHAIN:                                                        │
  │                                                                     │
  │   1. Claim CID: bafy2bzacew... (allergy = penicillin)               │
  │   2. Evidence CID: bafy2bzace... (patient statement)                │
  │   3. Block signature: ed25519:... (timestamp proof)                 │
  │   4. Merkle inclusion proof (cryptographic verification)            │
  │                                                                     │
  │   → CRYPTOGRAPHIC PROOF that agent knew, when, and from whom        │
  └─────────────────────────────────────────────────────────────────────┘
```

## Running the Demos

### 1. Simulation Demo (No dependencies)
```bash
python demo.py
```

### 2. Real AAPI SDK Demo (Python)
```bash
# Install dependencies
pip install pynacl canonicaljson pydantic httpx

# Run demo (works without gateway for SDK demo)
python demo_real.py

# For full demo, start AAPI gateway first:
cd ../../aapi && cargo run --bin aapi -- serve
```

### 3. Real VAC SDK Demo (TypeScript)
```bash
# Build VAC SDK first
cd ../../vac/packages/vac-sdk && npm install && npm run build && cd -

# Install demo dependencies
npm install

# Run demo
npx ts-node --esm demo_vac.ts
```

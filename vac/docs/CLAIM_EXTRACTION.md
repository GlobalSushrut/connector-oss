# Claim Extraction in VAC: Demo vs Production

## Demo (Current Implementation)

The demo uses **regex patterns** for claim extraction — this is a simulation to show the concept without requiring API keys.

```typescript
// Demo: Pattern matching (limited)
const haveMatch = text.match(/I\s+have\s+(?:a\s+)?(.+?)(?:\.|$)/i);
if (haveMatch) {
  claims.push({
    subject: 'user',
    predicate: 'owns',
    value: haveMatch[1],
    confidence: 0.85,
  });
}
```

**Limitations:**
- Only matches specific sentence patterns
- Can't understand context or nuance
- Misses implicit claims
- No semantic understanding

---

## Production (Real-World Implementation)

In production, VAC uses the **AI agent itself** to extract claims. The LLM understands natural language and extracts structured claims from any input.

### How It Works

```typescript
// Production: LLM-based extraction
async function extractClaimsWithLLM(
  userMessage: string,
  conversationContext: Message[],
  existingClaims: Claim[]
): Promise<Claim[]> {
  
  const response = await llm.chat({
    model: "gpt-4o" | "claude-3-5-sonnet" | "local-llama",
    messages: [
      {
        role: "system",
        content: `You are a claim extraction system. Extract structured claims from user messages.

Output JSON array of claims with this schema:
{
  "subject": string,      // who/what the claim is about
  "predicate": string,    // the relationship type
  "value": string,        // the value/object
  "confidence": number,   // 0-1 confidence score
  "temporal": string?,    // optional: when this is valid
  "source_quote": string  // exact text that supports this claim
}

Consider:
- Explicit statements ("I have a car")
- Implicit claims ("My Tesla needs charging" → owns:Tesla, owns:electric_vehicle)
- Preferences ("I'd rather walk" → preference:walking)
- Temporal context ("I used to smoke" → past_habit:smoking, current_status:non-smoker)
- Contradictions with existing claims

Existing claims for context:
${JSON.stringify(existingClaims, null, 2)}`
      },
      ...conversationContext,
      { role: "user", content: userMessage }
    ],
    response_format: { type: "json_object" }
  });
  
  return JSON.parse(response.content).claims;
}
```

### Example: "I have car"

**Demo (regex):**
```json
{
  "subject": "user",
  "predicate": "owns",
  "value": "car",
  "confidence": 0.85
}
```

**Production (LLM):**
```json
[
  {
    "subject": "user",
    "predicate": "owns",
    "value": "car",
    "confidence": 0.90,
    "source_quote": "I have car"
  },
  {
    "subject": "user",
    "predicate": "transportation",
    "value": "personal_vehicle",
    "confidence": 0.85,
    "source_quote": "I have car"
  }
]
```

### Example: "My Tesla needs charging, running late for the meeting with Sarah"

**Demo (regex):** ❌ No claims extracted (doesn't match patterns)

**Production (LLM):**
```json
[
  {
    "subject": "user",
    "predicate": "owns",
    "value": "Tesla",
    "confidence": 0.95,
    "source_quote": "My Tesla"
  },
  {
    "subject": "user",
    "predicate": "owns",
    "value": "electric_vehicle",
    "confidence": 0.90,
    "source_quote": "My Tesla needs charging"
  },
  {
    "subject": "user",
    "predicate": "has_meeting_with",
    "value": "Sarah",
    "confidence": 0.88,
    "source_quote": "meeting with Sarah"
  },
  {
    "subject": "user",
    "predicate": "current_status",
    "value": "running_late",
    "confidence": 0.85,
    "temporal": "now",
    "source_quote": "running late"
  }
]
```

---

## VAC's Unique Contribution

**The key insight:** VAC doesn't replace LLM-based extraction — it **adds verifiability** to it.

| System | Extraction | Storage | Verification |
|--------|------------|---------|--------------|
| MemGPT | LLM | Database | ❌ None |
| Zep | LLM | Neo4j | ❌ None |
| LangMem | LLM | Vector DB | ❌ None |
| **VAC** | LLM | Prolly Tree | ✅ CID + Merkle Proof |

### What VAC Adds

1. **Content-Addressed Storage**: Every claim gets a CID
   ```
   Claim CID: bafy2bzace...
   Evidence CID: bafy2bzace... (links to source event)
   ```

2. **Provenance Chain**: Trace any claim to its source
   ```
   Claim → Evidence CID → Event → Original Message
   ```

3. **Contradiction Handling**: LLM detects conflicts, VAC creates superseding chain
   ```
   New Claim.supersedes = Old Claim.CID
   ```

4. **Block Attestation**: Claims are committed to signed blocks
   ```
   Block { claims_root: Merkle(all_claim_CIDs), signature: Ed25519 }
   ```

---

## Integration Pattern

```typescript
// Real-world VAC integration
class VACAgent {
  private llm: LLMClient;
  private vault: VACVault;
  
  async processMessage(message: string): Promise<AgentResponse> {
    // 1. Store raw event (VAC)
    const event = await this.vault.storeEvent({
      content: message,
      ts: Date.now(),
    });
    // event.cid = "bafy2bzace..."
    
    // 2. Extract claims (LLM)
    const claims = await this.extractClaimsWithLLM(message);
    
    // 3. Check contradictions (LLM + VAC)
    const existingClaims = await this.vault.getActiveClaims();
    const contradictions = await this.detectContradictions(claims, existingClaims);
    
    // 4. Store claims with evidence links (VAC)
    for (const claim of claims) {
      const storedClaim = await this.vault.storeClaim({
        ...claim,
        evidenceCid: event.cid,  // Link to source!
        supersedes: contradictions.get(claim)?.cid,
      });
      // storedClaim.cid = "bafy2bzace..."
    }
    
    // 5. Generate response (LLM)
    const response = await this.generateResponse(message, claims);
    
    // 6. Periodically commit to block (VAC)
    if (this.shouldCommitBlock()) {
      await this.vault.commitBlock();
    }
    
    return response;
  }
}
```

---

## Summary

| Aspect | Demo | Production |
|--------|------|------------|
| Claim Extraction | Regex patterns | LLM (GPT-4, Claude, etc.) |
| Understanding | Pattern matching | Semantic understanding |
| Implicit Claims | ❌ Missed | ✅ Extracted |
| Context Awareness | ❌ None | ✅ Full conversation |
| Contradiction Detection | Pattern-based | LLM-based |
| **Storage** | ✅ CID-based | ✅ CID-based |
| **Verification** | ✅ Merkle proofs | ✅ Merkle proofs |
| **Provenance** | ✅ Evidence links | ✅ Evidence links |

**The demo shows VAC's storage/verification layer. Production adds LLM intelligence for extraction.**

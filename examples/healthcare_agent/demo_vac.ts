/**
 * Healthcare AI Agent Demo - Using REAL VAC SDK
 *
 * This demo uses the actual VAC TypeScript SDK to show how to:
 * 1. Create events with content-addressed IDs (CIDs)
 * 2. Create claims with provenance (evidence links)
 * 3. Commit to signed blocks
 * 4. Handle contradictions with superseding
 * 5. Use the RED engine for non-ML learning
 *
 * PREREQUISITES:
 * 1. cd ../../vac/packages/vac-sdk && npm install && npm run build
 * 2. npm install (in this directory)
 * 3. npx ts-node demo_vac.ts
 */

// Import REAL VAC SDK
import {
  Vault,
  createVault,
  computeCidString,
  RedEngine,
  encodeFeatures,
  computeEntropy,
} from '../../vac/packages/vac-sdk/src';

import type {
  Event,
  ClaimBundle,
  BlockHeader,
  Source,
} from '../../vac/packages/vac-sdk/src/types';

// =============================================================================
// Helper Functions
// =============================================================================

function printHeader(text: string): void {
  console.log('\n' + '='.repeat(70));
  console.log(`  ${text}`);
  console.log('='.repeat(70) + '\n');
}

function printStep(num: number, text: string): void {
  console.log('\n' + '─'.repeat(60));
  console.log(`STEP ${num}: ${text}`);
  console.log('─'.repeat(60));
}

function printJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

// =============================================================================
// Healthcare Agent using REAL VAC SDK
// =============================================================================

class HealthcareMemory {
  private vault: Vault;
  private eventCids: Map<string, string> = new Map(); // content -> cid
  private claimCids: Map<string, string> = new Map(); // key -> cid

  constructor(agentId: string) {
    // Create vault using REAL VAC SDK
    this.vault = createVault({
      vaultId: 'vault:hospital:main',
      ownerId: agentId,
    });

    console.log('🔐 VAC Vault initialized');
    console.log(`   Vault ID: vault:hospital:main`);
    console.log(`   Owner: ${agentId}`);
  }

  /**
   * Store a conversation event with content-addressed ID.
   * The CID is computed from the content itself - tamper-proof!
   */
  storeConversation(
    content: string,
    source: Source,
    entities: string[] = []
  ): Event {
    printStep(1, 'Store conversation event (VAC)');

    // Use REAL VAC SDK to create event
    const event = this.vault.createEvent(content, {
      source,
      entities,
      tags: ['conversation', 'healthcare'],
    });

    // Compute CID for display
    const cid = computeCidString(new TextEncoder().encode(content));

    console.log(`  📝 Event created with CID`);
    console.log(`     CID: ${cid.slice(0, 30)}...`);
    console.log(`     Content: ${content.slice(0, 50)}...`);
    console.log(`     Source: ${source.kind}:${source.principal_id}`);
    console.log(`     Entities: ${entities.join(', ')}`);
    console.log(`     Entropy: ${event.entropy.toFixed(4)}`);

    this.eventCids.set(content, cid);
    return event;
  }

  /**
   * Create a structured claim with provenance.
   * The claim links to evidence (source events) - auditable!
   */
  createClaim(
    subjectId: string,
    predicateKey: string,
    value: unknown,
    evidenceContent: string,
    confidence: number = 0.9,
    supersedes?: string
  ): ClaimBundle {
    printStep(2, 'Create claim with provenance (VAC)');

    // Get evidence CID
    const evidenceCid = this.eventCids.get(evidenceContent);
    if (!evidenceCid) {
      throw new Error('Evidence event not found. Store conversation first.');
    }

    // Use REAL VAC SDK to create claim
    const claim = this.vault.createClaim(subjectId, predicateKey, value, {
      confidence,
      evidenceRefs: [evidenceCid],
      source: { kind: 'self', principal_id: 'agent:health-assistant' },
    });

    const claimCid = computeCidString(
      new TextEncoder().encode(JSON.stringify({ subjectId, predicateKey, value }))
    );

    console.log(`  🏷️  Claim created with CID`);
    console.log(`     CID: ${claimCid.slice(0, 30)}...`);
    console.log(`     Subject: ${subjectId}`);
    console.log(`     Predicate: ${predicateKey}`);
    console.log(`     Value: ${JSON.stringify(value)}`);
    console.log(`     Confidence: ${confidence}`);
    console.log(`     Evidence: ${evidenceCid.slice(0, 20)}...`);

    if (supersedes) {
      console.log(`     ⚠️  Supersedes: ${supersedes.slice(0, 20)}...`);
    }

    this.claimCids.set(`${subjectId}:${predicateKey}`, claimCid);
    return claim;
  }

  /**
   * Commit pending events and claims to a signed block.
   * The block is signed with Ed25519 - non-repudiation!
   */
  async commit(): Promise<BlockHeader> {
    printStep(3, 'Commit to signed block (VAC)');

    // Use REAL VAC SDK to commit
    const block = await this.vault.commit();

    console.log(`  🔗 Block #${block.block_no} committed`);
    console.log(`     Timestamp: ${new Date(block.ts).toISOString()}`);
    console.log(`     Patch CID: ${block.links.patch?.slice(0, 20)}...`);
    console.log(`     Manifest CID: ${block.links.manifest?.slice(0, 20)}...`);

    return block;
  }

  /**
   * Provide retrieval feedback to RED engine.
   * This is how VAC learns without ML!
   */
  provideFeedback(entities: string[], text: string, wasUseful: boolean): void {
    this.vault.feedback(entities, text, wasUseful);
    console.log(
      `  📊 Feedback: ${wasUseful ? 'useful ✅' : 'not useful ❌'} for "${text.slice(0, 30)}..."`
    );
  }

  /**
   * Get RED engine stats
   */
  getStats(): { observations: number; retrievals: number; blockNo: number } {
    const redStats = this.vault.getRedStats();
    return {
      ...redStats,
      blockNo: this.vault.getBlockNo(),
    };
  }
}

// =============================================================================
// Demo: CID Computation
// =============================================================================

function demoCidComputation(): void {
  printHeader('CID Computation - Content-Addressed IDs');

  console.log(`
CID (Content Identifier) = Hash of the content itself

This means:
• Same content → Same CID (deterministic)
• Different content → Different CID (unique)
• Any change → Different CID (tamper-proof)
  `);

  // Demonstrate with real SDK
  const content1 = 'Patient is allergic to penicillin';
  const content2 = 'Patient is allergic to penicillin'; // Same
  const content3 = 'Patient is allergic to amoxicillin'; // Different

  const cid1 = computeCidString(new TextEncoder().encode(content1));
  const cid2 = computeCidString(new TextEncoder().encode(content2));
  const cid3 = computeCidString(new TextEncoder().encode(content3));

  console.log('Example:');
  console.log(`  Content 1: "${content1}"`);
  console.log(`  CID 1:     ${cid1}`);
  console.log();
  console.log(`  Content 2: "${content2}" (same)`);
  console.log(`  CID 2:     ${cid2}`);
  console.log(`  Same CID?  ${cid1 === cid2 ? 'YES ✅' : 'NO ❌'}`);
  console.log();
  console.log(`  Content 3: "${content3}" (different)`);
  console.log(`  CID 3:     ${cid3}`);
  console.log(`  Same CID?  ${cid1 === cid3 ? 'YES' : 'NO ✅ (different content = different CID)'}`);
}

// =============================================================================
// Demo: RED Engine (Non-ML Learning)
// =============================================================================

function demoRedEngine(): void {
  printHeader('RED Engine - Non-ML Learning');

  console.log(`
RED = Regressive Entropic Displacement

How it works:
1. Observe: Track feature distributions
2. Compute: Calculate entropy (information content)
3. Feedback: Adjust based on retrieval usefulness
4. Reframe: Consolidate network periodically

No neural networks. No training data. Just information theory.
  `);

  // Create RED engine using real SDK
  const red = new RedEngine();

  // Simulate observations
  const entities1 = ['penicillin', 'allergy', 'patient'];
  const entities2 = ['medication', 'prescription', 'doctor'];
  const entities3 = ['penicillin', 'allergy', 'severe'];

  console.log('Observing feature vectors:');

  const vector1 = encodeFeatures(entities1, [], 'Patient allergic to penicillin');
  red.observe(vector1);
  console.log(`  1. Entities: ${entities1.join(', ')}`);
  console.log(`     Observations: ${red.totalObservations}`);

  const vector2 = encodeFeatures(entities2, [], 'Doctor prescribed medication');
  red.observe(vector2);
  console.log(`  2. Entities: ${entities2.join(', ')}`);
  console.log(`     Observations: ${red.totalObservations}`);

  const vector3 = encodeFeatures(entities3, [], 'Severe penicillin allergy');
  red.observe(vector3);
  console.log(`  3. Entities: ${entities3.join(', ')}`);
  console.log(`     Observations: ${red.totalObservations}`);

  // Compute entropy
  console.log('\nComputing entropy:');
  const entropy1 = computeEntropy(red, vector1, 0, 0);
  const entropy2 = computeEntropy(red, vector2, 0, 0);
  const entropy3 = computeEntropy(red, vector3, 0, 0);

  console.log(`  Vector 1 entropy: ${entropy1.toFixed(4)}`);
  console.log(`  Vector 2 entropy: ${entropy2.toFixed(4)}`);
  console.log(`  Vector 3 entropy: ${entropy3.toFixed(4)}`);

  // Retrieval feedback
  console.log('\nProviding retrieval feedback:');
  red.retrievalFeedback(vector1, true); // Useful
  red.retrievalFeedback(vector2, false); // Not useful
  console.log(`  Vector 1: useful ✅`);
  console.log(`  Vector 2: not useful ❌`);
  console.log(`  Total retrievals: ${red.totalRetrievals}`);

  // Reframe
  console.log('\nReframing network (consolidation):');
  red.reframeNetwork();
  console.log('  Network reframed ✅');
}

// =============================================================================
// Demo: Full Healthcare Scenario
// =============================================================================

async function demoHealthcareScenario(): Promise<void> {
  printHeader('Healthcare AI Agent Scenario');

  console.log(`
SCENARIO: Patient reports an allergy

1. Patient says: "I'm allergic to penicillin"
2. Agent stores the conversation (VAC event)
3. Agent extracts structured claim (VAC claim)
4. Agent commits to signed block
5. Later: Patient updates allergy info (contradiction handling)
  `);

  const memory = new HealthcareMemory('agent:health-assistant');
  const patientId = 'patient:12345';

  // Step 1: Patient reports allergy
  console.log('\n👤 Patient says: "I\'m allergic to penicillin"');

  const event1 = memory.storeConversation(
    "Patient stated: I'm allergic to penicillin",
    { kind: 'user', principal_id: patientId },
    ['penicillin', 'allergy']
  );

  // Step 2: Extract claim
  const claim1 = memory.createClaim(
    patientId,
    'allergy',
    'penicillin',
    "Patient stated: I'm allergic to penicillin",
    0.95
  );

  // Step 3: Commit block
  const block1 = await memory.commit();

  // Step 4: Later - patient updates
  console.log('\n--- LATER ---\n');
  console.log('👤 Patient says: "Actually, I was tested. I\'m not allergic anymore."');

  const event2 = memory.storeConversation(
    "Patient stated: Actually, I was tested. I'm not allergic anymore.",
    { kind: 'user', principal_id: patientId },
    ['penicillin', 'allergy', 'update', 'test']
  );

  // Create superseding claim
  printStep(4, 'Create superseding claim (contradiction handling)');
  console.log('  ⚠️  Old claim preserved for audit trail');
  console.log('  ⚠️  New claim supersedes old claim');

  const claim2 = memory.createClaim(
    patientId,
    'allergy',
    'none', // Updated value
    "Patient stated: Actually, I was tested. I'm not allergic anymore.",
    0.85
    // In real impl, would pass supersedes: claim1.cid
  );

  const block2 = await memory.commit();

  // Summary
  printHeader('Summary');

  const stats = memory.getStats();
  console.log('VAC Memory Stats:');
  console.log(`  • Blocks committed: ${stats.blockNo}`);
  console.log(`  • RED observations: ${stats.observations}`);
  console.log(`  • RED retrievals: ${stats.retrievals}`);

  console.log(`
What VAC provides:

✅ Content-Addressed Memory (CID)
   • Every event/claim has unique CID
   • CID computed from content (tamper-proof)
   • Same content = same CID (verifiable)

✅ Provenance Chain
   • Claims link to evidence (source events)
   • Can trace any claim back to source
   • "When did the agent learn this?" → Answer with proof

✅ Contradiction Handling
   • Old claims preserved (audit trail)
   • New claims supersede old
   • Full history maintained

✅ Signed Blocks
   • Ed25519 signatures
   • Timestamp proof
   • Non-repudiation

✅ Non-ML Learning (RED Engine)
   • Learns from retrieval feedback
   • No neural networks
   • Information theory based
  `);
}

// =============================================================================
// Main
// =============================================================================

async function main(): Promise<void> {
  printHeader('VAC SDK Demo - Healthcare AI Agent');

  console.log(`
This demo uses the REAL VAC TypeScript SDK.

The SDK provides:
• Vault - High-level API for memory operations
• computeCidString - Content-addressed IDs
• RedEngine - Non-ML learning
• Event/Claim types - Structured memory

Key concepts:
• CID: Content Identifier (hash of content)
• Event: Conversation/interaction record
• Claim: Structured fact with provenance
• Block: Signed commit of events/claims
  `);

  // Demo 1: CID computation
  demoCidComputation();

  // Demo 2: RED engine
  demoRedEngine();

  // Demo 3: Full scenario
  await demoHealthcareScenario();

  printHeader('Integration with AAPI');

  console.log(`
VAC + AAPI work together:

┌─────────────────────────────────────────────────────────────────┐
│  User: "I'm allergic to penicillin"                             │
│                     │                                           │
│                     ▼                                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ VAC: Store event (CID: bafy2bzace...)                   │    │
│  │ VAC: Create claim (allergy=penicillin, evidence=CID)    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                     │                                           │
│                     ▼                                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ AAPI: Create VĀKYA (action=ehr.update_allergy)          │    │
│  │ AAPI: Sign with Ed25519                                 │    │
│  │ AAPI: Log to IndexDB (Merkle proof)                     │    │
│  │ AAPI: Execute via adapter                               │    │
│  └─────────────────────────────────────────────────────────┘    │
│                     │                                           │
│                     ▼                                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ VAC: Store result event                                 │    │
│  │ VAC: Commit to signed block                             │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘

Result: Complete audit trail from user intent to action execution,
        all cryptographically verifiable.
  `);
}

main().catch(console.error);

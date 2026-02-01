import { useState, useCallback } from 'react';
import {
  Brain,
  Database,
  GitBranch,
  Zap,
  MessageSquare,
  ChevronRight,
  Activity,
  RefreshCw,
  Send,
  Sparkles,
  Hash,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Bot,
  User,
  ArrowRight,
  Eye,
  FileText,
  Lightbulb,
  Link,
  Fingerprint,
  Scale,
  BookOpen,
  Cpu,
  Network,
} from 'lucide-react';

// ============================================================================
// RESEARCH-INFORMED: Why AI Agents Need VAC
// Based on analysis of MemGPT, Zep/Graphiti, LangMem, Mem0
// ============================================================================

const COMPETITOR_COMPARISON = [
  {
    name: 'MemGPT/Letta',
    approach: 'OS-inspired memory hierarchy with self-editing',
    strengths: ['Virtual context management', 'Self-editing memory', 'Multi-tier storage'],
    weaknesses: ['No verifiability', 'No provenance', 'ML-dependent'],
    vacAdvantage: 'VAC adds cryptographic CIDs and Merkle proofs to every memory',
  },
  {
    name: 'Zep/Graphiti',
    approach: 'Temporal knowledge graphs with bi-temporal model',
    strengths: ['Entity/fact extraction', 'Temporal validity', 'Point-in-time queries'],
    weaknesses: ['Requires Neo4j', 'Heavy LLM dependency', 'No content addressing'],
    vacAdvantage: 'VAC provides temporal tracking WITHOUT external DBs or LLM calls',
  },
  {
    name: 'LangMem',
    approach: 'Semantic/Episodic/Procedural memory taxonomy',
    strengths: ['Clean memory types', 'LangChain integration', 'Prompt optimization'],
    weaknesses: ['No audit trail', 'No verification', 'Server-dependent'],
    vacAdvantage: 'VAC adds immutable audit chain with offline-first sync',
  },
  {
    name: 'Mem0',
    approach: 'Universal memory layer with multi-level storage',
    strengths: ['Easy API', 'User/Session/Agent levels', 'Cross-platform'],
    weaknesses: ['No provenance', 'No contradiction handling', 'Centralized'],
    vacAdvantage: 'VAC tracks provenance and handles contradictions with superseding',
  },
];

const VAC_UNIQUE_FEATURES = [
  {
    icon: Fingerprint,
    title: 'Content-Addressed Memory (CID)',
    description: 'Every memory has a unique identifier computed from its content. Same content = same CID everywhere. Tamper-evident by design.',
    technical: 'CIDv1 = Multibase + Multicodec + Multihash(SHA256)',
    competitors: 'MemGPT uses row IDs, Zep uses node IDs — neither is content-derived',
  },
  {
    icon: Link,
    title: 'Verifiable Provenance Chain',
    description: 'Every claim links back to its source event. You can trace any fact to the exact conversation where it was learned.',
    technical: 'ClaimBundle.evidence = [CID of source Event]',
    competitors: 'No existing system provides cryptographic evidence links',
  },
  {
    icon: GitBranch,
    title: 'Block-Based Attestation',
    description: 'Memories are committed to signed blocks with Merkle roots. Full audit trail with Ed25519 signatures.',
    technical: 'BlockHeader { prev_block, events_root, claims_root, signature }',
    competitors: 'Other systems lack structured attestation with memory',
  },
  {
    icon: Zap,
    title: 'Non-ML Learning (RED Engine)',
    description: 'Regressive Entropic Displacement learns from retrieval feedback using information theory — no neural networks required.',
    technical: 'Entropy + KL Divergence + Multiplicative Weights Update',
    competitors: 'All competitors require LLM API calls for learning',
  },
  {
    icon: Scale,
    title: 'Contradiction Detection & Superseding',
    description: 'When facts conflict, VAC creates a superseding chain. Both versions remain for audit, but the latest is active.',
    technical: 'ClaimBundle.supersedes = CID of previous claim',
    competitors: 'Zep has invalidation but no superseding chain',
  },
  {
    icon: Network,
    title: 'Offline-First DAG Sync',
    description: 'Prolly trees enable deterministic merge without a central server. Content-addressing means conflict-free sync.',
    technical: 'Prolly Tree with Q=32 boundary detection',
    competitors: 'All competitors are server-centric',
  },
];

// ============================================================================
// DEMO: Interactive VAC Simulation
// ============================================================================

interface Message {
  id: string;
  role: 'user' | 'agent' | 'system';
  content: string;
  ts: number;
}

interface MemoryEvent {
  id: string;
  content: string;
  entropy: number;
  importance: number;
  entities: string[];
  cid: string;
  ts: number;
}

interface Claim {
  id: string;
  subject: string;
  predicate: string;
  value: string;
  confidence: number;
  cid: string;
  evidenceCid: string;
  validFrom: number;
  supersedes?: string;
  supersededBy?: string;
}

interface Block {
  blockNo: number;
  prevBlock: string;
  eventsRoot: string;
  claimsRoot: string;
  ts: number;
  signature: string;
  eventCount: number;
  claimCount: number;
}

interface RedStats {
  observations: number;
  retrievals: number;
  usefulRetrievals: number;
  displacement: number;
  learningRate: number;
}

// Simulated CID generation (deterministic for demo)
const generateCid = (content: string): string => {
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `bafy2bzace${hex}${hex}${hex}${hex}`.slice(0, 59);
};

// Simulated Merkle root
const computeMerkleRoot = (cids: string[]): string => {
  if (cids.length === 0) return generateCid('empty');
  return generateCid(cids.join(''));
};

// Entropy computation (information-theoretic)
const computeEntropy = (text: string, existingEvents: MemoryEvent[]): number => {
  const words = text.toLowerCase().split(/\s+/).filter(w => w.length > 2);
  const existingWords = new Set(
    existingEvents.flatMap((e) => e.content.toLowerCase().split(/\s+/))
  );
  
  // Novel words contribute to entropy
  const novelWords = words.filter((w) => !existingWords.has(w));
  const noveltyRatio = words.length > 0 ? novelWords.length / words.length : 0.5;
  
  // Information content (simplified Shannon entropy approximation)
  const uniqueWords = new Set(words);
  const diversity = uniqueWords.size / Math.max(words.length, 1);
  
  return Math.min(1, noveltyRatio * 0.6 + diversity * 0.4);
};

// Entity extraction
const extractEntities = (text: string): string[] => {
  const entities: string[] = [];
  const words = text.split(/\s+/);
  for (const word of words) {
    const clean = word.replace(/[.,!?'"]/g, '');
    if (clean.startsWith('@') || clean.startsWith('#')) {
      entities.push(clean);
    } else if (/^[A-Z][a-z]+$/.test(clean) && clean.length > 2) {
      entities.push(clean);
    }
  }
  return [...new Set(entities)];
};

// Claim extraction with structured output
const extractClaims = (text: string): Omit<Claim, 'id' | 'cid' | 'evidenceCid' | 'validFrom'>[] => {
  const claims: Omit<Claim, 'id' | 'cid' | 'evidenceCid' | 'validFrom'>[] = [];
  
  // Pattern: "I am X" / "I'm X"
  const iAmMatch = text.match(/I(?:'m| am)\s+(?:a\s+)?(\w+(?:\s+\w+)?)/i);
  if (iAmMatch) {
    claims.push({
      subject: 'user',
      predicate: 'identity',
      value: iAmMatch[1].toLowerCase(),
      confidence: 0.92,
    });
  }
  
  // Pattern: "I prefer/like/love/hate X"
  const prefMatch = text.match(/I\s+(prefer|like|love|hate|enjoy|dislike)\s+(.+?)(?:\.|$)/i);
  if (prefMatch) {
    claims.push({
      subject: 'user',
      predicate: prefMatch[1].toLowerCase(),
      value: prefMatch[2].toLowerCase().trim(),
      confidence: 0.88,
    });
  }
  
  // Pattern: "My X is Y"
  const myMatch = text.match(/My\s+(\w+)\s+is\s+(.+?)(?:\.|$)/i);
  if (myMatch) {
    claims.push({
      subject: 'user',
      predicate: myMatch[1].toLowerCase(),
      value: myMatch[2].toLowerCase().trim(),
      confidence: 0.90,
    });
  }
  
  // Pattern: "I'm allergic to X" (healthcare use case)
  const allergyMatch = text.match(/I(?:'m| am)\s+allergic\s+to\s+(.+?)(?:\.|$)/i);
  if (allergyMatch) {
    claims.push({
      subject: 'user',
      predicate: 'allergy',
      value: allergyMatch[1].toLowerCase().trim(),
      confidence: 0.95, // High confidence for medical claims
    });
  }
  
  // Pattern: "I work at/for X"
  const workMatch = text.match(/I\s+work\s+(?:at|for)\s+(.+?)(?:\.|$)/i);
  if (workMatch) {
    claims.push({
      subject: 'user',
      predicate: 'employer',
      value: workMatch[1].trim(),
      confidence: 0.91,
    });
  }
  
  // Pattern: "I have X" / "I have a X"
  const haveMatch = text.match(/I\s+have\s+(?:a\s+)?(.+?)(?:\.|$)/i);
  if (haveMatch) {
    claims.push({
      subject: 'user',
      predicate: 'owns',
      value: haveMatch[1].toLowerCase().trim(),
      confidence: 0.85,
    });
  }
  
  // Pattern: "I live in X"
  const liveMatch = text.match(/I\s+live\s+in\s+(.+?)(?:\.|$)/i);
  if (liveMatch) {
    claims.push({
      subject: 'user',
      predicate: 'location',
      value: liveMatch[1].trim(),
      confidence: 0.89,
    });
  }
  
  // Pattern: "I'm from X" / "I am from X"
  const fromMatch = text.match(/I(?:'m| am)\s+from\s+(.+?)(?:\.|$)/i);
  if (fromMatch) {
    claims.push({
      subject: 'user',
      predicate: 'origin',
      value: fromMatch[1].trim(),
      confidence: 0.88,
    });
  }
  
  // Pattern: "I need X" / "I want X"
  const needMatch = text.match(/I\s+(need|want)\s+(.+?)(?:\.|$)/i);
  if (needMatch) {
    claims.push({
      subject: 'user',
      predicate: needMatch[1].toLowerCase(),
      value: needMatch[2].toLowerCase().trim(),
      confidence: 0.82,
    });
  }
  
  return claims;
};

// Agent response generator (research-informed)
const generateAgentResponse = (
  userMessage: string,
  claims: Claim[],
  events: MemoryEvent[],
  newClaims: Claim[],
  contradictions: { old: Claim; new: Claim }[]
): string => {
  const lowerMsg = userMessage.toLowerCase();
  
  // Handle contradiction detection
  if (contradictions.length > 0) {
    const c = contradictions[0];
    return `🔄 **Contradiction Detected!**

**Previous claim** (${new Date(c.old.validFrom).toLocaleDateString()}):
\`${c.old.subject}.${c.old.predicate} = "${c.old.value}"\`
CID: \`${c.old.cid.slice(0, 24)}...\`

**New claim** (now):
\`${c.new.subject}.${c.new.predicate} = "${c.new.value}"\`
CID: \`${c.new.cid.slice(0, 24)}...\`

**VAC Handling**: The new claim now **supersedes** the old one. Both remain in the chain for audit purposes, but queries will return the latest value.

*This is how VAC differs from MemGPT/Zep: full provenance chain, not just overwrite.*`;
  }
  
  // Handle memory queries
  if (lowerMsg.includes('what do you know') || lowerMsg.includes('what have you learned')) {
    if (claims.length === 0) {
      return `I haven't learned anything about you yet.

**Try saying:**
- "I'm a software engineer"
- "I'm allergic to penicillin"
- "My name is Alex"
- "I prefer dark mode"

Each statement becomes a **ClaimBundle** with:
- Unique CID (content hash)
- Evidence link to source event
- Confidence score
- Timestamp for temporal queries`;
    }
    
    const claimList = claims
      .filter(c => !c.supersededBy)
      .slice(0, 5)
      .map((c) => `• **${c.predicate}**: "${c.value}" (${Math.round(c.confidence * 100)}% confident)\n  CID: \`${c.cid.slice(0, 24)}...\``)
      .join('\n');
    
    return `**Active Claims in VAC Memory:**

${claimList}

**Why this matters:**
- Each claim has a **CID** computed from its content
- You can **verify** any claim hasn't been tampered with
- You can **trace** each claim to its source conversation
- **Contradictions** are handled via superseding, not deletion

*MemGPT/Zep store facts but can't prove when/where they learned them.*`;
  }
  
  // Handle provenance queries
  if (lowerMsg.includes('prove') || lowerMsg.includes('when did') || lowerMsg.includes('how do you know')) {
    const relevantClaim = claims.find(c => 
      lowerMsg.includes(c.predicate) || lowerMsg.includes(c.value)
    );
    
    if (relevantClaim) {
      return `**Provenance Proof for "${relevantClaim.predicate}: ${relevantClaim.value}"**

📋 **Claim CID**: \`${relevantClaim.cid}\`
📎 **Evidence CID**: \`${relevantClaim.evidenceCid}\`
🕐 **Valid From**: ${new Date(relevantClaim.validFrom).toLocaleString()}
📊 **Confidence**: ${Math.round(relevantClaim.confidence * 100)}%
${relevantClaim.supersedes ? `🔄 **Supersedes**: \`${relevantClaim.supersedes.slice(0, 24)}...\`` : ''}

**Verification**: Anyone with the CID can verify this claim exists and hasn't been modified. The evidence CID links to the exact conversation event.

*This is VAC's key differentiator: cryptographic provenance that no other system provides.*`;
    }
    
    return `I can provide provenance for any stored claim. Tell me something about yourself first, then ask me to prove it!`;
  }
  
  // Handle new claims
  if (newClaims.length > 0) {
    const claim = newClaims[0];
    const event = events[events.length - 1];
    
    return `✅ **Stored in VAC Memory**

**Claim Extracted:**
\`\`\`
{
  subject: "${claim.subject}",
  predicate: "${claim.predicate}",
  value: "${claim.value}",
  confidence: ${claim.confidence},
  evidence: "${claim.evidenceCid.slice(0, 24)}..."
}
\`\`\`

**Content Identifiers:**
- Event CID: \`${event?.cid.slice(0, 32)}...\`
- Claim CID: \`${claim.cid.slice(0, 32)}...\`

**RED Engine Update:**
- Entropy: ${event?.entropy.toFixed(3)} (novelty of this information)
- Importance: ${event?.importance.toFixed(3)} (will adjust based on retrieval)

*Unlike MemGPT which uses LLM summarization, VAC's RED engine learns from retrieval patterns using information theory.*`;
  }
  
  // Default response
  const event = events[events.length - 1];
  return `📝 **Event Recorded**

Your message has been stored as an Event in VAC:
- **CID**: \`${event?.cid || 'pending'}...\`
- **Entropy**: ${event?.entropy.toFixed(3) || '0.500'}
- **Entities**: ${event?.entities.join(', ') || 'none detected'}

No structured claims were extracted from this message. Try statements like:
- "I'm a vegetarian" → identity claim
- "I prefer Python over JavaScript" → preference claim
- "My favorite color is blue" → attribute claim`;
};

function App() {
  const [activeTab, setActiveTab] = useState<'why' | 'how' | 'compare' | 'demo'>('why');
  const [messages, setMessages] = useState<Message[]>([]);
  const [events, setEvents] = useState<MemoryEvent[]>([]);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [input, setInput] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [redStats, setRedStats] = useState<RedStats>({
    observations: 0,
    retrievals: 0,
    usefulRetrievals: 0,
    displacement: 0,
    learningRate: 0.1,
  });
  const [selectedClaim, setSelectedClaim] = useState<Claim | null>(null);

  const sendMessage = useCallback(async () => {
    if (!input.trim()) return;
    
    setIsProcessing(true);
    const userInput = input;
    setInput('');
    
    // Add user message
    const userMsg: Message = {
      id: `msg_${Date.now()}`,
      role: 'user',
      content: userInput,
      ts: Date.now(),
    };
    setMessages((prev) => [...prev, userMsg]);
    
    // Create memory event
    const entropy = computeEntropy(userInput, events);
    const entities = extractEntities(userInput);
    const eventCid = generateCid(userInput + Date.now());
    
    const newEvent: MemoryEvent = {
      id: `evt_${Date.now()}`,
      content: userInput,
      entropy,
      importance: Math.min(1, 0.5 + entities.length * 0.1 + entropy * 0.2),
      entities,
      cid: eventCid,
      ts: Date.now(),
    };
    setEvents((prev) => [...prev, newEvent]);
    
    // Extract claims
    const extractedClaims = extractClaims(userInput);
    const contradictions: { old: Claim; new: Claim }[] = [];
    
    const newClaims: Claim[] = extractedClaims.map((c, i) => {
      const claimCid = generateCid(`${c.subject}${c.predicate}${c.value}${Date.now()}`);
      
      // Check for contradictions (same subject+predicate, different value)
      const existing = claims.find(
        (ec) => ec.subject === c.subject && 
                ec.predicate === c.predicate && 
                !ec.supersededBy &&
                ec.value.toLowerCase() !== c.value.toLowerCase()
      );
      
      const newClaim: Claim = {
        ...c,
        id: `clm_${Date.now()}_${i}`,
        cid: claimCid,
        evidenceCid: eventCid,
        validFrom: Date.now(),
        supersedes: existing?.cid,
      };
      
      if (existing) {
        contradictions.push({ old: existing, new: newClaim });
      }
      
      return newClaim;
    });
    
    // Update superseded claims
    if (contradictions.length > 0) {
      setClaims((prev) => prev.map((c) => {
        const contradiction = contradictions.find((con) => con.old.cid === c.cid);
        if (contradiction) {
          return { ...c, supersededBy: contradiction.new.cid };
        }
        return c;
      }));
    }
    
    if (newClaims.length > 0) {
      setClaims((prev) => [...newClaims, ...prev]);
    }
    
    // Update RED stats
    const isRetrieval = userInput.toLowerCase().includes('what') || 
                        userInput.toLowerCase().includes('know') ||
                        userInput.toLowerCase().includes('prove');
    
    setRedStats((prev) => ({
      observations: prev.observations + 1,
      retrievals: prev.retrievals + (isRetrieval ? 1 : 0),
      usefulRetrievals: prev.usefulRetrievals + (isRetrieval && claims.length > 0 ? 1 : 0),
      displacement: prev.displacement + entropy * prev.learningRate,
      learningRate: prev.learningRate,
    }));
    
    // Simulate processing
    await new Promise((r) => setTimeout(r, 600));
    
    // Generate response
    const response = generateAgentResponse(
      userInput,
      [...newClaims, ...claims],
      [...events, newEvent],
      newClaims,
      contradictions
    );
    
    const agentMsg: Message = {
      id: `msg_${Date.now()}_agent`,
      role: 'agent',
      content: response,
      ts: Date.now(),
    };
    setMessages((prev) => [...prev, agentMsg]);
    
    setIsProcessing(false);
  }, [input, events, claims]);

  const commitBlock = useCallback(() => {
    const uncommittedEvents = events.filter(
      (e) => !blocks.some((b) => b.ts > e.ts)
    );
    const uncommittedClaims = claims.filter(
      (c) => !blocks.some((b) => b.ts > c.validFrom)
    );
    
    if (uncommittedEvents.length === 0 && uncommittedClaims.length === 0) return;
    
    const prevBlock = blocks[0]?.eventsRoot || generateCid('genesis');
    const eventsRoot = computeMerkleRoot(uncommittedEvents.map((e) => e.cid));
    const claimsRoot = computeMerkleRoot(uncommittedClaims.map((c) => c.cid));
    
    const newBlock: Block = {
      blockNo: blocks.length,
      prevBlock,
      eventsRoot,
      claimsRoot,
      ts: Date.now(),
      signature: generateCid(`sig_${Date.now()}`).slice(0, 32),
      eventCount: uncommittedEvents.length,
      claimCount: uncommittedClaims.length,
    };
    
    setBlocks((prev) => [newBlock, ...prev]);
    
    // Add system message
    const sysMsg: Message = {
      id: `msg_${Date.now()}_sys`,
      role: 'system',
      content: `📦 **Block #${newBlock.blockNo} Committed**\n\nEvents: ${newBlock.eventCount} | Claims: ${newBlock.claimCount}\nMerkle Root: \`${eventsRoot.slice(0, 24)}...\`\nSignature: \`${newBlock.signature}...\``,
      ts: Date.now(),
    };
    setMessages((prev) => [...prev, sysMsg]);
  }, [events, claims, blocks]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-white/10 bg-black/20">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="relative">
                <Brain className="w-10 h-10 text-cyan-400" />
                <Sparkles className="w-4 h-4 text-yellow-400 absolute -top-1 -right-1" />
              </div>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                  VAC — Vault Attestation Chain
                </h1>
                <p className="text-slate-400 text-sm">
                  Verifiable Memory for AI Agents • No ML Required
                </p>
              </div>
            </div>
            
            <nav className="flex gap-1">
              {[
                { id: 'why', label: 'Why VAC?', icon: Lightbulb },
                { id: 'how', label: 'How It Works', icon: Cpu },
                { id: 'compare', label: 'vs Others', icon: Scale },
                { id: 'demo', label: 'Live Demo', icon: Bot },
              ].map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setActiveTab(id as typeof activeTab)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    activeTab === id
                      ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </button>
              ))}
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* TAB: Why VAC? */}
        {activeTab === 'why' && (
          <div className="space-y-12">
            <div className="text-center max-w-3xl mx-auto">
              <h2 className="text-4xl font-bold mb-4">
                The Problem with AI Agent Memory
              </h2>
              <p className="text-xl text-slate-400">
                Current solutions (MemGPT, Zep, LangMem, Mem0) store memories but can't <strong className="text-cyan-400">prove</strong> them.
              </p>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {[
                {
                  icon: AlertTriangle,
                  title: 'No Verifiability',
                  problem: 'When an AI says "you told me X", you can\'t verify if that\'s true or when it was learned.',
                  current: 'MemGPT/Zep store facts in databases with row IDs — no cryptographic proof.',
                  vac: 'Every memory has a CID (content hash). Verify any memory hasn\'t been tampered with.',
                },
                {
                  icon: Link,
                  title: 'No Provenance',
                  problem: 'You can\'t trace a fact back to the exact conversation where it was learned.',
                  current: 'LangMem extracts facts but loses the evidence link to source.',
                  vac: 'ClaimBundle.evidence links to the source Event CID. Full audit trail.',
                },
                {
                  icon: XCircle,
                  title: 'No Contradiction Handling',
                  problem: '"I\'m vegetarian" then "I love steak" — what happens to the old fact?',
                  current: 'Mem0 overwrites. Zep invalidates. Both lose history.',
                  vac: 'Superseding chain: new claim links to old. Both remain for audit.',
                },
                {
                  icon: Cpu,
                  title: 'ML Dependency',
                  problem: 'Every memory operation requires LLM API calls. Expensive, slow, unpredictable.',
                  current: 'All competitors use LLMs for extraction, summarization, and retrieval.',
                  vac: 'RED engine uses information theory. Local compute, deterministic, fast.',
                },
              ].map((item, i) => (
                <div key={i} className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6">
                  <div className="flex items-start gap-4">
                    <div className="p-3 bg-red-500/10 rounded-xl">
                      <item.icon className="w-6 h-6 text-red-400" />
                    </div>
                    <div className="flex-1">
                      <h3 className="text-xl font-semibold text-red-300 mb-2">{item.title}</h3>
                      <p className="text-slate-300 mb-4">{item.problem}</p>
                      
                      <div className="space-y-2 text-sm">
                        <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3">
                          <span className="text-red-400 font-medium">Current: </span>
                          <span className="text-slate-400">{item.current}</span>
                        </div>
                        <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg p-3">
                          <span className="text-cyan-400 font-medium">VAC: </span>
                          <span className="text-slate-300">{item.vac}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="text-center">
              <button
                onClick={() => setActiveTab('how')}
                className="bg-cyan-500 hover:bg-cyan-400 px-8 py-3 rounded-xl font-semibold inline-flex items-center gap-2 transition-colors"
              >
                See How VAC Works
                <ArrowRight className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}

        {/* TAB: How It Works */}
        {activeTab === 'how' && (
          <div className="space-y-12">
            <div className="text-center max-w-3xl mx-auto">
              <h2 className="text-4xl font-bold mb-4">
                VAC's Unique Architecture
              </h2>
              <p className="text-xl text-slate-400">
                Six features that no other AI memory system provides.
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {VAC_UNIQUE_FEATURES.map((feature, i) => (
                <div key={i} className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 hover:border-cyan-500/30 transition-colors">
                  <div className="p-3 bg-cyan-500/10 rounded-xl w-fit mb-4">
                    <feature.icon className="w-6 h-6 text-cyan-400" />
                  </div>
                  <h3 className="text-lg font-semibold text-cyan-300 mb-2">{feature.title}</h3>
                  <p className="text-slate-400 text-sm mb-4">{feature.description}</p>
                  
                  <div className="space-y-2 text-xs">
                    <div className="bg-slate-900/50 rounded-lg p-2 font-mono text-cyan-400">
                      {feature.technical}
                    </div>
                    <div className="text-slate-500 italic">
                      {feature.competitors}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Production Architecture Diagram */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8">
              <h3 className="text-2xl font-semibold text-center mb-2">Production Agent Architecture</h3>
              <p className="text-slate-400 text-center text-sm mb-8">Where VAC sits in a real AI agent stack</p>
              
              {/* Full Stack Diagram */}
              <div className="max-w-4xl mx-auto">
                {/* User Layer */}
                <div className="flex justify-center mb-4">
                  <div className="bg-blue-500/20 border border-blue-500/30 rounded-xl px-6 py-3 flex items-center gap-3">
                    <User className="w-6 h-6 text-blue-400" />
                    <span className="text-blue-300 font-medium">User / Application</span>
                  </div>
                </div>
                <div className="flex justify-center mb-4">
                  <div className="w-0.5 h-6 bg-slate-600"></div>
                </div>

                {/* Agent Framework Layer */}
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-2xl p-4 mb-4">
                  <div className="text-center mb-3">
                    <span className="text-purple-400 font-semibold text-sm">Agent Framework (LangChain / LlamaIndex / Custom)</span>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-slate-900/50 rounded-lg p-3 text-center">
                      <Bot className="w-5 h-5 text-purple-400 mx-auto mb-1" />
                      <span className="text-xs text-slate-400">Agent Loop</span>
                    </div>
                    <div className="bg-slate-900/50 rounded-lg p-3 text-center">
                      <MessageSquare className="w-5 h-5 text-purple-400 mx-auto mb-1" />
                      <span className="text-xs text-slate-400">Prompt Builder</span>
                    </div>
                    <div className="bg-slate-900/50 rounded-lg p-3 text-center">
                      <Zap className="w-5 h-5 text-purple-400 mx-auto mb-1" />
                      <span className="text-xs text-slate-400">Tool Executor</span>
                    </div>
                  </div>
                </div>
                <div className="flex justify-center mb-4">
                  <div className="w-0.5 h-6 bg-slate-600"></div>
                </div>

                {/* LLM Layer */}
                <div className="flex justify-center gap-4 mb-4">
                  <div className="bg-green-500/20 border border-green-500/30 rounded-xl px-4 py-3 flex items-center gap-2">
                    <Brain className="w-5 h-5 text-green-400" />
                    <div className="text-left">
                      <span className="text-green-300 font-medium text-sm block">LLM Provider</span>
                      <span className="text-green-400/60 text-xs">GPT-4 / Claude / Llama</span>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <ArrowRight className="w-5 h-5 text-slate-500" />
                  </div>
                  <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-xl px-4 py-3 flex items-center gap-2">
                    <BookOpen className="w-5 h-5 text-yellow-400" />
                    <div className="text-left">
                      <span className="text-yellow-300 font-medium text-sm block">Claim Extraction</span>
                      <span className="text-yellow-400/60 text-xs">LLM extracts structured claims</span>
                    </div>
                  </div>
                </div>
                <div className="flex justify-center mb-4">
                  <div className="w-0.5 h-6 bg-slate-600"></div>
                </div>

                {/* VAC Layer - Highlighted */}
                <div className="bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border-2 border-cyan-500/50 rounded-2xl p-4 mb-4 relative">
                  <div className="absolute -top-3 left-4 bg-cyan-500 text-white text-xs font-bold px-2 py-0.5 rounded">
                    VAC MEMORY LAYER
                  </div>
                  <div className="grid grid-cols-4 gap-3 mt-2">
                    <div className="bg-slate-900/70 rounded-lg p-3 text-center border border-cyan-500/20">
                      <Hash className="w-5 h-5 text-cyan-400 mx-auto mb-1" />
                      <span className="text-xs text-cyan-300 font-medium">CID Store</span>
                      <p className="text-xs text-slate-500 mt-1">Content-addressed</p>
                    </div>
                    <div className="bg-slate-900/70 rounded-lg p-3 text-center border border-cyan-500/20">
                      <Database className="w-5 h-5 text-cyan-400 mx-auto mb-1" />
                      <span className="text-xs text-cyan-300 font-medium">Prolly Tree</span>
                      <p className="text-xs text-slate-500 mt-1">Merkle proofs</p>
                    </div>
                    <div className="bg-slate-900/70 rounded-lg p-3 text-center border border-cyan-500/20">
                      <Zap className="w-5 h-5 text-yellow-400 mx-auto mb-1" />
                      <span className="text-xs text-cyan-300 font-medium">RED Engine</span>
                      <p className="text-xs text-slate-500 mt-1">Non-ML learning</p>
                    </div>
                    <div className="bg-slate-900/70 rounded-lg p-3 text-center border border-cyan-500/20">
                      <GitBranch className="w-5 h-5 text-cyan-400 mx-auto mb-1" />
                      <span className="text-xs text-cyan-300 font-medium">Attestation Log</span>
                      <p className="text-xs text-slate-500 mt-1">Signed commits</p>
                    </div>
                  </div>
                  <div className="flex justify-center gap-6 mt-4 text-xs">
                    <div className="flex items-center gap-1 text-cyan-400">
                      <Fingerprint className="w-3 h-3" />
                      <span>Verifiable</span>
                    </div>
                    <div className="flex items-center gap-1 text-cyan-400">
                      <Link className="w-3 h-3" />
                      <span>Provenance</span>
                    </div>
                    <div className="flex items-center gap-1 text-cyan-400">
                      <Scale className="w-3 h-3" />
                      <span>Auditable</span>
                    </div>
                  </div>
                </div>
                <div className="flex justify-center mb-4">
                  <div className="w-0.5 h-6 bg-slate-600"></div>
                </div>

                {/* Storage Layer */}
                <div className="flex justify-center gap-4">
                  <div className="bg-slate-700/50 border border-slate-600 rounded-xl px-4 py-3 text-center">
                    <Database className="w-5 h-5 text-slate-400 mx-auto mb-1" />
                    <span className="text-slate-400 text-xs block">Local Storage</span>
                    <span className="text-slate-500 text-xs">(SQLite / File)</span>
                  </div>
                  <div className="bg-slate-700/50 border border-slate-600 rounded-xl px-4 py-3 text-center">
                    <Network className="w-5 h-5 text-slate-400 mx-auto mb-1" />
                    <span className="text-slate-400 text-xs block">IPFS / Sync</span>
                    <span className="text-slate-500 text-xs">(Optional)</span>
                  </div>
                </div>
              </div>

              {/* Comparison: Traditional vs VAC */}
              <div className="grid md:grid-cols-2 gap-6 mt-8">
                <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4">
                  <h4 className="text-red-400 font-semibold mb-3 flex items-center gap-2">
                    <XCircle className="w-4 h-4" />
                    Traditional Agent Memory
                  </h4>
                  <div className="space-y-2 text-xs text-slate-400">
                    <p>• LLM → <span className="text-red-300">Vector DB (Pinecone/Chroma)</span></p>
                    <p>• No content addressing</p>
                    <p>• No provenance tracking</p>
                    <p>• No audit trail</p>
                    <p>• Server-dependent sync</p>
                  </div>
                </div>
                <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-4">
                  <h4 className="text-cyan-400 font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    VAC-Powered Agent Memory
                  </h4>
                  <div className="space-y-2 text-xs text-slate-400">
                    <p>• LLM → <span className="text-cyan-300">VAC (CID + Prolly Tree)</span></p>
                    <p>• Every memory has unique CID</p>
                    <p>• Full provenance chain</p>
                    <p>• Signed attestation log</p>
                    <p>• Offline-first DAG sync</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="text-center">
              <button
                onClick={() => setActiveTab('compare')}
                className="bg-cyan-500 hover:bg-cyan-400 px-8 py-3 rounded-xl font-semibold inline-flex items-center gap-2 transition-colors"
              >
                Compare to Other Systems
                <ArrowRight className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}

        {/* TAB: Comparison */}
        {activeTab === 'compare' && (
          <div className="space-y-12">
            <div className="text-center max-w-3xl mx-auto">
              <h2 className="text-4xl font-bold mb-4">
                VAC vs. The Competition
              </h2>
              <p className="text-xl text-slate-400">
                Based on research of MemGPT, Zep/Graphiti, LangMem, and Mem0.
              </p>
            </div>

            {/* Feature Matrix */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left p-4 text-slate-400">Feature</th>
                    <th className="p-4 text-slate-400">MemGPT</th>
                    <th className="p-4 text-slate-400">Zep</th>
                    <th className="p-4 text-slate-400">LangMem</th>
                    <th className="p-4 text-slate-400">Mem0</th>
                    <th className="p-4 text-cyan-400 font-bold">VAC</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['Content-Addressed (CID)', false, false, false, false, true],
                    ['Cryptographic Signatures', false, false, false, false, true],
                    ['Merkle Proofs', false, false, false, false, true],
                    ['Provenance Chain', false, 'partial', false, false, true],
                    ['Contradiction Handling', false, true, false, false, true],
                    ['Non-ML Learning', false, false, false, false, true],
                    ['Offline-First Sync', false, false, false, false, true],
                    ['No External DB Required', false, false, true, false, true],
                    ['Temporal Queries', false, true, false, false, true],
                    ['Block Attestation', false, false, false, false, true],
                  ].map(([feature, ...values], i) => (
                    <tr key={i} className="border-b border-slate-800">
                      <td className="p-4 text-slate-300">{feature}</td>
                      {values.map((v, j) => (
                        <td key={j} className={`p-4 text-center ${j === 4 ? 'bg-cyan-500/5' : ''}`}>
                          {v === true ? (
                            <CheckCircle className="w-5 h-5 text-green-400 mx-auto" />
                          ) : v === false ? (
                            <XCircle className="w-5 h-5 text-red-400/50 mx-auto" />
                          ) : (
                            <span className="text-yellow-400 text-xs">{v}</span>
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Detailed Comparisons */}
            <div className="grid md:grid-cols-2 gap-6">
              {COMPETITOR_COMPARISON.map((comp, i) => (
                <div key={i} className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6">
                  <h3 className="text-xl font-semibold text-slate-200 mb-2">{comp.name}</h3>
                  <p className="text-slate-400 text-sm mb-4">{comp.approach}</p>
                  
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <h4 className="text-xs font-medium text-green-400 mb-2">Strengths</h4>
                      <ul className="text-xs text-slate-400 space-y-1">
                        {comp.strengths.map((s, j) => (
                          <li key={j}>• {s}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-red-400 mb-2">Weaknesses</h4>
                      <ul className="text-xs text-slate-400 space-y-1">
                        {comp.weaknesses.map((w, j) => (
                          <li key={j}>• {w}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  
                  <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-3">
                    <span className="text-cyan-400 text-xs font-medium">VAC Advantage: </span>
                    <span className="text-slate-300 text-xs">{comp.vacAdvantage}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="text-center">
              <button
                onClick={() => setActiveTab('demo')}
                className="bg-cyan-500 hover:bg-cyan-400 px-8 py-3 rounded-xl font-semibold inline-flex items-center gap-2 transition-colors"
              >
                Try the Live Demo
                <ArrowRight className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}

        {/* TAB: Live Demo */}
        {activeTab === 'demo' && (
          <div className="grid lg:grid-cols-3 gap-6">
            {/* Chat Panel */}
            <div className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-2xl overflow-hidden">
              <div className="p-4 border-b border-slate-700 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Bot className="w-6 h-6 text-cyan-400" />
                  <div>
                    <h3 className="font-semibold">VAC-Powered Agent</h3>
                    <p className="text-xs text-slate-500">Verifiable • Auditable • Non-ML Learning</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <button
                    onClick={commitBlock}
                    className="text-xs bg-green-500/20 text-green-400 px-3 py-1.5 rounded-lg hover:bg-green-500/30 transition-colors flex items-center gap-1"
                  >
                    <GitBranch className="w-3 h-3" />
                    Commit Block
                  </button>
                  <div className="flex items-center gap-1">
                    <Activity className="w-4 h-4 text-green-400" />
                    <span className="text-xs text-green-400">Live</span>
                  </div>
                </div>
              </div>

              {/* Messages */}
              <div className="h-[400px] overflow-y-auto p-4 space-y-4">
                {messages.length === 0 ? (
                  <div className="text-center text-slate-500 py-12">
                    <MessageSquare className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p className="mb-4">Start a conversation to see VAC in action!</p>
                    <div className="text-sm space-y-2 max-w-md mx-auto">
                      <p className="text-cyan-400 font-medium">Try these:</p>
                      <p className="bg-slate-900/50 rounded-lg px-3 py-2">"I'm a software engineer"</p>
                      <p className="bg-slate-900/50 rounded-lg px-3 py-2">"I'm allergic to penicillin"</p>
                      <p className="bg-slate-900/50 rounded-lg px-3 py-2">"What do you know about me?"</p>
                      <p className="bg-slate-900/50 rounded-lg px-3 py-2">"I'm a data scientist" (contradiction!)</p>
                    </div>
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`flex gap-3 ${
                        msg.role === 'user' ? 'justify-end' : 
                        msg.role === 'system' ? 'justify-center' : 'justify-start'
                      }`}
                    >
                      {msg.role === 'agent' && (
                        <div className="p-2 bg-cyan-500/20 rounded-full h-fit">
                          <Bot className="w-4 h-4 text-cyan-400" />
                        </div>
                      )}
                      <div
                        className={`max-w-lg rounded-2xl px-4 py-3 ${
                          msg.role === 'user'
                            ? 'bg-cyan-500 text-white'
                            : msg.role === 'system'
                            ? 'bg-green-500/10 border border-green-500/20 text-green-300 text-sm'
                            : 'bg-slate-700/50 text-slate-200'
                        }`}
                      >
                        <div className="whitespace-pre-wrap text-sm prose prose-invert prose-sm max-w-none">
                          {msg.content.split('\n').map((line, i) => {
                            if (line.startsWith('**') && line.endsWith('**')) {
                              return <p key={i} className="font-bold text-cyan-300">{line.replace(/\*\*/g, '')}</p>;
                            }
                            if (line.startsWith('`') && line.endsWith('`')) {
                              return <code key={i} className="bg-slate-900/50 px-1 rounded text-xs">{line.replace(/`/g, '')}</code>;
                            }
                            return <p key={i}>{line}</p>;
                          })}
                        </div>
                      </div>
                      {msg.role === 'user' && (
                        <div className="p-2 bg-blue-500/20 rounded-full h-fit">
                          <User className="w-4 h-4 text-blue-400" />
                        </div>
                      )}
                    </div>
                  ))
                )}
                {isProcessing && (
                  <div className="flex gap-3">
                    <div className="p-2 bg-cyan-500/20 rounded-full h-fit">
                      <Bot className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div className="bg-slate-700/50 rounded-2xl px-4 py-3">
                      <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                    </div>
                  </div>
                )}
              </div>

              {/* Input */}
              <div className="p-4 border-t border-slate-700">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Tell me about yourself..."
                    className="flex-1 bg-slate-900/50 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-cyan-500"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendMessage();
                      }
                    }}
                  />
                  <button
                    onClick={sendMessage}
                    disabled={isProcessing || !input.trim()}
                    className="bg-cyan-500 hover:bg-cyan-400 px-4 py-3 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <Send className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>

            {/* Memory Inspector */}
            <div className="space-y-4">
              {/* Demo Note */}
              <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3 text-xs">
                <p className="text-yellow-400 font-medium mb-1">⚡ Demo Mode</p>
                <p className="text-slate-400">
                  Claim extraction uses <strong>regex patterns</strong> for simulation. 
                  In production, VAC uses <strong>LLM (GPT-4/Claude)</strong> for semantic understanding.
                </p>
              </div>

              {/* Claims */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-4">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold flex items-center gap-2">
                    <Hash className="w-4 h-4 text-cyan-400" />
                    Claims ({claims.filter(c => !c.supersededBy).length} active)
                  </h3>
                </div>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {claims.length === 0 ? (
                    <p className="text-xs text-slate-500 text-center py-4">
                      No claims yet
                    </p>
                  ) : (
                    claims.map((claim) => (
                      <div
                        key={claim.id}
                        onClick={() => setSelectedClaim(claim)}
                        className={`bg-slate-900/50 rounded-lg p-3 text-xs cursor-pointer hover:bg-slate-900 transition-colors ${
                          claim.supersededBy ? 'opacity-50' : ''
                        } ${selectedClaim?.id === claim.id ? 'ring-1 ring-cyan-500' : ''}`}
                      >
                        <div className="flex items-center gap-1 text-slate-300">
                          <span className="text-cyan-400">{claim.subject}</span>
                          <ChevronRight className="w-3 h-3 text-slate-600" />
                          <span className="text-yellow-400">{claim.predicate}</span>
                          <ChevronRight className="w-3 h-3 text-slate-600" />
                          <span className="text-green-400">"{claim.value}"</span>
                        </div>
                        <div className="flex items-center gap-2 mt-1 text-slate-500">
                          <span>{Math.round(claim.confidence * 100)}%</span>
                          {claim.supersededBy && (
                            <span className="text-red-400">(superseded)</span>
                          )}
                          {claim.supersedes && (
                            <span className="text-orange-400">(supersedes)</span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Selected Claim Details */}
              {selectedClaim && (
                <div className="bg-slate-800/50 border border-cyan-500/30 rounded-2xl p-4">
                  <h3 className="font-semibold flex items-center gap-2 mb-3">
                    <Eye className="w-4 h-4 text-cyan-400" />
                    Claim Inspector
                  </h3>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500">CID:</span>
                      <span className="text-cyan-400 truncate ml-2">{selectedClaim.cid.slice(0, 24)}...</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Evidence:</span>
                      <span className="text-purple-400 truncate ml-2">{selectedClaim.evidenceCid.slice(0, 24)}...</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Valid From:</span>
                      <span className="text-slate-300">{new Date(selectedClaim.validFrom).toLocaleString()}</span>
                    </div>
                    {selectedClaim.supersedes && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Supersedes:</span>
                        <span className="text-orange-400 truncate ml-2">{selectedClaim.supersedes.slice(0, 24)}...</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* RED Stats */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-4">
                <h3 className="font-semibold flex items-center gap-2 mb-4">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  RED Engine (Non-ML)
                </h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Observations</span>
                    <span className="font-mono text-cyan-400">{redStats.observations}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Retrievals</span>
                    <span className="font-mono text-cyan-400">{redStats.retrievals}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Useful Retrievals</span>
                    <span className="font-mono text-green-400">{redStats.usefulRetrievals}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Entropic Displacement</span>
                    <span className="font-mono text-yellow-400">{redStats.displacement.toFixed(4)}</span>
                  </div>
                  <div className="pt-2 border-t border-slate-700 text-xs text-slate-500">
                    Learning without ML: entropy + KL divergence
                  </div>
                </div>
              </div>

              {/* Blocks */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-4">
                <h3 className="font-semibold flex items-center gap-2 mb-4">
                  <GitBranch className="w-4 h-4 text-green-400" />
                  Attestation Chain
                </h3>
                <div className="space-y-2 max-h-32 overflow-y-auto">
                  {blocks.length === 0 ? (
                    <p className="text-xs text-slate-500 text-center py-2">
                      No blocks yet. Click "Commit Block" to attest.
                    </p>
                  ) : (
                    blocks.map((block) => (
                      <div key={block.blockNo} className="bg-slate-900/50 rounded-lg p-2 text-xs">
                        <div className="flex justify-between text-slate-300">
                          <span className="text-green-400">Block #{block.blockNo}</span>
                          <span>{block.eventCount}E / {block.claimCount}C</span>
                        </div>
                        <div className="text-slate-500 font-mono truncate">
                          Root: {block.eventsRoot.slice(0, 20)}...
                        </div>
                        <div className="text-slate-600 font-mono truncate">
                          Sig: {block.signature}...
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-6 text-center text-slate-500 text-sm">
          <p className="mb-2">
            <strong className="text-cyan-400">VAC v0.1.0</strong> — Rust Core + TypeScript SDK
          </p>
          <p>
            The first <strong>verifiable</strong> memory system for AI agents. No ML. No neural networks. Just information theory + cryptography.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;

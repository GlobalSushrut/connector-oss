# Intelligence Identity Architecture (IIA) v2 — Canon Import

> Source: `Connector_OS_Intelligence_Identity_Architecture_v2.docx` (August 2026).  
> Implementation queue: [IIA_CORE_UPGRADE_CHECKLIST.md](../../IIA_CORE_UPGRADE_CHECKLIST.md) · capability vision: [CONNECTOR_WHEN_IIA_COMPLETE.md](../../CONNECTOR_WHEN_IIA_COMPLETE.md).

---

CONNECTOR OS
Verifiable Intelligence Identity & Execution Architecture
Architecture synthesis: N4 Intelligence Admission Matrix · Agent Kernel · Agent Identity · Agent Contract · Quanta/Polar Ring · DockLock · Hardware Truth · Agent Trust · Forensic Evidence
Core thesis
“The internet knows machines. Linux knows processes. IAM knows users and services. Connector makes infrastructure know the intelligence that is acting through them.”
Working Architecture Specification — August 2026
1. Executive Summary
Connector OS is conceived as an identity, intelligence-admission, authority, execution-control, and forensic layer for autonomous intelligence. Its purpose is not merely to sandbox an AI model, attach an agent ID to an application, or store a persona in memory. The architecture treats every LLM or other intelligence model as an untrusted/probabilistic intelligence component that must first handshake with N4 before it can participate in a persistent Agent Kernel. Identity, contract, state, continuity, authority, delegation, and evidence remain outside the model so that model weaknesses do not automatically become Agent Kernel weaknesses.
The central separation is: intelligence is not identity, identity is not authority, and authority is not execution. A model may reason about an action, but it does not become an executable agent merely by being connected to tools. N4 first admits, qualifies, normalizes, and contains the intelligence; the Agent Kernel preserves principal identity and contract; QPR decides whether a bounded cognitive proposal may become authority; DockLock and the OS enforce the resulting machine transition.
INTELLIGENCE != IDENTITY != AUTHORITY != EXECUTION != EVIDENCE
Model / intelligence is presented
↓
N4 handshake: identify · qualify · normalize · contain
↓
Qualified intelligence becomes a parameter of Agent Kernel
↓
Agent Principal proves identity + contract + continuity
↓
N4 emits a normalized Cognitive Proposal Object (CPO)
↓
Quanta/Polar Ring authorizes one bounded transition
↓
DockLock + OS enforce the transition
↓
Hardware performs the effect
↓
Witness/Trace layer produces verifiable evidence
The architectural ambition can be summarized as:
Every autonomous agent has a cryptographic identity independent of the underlying LLM model.
The same model weights can instantiate multiple distinct agents without collapsing their identity, authority, history, or accountability.
Every meaningful agent action is constrained by a signed contract and transformed into short-lived, specific execution authority rather than ambient privilege.
A mandatory Quanta/Polar Ring sits between intelligence intent and real-world execution, making identity, contract, continuity, and capability part of authorization itself.
DockLock and lower-level OS controls physically enforce filesystem, process, network, syscall, device, CPU, memory, and execution constraints.
Hardware/OS witnessing gives the agent and auditors a signed view of the environment in which execution actually occurred.
TraceTram and WitnessCTL link intelligence-level causality to process/syscall/machine effects and produce tamper-evident evidence suitable for rigorous forensic workflows.
Every LLM or intelligence model is treated as a replaceable intelligence parameter, not as the operational identity of the agent.
No probabilistic property of a model is allowed to become a security invariant of the Agent Kernel; identity, contract, state, authority, delegation, and evidence are externally maintained.
N4 acts as Gate 1: intelligence admission, qualification, normalization, provenance, context separation, and fault containment before cognition can enter the Agent Kernel.
QPR acts as Gate 2: authorization of a specific normalized cognitive proposal into a short-lived execution quantum. Model output is never authority by itself.
2. The Missing Primitive in Today’s AI Stack
Current AI-agent systems generally inherit identities from the software layers underneath them. An LLM may be told “you are the finance agent,” but the network sees a TLS certificate, Linux sees a UID/PID, Docker sees a container ID, a cloud provider sees an IAM role, and an application sees an API token. These identifiers are usually not bound into one continuous identity for the autonomous intelligence itself.
Current fragmented identity chain
LLM prompt:       "You are Finance Agent"
Agent framework:  agent_17
Runtime:          python PID 8132
Container:        0a9f...
Linux:            uid=1001
Cloud:            role/acme-worker
Network:          cert svc-worker.acme
API:              bearer token xyz...
No single cryptographic principal proves that all of these effects
belong to the same autonomous intelligence under the same contract.
This fragmentation creates seven core real-world execution problems that Connector targets: identity ambiguity, excessive/ambient authority, containment escape, runtime integrity loss, environment/hardware uncertainty, weak agent-to-agent trust, and incomplete accountability/forensics.
3. Core Design Principles
Principle
Meaning in Connector
Identity is infrastructure, not memory
An agent does not become a principal because a system prompt says so. Identity is cryptographically established by the runtime and authority chain.
Reasoning is not authority
The model can decide or propose an action without possessing permission to perform it.
Authority is quantized
Permissions are issued as narrow, short-lived capabilities for specific actions/resources/states rather than long-lived broad credentials.
No trusted self-reporting
Security-sensitive facts about identity, runtime, hardware, permissions, and continuity are provided by the Connector control plane or lower trust anchors, not generated by the model.
Continuity must be provable
An agent that changes materially must not automatically inherit the identity and authority of the previous runtime.
Every boundary crossing is attributable
Network, file, process, tool, device, and agent-to-agent effects preserve the intelligence principal’s provenance.
Execution ends in evidence
A privileged or material action is not complete until it is correlated with a verifiable receipt/evidence record.
4. The Connector Intelligence Principal
The foundational abstraction is an Intelligence Principal / Agent Kernel: a persistent autonomous computational actor with cryptographic identity, signed contract, state, delegated authority, runtime continuity, and evidence history. The LLM or other intelligence model is not the principal. It is admitted through N4 as an intelligence parameter that may be replaced, composed, degraded, or revoked without silently rewriting the principal itself.
SAME MODEL WEIGHTS
│
┌───────────┴───────────┐
▼                       ▼
Agent Principal A       Agent Principal B
ID: CNK:A91F           ID: CNK:B72C
Contract: Dev          Contract: Finance
Owner: Org A           Owner: Org B
Caps: Git/Build        Caps: Ledger/Read
Runtime: QPR-17        Runtime: QPR-42
History: A-chain       History: B-chain
Same intelligence engine; different operational identities.
4.1 Identity Composition
A Connector AgentID should be bound to more than a name. A possible identity envelope includes:
Agent public key / principal identifier.
Issuer or organizational authority.
Model measurement or model-reference hash when measurable.
Agent/runtime code measurement.
Signed Agent Contract hash.
Runtime instance identifier.
Delegation/ownership chain.
Hardware or node witness reference.
Continuity/checkpoint state.
Creation time, expiry policy, and revocation state.
cnktr.self()
principal:        cnktr:agent:A91F...
issuer:           cnktr:org:acme
contract_hash:    C82A...
runtime_hash:     R91D...
model_ref:        M19F...
node_witness:     N07A...
continuity:       VERIFIED
authority_chain:  human:H72C -> org:acme -> agent:A91F
4.2 Cryptographic Self-Awareness, Not Consciousness
The phrase “self-consciousness” should be used carefully. Connector does not need to claim subjective consciousness. The technically defensible concept is cryptographic self-awareness: the agent can query an authoritative runtime interface to learn who it is, what contract governs it, which resources it has, where it is executing, and whether its identity continuity is valid. These facts are produced by trusted runtime components rather than synthesized from model memory.
5. Agent Contract: The Non-Self-Modifiable Constitution
Every Intelligence Principal operates under a signed Agent Contract. The contract defines purpose, capabilities, prohibited operations, resource ceilings, delegation rules, execution environment constraints, expiry, and evidence requirements. The model may reason about the contract, but it cannot grant itself authority by editing the contract text.
agent:
id: cnktr://agent/code-review-71
identity:
issuer: cnktr://org/acme
runtime_measurement: required
purpose:
- inspect_repository
- generate_patch
- run_tests
filesystem:
read:  [/workspace/**]
write: [/workspace/src/**]
deny:  [/etc/**, /secrets/**]
process:
allow: [git, cargo, rustc]
network:
allow: [github.com, registry.internal]
default: deny
hardware:
cpu_max: 2
memory_max: 4GB
gpu: false
privilege:
root: false
raw_device: false
delegation:
create_agents: false
modify_contract: false
evidence:
receipt_required: true
chain_of_custody: true
Changing the contract changes its cryptographic digest and therefore changes the authorization context. A valid contract transition must come from an authorized issuer/delegator, not from the agent’s own text generation.
6. Quanta/Polar Ring (QPR)
The Quanta/Polar Ring is the architecture’s central intelligence-execution boundary. It sits above the conventional OS/kernel in logical placement but must anchor enforcement into lower layers. Its role is to control whether an AI intention is allowed to become a real machine action.
6.1 Why “Quanta”
Authority is not treated as a continuous pool of privilege. The Ring converts intent into a discrete, narrow execution quantum: a signed or internally verifiable capability that authorizes one bounded action under one current state.
Intent: "deploy service-a"
↓
Identity check
Contract check
Continuity check
Context/state check
Resource policy check
↓
Execution Quantum Q921
action: deploy
target: staging/service-a
image: sha256:91f...
cpu: 2
memory: 2GB
network: internal-only
expiry: +90s
nonce: 829AD...
↓
DockLock enforcement
The important security property is that an agent does not permanently “have filesystem access” or “have cloud access.” It receives a scoped right to perform a specific operation, with explicit boundaries and expiry.
6.2 Why “Polar”
Polarization is the decision and transformation stage. Every proposed transition is classified relative to identity, contract, authority, state, provenance, and runtime integrity. Valid intent becomes an executable capability. Invalid or unverifiable intent becomes non-executable, denied, or quarantined.
REQUEST / INTENT
│
▼
POLARIZATION
│
┌───────────┴───────────┐
▼                       ▼
VALID (+)               INVALID (-)
attributable                unverifiable
contract-aligned            out-of-contract
capability-bounded          continuity-broken
executable                  non-executable
6.3 Mandatory Transition Property
The Ring only provides a meaningful security guarantee if supported execution paths cannot bypass it. Therefore every Connector-controlled route to filesystem, process creation, network egress, secrets, devices, agent delegation, and privileged tools must require a QPR-issued authority token or equivalent kernel-enforced state. The objective is “no valid execution without a valid transition,” not merely “most SDK calls pass through middleware.”
7. Layered Runtime Architecture
HUMAN / ORGANIZATION
│
delegated authority / goal
▼
┌────────────────────────────┐
│       AGENT KERNEL         │
│ AgentID · Contract · State │
│ Continuity · Delegation    │
│ Authority · Evidence       │
└─────────────┬──────────────┘
│ intelligence request
▼
╔═════════════▼══════════════╗
║          N4 MATRIX         ║
║ Gate 1: intelligence       ║
║ admission + normalization  ║
║ handshake · provenance     ║
║ capability · context       ║
║ fault containment          ║
╚═════════════╤══════════════╝
│ Cognitive Proposal Object
▼
╔═════════════▼══════════════╗
║      QUANTA/POLAR RING     ║
║ Gate 2: authority          ║
║ identity · contract        ║
║ continuity · capability    ║
║ runtime state · policy     ║
╚═════════════╤══════════════╝
│ Execution Quantum
▼
┌────────────────────────────┐
│          DockLock          │
│ process · syscall · fs     │
│ network · device · secrets │
│ CPU · RAM · GPU · IPC      │
└─────────────┬──────────────┘
│
▼
Linux / OS Kernel
│
▼
CPU / GPU / RAM / NIC / TPM / TEE
│ measurements
▼
WitnessCTL → TraceTram → Cryptographic Evidence
The two-gate separation is fundamental. N4 decides whether and how a probabilistic intelligence may participate in the Agent Kernel; QPR decides whether a particular normalized cognitive proposal is authorized to become a real machine effect. DockLock then makes that authorization physically enforceable. Linux protects computation; Connector protects both the admission of intelligence into an agent and the transition from cognition into computation.
8. DockLock: The Physical Body of the Contract
DockLock is the lower enforcement body of an Intelligence Principal. QPR decides what transition is authorized; DockLock translates that decision into concrete host controls. Existing Connector ideas around deterministic execution, syscall filtering, controlled I/O, receipts, and isolation become especially valuable here.
Boundary
Possible enforcement mechanisms
Process
namespaces, process supervision, executable allowlists, cgroups
Syscall
seccomp-bpf, LSM/eBPF policy hooks where appropriate
Filesystem
mount namespaces, read-only mounts, path capabilities, brokered I/O
Network
network namespaces, egress proxy, mTLS identity, capability-aware service mesh
Secrets
brokered short-lived credentials, hardware/key-store backed signing, no raw master key in model memory
Hardware
device cgroups, GPU/device assignment, attested node/device metadata
Resources
CPU/memory/I/O quotas, time budgets, execution-quantum limits
Evidence
pre/post state hashes, tool/process mapping, signed receipts
9. Execution Reality Manifest: Hardware and OS Truth
---TOTAL_LINES--- 798

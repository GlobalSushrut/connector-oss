#!/usr/bin/env python3
"""Generate Connector OS architecture thesis PDF."""

from pathlib import Path

from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
    ListFlowable,
    ListItem,
)

OUT = Path(__file__).resolve().parent / "CONNECTOR_OS_ARCHITECTURE_THESIS.pdf"

INK = HexColor("#0f172a")
MUTED = HexColor("#334155")
ACCENT = HexColor("#0f766e")
RULE = HexColor("#94a3b8")
SOFT = HexColor("#f1f5f9")
WARN = HexColor("#9a3412")


def styles():
    base = getSampleStyleSheet()
    s = {}
    s["cover_brand"] = ParagraphStyle(
        "cover_brand",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=28,
        textColor=INK,
        alignment=TA_CENTER,
        spaceAfter=8,
        leading=34,
    )
    s["cover_sub"] = ParagraphStyle(
        "cover_sub",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=12,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceAfter=6,
        leading=16,
    )
    s["cover_tag"] = ParagraphStyle(
        "cover_tag",
        parent=base["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=11,
        textColor=ACCENT,
        alignment=TA_CENTER,
        spaceAfter=18,
        leading=15,
    )
    s["h1"] = ParagraphStyle(
        "h1",
        parent=base["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        textColor=INK,
        spaceBefore=4,
        spaceAfter=10,
        leading=20,
    )
    s["h2"] = ParagraphStyle(
        "h2",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12.5,
        textColor=ACCENT,
        spaceBefore=12,
        spaceAfter=6,
        leading=16,
    )
    s["h3"] = ParagraphStyle(
        "h3",
        parent=base["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=INK,
        spaceBefore=8,
        spaceAfter=4,
        leading=14,
    )
    s["body"] = ParagraphStyle(
        "body",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        textColor=INK,
        alignment=TA_JUSTIFY,
        spaceAfter=7,
        leading=13,
    )
    s["bullet"] = ParagraphStyle(
        "bullet",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9.3,
        textColor=INK,
        leftIndent=10,
        spaceAfter=3,
        leading=12.5,
    )
    s["mono"] = ParagraphStyle(
        "mono",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=8,
        textColor=INK,
        leading=11,
        spaceAfter=2,
    )
    s["caption"] = ParagraphStyle(
        "caption",
        parent=base["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceBefore=4,
        spaceAfter=10,
    )
    s["footer"] = ParagraphStyle(
        "footer",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=8,
        textColor=MUTED,
        alignment=TA_CENTER,
    )
    s["pull"] = ParagraphStyle(
        "pull",
        parent=base["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=10,
        textColor=ACCENT,
        alignment=TA_CENTER,
        spaceBefore=8,
        spaceAfter=12,
        leading=14,
        leftIndent=20,
        rightIndent=20,
    )
    return s


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(0.75 * inch, 0.55 * inch, letter[0] - 0.75 * inch, 0.55 * inch)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.75 * inch, 0.35 * inch, "Connector OS — Architecture Thesis")
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.35 * inch, f"{doc.page}")
    canvas.restoreState()


def cover_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawCentredString(
        letter[0] / 2,
        0.5 * inch,
        "Confidential product thesis · try.cnktros.com · cnktros.com",
    )
    canvas.restoreState()


def hr():
    return HRFlowable(width="100%", thickness=0.6, color=RULE, spaceBefore=4, spaceAfter=10)


def bullets(items, st):
    return [
        Paragraph(f"• {t}", st["bullet"]) for t in items
    ]


def comparison_table(st):
    header = [
        Paragraph("<b>Concern</b>", st["mono"]),
        Paragraph("<b>POSIX / Linux process model</b>", st["mono"]),
        Paragraph("<b>Connector MemPacket + agent model</b>", st["mono"]),
    ]
    rows = [
        [
            "Unit of work",
            "Process / thread / file descriptor",
            "Intelligence with PID, principal, charter, budget",
        ],
        [
            "Memory unit",
            "Bytes in address space / files on VFS",
            "Content-addressed MemPacket (3D envelope)",
        ],
        [
            "Identity",
            "UID/GID, capabilities, SELinux labels",
            "AgentID + IntelligenceID + principal mint",
        ],
        [
            "Authority",
            "Kernel capability bits, file mode bits",
            "Admission + PATE/ATU digest + address DAC",
        ],
        [
            "Provenance",
            "Optional auditd / journald (often incomplete)",
            "Provenance plane on every packet (source, trust)",
        ],
        [
            "Revocation",
            "kill(2), revoke FD, remount",
            "Quarantine, broker epoch bump, seal void",
        ],
        [
            "Cross-tenant",
            "User namespaces / containers (host-coupled)",
            "Tenant namespaces + isolated trial sandboxes",
        ],
        [
            "Evidence",
            "Logs that operators can rewrite",
            "CID + hash-chain / WitnessCtl receipts",
        ],
        [
            "LLM I/O",
            "Not a first-class OS object",
            "llm_raw / decision / tool_call packet types",
        ],
        [
            "Secrets to model",
            "Env vars / files often pasted into prompts",
            "Tokenization + sealed context epochs",
        ],
    ]
    data = [header]
    for r in rows:
        data.append([Paragraph(c, st["mono"]) for c in r])
    t = Table(data, colWidths=[1.15 * inch, 2.55 * inch, 2.95 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0f766e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("BACKGROUND", (0, 1), (-1, -1), SOFT),
                ("GRID", (0, 0), (-1, -1), 0.3, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SOFT, white]),
            ]
        )
    )
    return t


def build():
    st = styles()
    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.75 * inch,
        title="Connector OS — Architecture Thesis",
        author="Connector OS",
        subject="MemPacket, cryptography, tokenization, and domain use cases",
    )
    story = []

    # ── COVER ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("CONNECTOR OS", st["cover_brand"]))
    story.append(Paragraph("Architecture Thesis", st["cover_sub"]))
    story.append(
        Paragraph(
            "The operating substrate for governed intelligence — "
            "identity, memory packets, cryptographic custody, and payable proof",
            st["cover_tag"],
        )
    )
    story.append(hr())
    story.append(
        Paragraph(
            "What we built · Why MemPacket replaces improvised agent plumbing · "
            "POSIX contrast · Cryptography &amp; tokenization · "
            "Generalized, finance, military, and blockchain use cases · "
            "Why organizations pay to try and adopt",
            st["cover_sub"],
        )
    )
    story.append(Spacer(1, 0.5 * inch))
    story.append(
        Paragraph(
            "Live trial: <b>https://try.cnktros.com</b> · Product: <b>https://cnktros.com</b>",
            st["cover_sub"],
        )
    )
    story.append(Spacer(1, 0.8 * inch))
    story.append(
        Paragraph(
            "Thesis stance: AI is repeating the pre-kernel era of computing. "
            "Models are transformers of capability; Connector is the switchgear — "
            "identity, isolation, metering, evidence, and revocation for intelligence "
            "that spends money, calls tools, and crosses organizational boundaries.",
            st["pull"],
        )
    )
    story.append(PageBreak())

    # ── 1. WHAT WE BUILT ───────────────────────────────────────────────────
    story.append(Paragraph("1. What We Have Built", st["h1"]))
    story.append(hr())
    story.append(
        Paragraph(
            "Connector OS is a <b>sovereign operating substrate for distributed "
            "intelligence</b>. It is not an LLM, not a chat UI wrapper, and not "
            "another agent framework. It is the layer beneath those things: the "
            "system that turns raw model capability into intelligence that can be "
            "<b>addressed, governed, switched, inspected, revoked, and proven</b>.",
            st["body"],
        )
    )
    story.append(Paragraph("1.1 Product shape", st["h2"]))
    story.append(
        Paragraph(
            "Operators install <b>one node</b> — <font face='Courier'>connector-platform</font> "
            "as the long-running runtime and <font face='Courier'>connectorctl</font> as the "
            "lifecycle CLI — with an embedded operator dashboard. On that node run "
            "agents, Talk/LLM gateway, workflows, plugins (AGOS / <font face='Courier'>.cpkg</font>), "
            "and first-party institutions such as TraceTramp (causal execution graph), "
            "WitnessCtl (hash-chained receipts), and DevGuard (coding-agent cage).",
            st["body"],
        )
    )
    story.extend(
        bullets(
            [
                "<b>Hosted playground</b> at try.cnktros.com — email-gated 90-minute "
                "isolated tenants, demo Talk agent, LLM key paste, five-mode operator rail "
                "(RUN / WATCH / FIX / SETUP / DEV).",
                "<b>Intelligence Identity Architecture (IIA)</b> — principal mint, activation, "
                "charter, compliance contract, forensic envelopes.",
                "<b>VAC / MemoryKernel</b> — content-addressed memory, namespaces, audit, "
                "agent control blocks, registration caps.",
                "<b>Admission &amp; effect path</b> — governed Talk and tools via digest-bound "
                "authority (PATE/ATU), address DAC, HITL, quarantine.",
                "<b>Broker / sealed context</b> — opaque context tokens and epoch keys so the "
                "shared LLM never owns durable agent authority or raw secrets.",
            ],
            st,
        )
    )
    story.append(Paragraph("1.2 The problem statement (why this category exists)", st["h2"]))
    story.append(
        Paragraph(
            "Before operating systems, every program reinvented isolation, identity, "
            "scheduling, and accounting. AI is repeating that era: agents are wired "
            "directly to models, tools, credentials, databases, and networks. Teams "
            "rebuild partial identity, permissions, memory, logs, budgets, and safety. "
            "Systems look capable while lacking reliable answers to: <i>Who acted? Under "
            "whose authority? What information was available? What policy governed the "
            "decision? What changed? Can an independent party reconstruct and verify it?</i>",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "When AI only suggests text, missing substrate can be tolerated. When "
            "intelligence retains memory, spends money, writes infrastructure, delegates "
            "to other agents, or crosses jurisdictions, missing identity becomes missing "
            "accountability; missing authority becomes excessive agency; missing custody "
            "becomes rewriteable history. The world may not require Connector specifically — "
            "but it will require this <b>category</b> of infrastructure.",
            st["body"],
        )
    )
    story.append(PageBreak())

    # ── 2. MEMPACKET VS POSIX ──────────────────────────────────────────────
    story.append(Paragraph("2. Core Packet Data Type — MemPacket vs POSIX", st["h1"]))
    story.append(hr())
    story.append(
        Paragraph(
            "POSIX gave processes a universal abstraction over machines: files, "
            "processes, signals, memory maps. Agents today still lack an equivalent "
            "universal unit. Chat logs, JSON blobs, vector DB rows, and SIEM events "
            "are not the same object — so identity, authority, and evidence fracture. "
            "Connector’s answer is the <b>MemPacket</b>: every agent artifact becomes "
            "one content-addressed, provenance-tracked, authority-wrapped card.",
            st["body"],
        )
    )
    story.append(Paragraph("2.1 What an agent actually gets", st["h2"]))
    story.append(
        Paragraph(
            "In Connector, an agent is not “a prompt plus a tool list.” It receives a "
            "<b>kernel-backed control block</b>, a <b>principal</b>, a <b>namespace</b>, "
            "optional <b>IntelligenceSpec / charter</b>, <b>token budget</b>, and a "
            "stream of MemPackets classified by cognitive function:",
            st["body"],
        )
    )
    story.extend(
        bullets(
            [
                "<b>Packet types:</b> Input, LlmRaw, Extraction, Decision, ToolCall, "
                "ToolResult, Action, Feedback, Contradiction, StateChange.",
                "<b>Memory types:</b> Working, Episodic, Semantic, Procedural, Relational, "
                "Reflective, Evidentiary — orthogonal to hot/warm/cold storage tiers.",
                "<b>Cognitive paths:</b> filesystem-like addresses such as "
                "<font face='Courier'>/entity/{pid}/memory/{type}/</font> and "
                "<font face='Courier'>/entity/{pid}/actions/</font>.",
                "<b>Three planes:</b> Content (what), Provenance (where from / trust), "
                "Authority (who authorized) — plus an Index for storage location.",
                "<b>Graph links &amp; trust score:</b> causal/semantic links between packets; "
                "inherited trust from source agent or tool.",
            ],
            st,
        )
    )
    story.append(Paragraph("2.2 Why POSIX alone is not enough for intelligence", st["h2"]))
    story.append(
        Paragraph(
            "POSIX process isolation answers “can this binary touch that file?” It does "
            "not answer “may this intelligence spend $X citing memory CID Y under mission "
            "Z after human approval of digest D?” LLM I/O is not a first-class OS object "
            "in Linux. File ACLs do not express broker epochs. <font face='Courier'>kill(2)</font> "
            "stops a process; it does not void sealed context already pasted into a vendor "
            "model. MemPacket + admission is the missing abstraction layer between "
            "probabilistic models and irreversible world effects.",
            st["body"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(comparison_table(st))
    story.append(
        Paragraph(
            "Table 1 — Process OS vs Intelligence OS: what the unit of governance is.",
            st["caption"],
        )
    )
    story.append(Paragraph("2.3 Why we need a packet type (engineering thesis)", st["h2"]))
    story.append(
        Paragraph(
            "Without a universal packet: (1) <b>audit is optional</b> — teams log when "
            "convenient; (2) <b>memory poisoning</b> has no typed quarantine surface; "
            "(3) <b>tool calls</b> are free-form JSON with no digest-bound HITL; "
            "(4) <b>cross-agent handoff</b> cannot carry authority envelopes; "
            "(5) <b>regulators</b> cannot demand a single reconstructable artifact. "
            "MemPacket makes every step of “intent → model → tool → world” the same "
            "kind of object — so policy, retrieval, and evidence share one schema. "
            "That is the difference between “we have logs” and “we have a kernel object.”",
            st["body"],
        )
    )
    story.append(PageBreak())

    # ── 3. CRYPTO + TOKENIZATION ───────────────────────────────────────────
    story.append(Paragraph("3. Cryptography &amp; Tokenization Side of the Software", st["h1"]))
    story.append(hr())
    story.append(
        Paragraph(
            "Connector treats the LLM as <b>untrusted probabilistic substrate</b>. "
            "Useful for generation; never the owner of identity, secrets, or durable "
            "authority. Cryptography and tokenization exist to enforce that stance "
            "even when prompts leak, clients are compromised, or operators are hostile.",
            st["body"],
        )
    )
    story.append(Paragraph("3.1 Content addressing &amp; custody", st["h2"]))
    story.extend(
        bullets(
            [
                "<b>CIDs</b> on packet payloads — memory is addressable by content, not by "
                "mutable row IDs that can be silently overwritten.",
                "<b>Audit / receipt chains</b> (WitnessCtl alignment) — hash-linked evidence "
                "intended to survive distrust of the producing operator.",
                "<b>Activation &amp; compliance digests</b> — setup/activation profiles bind "
                "capability manifests so “what this agent may do” is measurable.",
                "<b>Machine / license fingerprints</b> — node-bound licensing and integrity "
                "paths for commercial and air-gapped deployments.",
            ],
            st,
        )
    )
    story.append(Paragraph("3.2 LLM context broker &amp; sealed epochs", st["h2"]))
    story.append(
        Paragraph(
            "Talk injects <b>opaque context tokens</b> (<font face='Courier'>ctx_tok_…</font>) "
            "rather than dumping full who-am-I plaintext into every vendor request when "
            "broker mode is enforced. Generation numbers bind agent identity to a live "
            "epoch. <b>Quarantine / revoke bumps generation and voids tokens</b> — prior "
            "prompt text cannot authorize later effects. Advanced sealed context uses "
            "per-(agent, generation) keys so the model receives semantic cards and seal "
            "references without owning durable plaintext secrets.",
            st["body"],
        )
    )
    story.append(Paragraph("3.3 Tokenization of sensitive data", st["h2"]))
    story.append(
        Paragraph(
            "Before strings reach the model brain, Connector can <b>tokenize / seal</b> "
            "emails, keys, URLs, and other sensitive shapes — then refuse tool arguments "
            "that invent raw secrets past the broker. Residual redaction protects opaque "
            "spans. This is the software analog of a vault proxy: the probabilistic "
            "component plans; the kernel retains custody of the real identifiers.",
            st["body"],
        )
    )
    story.append(Paragraph("3.4 Why crypto matters commercially", st["h2"]))
    story.append(
        Paragraph(
            "Buyers do not pay for “another chat UI.” They pay when leakage becomes "
            "existential: regulated PII in prompts, trading keys in agent memory, "
            "mission data in vendor logs, or unprovable agent actions in litigation. "
            "Cryptographic custody converts marketing claims (“we take security "
            "seriously”) into <b>fail-closed mechanisms</b> — epochs, digests, seals, "
            "and receipts that auditors and courts can examine.",
            st["body"],
        )
    )
    story.append(PageBreak())

    # ── 4. USE CASES ───────────────────────────────────────────────────────
    story.append(Paragraph("4. Important Use Cases", st["h1"]))
    story.append(hr())

    story.append(Paragraph("4.1 Generalized enterprise &amp; product teams", st["h2"]))
    story.append(
        Paragraph(
            "Any organization shipping agents into CRM, support, coding, ops, or "
            "knowledge work hits the same wall: uncontrolled tool use, shared "
            "API keys, no tenant isolation, and “who deleted the customer record?” "
            "with only Slack archaeology. Connector gives a <b>shared node</b> where "
            "agents are tenants, Talk is admitted, tools are proposals until DAL/PATE "
            "allows, and Fix/HITL is a first-class rail — not a ticket after the breach.",
            st["body"],
        )
    )
    story.extend(
        bullets(
            [
                "Internal copilots that may read tickets but cannot exfiltrate secrets.",
                "Multi-team agent fleets with per-tenant namespaces and budgets.",
                "Vendor playground / PoC in 90 minutes without installing a lab cluster.",
            ],
            st,
        )
    )

    story.append(Paragraph("4.2 Finance &amp; markets", st["h2"]))
    story.append(
        Paragraph(
            "Finance already has settlement rails, trade surveillance, and model risk "
            "governance — but agentic systems break those assumptions by acting "
            "continuously and non-deterministically. MemPacket + evidentiary memory "
            "types map to <b>who authorized a trade-adjacent action</b>, what "
            "context was retrieved, and whether human digest approval existed. "
            "Token budgets and economy gates meter spend; quarantine stops a "
            "runaway agent mid-generation. Tokenization keeps account numbers and "
            "PII out of vendor LLM logs while still allowing the model to reason "
            "over sealed references.",
            st["body"],
        )
    )
    story.extend(
        bullets(
            [
                "Agent-assisted research with citation-bound memory CIDs.",
                "Ops agents that propose but do not wire payments without HITL digests.",
                "Audit packages for model risk / FINRA-style supervision narratives.",
            ],
            st,
        )
    )

    story.append(Paragraph("4.3 Military, defense &amp; high-assurance ops", st["h2"]))
    story.append(
        Paragraph(
            "Defense buyers need air-gap and VPC installability, explicit processes, "
            "and evidence that survives operator distrust. Connector’s constitutional "
            "stance — one installable node, local/edge operation, content addressing, "
            "revocation — matches that world better than SaaS-only agent clouds. "
            "Agents become <b>addressable intelligences with kill-switches</b>, not "
            "chat sessions. Isolation profiles (subprocess → microVM direction), "
            "egress cages, and forensic envelopes support after-action reconstruction. "
            "Honesty matters: playground grades are never greenwashed to “military "
            "court”; the substrate aims at court-defensible identity and custody "
            "paths that enterprises and defense programs can harden further.",
            st["body"],
        )
    )

    story.append(Paragraph("4.4 Blockchain, crypto, and on-chain / off-chain bridges", st["h2"]))
    story.append(
        Paragraph(
            "Blockchains already solved <b>append-only shared state</b> for value "
            "transfer. They did not solve <b>governed off-chain intelligence</b> that "
            "decides when to sign, when to bridge, or when to call a custodian API. "
            "Agents that hold keys or propose transactions need: principal identity, "
            "policy before signature, sealed secrets, and replayable decision packets. "
            "Connector sits beside chain infrastructure as the <b>intelligence OS</b>: "
            "MemPackets record decisions and tool calls; WitnessCtl-style receipts "
            "bind off-chain intent to on-chain effects; quarantine voids broker epochs "
            "if an agent is compromised — without requiring a chain reorg.",
            st["body"],
        )
    )
    story.extend(
        bullets(
            [
                "Treasury / ops agents that cannot raw-export seed material into prompts.",
                "Compliance bots that propose freezes with digest-bound human approval.",
                "Cross-org agent meshes where CNP-style routing carries governed effects.",
            ],
            st,
        )
    )

    story.append(Paragraph("4.5 Additional high-value domains", st["h2"]))
    story.extend(
        bullets(
            [
                "<b>Healthcare / life sciences</b> — HIPAA-oriented gates, BAA-aware "
                "routing, evidentiary packets for clinical decision support (human remains "
                "the clinical authority; substrate preserves custody).",
                "<b>Software engineering platforms</b> — DevGuard-class cages so coding "
                "agents cannot silently push secrets or escape the workspace.",
                "<b>Critical infrastructure / ICS-adjacent ops</b> — effects exclusivity, "
                "HITL for high-impact tools, reconstructable timelines.",
                "<b>Public sector / regulated AI Act paths</b> — record-keeping and "
                "provenance planes aligned with “logging of high-risk systems” needs.",
                "<b>Multi-vendor agent ecosystems</b> — plugins and workflows as apps on "
                "one kernel, not twenty bespoke permission models.",
            ],
            st,
        )
    )
    story.append(PageBreak())

    # ── 5. WHY PAY ─────────────────────────────────────────────────────────
    story.append(Paragraph("5. Why Anyone Will Pay Money to Try — and Buy", st["h1"]))
    story.append(hr())
    story.append(
        Paragraph(
            "Willingness to pay follows from <b>asymmetric downside</b>. One "
            "ungoverned agent with a production API key can create more loss in an "
            "afternoon than a year of Connector licenses. Buyers trial when the "
            "cost of learning is low (hosted playground) and the cost of ignorance "
            "is high (breach, fine, failed audit, wrongful autonomous action).",
            st["body"],
        )
    )
    story.append(Paragraph("5.1 What the trial proves in 90 minutes", st["h2"]))
    story.extend(
        bullets(
            [
                "An isolated tenant of the same software — not a mocked demo skin.",
                "A real demo agent with Talk, identity chips, and operator rails.",
                "That LLM keys can be pasted and routed without giving the model "
                "ownership of the node.",
                "That the product vocabulary (RUN / WATCH / FIX / SETUP / DEV) maps "
                "to identity, evidence, and remediation — not vanity dashboards.",
            ],
            st,
        )
    )
    story.append(Paragraph("5.2 Economic argument (buyer logic)", st["h2"]))
    story.append(
        Paragraph(
            "<b>Replace rebuild cost.</b> Every serious agent program eventually "
            "rebuilds identity, authz, memory isolation, audit, budgets, and HITL. "
            "That rebuild is months of senior engineering and still usually fails "
            "court/audit tests. Connector sells the substrate category as "
            "<b>installable software</b> — one node, operator-owned — so teams buy "
            "time-to-governed-production instead of time-to-demo-chat.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Insurance against probabilistic systems.</b> Models will keep "
            "improving; liability grows with autonomy. Cryptographic custody, "
            "digest-bound approval, and quarantine are the difference between "
            "“we used AI” and “we can prove what the AI was allowed to do.” "
            "That proof is what CISOs, compliance, and procurement actually fund.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Platform leverage.</b> Plugins, workflows, and multi-agent meshes "
            "compound on a kernel. Buyers pay for a substrate that becomes more "
            "valuable as they attach TraceTramp/WitnessCtl-class institutions and "
            "third-party AGOS packages — analogous to paying for Linux rather than "
            "rewriting process isolation per application.",
            st["body"],
        )
    )
    story.append(Paragraph("5.3 Competitive honesty", st["h2"]))
    story.append(
        Paragraph(
            "Connector does not claim to be the model. It claims to be the "
            "<b>operating layer that makes models deployable where trust is "
            "mandatory</b>. Frameworks optimize developer velocity to first demo. "
            "Observability products watch after the fact. SaaS agent clouds "
            "centralize custody. Connector’s thesis is: sovereignty + packets + "
            "admission + evidence, on hardware you control, with a path from "
            "90-minute trial to production node.",
            st["body"],
        )
    )
    story.append(PageBreak())

    # ── 6. CLOSING ─────────────────────────────────────────────────────────
    story.append(Paragraph("6. Closing Thesis", st["h1"]))
    story.append(hr())
    story.append(
        Paragraph(
            "Electric grids needed transformers, switches, metering, and protection "
            "before raw power became universally useful. Intelligence needs the same "
            "class of infrastructure. <b>MemPacket</b> is the voltmeter and the "
            "wire label. <b>Admission and broker epochs</b> are the switchgear. "
            "<b>Cryptographic custody and tokenization</b> are the locked substations "
            "that keep secrets out of the public feeder. Finance, military, "
            "blockchain, healthcare, and general enterprise are not separate products — "
            "they are load profiles on the same substrate.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "What we have built is that substrate in runnable form: a single "
            "Connector OS node, a hosted trial that proves the loop, and a "
            "packetized memory and identity architecture that POSIX never had to "
            "invent because processes were not probabilistic, tool-calling, "
            "cross-tenant intelligences. Organizations will pay to try because "
            "the alternative is improvising a kernel under production fire — "
            "and because a ninety-minute sandbox is cheaper than a single "
            "ungoverned agent with a live credential.",
            st["body"],
        )
    )
    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "“The world may not require Connector OS specifically. It will require "
            "the category of infrastructure Connector is attempting to define.”",
            st["pull"],
        )
    )
    story.append(
        Paragraph(
            "— Connector constitutional preamble",
            st["caption"],
        )
    )
    story.append(Spacer(1, 20))
    story.append(hr())
    story.append(
        Paragraph(
            "Document: Connector OS Architecture Thesis · Grounded in MemPacket "
            "(vac-core), constitutional preamble, and live playground at "
            "try.cnktros.com · Generated for depth briefing, not marketing fluff.",
            st["caption"],
        )
    )

    doc.build(story, onFirstPage=cover_footer, onLaterPages=footer)
    return OUT


if __name__ == "__main__":
    path = build()
    print(path)
    print(f"bytes={path.stat().st_size}")

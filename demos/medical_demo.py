#!/usr/bin/env python3
"""
Connector Platform — Enterprise Medical AI Demo
16 slides demonstrating real platform + DeepSeek LLM

Architecture:
- DeepSeek LLM with medical knowledge injected as system prompt
- Real Connector platform APIs (agents, memory, audit, books)
- Zero hardcoded text - all output from LLM or raw kernel JSON

Usage:
    export DEEPSEEK_API_KEY=sk-...
    export CONNECTOR_DEV_MODE=1
    python medical_demo.py              # all 16 slides
    python medical_demo.py 5            # single slide
    python medical_demo.py 5 11         # slide range
"""

import sys
import json
from llm import DeepSeekLLM
from system_data import ConnectorPlatform

llm = DeepSeekLLM()
platform = ConnectorPlatform()


def slide_1_market_analysis():
    """Slide 1: Healthcare AI Market Analysis (LLM writes everything)"""
    prompt = """You are a healthcare industry analyst presenting to hospital CIOs and VCs.
    
Write a 200-word executive summary of the 2024-2025 healthcare AI market covering:
- Physician documentation burden (hours per day, % of time)
- Prior authorization delays (average days, denial rates)
- Medical error costs ($ billions annually)
- Why infrastructure-grade AI agents are needed now
- Market size and growth projections

Use specific 2024 data. Be compelling but factual."""

    result = llm.generate(prompt, max_tokens=400)
    return result  # Pure LLM output


def slide_2_competitive_landscape():
    """Slide 2: Why Existing Solutions Fail (LLM writes critique)"""
    prompt = """You are a healthcare CTO evaluating AI solutions. Write a critical 250-word analysis of why existing healthcare AI solutions fail:

- Black box models → no clinical trust
- Missing audit trails → compliance risk
- Security vulnerabilities (prompt injection, data leakage)
- No persistent memory → context loss between interactions
- Vendor lock-in → integration nightmares

Be technical but accessible. Cite specific failure modes."""

    result = llm.generate(prompt, max_tokens=500)
    return result  # Pure LLM output


def slide_3_architecture():
    """Slide 3: Platform Architecture (LLM writes with ASCII diagram)"""
    prompt = """You are a solutions architect. Describe the Connector Platform architecture for healthcare AI in 300 words:

Components to explain:
- Memory Kernel (CID-addressed, bi-temporal)
- Knowledge Graph (Kafka-style ingestion)
- Audit Trail (HMAC-signed, tamper-proof)
- Compliance Engine (HIPAA, EU AI Act, SOC2)
- CLS Contracts (declarative governance)
- Guard Pipeline (5-layer security)

Include an ASCII diagram showing how these enable 7 medical use cases.
Explain why this is infrastructure-grade vs typical AI wrappers."""

    result = llm.generate(prompt, max_tokens=600)
    return result  # Pure LLM output


def slide_4_demo_intro():
    """Slide 4: Demo Roadmap (LLM writes intro)"""
    prompt = """You are presenting a live demo. Write an engaging 200-word introduction to a 7-use-case medical AI demo:

What the audience will see:
- Real DeepSeek LLM responses (not mocks)
- Live compliance verification from running platform
- ROI calculations for each use case
- Raw system audit logs and receipts

Emphasize:
- Each use case is a payable product ($500-2000/month)
- Total physician time saved: 15+ hours/week
- Real medical scenarios, not toy examples
- Platform is running live, not slides

Build excitement while staying professional."""

    result = llm.generate(prompt, max_tokens=400)
    return result  # Pure LLM output


def slide_5_clinical_documentation():
    """Slide 5: Clinical Documentation Assistant (LLM generates scenario + SOAP note)"""
    
    # Step 1: LLM generates patient scenario
    scenario_prompt = """Generate a realistic patient encounter for a 45-year-old male presenting to the ER with chest pain.

Include:
- Chief complaint
- History of present illness (OLDCARTS format)
- Vital signs (BP, HR, RR, SpO2, Temp)
- Relevant physical exam findings
- Brief medical history

Make it clinically realistic with enough detail for a SOAP note. 150 words."""

    scenario_result = llm.generate(scenario_prompt, max_tokens=300)

    # Step 2: LLM processes scenario into SOAP note
    soap_prompt = f"""You are a clinical documentation AI. Convert this patient encounter into a structured SOAP note:

{scenario_result["content"]}

Format:
S: Subjective (CC, HPI, ROS if relevant)
O: Objective (vitals, physical exam, labs if mentioned)
A: Assessment (primary diagnosis with ICD-10, differential diagnoses)
P: Plan (workup, medications, disposition)

Be thorough and professional. Use medical terminology."""

    soap_result = llm.generate(soap_prompt, max_tokens=600)

    # Step 3: Get books position (raw system data)
    books = platform.get_books_position()

    # Step 4: LLM calculates ROI
    roi_prompt = f"""Calculate ROI for this clinical documentation use case:

Manual SOAP note: 12 minutes average
AI processing time: {soap_result['meta']['latency_ms']}ms
Physician hourly rate: $200
Notes per day: 20

Show:
- Time saved per note
- Time saved per day
- Cost savings per day
- Annual savings per physician

Be specific with calculations."""

    roi_result = llm.generate(roi_prompt, max_tokens=300)

    # Return: LLM outputs + raw system data only
    return [
        scenario_result["content"],
        soap_result["content"],
        books,
        roi_result["content"],
        scenario_result["meta"],
        soap_result["meta"],
        roi_result["meta"]
    ]


def slide_6_prior_authorization():
    """Slide 6: Prior Authorization Automation"""
    
    # Step 1: LLM generates PA scenario
    pa_prompt = """Generate a prior authorization scenario:
Patient needs MRI lumbar spine for chronic lower back pain with radiculopathy.
Insurance requires medical necessity documentation.
Include: patient demographics, diagnosis, symptoms duration, conservative treatments tried.
150 words."""

    pa_scenario = llm.generate(pa_prompt, max_tokens=300)

    # Step 2: Query knowledge base for guidelines
    kb_results = platform.search_memory(
        ns="k/medical",
        query="MRI lumbar spine medical necessity criteria radiculopathy",
        top_k=3
    )

    # Step 3: LLM generates PA request
    pa_request_prompt = f"""You are a medical authorization specialist. Write a prior authorization request:

Scenario: {pa_scenario['content']}

Guidelines from knowledge base: {json.dumps(kb_results, indent=2)}

Include:
- Patient demographics and insurance
- Diagnosis with ICD-10
- Clinical history and exam findings
- Conservative treatments attempted (PT, NSAIDs, duration)
- Medical necessity justification citing guidelines
- Requested service with CPT code

Professional medical format."""

    pa_request = llm.generate(pa_request_prompt, max_tokens=800)

    # Step 4: ROI calculation
    roi_prompt = """Calculate ROI for prior authorization automation:

Manual PA: 2 days average (staff time + waiting)
AI PA: 3 minutes
Denial rate manual: 30%
Denial rate AI-assisted: 15% (better documentation)
PAs per week: 50

Show time saved and denial reduction impact."""

    roi = llm.generate(roi_prompt, max_tokens=300)

    # Return: LLM outputs + raw system data only
    return [
        pa_scenario["content"],
        kb_results,
        pa_request["content"],
        roi["content"],
        pa_scenario["meta"],
        pa_request["meta"],
        roi["meta"]
    ]


def slide_7_differential_diagnosis():
    """Slide 7: Differential Diagnosis Assistant"""
    
    # Step 1: LLM generates clinical case
    case_prompt = """Generate a complex clinical case presenting to the ER:
Patient with fever (101.5°F), fatigue, joint pain (bilateral knees and wrists).
Include: age, gender, relevant history, exam findings, initial labs.
Make it diagnostically challenging. 150 words."""
    
    case = llm.generate(case_prompt, max_tokens=300)
    
    # Step 2: Query knowledge graph
    kg_results = platform.search_memory(
        ns="k/medical",
        query="fever fatigue arthralgia differential diagnosis autoimmune infectious",
        top_k=10
    )
    
    # Step 3: LLM generates differential diagnosis
    ddx_prompt = f"""You are an expert diagnostician. Given this case and knowledge base, provide a ranked differential diagnosis:

Case: {case["content"]}

Knowledge Base: {json.dumps(kg_results, indent=2)}

For each diagnosis (top 5):
- Diagnosis name with ICD-10
- Likelihood percentage
- Supporting evidence from case
- Distinguishing features
- Next diagnostic steps

Cite knowledge base sources."""
    
    ddx = llm.generate(ddx_prompt, max_tokens=1000)
    
    # Step 4: ROI calculation
    roi_prompt = """Calculate diagnostic error reduction:
Baseline diagnostic error rate: 5-10%
AI-assisted error rate: 3-7% (30% reduction)
Cases per day: 50
Cost of diagnostic error: $50,000 average

Show annual error reduction and cost savings."""
    
    roi = llm.generate(roi_prompt, max_tokens=300)
    
    return [
        case["content"],
        kg_results,
        ddx["content"],
        roi["content"],
        case["meta"],
        ddx["meta"],
        roi["meta"]
    ]


def slide_8_lab_triage():
    """Slide 8: Lab Result Triage"""
    
    # Step 1: LLM generates lab scenario
    lab_prompt = """Generate critical lab results for ER patient:
Troponin elevated (0.8 ng/mL), Potassium 6.2 mEq/L, Creatinine 3.5 mg/dL.
Include: patient demographics, current symptoms, medications.
150 words."""
    
    lab_scenario = llm.generate(lab_prompt, max_tokens=300)
    
    # Step 2: Query reference ranges
    ref_ranges = platform.search_memory(
        ns="k/medical",
        query="troponin potassium creatinine critical values reference ranges",
        top_k=5
    )
    
    # Step 3: LLM performs triage
    triage_prompt = f"""You are an ER triage AI. Analyze these labs:

Labs: {lab_scenario["content"]}

Reference Ranges: {json.dumps(ref_ranges, indent=2)}

Provide:
- Critical value identification
- Urgency level (1-5, 5=life-threatening)
- Immediate actions required
- Who to notify (attending, cardiology, nephrology)
- Timeframe for intervention

Medical emergency format."""
    
    triage = llm.generate(triage_prompt, max_tokens=600)
    
    # Step 4: Get books position
    books = platform.get_books_position()
    
    # Step 5: ROI
    roi_prompt = """Calculate time savings:
Manual triage: 4-6 hours average
AI triage: 2 minutes
Critical results per day: 20

Show time to notification improvement and lives potentially saved."""
    
    roi = llm.generate(roi_prompt, max_tokens=300)
    
    return [
        lab_scenario["content"],
        ref_ranges,
        triage["content"],
        books,
        roi["content"],
        lab_scenario["meta"],
        triage["meta"],
        roi["meta"]
    ]


def slide_9_med_reconciliation():
    """Slide 9: Medication Reconciliation"""
    
    # Step 1: LLM generates med lists
    med_prompt = """Generate 3 medication lists for same patient:
1. Home medications (5 drugs)
2. Hospital admission meds (6 drugs, 2 changes from home)
3. Discharge meds (5 drugs, 1 dangerous interaction)

Include drug names, doses, frequencies. Make discrepancies realistic."""
    
    med_lists = llm.generate(med_prompt, max_tokens=500)
    
    # Step 2: Query drug database
    drug_db = platform.search_memory(
        ns="k/medical",
        query="drug interactions contraindications warfarin NSAIDs ACE inhibitors",
        top_k=10
    )
    
    # Step 3: LLM reconciles
    recon_prompt = f"""You are a clinical pharmacist. Reconcile these medication lists:

Lists: {med_lists["content"]}

Drug Database: {json.dumps(drug_db, indent=2)}

Provide:
- Discrepancies identified (added, removed, dose changes)
- Drug interactions flagged with severity
- Contraindications
- Final reconciled list with rationale
- Pharmacist recommendations

Clinical format."""
    
    reconciliation = llm.generate(recon_prompt, max_tokens=800)
    
    # Step 4: ROI
    roi_prompt = """Calculate ROI:
Manual reconciliation: 45 minutes
AI reconciliation: 3 minutes
Med error rate manual: 50%
Med error rate AI-assisted: 10%
Reconciliations per day: 30

Show time saved and error reduction."""
    
    roi = llm.generate(roi_prompt, max_tokens=300)
    
    return [
        med_lists["content"],
        drug_db,
        reconciliation["content"],
        roi["content"],
        med_lists["meta"],
        reconciliation["meta"],
        roi["meta"]
    ]


def slide_10_trial_matching():
    """Slide 10: Clinical Trial Matching"""
    
    # Step 1: LLM generates patient profile
    patient_prompt = """Generate cancer patient profile:
62-year-old female, stage III breast cancer, ER+/PR+/HER2-.
Prior treatments: surgery, adjuvant chemo (AC-T completed 6 months ago).
Comorbidities: controlled hypertension, hypothyroidism.
ECOG 1.
150 words."""
    
    patient = llm.generate(patient_prompt, max_tokens=300)
    
    # Step 2: Query trials database
    trials = platform.search_memory(
        ns="k/medical",
        query="breast cancer ER positive HER2 negative clinical trials phase 2 3",
        top_k=15
    )
    
    # Step 3: LLM screens eligibility
    matching_prompt = f"""You are a clinical research coordinator. Screen this patient for trials:

Patient: {patient["content"]}

Trials: {json.dumps(trials, indent=2)}

For top 5 matching trials:
- Trial ID and name
- Eligibility assessment (met/not met criteria)
- Inclusion criteria matched
- Exclusion criteria concerns
- Suitability score (0-100)
- Enrollment recommendation

Clinical trials format."""
    
    matching = llm.generate(matching_prompt, max_tokens=1000)
    
    # Step 4: ROI
    roi_prompt = """Calculate enrollment impact:
Baseline enrollment rate: <5%
AI-assisted enrollment: 15% (3x improvement)
Eligible patients per month: 100
Trial recruitment acceleration: 60%

Show enrollment increase and trial completion timeline impact."""
    
    roi = llm.generate(roi_prompt, max_tokens=300)
    
    return [
        patient["content"],
        trials,
        matching["content"],
        roi["content"],
        patient["meta"],
        matching["meta"],
        roi["meta"]
    ]


def slide_11_radiology_reports():
    """Slide 11: Radiology Report Generation"""
    
    # Step 1: LLM generates imaging findings
    findings_prompt = """Generate chest CT findings:
2.3cm spiculated nodule in right upper lobe, SUL location.
Mediastinal lymphadenopathy (station 4R, 1.8cm short axis).
No pleural effusion, no bone lesions.
Include technical details (slice thickness, contrast, window settings).
150 words."""
    
    findings = llm.generate(findings_prompt, max_tokens=300)
    
    # Step 2: Query radiology knowledge
    rad_kb = platform.search_memory(
        ns="k/medical",
        query="lung nodule spiculated malignancy criteria Fleischner Lung-RADS",
        top_k=8
    )
    
    # Step 3: LLM generates structured report
    report_prompt = f"""You are a radiologist. Write a complete radiology report:

Findings: {findings["content"]}

Knowledge Base: {json.dumps(rad_kb, indent=2)}

Report sections:
- TECHNIQUE
- COMPARISON (if any)
- FINDINGS (systematic, detailed)
- IMPRESSION (numbered, most significant first)
- RECOMMENDATIONS (follow-up, biopsy, staging)

Use standard radiology terminology and Lung-RADS classification."""
    
    report = llm.generate(report_prompt, max_tokens=800)
    
    # Step 4: Get books position
    books = platform.get_books_position()
    
    # Step 5: ROI
    roi_prompt = """Calculate ROI:
Manual report: 20 minutes
AI draft: 2 minutes + 5 minutes radiologist review = 7 minutes total
Reports per day: 40
Throughput improvement: 65%

Show time saved and capacity increase."""
    
    roi = llm.generate(roi_prompt, max_tokens=300)
    
    return [
        findings["content"],
        rad_kb,
        report["content"],
        books,
        roi["content"],
        findings["meta"],
        report["meta"],
        roi["meta"]
    ]


def slide_12_compliance():
    """Slide 12: Live Compliance Verification (Real system data + LLM analysis)"""
    
    # Step 1: Get books position
    books_data = platform.get_books_position()
    
    # Step 2: Get books position
    books = platform.get_books_position()
    
    # Step 3: LLM analyzes compliance
    compliance_prompt = f"""You are a compliance officer. Analyze this system data for HIPAA, EU AI Act, and SOC2 compliance:

Books Position:
{json.dumps(books_data, indent=2)}

Books Journal:
{json.dumps(books, indent=2)}

For each standard (HIPAA, EU AI Act, SOC2), explain:
- Which controls are satisfied
- What evidence proves compliance
- Any gaps or concerns

Be specific about:
- Audit trail integrity (HMAC signatures)
- Encryption (at rest, in transit)
- Access controls
- Human oversight mechanisms

Executive summary format, 400 words."""

    analysis = llm.generate(compliance_prompt, max_tokens=800)

    # Return: Raw system data + LLM analysis only
    return [
        books_data,
        books,
        analysis["content"],
        analysis["meta"]
    ]


def slide_13_explainability():
    """Slide 13: Explainability - Cognitive Substrate"""
    
    # Step 1: Get audit log and books journal from platform
    audit = platform.get_audit_log(limit=20)
    journal = platform.get_books_journal()
    
    # Step 2: LLM explains the cognitive process
    explain_prompt = f"""You are an AI researcher explaining to a healthcare executive.

System Data:
Audit Log: {json.dumps(audit, indent=2)}
Journal: {json.dumps(journal, indent=2)}

Explain how the Connector cognitive substrate makes AI explainable vs black box:

1. 11-Layer Thought Process:
   - Perception → Meaning → Tension → Knowledge → Possibility
   - Evaluation → Expertise → Commitment → Plan → Exposure → Reflection

2. Why This Matters for Clinical Trust:
   - Every decision traces to source
   - Citation chain proves reasoning
   - Audit trail shows full process
   - Human oversight points visible

3. Contrast with Black Box Models:
   - No "the AI said so" - full reasoning visible
   - Regulatory compliance (EU AI Act transparency)
   - Clinical liability protection

400 words, executive-friendly."""
    
    explanation = llm.generate(explain_prompt, max_tokens=800)
    
    return [
        audit,
        journal,
        explanation["content"],
        explanation["meta"]
    ]


def slide_14_security():
    """Slide 14: Security Architecture - 5-Layer Guard Pipeline"""
    
    # Step 1: Get books position
    books_data = platform.get_books_position()
    
    # Step 2: Get books journal
    books = platform.get_books_journal()
    
    # Step 3: LLM explains security architecture
    security_prompt = f"""You are a security architect presenting to a CISO.

System Data:
Books Position: {json.dumps(books_data, indent=2)}
Books Journal: {json.dumps(books, indent=2)}

Explain the 5-layer guard pipeline:

1. Layer 1 - MAC (Bell-LaPadula + Biba):
   - Prevents data leakage (no write-down)
   - Prevents contamination (no write-up without grant)
   - Integer security levels, deterministic

2. Layer 2 - Policy Engine:
   - RBAC + ABAC combined
   - Context-aware decisions
   - Deny-overrides composition

3. Layer 3 - Content Guard:
   - Prompt injection detection
   - PII scanning and redaction
   - Jailbreak attempt blocking

4. Layer 4 - Circuit Breaker:
   - Rate limiting per agent
   - Anomaly detection
   - Auto-isolation on suspicious behavior

5. Layer 5 - Audit + HITL:
   - Every operation logged with HMAC
   - Human-in-loop for high-risk ops
   - Tamper-proof receipt chain

Show how this prevents:
- Prompt injection attacks
- RAG poisoning
- Data exfiltration
- Unauthorized escalation

450 words, technical but clear."""
    
    security_analysis = llm.generate(security_prompt, max_tokens=900)
    
    return [
        books_data,
        books,
        security_analysis["content"],
        security_analysis["meta"]
    ]


def slide_15_integration():
    """Slide 15: Enterprise Integration"""
    
    # Step 1: Get system metrics
    metrics = platform.get_system_metrics()
    
    # Step 2: Get agent list
    agents = platform.list_agents()
    
    # Step 3: Get books position
    books = platform.get_books_position()
    
    # Step 4: LLM writes integration architecture
    integration_prompt = f"""You are a solutions architect presenting to a CTO.

System Metrics:
{json.dumps(metrics, indent=2)}

Active Agents:
{json.dumps(agents, indent=2)}

Books Position:
{json.dumps(books, indent=2)}

Write a technical integration guide covering:

1. EHR Integration:
   - HL7 FHIR R4 APIs
   - Epic, Cerner, Meditech connectors
   - Bidirectional sync patterns
   - Real-time vs batch processing

2. Deployment Options:
   - On-premises (Kubernetes, Docker)
   - Cloud (AWS, Azure, GCP)
   - Hybrid (edge + cloud)
   - Air-gapped environments (HIPAA/DoD)

3. Scalability:
   - Horizontal scaling (add nodes)
   - Load balancing strategies
   - Multi-region deployment
   - Current metrics show capacity for X agents

4. Monitoring & Observability:
   - Prometheus metrics
   - Grafana dashboards
   - Alert manager integration
   - Audit log export (SIEM)

5. Data Migration:
   - Legacy system connectors
   - ETL pipelines
   - Knowledge base seeding
   - Validation and testing

Include ASCII architecture diagram.
500 words."""
    
    integration_guide = llm.generate(integration_prompt, max_tokens=1000)
    
    return [
        metrics,
        agents,
        books,
        integration_guide["content"],
        integration_guide["meta"]
    ]


def slide_16_business_case():
    """Slide 16: Business Case & Pilot (LLM generates from session stats)"""
    
    # Get session stats
    stats = llm.session_stats()
    books = platform.get_books_position()
    
    business_prompt = f"""You are a healthcare CFO. Write a compelling business case for adopting this AI platform:

Demo Statistics:
- Total LLM calls: {stats['total_calls']}
- Total tokens: {stats['total_tokens']}
- Total cost: ${stats['total_cost_usd']}

Platform Data:
{json.dumps(books, indent=2)}

Calculate:
- ROI per use case (7 use cases total)
- Time saved per physician per week (15+ hours)
- Annual savings per physician at $200/hr
- Payback period at $1000/month per use case
- Competitive advantage (compliance, security, explainability)

Then propose a 30-day pilot program:
- Week 1-2: Integration and setup
- Week 3-4: Training
- Week 5-8: Live pilot with 2 use cases
- Success metrics
- Next steps

Professional but compelling. 400 words."""

    business_case = llm.generate(business_prompt, max_tokens=800)

    # Return: Raw system data + LLM analysis only
    return [
        stats,
        books,
        business_case["content"],
        business_case["meta"]
    ]


# Slide registry
SLIDES = {
    1: slide_1_market_analysis,
    2: slide_2_competitive_landscape,
    3: slide_3_architecture,
    4: slide_4_demo_intro,
    5: slide_5_clinical_documentation,
    6: slide_6_prior_authorization,
    7: slide_7_differential_diagnosis,
    8: slide_8_lab_triage,
    9: slide_9_med_reconciliation,
    10: slide_10_trial_matching,
    11: slide_11_radiology_reports,
    12: slide_12_compliance,
    13: slide_13_explainability,
    14: slide_14_security,
    15: slide_15_integration,
    16: slide_16_business_case,
}


def run_demo(start=1, end=16):
    """Run demo slides - output is pure JSON only"""
    results = []
    
    for slide_num in range(start, end + 1):
        if slide_num not in SLIDES:
            continue
            
        try:
            result = SLIDES[slide_num]()
            results.append(result)
            # Output raw result as JSON
            print(json.dumps(result, indent=2))
            
        except Exception as e:
            # Even errors as JSON
            print(json.dumps({"error": str(e), "slide": slide_num}))
    
    # Final stats as JSON
    print(json.dumps(llm.session_stats(), indent=2))
    
    return results


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_demo(1, 16)
    elif len(sys.argv) == 2:
        slide = int(sys.argv[1])
        run_demo(slide, slide)
    elif len(sys.argv) == 3:
        start = int(sys.argv[1])
        end = int(sys.argv[2])
        run_demo(start, end)

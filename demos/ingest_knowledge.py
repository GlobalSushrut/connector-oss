#!/usr/bin/env python3
"""
Ingest medical knowledge into Connector platform
Populates /k/medical/ namespace with real clinical data
"""

import requests
import json

BASE_URL = "http://localhost:9090"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer dev-token"
}

def register_agent():
    """Register knowledge ingestion agent"""
    payload = {
        "name": "knowledge_ingest",
        "description": "Medical knowledge base ingestion agent",
        "clearance": 3
    }
    r = requests.post(f"{BASE_URL}/api/v1/agents", headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()["pid"]

def write_knowledge(agent_pid, namespace, content, metadata=None):
    """Write knowledge packet to platform"""
    payload = {
        "agent_pid": agent_pid,
        "content": content,
        "namespace": namespace,
        "metadata": metadata or {}
    }
    r = requests.post(f"{BASE_URL}/api/v1/memory/write", headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()

# Clinical Guidelines
guidelines = [
    {
        "ns": "k/medical/guidelines/chest_pain",
        "content": "ACC/AHA 2021 Chest Pain Guidelines: HEART Score for ACS risk stratification. Score 0-3 (low risk): discharge with follow-up. Score 4-6 (moderate): observe, serial troponin, stress test. Score 7-10 (high): admit, cardiology consult, possible cath. Components: History (0-2), ECG (0-2), Age (0-2), Risk factors (0-2), Troponin (0-2).",
        "meta": {"source": "ACC/AHA", "year": 2021, "category": "cardiovascular"}
    },
    {
        "ns": "k/medical/guidelines/diabetes",
        "content": "ADA 2024 Diabetes Standards: A1C target <7% for most adults, <8% for elderly/comorbid, <6.5% for newly diagnosed. First-line: Metformin 500mg BID, titrate to 1000mg BID. If A1C >9%: dual therapy (metformin + GLP-1 RA or SGLT2i). ASCVD/CKD: add SGLT2i (empagliflozin 10mg, dapagliflozin 10mg) regardless of A1C.",
        "meta": {"source": "ADA", "year": 2024, "category": "endocrine"}
    },
    {
        "ns": "k/medical/guidelines/pneumonia",
        "content": "IDSA/ATS 2019 CAP Guidelines: CURB-65 severity score (Confusion, Urea>7, RR≥30, BP<90/60, Age≥65). Score 0-1: outpatient (amoxicillin 1g TID or doxycycline 100mg BID). Score 2: short hospital stay. Score 3-5: ICU admission. Inpatient non-ICU: ceftriaxone 1g IV + azithromycin 500mg. ICU: add vancomycin if MRSA risk.",
        "meta": {"source": "IDSA/ATS", "year": 2019, "category": "infectious_disease"}
    }
]

# Drug Interactions
drug_interactions = [
    {
        "ns": "k/medical/drugs/interactions/warfarin_nsaids",
        "content": "Critical Drug Interaction: Warfarin + NSAIDs → Increased bleeding risk (GI hemorrhage). Mechanism: NSAIDs inhibit platelet aggregation and can cause gastric ulceration. Monitor INR closely if combination unavoidable. Consider COX-2 selective NSAID or alternative analgesic.",
        "meta": {"severity": "high", "category": "anticoagulant"}
    },
    {
        "ns": "k/medical/drugs/interactions/acei_potassium",
        "content": "Critical Drug Interaction: ACE inhibitors + K-sparing diuretics → Hyperkalemia (K+ >5.5 → cardiac arrest risk). Mechanism: Both reduce renal K+ excretion. Monitor K+ levels weekly initially, then monthly. Avoid in CKD stage 4-5.",
        "meta": {"severity": "high", "category": "cardiovascular"}
    },
    {
        "ns": "k/medical/drugs/interactions/metformin_contrast",
        "content": "Critical Drug Interaction: Metformin + IV contrast → Lactic acidosis risk. Hold metformin 48 hours post-contrast. Check renal function before restarting. Risk highest in CKD, CHF, liver disease, age >80.",
        "meta": {"severity": "high", "category": "endocrine"}
    }
]

# Lab Reference Ranges
lab_ranges = [
    {
        "ns": "k/medical/labs/troponin",
        "content": "Troponin I (high-sensitivity): Normal <0.04 ng/mL (99th percentile). Acute MI: >0.04 with rise/fall pattern. STEMI equivalent: >10x URL with symptoms. Serial measurements at 0h, 1h (or 0h, 3h) required for diagnosis.",
        "meta": {"category": "cardiac_markers", "critical_high": 0.4}
    },
    {
        "ns": "k/medical/labs/potassium",
        "content": "Potassium: Normal 3.5-5.0 mEq/L. Critical low <2.5 (cardiac arrhythmia risk). Critical high >6.5 (cardiac arrest risk). Moderate hyperkalemia 5.5-6.0: restrict dietary K+, stop K-sparing drugs. Severe >6.5: IV calcium gluconate, insulin+glucose, dialysis if refractory.",
        "meta": {"category": "electrolytes", "critical_low": 2.5, "critical_high": 6.5}
    },
    {
        "ns": "k/medical/labs/creatinine",
        "content": "Creatinine: Normal 0.7-1.3 mg/dL. GFR estimation: CKD-EPI equation. CKD stages: 1 (GFR >90), 2 (60-89), 3a (45-59), 3b (30-44), 4 (15-29), 5 (<15 or dialysis). Stage 4-5: nephrology referral, prepare for RRT.",
        "meta": {"category": "renal", "ckd_threshold": 3.0}
    }
]

# ICD-10 Codes
icd10_codes = [
    {
        "ns": "k/medical/icd10/i20_0",
        "content": "ICD-10 I20.0: Unstable angina. Acute coronary syndrome without ST elevation or troponin rise. Requires admission, serial troponin, cardiology consult. Differential: NSTEMI (troponin positive), stable angina (predictable pattern), GERD.",
        "meta": {"category": "cardiovascular", "billable": True}
    },
    {
        "ns": "k/medical/icd10/e11_9",
        "content": "ICD-10 E11.9: Type 2 diabetes mellitus without complications. Requires A1C documentation. Related codes: E11.65 (with hyperglycemia), E11.40 (with neuropathy), E11.21 (with nephropathy). CMS quality measures: A1C <8%, eye exam, foot exam.",
        "meta": {"category": "endocrine", "billable": True}
    },
    {
        "ns": "k/medical/icd10/j18_9",
        "content": "ICD-10 J18.9: Pneumonia, unspecified organism. Requires chest X-ray documentation. Specify organism if known: J15.0 (Strep pneumoniae), J15.1 (Pseudomonas), J18.1 (Lobar pneumonia). Link to severity: CURB-65 score, ICU admission.",
        "meta": {"category": "respiratory", "billable": True}
    }
]

# Clinical Trials
clinical_trials = [
    {
        "ns": "k/medical/trials/nct05437458",
        "content": "NCT05437458 DESTINY-Breast09: Phase III trial for HER2-low metastatic breast cancer. Drug: Trastuzumab deruxtecan (T-DXd) vs investigator's choice chemo. Inclusion: HER2-low (IHC 1+ or IHC 2+/ISH-), prior CDK4/6i + endocrine, ≥1 prior chemo. Exclusion: HER2-positive, active brain mets, ILD history, LVEF <50%. Status: Recruiting at 350+ sites globally.",
        "meta": {"phase": "III", "condition": "breast_cancer", "status": "recruiting"}
    },
    {
        "ns": "k/medical/trials/nct04191135",
        "content": "NCT04191135 KEYNOTE-B49: Phase III trial for PD-L1 positive TNBC. Drug: Pembrolizumab + chemo vs placebo + chemo. Inclusion: Locally recurrent or metastatic TNBC, PD-L1 CPS ≥10, no prior systemic therapy. Exclusion: Autoimmune disease requiring systemic treatment, prior anti-PD-1/PD-L1. Status: Active, not recruiting.",
        "meta": {"phase": "III", "condition": "breast_cancer", "status": "active"}
    }
]

# Radiology Criteria
radiology = [
    {
        "ns": "k/medical/radiology/fleischner",
        "content": "Fleischner Society 2017 Lung Nodule Guidelines: Solid nodules <6mm: no follow-up (low risk). 6-8mm: CT at 6-12 months, then 18-24 months. >8mm: CT at 3 months, PET/CT, or tissue sampling. Ground-glass ≥6mm: CT at 6-12 months, then every 2 years for 5 years. Part-solid ≥6mm: CT at 3-6 months, if stable annual CT for 5 years.",
        "meta": {"category": "thoracic", "year": 2017}
    },
    {
        "ns": "k/medical/radiology/lung_rads",
        "content": "Lung-RADS (ACR): Category 1 (Negative), 2 (Benign), 3 (Probably benign, 6-month follow-up), 4A (Suspicious, 3-month follow-up, PET helpful), 4B (Very suspicious, tissue sampling), 4X (Additional suspicious features, staging CT, PET, biopsy). Standardizes lung cancer screening CT interpretation.",
        "meta": {"category": "thoracic", "screening": True}
    }
]

print("Ingesting medical knowledge into Connector platform...")
print(f"Target: {BASE_URL}")
print()

# Register agent for knowledge ingestion
print("Registering knowledge ingestion agent...")
try:
    agent_pid = register_agent()
    print(f"✓ Agent registered: {agent_pid}")
except Exception as e:
    print(f"✗ Failed to register agent: {e}")
    print("Attempting to use existing agent...")
    # Try to get existing agents
    r = requests.get(f"{BASE_URL}/api/v1/agents", headers=HEADERS)
    agents = r.json().get("agents", [])
    if agents:
        agent_pid = agents[0]["pid"]
        print(f"✓ Using existing agent: {agent_pid}")
    else:
        print("✗ No agents available. Exiting.")
        exit(1)

print()
total_ingested = 0

for dataset_name, dataset in [
    ("Clinical Guidelines", guidelines),
    ("Drug Interactions", drug_interactions),
    ("Lab Reference Ranges", lab_ranges),
    ("ICD-10 Codes", icd10_codes),
    ("Clinical Trials", clinical_trials),
    ("Radiology Criteria", radiology)
]:
    print(f"Ingesting {dataset_name}...")
    for item in dataset:
        try:
            result = write_knowledge(agent_pid, item["ns"], item["content"], item["meta"])
            if result.get("ok"):
                print(f"  ✓ {item['ns']} → CID: {result.get('cid', 'N/A')}")
                total_ingested += 1
            else:
                print(f"  ✗ {item['ns']}: {result}")
        except Exception as e:
            print(f"  ✗ {item['ns']}: {e}")

print()
print(f"Total ingested: {total_ingested} knowledge packets")
print("Knowledge base ready for semantic search and retrieval.")

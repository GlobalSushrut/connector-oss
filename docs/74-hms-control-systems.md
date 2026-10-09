# 74 — HMS and Healthcare Management Systems

> Healthcare Management System (HMS) integration with Connector's governance layer. Patient data handling, HL7/FHIR protocols, medical device integration, and healthcare-specific compliance controls.

---

## HMS Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Clinical Decision Support Agent              │
│         (Treatment recommendations, alerts)               │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
│              │   Connector Control     │
│              │   HIPAA Enforcement     │
│              │   PHI Never Reaches LLM │
│              │   9 Chains for Audit    │
│              └───────────┬───────────────┘
│                          │
│        ┌─────────────────┼─────────────────┐
│        │                 │                 │
│        ▼                 ▼                 ▼
┌────────────┐     ┌────────────┐     ┌────────────┐
│   EHR/HIS  │     │   Medical  │     │   Lab/Rad  │
│  (Epic,    │     │   Devices  │     │   Systems  │
│  Cerner)   │     │ (Monitors) │     │            │
└────────────┘     └────────────┘     └────────────┘
```

---

## HL7 and FHIR Integration

### HL7 v2.x Message Handling

```yaml
hms:
  hl7:
    version: "2.5.1"
    message_types:
      - ADT^A01    # Admit
      - ADT^A08    # Update
      - ORM^O01    # Order
      - ORU^R01    # Result
      - MDM^T02    # Document
      
    phi_handling:
      redact_in_context: true
      allowed_segments_for_llm:
        - MSH       # Message header (no PHI)
        - EVN       # Event type
        - PV1       # Visit (masked)
      
      denied_segments:
        - PID       # Patient ID (never to LLM)
        - NK1       # Next of kin
        - IN1       # Insurance
        - GT1       # Guarantor
        
    routing:
      - if: "MSH.9 == 'ADT^A01'"
        action: admit_patient
        
      - if: "MSH.9 == 'ORU^R01'"
        action: process_lab_result
        notify: ordering_provider
```

### FHIR R4 Resource Access

```python
from connector import HealthcareAgent

agent = HealthcareAgent(
    role="clinical_analyst",
    hipaa_compliant=True,
    minimum_necessary=True
)

# Query FHIR server (through Connector governance)
patient = agent.fhir_query(
    resource="Patient",
    patient_id="12345",
    access_reason="treatment",
    minimum_necessary=True
)

# AI analyzes (with PHI masked)
analysis = agent.clinical_analysis(
    patient_context=patient.redacted_summary,
    question="What are the drug interaction risks?"
)

# Response includes audit trail
print(f"Analysis: {analysis.recommendation}")
print(f"PHI Access Log: {analysis.phi_access_log}")
print(f"Audit CID: {analysis.audit_cid}")
```

---

## EHR Integration

### Epic Integration

```yaml
ehr:
  provider: epic
  version: "2023"
  
  api:
    base_url: https://epic.hospital.com/interconnect-fhir-oauth
    auth: oauth2
    scopes:
      - "read_patient"
      - "read_medications"
      - "read_lab_results"
      - "write_clinical_note"
      
  phi_controls:
    # PHI fields never sent to LLM
    always_mask:
      - Patient.name
      - Patient.birthDate
      - Patient.address
      - Patient.telecom
      - Patient.ssn
      
    # Can be included with patient consent
    conditional:
      - Patient.gender
      - Patient.age  # Not birthdate
      - Condition.code  # Diagnosis codes
      - Medication.code
      
    allowed_in_context:
      - "60-year-old male"
      - "History of hypertension"
      - "Current medications: Lisinopril, Metformin"
      # NOT: "John Smith, DOB 1964-03-15, SSN 123-45-6789"
```

### Clinical Documentation

```python
# Generate clinical note (governed)
note = agent.generate_clinical_note(
    patient_id="12345",
    encounter_id="67890",
    note_type="progress_note",
    sections=["history", "assessment", "plan"],
    
    # PHI handling
    patient_name="Patient-A",  # De-identified
    provider_id="provider_789",
    
    # Compliance
    hipaa_compliant=True,
    attestation_required=True
)

# Note includes attestation requirements
print(f"Note ready for provider review: {note.draft}")
print(f"Attestation CID: {note.attestation_cid}")
print(f"Must be signed by: {note.required_signer}")
```

---

## Medical Device Integration

### HL7 FHIR Device Integration

```yaml
devices:
  - type: patient_monitor
    manufacturer: philips
    model: IntelliVue MX800
    protocol: hl7
    
    data_streams:
      - heart_rate
      - blood_pressure
      - spo2
      - respiratory_rate
      - temperature
      
    alerts:
      - condition: "heart_rate > 120"
        severity: warning
        notify: nurse_station
        
      - condition: "spo2 < 90"
        severity: critical
        notify: [nurse_station, rapid_response]
        
      - condition: "heart_rate > 150 OR heart_rate < 40"
        severity: critical
        notify: [nurse_station, attending, rapid_response]
        
    governance:
      log_all_vitals: true
      retention_days: 2555  # 7 years
      hipaa_audit_trail: true
```

### Device Data Processing

```python
# Process vital signs stream
vitals = device.get_vitals(patient_id="12345")

# AI monitoring
trends = agent.analyze_vitals(
    history=vitals.last_24h,
    detect: [
        "sepsis_risk",
        "deterioration",
        "medication_response"
    ]
)

if trends.sepsis_risk_score > 0.7:
    alert = agent.generate_alert(
        type="sepsis_warning",
        priority="high",
        notify="attending_physician",
        include_recommendation=True,
        evidence=trends.evidence
    )
```

---

## Clinical Decision Support

### CDSS Integration

```yaml
cdss:
  rules:
    - name: drug_interaction_check
      trigger: "new_medication_ordered"
      action: check_interactions
      
    - name: allergy_alert
      trigger: "medication_order"
      condition: "medication.matches_patient_allergies"
      severity: critical
      action: block_order
      
    - name: dosing_guidance
      trigger: "medication_order"
      action: provide_dosing_recommendation
      
    - name: lab_followup
      trigger: "medication_started"
      condition: "medication.requires_monitoring"
      action: schedule_followup_lab
```

### Clinical Recommendations

```python
# Get evidence-based recommendation
recommendation = agent.clinical_recommendation(
    diagnosis="community_acquired_pneumonia",
    patient_factors={
        "age": 65,
        "comorbidities": ["diabetes", "hypertension"],
        "allergies": ["penicillin"],
        "severity": "moderate"
    },
    guidelines="idsa_cap_2019"
)

# Recommendation includes evidence
guideline_citation = recommendation.source_guideline
confidence = recommendation.evidence_level
alternatives = recommendation.alternatives

# Grounding verification
assert recommendation.grounded_in_guidelines  # Must be evidence-based
```

---

## Lab and Radiology Systems

### Lab Result Processing

```python
# Process incoming lab result
lab_result = agent.receive_lab_result(
    order_id="LAB-12345",
    patient_id="PT-67890",
    test="CBC",
    results={
        "wbc": 12.5,
        "hemoglobin": 10.2,
        "platelets": 150
    }
)

# AI analysis
critical_values = agent.identify_critical_values(lab_result)
trends = agent.compare_to_baseline(lab_result)

if critical_values:
    agent.notify_provider(
        priority="critical",
        message=f"Critical value: {critical_values}"
    )

# Generate interpretation (with PHI masked)
interpretation = agent.generate_lab_interpretation(
    result=lab_result,
    patient_context="Patient-A, 60M",
    include_differential=True
)
```

### Radiology Integration

```yaml
radiology:
  pacs: dicom
  ris: hl7
  
  ai_models:
    - name: chest_xray_screening
      type: classification
      findings: ["pneumonia", "pneumothorax", "effusion", "normal"]
      
    - name: ct_nodule_detection
      type: detection
      sensitivity: 0.95
      
  workflow:
    - receive_study
    - ai_screening
    - prioritize_urgent
    - route_to_radiologist
    - ai_second_read
    - generate_report
```

---

## Patient Privacy Controls

### Minimum Necessary Enforcement

```yaml
hipaa:
  minimum_necessary:
    role_based:
      billing:
        access:
          - patient.demographics
          - insurance.info
          - billing_codes
        deny:
          - clinical.notes
          - lab.results
          - medications
          
      nurse:
        access:
          - patient.current_encounter
          - current_medications
          - vital_signs
          - allergies
        deny:
          - previous_psychiatric_notes
          - hiv_status  # Special protections
          - substance_abuse_records
          
      physician:
        access:
          - full_record  # Except special protections
        special_authorization:
          - psychiatric_notes
          - hiv_status
          - substance_abuse
```

### Consent Management

```python
# Check consent before accessing data
consent = agent.verify_consent(
    patient_id="12345",
    purpose="treatment",
    data_types=["medications", "lab_results"],
    provider_id="provider_789"
)

if consent.granted:
    data = agent.access_patient_data(
        patient_id="12345",
        authorized_by=consent.consent_cid
    )
else:
    agent.log_access_denied(
        reason="consent_not_granted",
        audit_trail=True
    )
```

---

## Audit and Compliance

### Healthcare Audit Trail

Every HMS interaction generates:

```json
{
  "event_type": "phi_access",
  "patient_id": "hashed_patient_id",
  "user": "provider_789",
  "role": "attending_physician",
  "access_reason": "treatment",
  "data_accessed": ["medications", "lab_results"],
  "minimum_necessary": true,
  "consent_verified": true,
  "timestamp": "2026-04-14T08:30:00Z",
  "hipaa_compliant": true,
  "audit_cid": "mem1-sha256-d4e8f1...",
  "chain_verified": true
}
```

### Compliance Reporting

```python
# Generate HIPAA compliance report
report = agent.generate_compliance_report(
    period="2026-Q1",
    regulations=["hipaa", "hitech"],
    include:
      - phi_access_log
      - minimum_necessary_verification
      - consent_audit
      - breach_risk_assessment
)

# Export for auditor
report.export(format="pdf", signed=True)
report.export(format="json", structured=True)
```

---

## Emergency Override

### Break-Glass Access

```yaml
emergency_override:
  enabled: true
  
  triggers:
    - "patient.unconscious"
    - "patient.life_threatening"
    - "disaster_mode_active"
    
  requirements:
    - user_must_be_physician: true
    - dual_authorization: false  # In emergency
    - post_hoc_review: true      # Reviewed within 24h
    - justification_required: true
    - full_audit: true
    
  limitations:
    - max_duration_hours: 24
    - requires_supervisor_notification: true
    - automatic_review_scheduled: true
```

```python
# Emergency access
emergency_access = agent.request_emergency_access(
    patient_id="12345",
    reason="unconscious_trauma_patient",
    requesting_provider="provider_789",
    emergency_type="life_threatening"
)

# Full record access granted with enhanced audit
full_record = agent.access_patient_data(
    patient_id="12345",
    emergency_override=emergency_access.cid,
    full_audit=True
)
```

---

## HMS Integration Checklist

- [ ] HL7/FHIR connectivity established
- [ ] EHR authentication configured
- [ ] PHI masking rules tested
- [ ] Minimum necessary policy enforced
- [ ] Consent management integrated
- [ ] Medical devices connected
- [ ] CDSS rules validated
- [ ] Emergency override tested
- [ ] Audit trail verified
- [ ] HIPAA compliance confirmed
- [ ] Clinical staff trained
- [ ] Incident response plan ready

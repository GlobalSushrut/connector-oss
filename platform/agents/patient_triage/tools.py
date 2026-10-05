"""Patient Triage Agent — Tool Implementations.

Each function maps to a tool declared in contract.yaml.
The contract says WHAT to call. This file says HOW it works.

In production: these call real EHR APIs, clinical systems, notification services.
In stub mode: they return mock data for testing and CI.

Tool lifecycle:
  1. contract.yaml declares: tool lookup_patient
  2. Kernel executor hits a tool_call step
  3. Kernel resolves params from ${var} context
  4. Kernel gates through ACL + firewall + rate limit
  5. Kernel calls tools.registry()["lookup_patient"](**params)
  6. Kernel records audit entry + deducts from budget
"""

from __future__ import annotations

import os
from typing import Any


# ═══════════════════════════════════════════════════════════════
# Tool: lookup_patient
# ═══════════════════════════════════════════════════════════════

def lookup_patient(patient_id: str) -> dict:
    """Look up patient record from EHR system.

    Production: calls EHR FHIR API (Epic, Cerner, etc.)
    Stub: returns mock patient data.
    """
    # TODO: Replace with real EHR integration
    return {
        "patient_id": patient_id,
        "name": "Jane Doe",
        "age": 45,
        "gender": "F",
        "conditions": ["hypertension", "diabetes_type2"],
        "medications": ["metformin", "lisinopril"],
        "last_visit": "2026-01-15",
        "insurance": "BlueCross PPO",
        "emergency_contact": {"name": "John Doe", "phone": "555-0123"},
    }


# ═══════════════════════════════════════════════════════════════
# Tool: check_allergies
# ═══════════════════════════════════════════════════════════════

def check_allergies(patient_id: str) -> dict:
    """Check patient allergy records.

    Production: queries allergy registry / EHR allergy module.
    Stub: returns mock allergy data.
    """
    return {
        "patient_id": patient_id,
        "allergies": ["penicillin", "sulfa"],
        "severity": {"penicillin": "severe", "sulfa": "moderate"},
        "last_updated": "2025-11-20",
    }


# ═══════════════════════════════════════════════════════════════
# Tool: assess_severity
# ═══════════════════════════════════════════════════════════════

CRITICAL_KEYWORDS = [
    "chest pain", "difficulty breathing", "shortness of breath",
    "unresponsive", "unconscious", "seizure", "severe bleeding",
    "stroke symptoms", "anaphylaxis", "cardiac arrest",
    "crushing chest", "respiratory distress", "altered mental status",
]

VITAL_THRESHOLDS = {
    "heart_rate":      {"critical_low": 40, "low": 50, "high": 100, "critical_high": 150},
    "systolic_bp":     {"critical_low": 70, "low": 90, "high": 180, "critical_high": 200},
    "diastolic_bp":    {"critical_low": 40, "low": 60, "high": 110, "critical_high": 120},
    "spo2":            {"critical_low": 85, "low": 92, "high": 100, "critical_high": 101},
    "temperature":     {"critical_low": 34.0, "low": 36.0, "high": 38.5, "critical_high": 40.5},
    "respiratory_rate": {"critical_low": 8, "low": 12, "high": 22, "critical_high": 30},
}


def assess_severity(
    assessment: str = "",
    symptoms: str = "",
    vitals: dict | None = None,
) -> dict:
    """Compute severity score 0.0–10.0 using clinical rules.

    Scoring:
      - Symptom keywords:   0–4 points
      - Vital abnormalities: 0–4 points
      - Assessment modifier: 0–2 points

    Returns dict with score, factors, and vital alerts.
    """
    score = 0.0
    factors = []
    vital_alerts = []

    # Symptom-based scoring
    symptoms_lower = symptoms.lower()
    critical_matches = [kw for kw in CRITICAL_KEYWORDS if kw in symptoms_lower]
    if critical_matches:
        score += min(4.0, len(critical_matches) * 2.0)
        factors.extend([f"Critical symptom: {kw}" for kw in critical_matches])
    elif any(w in symptoms_lower for w in ["pain", "fever", "vomiting", "dizziness"]):
        score += 2.0
        factors.append("Moderate symptom severity")
    elif any(w in symptoms_lower for w in ["cough", "rash", "headache", "sore throat"]):
        score += 1.0
        factors.append("Mild symptom severity")

    # Vital sign scoring
    if vitals:
        for vital_name, value in vitals.items():
            if vital_name not in VITAL_THRESHOLDS:
                continue
            if not isinstance(value, (int, float)):
                continue
            thresholds = VITAL_THRESHOLDS[vital_name]
            if value <= thresholds["critical_low"] or value >= thresholds["critical_high"]:
                score += 2.0
                alert = f"CRITICAL: {vital_name}={value}"
                vital_alerts.append(alert)
                factors.append(alert)
            elif value <= thresholds["low"] or value >= thresholds["high"]:
                score += 1.0
                alert = f"Abnormal: {vital_name}={value}"
                vital_alerts.append(alert)
                factors.append(alert)

    # Assessment modifier
    if assessment:
        assessment_lower = assessment.lower()
        if any(w in assessment_lower for w in ["critical", "emergent", "immediate"]):
            score += 2.0
            factors.append("Clinical assessment: critical/emergent")
        elif any(w in assessment_lower for w in ["urgent", "concerning", "significant"]):
            score += 1.0
            factors.append("Clinical assessment: urgent/concerning")

    score = min(10.0, max(0.0, round(score, 1)))

    return {
        "severity_score": score,
        "factors": factors,
        "vital_alerts": vital_alerts,
        "is_critical": score >= 8.0,
    }


# ═══════════════════════════════════════════════════════════════
# Tool: assign_priority
# ═══════════════════════════════════════════════════════════════

def assign_priority(severity: float, patient_id: str) -> dict:
    """Assign patient to priority queue based on severity score.

    ESI mapping:
      >= 8.0  → critical  (ESI 1: Resuscitation)
      >= 6.0  → urgent    (ESI 2: Emergent)
      >= 4.0  → standard  (ESI 3: Urgent)
      >= 2.0  → low       (ESI 4: Less urgent)
      <  2.0  → low       (ESI 5: Non-urgent)
    """
    if isinstance(severity, dict):
        severity = severity.get("severity_score", 0)

    if severity >= 8.0:
        level, esi = "critical", 1
    elif severity >= 6.0:
        level, esi = "urgent", 2
    elif severity >= 4.0:
        level, esi = "standard", 3
    elif severity >= 2.0:
        level, esi = "low", 4
    else:
        level, esi = "low", 5

    return {
        "patient_id": patient_id,
        "priority": level,
        "esi_level": esi,
        "queue_position": 1,
        "estimated_wait_minutes": {1: 0, 2: 5, 3: 15, 4: 30, 5: 60}.get(esi, 30),
    }


# ═══════════════════════════════════════════════════════════════
# Tool: notify_staff
# ═══════════════════════════════════════════════════════════════

def notify_staff(
    priority: str,
    patient_id: str,
    severity: float = 0,
    assessment: str = "",
) -> dict:
    """Alert clinical staff about a patient.

    Production: sends pager/SMS for critical, dashboard alert for others.
    Stub: returns notification confirmation.
    """
    channel = "pager" if priority == "critical" else "dashboard"
    return {
        "notified": True,
        "channel": channel,
        "patient_id": patient_id,
        "priority": priority,
        "severity": severity,
        "message": f"[{priority.upper()}] Patient {patient_id} — severity {severity}",
    }


# ═══════════════════════════════════════════════════════════════
# Tool Registry — maps contract tool names to implementations
# ═══════════════════════════════════════════════════════════════

def registry() -> dict[str, Any]:
    """Return all tool implementations keyed by contract tool name.

    Every tool declared in contract.yaml must have an entry here.
    The kernel executor calls: registry()["tool_name"](**params)
    """
    return {
        "lookup_patient": lookup_patient,
        "check_allergies": check_allergies,
        "assess_severity": assess_severity,
        "assign_priority": assign_priority,
        "notify_staff": notify_staff,
    }

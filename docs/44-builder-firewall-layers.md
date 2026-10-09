# 44 — Builder: Custom Guard Layers

> Add domain-specific inspection layers to the firewall pipeline.

---

## Custom Layer Architecture

The 5-layer guard pipeline can be extended with custom layers after the standard 5:

```
Layer 1: Semantic injection       (built-in)
Layer 2: PII and PHI guard        (built-in)
Layer 3: Tool command validation  (built-in)
Layer 4: Budget enforcement       (built-in)
Layer 5: Behavioral anomaly       (built-in)
Layer 6: [Your custom layer]      ← add here
Layer 7: [Your domain layer]      ← add here
```

---

## Defining a Custom Guard in Policy YAML

```yaml
# policies/medical_guard.yaml
name: medical_guard
description: "Domain-specific guard for medical AI systems"
version: "1.0"

custom_layers:
  - id: treatment_claim_guard
    description: "Block unqualified treatment recommendations"
    position: 6   # after built-in layer 5
    condition:
      content_matches: "(prescribe|administer|dosage|treatment|diagnos)"
      is_regex: true
      confidence_below: 0.85
    action: require_hitl
    reason: "Treatment claim detected with low confidence"

  - id: drug_interaction_check
    description: "Flag potential drug interactions"
    position: 7
    condition:
      content_matches: "(metformin|warfarin|aspirin|lisinopril)"
      is_regex: true
    action: log_and_allow
    side_effects:
      - write_memory: true
        ptype: "drug_interaction_flag"

  - id: financial_advice_guard
    description: "Block unqualified financial advice"
    position: 6
    condition:
      content_matches: "(invest|buy|sell|stock|option|return|portfolio)"
      is_regex: true
      context_matches: "financial_advice"
    action: deny
    reason: "Financial advice requires licensed advisor"
```

---

## Custom Layer in Python

```python
class CustomGuardLayer:
    """
    Base class for implementing a custom guard layer.
    Implement check() to add domain logic.
    """

    def __init__(self, layer_id: str, description: str):
        self.layer_id    = layer_id
        self.description = description

    def check(self, content: str, agent_pid: str, namespace: str) -> dict:
        """
        Returns: {
          "blocked": bool,
          "reason":  str or None,
          "score":   float 0.0-1.0,
          "tags":    list
        }
        """
        raise NotImplementedError


class MedicalClaimGuard(CustomGuardLayer):
    """Block unqualified treatment recommendations."""

    TREATMENT_PATTERNS = [
        "you should take", "prescribe", "administer",
        "recommended dosage", "take X mg"
    ]

    def check(self, content: str, agent_pid: str, namespace: str) -> dict:
        content_lower = content.lower()
        for pattern in self.TREATMENT_PATTERNS:
            if pattern in content_lower:
                return {
                    "blocked": True,
                    "reason":  f"Unqualified treatment claim detected: '{pattern}'",
                    "score":   0.85,
                    "tags":    ["medical_claim", "requires_review"]
                }
        return {"blocked": False, "score": 0.0, "tags": []}


class APIKeyLeakGuard(CustomGuardLayer):
    """Detect API key patterns beyond the built-in guard."""
    import re

    PATTERNS = [
        r"sk-[a-zA-Z0-9]{20,}",          # OpenAI
        r"AKIA[0-9A-Z]{16}",              # AWS
        r"gh[pousr]_[A-Za-z0-9]{36}",     # GitHub
        r"xox[baprs]-[0-9A-Za-z-]{10,}",  # Slack
        r"AIza[0-9A-Za-z\-_]{35}",        # Google
    ]

    def check(self, content: str, agent_pid: str, namespace: str) -> dict:
        import re
        for pattern in self.PATTERNS:
            if re.search(pattern, content):
                return {
                    "blocked": True,
                    "reason":  f"API key pattern detected: {pattern[:20]}",
                    "score":   1.0,
                    "tags":    ["api_key_leak", "critical"]
                }
        return {"blocked": False, "score": 0.0, "tags": []}
```

---

## Integrating Custom Layers

```python
class GovernedInspector:
    """
    Extended firewall inspector that runs built-in + custom layers.
    """

    def __init__(self, platform, custom_layers: list = None):
        self.p              = platform
        self.custom_layers  = custom_layers or []

    def inspect(self, pid: str, content: str, ns: str) -> dict:
        # 1. Run built-in layers (rings 3's guard pipeline)
        fw = self.p.firewall_inspect(pid, content, ns)
        if fw.get("blocked"):
            return fw

        # 2. Run custom layers
        for layer in self.custom_layers:
            result = layer.check(content, pid, ns)
            if result.get("blocked"):
                # Record custom block
                self.p.record_decision(pid,
                    f"custom_guard.{layer.layer_id}",
                    content[:60],
                    "blocked",
                    rationale=result.get("reason"),
                    confidence=result.get("score", 0.9))

                return {
                    **fw,
                    "blocked":         True,
                    "final_decision":  f"Deny {{ reason: '{result['reason']}' }}",
                    "custom_layer":    layer.layer_id,
                    "layers_evaluated": 5 + self.custom_layers.index(layer) + 1
                }

        return fw


# Usage
inspector = GovernedInspector(p, custom_layers=[
    MedicalClaimGuard("medical_claim", "Block treatment claims"),
    APIKeyLeakGuard("api_key_leak", "Detect additional API key patterns"),
])

result = inspector.inspect(pid, "You should prescribe 500mg of metformin", ns)
print(f"Blocked: {result['blocked']}")
print(f"Reason: {result.get('final_decision')}")
```

---

## Domain-Specific PII Patterns

Extend PII detection for domain-specific identifiers:

```yaml
# In connector.yaml firewall section
firewall:
  pii_detection: true
  custom_patterns:
    - name: medical_record_number
      pattern: "MRN-[0-9]{6,}"
      action: block
      regulation: hipaa

    - name: npi_number
      pattern: "NPI[: ][0-9]{10}"
      action: log_and_allow
      regulation: hipaa

    - name: employee_id
      pattern: "EMP-[A-Z]{2}[0-9]{5}"
      action: redact
      regulation: soc2

    - name: contract_number
      pattern: "CONTRACT-[0-9]{8}"
      action: log_and_allow
      regulation: soc2
```

---

## Testing Custom Layers

```python
def test_custom_guards():
    test_cases = [
        ("Normal question about diabetes management",             False),
        ("You should prescribe 1000mg of metformin",             True),   # medical claim
        ("AKIAIOSFODNN7EXAMPLE is my AWS key",                   True),   # API key
        ("My API token is sk-proj-abc123def456ghi789jkl0",      True),   # OpenAI key
        ("What is the standard protocol for type 2 diabetes?",  False),  # benign medical
    ]

    for content, expected_blocked in test_cases:
        result  = inspector.inspect(pid, content, ns)
        blocked = result["blocked"]
        icon    = "✓" if blocked == expected_blocked else "✗ UNEXPECTED"
        layer   = result.get("custom_layer", "built-in" if blocked else "none")
        print(f"{icon} blocked={blocked} layer={layer}: {content[:60]}")

test_custom_guards()
```

---

## Next Steps

- **[14 — Ring 3: Firewall](14-ring-3-firewall-guard.md)**
- **[45 — Builder: CCL Extensions](45-builder-ccl-extensions.md)**
- **[35 — Tutorial: Firewall Rules](35-tutorial-firewall-rules.md)**

# Travel Web Network - Client Requirements Analysis

## What They Want (Core Needs)

1. **Embedded Control Plane** - A sidecar governance system that sits alongside live AI systems (search, booking, CRM) without disrupting existing workflows

2. **Real-Time Event Ingestion** - Capture all AI-assisted interactions as they happen: prompts, model outputs, ranking decisions, human overrides

3. **Policy Enforcement Engine** - Dynamically evaluate rules like "user opted out of personalization", "high-value bookings require human approval", "GDPR data restrictions"

4. **Consent Management** - Track and enforce user consent states per interaction, with ability to halt processing if consent is withdrawn or missing

5. **Tamper-Evident Audit Trail** - Immutable, cryptographically verifiable log of every AI decision, input, and output for regulatory compliance

6. **Replay Capability** - Ability to reconstruct exactly what the AI saw and decided at any point in time, for debugging or regulatory inquiry

7. **Memory Compilation** - Transform raw event streams into structured, reusable state objects rather than disposable logs

8. **Warm-Start Personalization** - Enable AI systems to "remember" traveler context across sessions without re-collecting preferences

9. **AWS-Native Deployment** - Run entirely within their existing AWS infrastructure (no external SaaS dependencies)

10. **Compliance-First Architecture** - Design where governance and audit are foundational, not bolted-on afterthoughts

---

## What They Need in the PoC (Proof of Concept Deliverables)

1. **Event Ingestion Pipeline** - Working Kafka or Kinesis-style stream that captures mock travel AI interactions (search queries, booking attempts, recommendations)

2. **Policy Rule Definitions** - 3-5 concrete policies implemented: e.g., "no AI recommendations for users without marketing consent", "bookings over $5000 require manual review"

3. **Consent State Tracking** - Simple consent store per traveler with enforcement at ingestion point

4. **Audit Ledger Storage** - Tamper-evident write-once storage demonstrating proof of what the AI did and why

5. **Memory Compilation Engine** - Pipeline that transforms raw events into structured output

6. **Traveler Profile Output** - Generated `traveler_profile.md` file containing: preferences, consent status, interaction history, policy decisions applied

7. **Trip Details Output** - Generated `trip_details.md` file containing: trip context, AI decisions made, human overrides, audit trail reference

8. **Basic Policy Dashboard** - Read-only view showing: policies evaluated, consent states, recent audit events

9. **Replay Demo** - Ability to show regulator-style query: "show me exactly what the AI saw when it recommended this package to this user on this date"

10. **AWS Deployment Spec** - Terraform/CloudFormation configs for ECS/EKS deployment, showing it runs in their AWS account with their data

---

## Open Questions for Discovery

- What AI systems specifically? (OpenAI API, custom models, recommendation engines?)
- What is their current log storage? (S3, CloudWatch, custom?)
- What regulations apply? (GDPR, CCPA, travel-industry specific?)
- Volume expectations? (events/second in production)
- Integration timeline? (weeks vs months)
- Budget range for PoC vs production?

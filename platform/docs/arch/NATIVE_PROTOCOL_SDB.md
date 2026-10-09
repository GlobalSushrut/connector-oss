# Native Protocol × SDB

Connector-native principle: **CNP carries; CONP names; ActionBinding admits; AAPI audits.**

## CONP commit

On successful HAL (lab echo / partner / microVM):

1. Mission journal completes the step (if present).
2. PATE `complete_augmented_task` records outcome.
3. `cnp_commit::commit_conp_to_cnp` mints a signed `WireEnvelope` (`conp.command_ack`) with Agent Packet DNA.
4. `aapi_bridge::record_atu_commit` writes the AAPI action log + CLS compile hint (advisory).

Partner HAL and microVM channel paths are unchanged — CNP commit is a receipt, not a second actuator.

## Talk / tools

Same PATE envelope via `governed_effect` + `AdmissionOp`. CapabilityGrantV2 mint stays single-path.

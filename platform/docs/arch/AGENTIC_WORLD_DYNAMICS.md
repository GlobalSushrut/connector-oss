# Agentic World Dynamics

**Status:** V0 is a view. It is not a second brain, a second memory store, or a second authority.

AWD reads the stores Connector already owns and writes one transition beside the Augmented Task Unit. PATE still admits. DIM still holds condition. World grants still hold authority. The context broker still holds the live generation. Experience does not mint or widen a grant.

## What V0 is

| Record | Schema | Role |
| --- | --- | --- |
| State view | `connector.awd.state.v1` | Digest of the live DIM row, principal id, broker generation, grant count, and spend ceiling. Missing rows are `absent`. |
| Transition | `connector.awd.transition.v1` | Written when PATE mints an ATU. Updated with the outcome when the ATU completes. Prediction stays `absent` until a later version measures it. |
| Perception packet | `connector.awd.perception.v1` | A short block injected into talk only while the memory epoch is live. A sealed epoch omits it. |

The loop assessment is a field on the packet (`continuing`, `no_progress`, or `absent`). It does not call Cease. Spend ceilings and `kernel_cease` remain the stop.

Code: `platform/server/src/substrate/awd/`.

## Where each coordinate already lives

| AWD idea | Owner today | V0 |
| --- | --- | --- |
| Condition Z_t (prediction error, entropy, precision, affordance, empowerment, resources, goal tension, consequence, continuity) | DIM. Condition is in [0, 1]. It is not permission. | Read the stored DIM row. If none exists, `condition` is `absent`. The view does not invent a fresh DIM vector. |
| Next-state prediction P(S' \| S, A) | Not measured. | `prediction` and `confidence` are `absent`. A confidence near 1 still does not admit. |
| Action | PATE ATU. Verdict is proceed, ask, defer, quarantine, or block. | The transition copies the verdict. It does not change it. |
| Observation | ATU outcome and, when present, the MomentProof id. | Stored on the transition when the ATU completes. |
| Experience | MomentProof and CRK sequence DNA. | A moment id already written on a transition. If none exists, `experience` is `absent`. |
| Authority | WorldGrant and the authority root. | Grant count is read. `authority_delta` on every transition is 0. The only folder written is `awd_transition_v1`. |
| Memory validity | Context broker generation and the memory-epoch seal. | The packet uses the same `injection_allowed` gate as the memory capsule. |
| Cost | Spend ceiling. | Read. Not created by this view. |
| Stop | SpendCease. | Not called from the loop field. |

## Invariants

1. An experience update does not create or widen a WorldGrant.
2. A prediction does not admit. If PATE would deny, the transition records that verdict and `admits: false`.
3. A sealed memory epoch omits the perception packet.
4. A missing experience is `absent`. It is not filled in.

## TARGET

These are not implemented. Do not mark them done.

- V1. Empirical P(S' \| S, A) from observed transitions, with calibration.
- V2. Clustering of similar states.
- V3. Successor features.
- V4. Learned latents.
- V5. A cross-agent world model, decay, and a calibration experiment.

Also still TARGET: treating a high-confidence prediction as evidence that an effect should proceed. Admission stays with PATE.

## Related

- [DYNAMIC_INTELLIGENCE_MANIFOLD.md](DYNAMIC_INTELLIGENCE_MANIFOLD.md) — condition, not authority.
- [CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md](CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md) — the control path this view reads.

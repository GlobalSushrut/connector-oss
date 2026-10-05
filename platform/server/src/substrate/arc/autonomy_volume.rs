//! Finite Autonomy Volume as facet meet + enforcement grades.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Honesty grade for each facet (CVR R/A/E analogue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementGrade {
    /// Documented / visible — not runtime-enforced.
    Observed,
    /// Checked on live admit/sink path.
    Enforced,
    /// Enforced and host-proven when required.
    Effective,
}

impl EnforcementGrade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Enforced => "enforced",
            Self::Effective => "effective",
        }
    }

    /// Effective A uses facets with grade ≥ Enforced.
    pub fn counts_for_effective_a(self) -> bool {
        matches!(self, Self::Enforced | Self::Effective)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FacetAxis {
    pub name: String,
    pub digest: String,
    pub grade: EnforcementGrade,
    /// Canonical constraint encoding (tools, grants, caps, …).
    pub encoding: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AutonomyFacets {
    pub c_capability: Option<FacetAxis>,
    pub g_grants: Option<FacetAxis>,
    pub d_ifc: Option<FacetAxis>,
    pub i_irreversibility: Option<FacetAxis>,
    pub t_temporal: Option<FacetAxis>,
    pub q_budgets: Option<FacetAxis>,
    pub p_posture: Option<FacetAxis>,
    pub n_topology: Option<FacetAxis>,
}

impl AutonomyFacets {
    /// Phase A lab compile: all facets Observed stubs.
    pub fn lab_partial_v0() -> Self {
        let stub = |name: &str, grade: EnforcementGrade| FacetAxis {
            name: name.into(),
            digest: format!("{:x}", Sha256::digest(name.as_bytes())),
            grade,
            encoding: json!({ "phase": "a_stub", "name": name }),
        };
        Self {
            c_capability: Some(stub("C", EnforcementGrade::Observed)),
            g_grants: Some(stub("G", EnforcementGrade::Observed)),
            d_ifc: Some(stub("D", EnforcementGrade::Observed)),
            i_irreversibility: Some(stub("I", EnforcementGrade::Observed)),
            t_temporal: Some(stub("T", EnforcementGrade::Observed)),
            q_budgets: Some(stub("Q", EnforcementGrade::Observed)),
            p_posture: Some(stub("P", EnforcementGrade::Observed)),
            n_topology: Some(stub("N", EnforcementGrade::Observed)),
        }
    }

    /// G1: D/I/T filled at Enforced with real encodings (IFC + irreversibility + temporal).
    pub fn with_dit_enforced(mut self) -> Self {
        let fill = |name: &str, encoding: Value| FacetAxis {
            name: name.into(),
            digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&encoding).unwrap_or_default())
            ),
            grade: EnforcementGrade::Enforced,
            encoding,
        };
        self.d_ifc = Some(fill(
            "D",
            json!({ "algebras": ["confidentiality", "integrity", "provenance"], "flag": "CONNECTOR_ARC_IFC" }),
        ));
        self.i_irreversibility = Some(fill(
            "I",
            json!({ "classes": ["R0", "R1", "R2"], "hitl_r2": true }),
        ));
        self.t_temporal = Some(fill(
            "T",
            json!({ "lease_ttl_ms": 60_000, "epoch_fence": true }),
        ));
        self
    }

    /// Promote C/G/Q/P to Enforced — live on admit/budget/posture paths (N stays Observed until mesh topology gate).
    pub fn with_cgqp_enforced(mut self) -> Self {
        let fill = |name: &str, encoding: Value| FacetAxis {
            name: name.into(),
            digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&encoding).unwrap_or_default())
            ),
            grade: EnforcementGrade::Enforced,
            encoding,
        };
        self.c_capability = Some(fill(
            "C",
            json!({ "hooks": ["admission", "contract.capabilities"], "sinks": ["llm.chat", "tool.dispatch", "conp.command"] }),
        ));
        self.g_grants = Some(fill(
            "G",
            json!({ "capability_grant_v2": true, "no_self_authorization": true }),
        ));
        self.q_budgets = Some(fill(
            "Q",
            json!({ "economy_budget_gate": true, "playground_talk_budget": true }),
        ));
        self.p_posture = Some(fill(
            "P",
            json!({ "lab_applied": true, "harden_refuse_closed": true, "flags": "CONNECTOR_ARC_*" }),
        ));
        self
    }

    pub fn iter_grades(&self) -> Vec<(&'static str, EnforcementGrade)> {
        let mut out = Vec::new();
        if let Some(ax) = &self.c_capability {
            out.push(("C", ax.grade));
        }
        if let Some(ax) = &self.g_grants {
            out.push(("G", ax.grade));
        }
        if let Some(ax) = &self.d_ifc {
            out.push(("D", ax.grade));
        }
        if let Some(ax) = &self.i_irreversibility {
            out.push(("I", ax.grade));
        }
        if let Some(ax) = &self.t_temporal {
            out.push(("T", ax.grade));
        }
        if let Some(ax) = &self.q_budgets {
            out.push(("Q", ax.grade));
        }
        if let Some(ax) = &self.p_posture {
            out.push(("P", ax.grade));
        }
        if let Some(ax) = &self.n_topology {
            out.push(("N", ax.grade));
        }
        out
    }

    pub fn to_json(&self) -> Value {
        json!({
            "C": self.c_capability,
            "G": self.g_grants,
            "D": self.d_ifc,
            "I": self.i_irreversibility,
            "T": self.t_temporal,
            "Q": self.q_budgets,
            "P": self.p_posture,
            "N": self.n_topology,
        })
    }

    /// Child must be componentwise ≤ parent (digest equality or empty child). Amplify = Err.
    pub fn meet_child(&self, child: &AutonomyFacets) -> Result<AutonomyFacets, String> {
        fn axis_leq(
            parent: &Option<FacetAxis>,
            child: &Option<FacetAxis>,
            name: &str,
        ) -> Result<Option<FacetAxis>, String> {
            match (parent, child) {
                (_, None) => Ok(None),
                (None, Some(_)) => {
                    Err(format!("facet {name}: child present but parent missing — amplify"))
                }
                (Some(p), Some(c)) => {
                    if c.digest == p.digest {
                        return Ok(Some(c.clone()));
                    }
                    if c.encoding.get("subset_of").and_then(|v| v.as_str())
                        == Some(p.digest.as_str())
                    {
                        return Ok(Some(c.clone()));
                    }
                    Err(format!("facet {name}: child does not attenuate parent"))
                }
            }
        }
        Ok(AutonomyFacets {
            c_capability: axis_leq(&self.c_capability, &child.c_capability, "C")?,
            g_grants: axis_leq(&self.g_grants, &child.g_grants, "G")?,
            d_ifc: axis_leq(&self.d_ifc, &child.d_ifc, "D")?,
            i_irreversibility: axis_leq(&self.i_irreversibility, &child.i_irreversibility, "I")?,
            t_temporal: axis_leq(&self.t_temporal, &child.t_temporal, "T")?,
            q_budgets: axis_leq(&self.q_budgets, &child.q_budgets, "Q")?,
            p_posture: axis_leq(&self.p_posture, &child.p_posture, "P")?,
            n_topology: axis_leq(&self.n_topology, &child.n_topology, "N")?,
        })
    }
}

/// G3: named facet + grade denial diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FacetDenial {
    pub facet: String,
    pub grade: String,
    pub reason: String,
}

impl FacetDenial {
    pub fn new(facet: &str, grade: EnforcementGrade, reason: impl Into<String>) -> Self {
        Self {
            facet: facet.into(),
            grade: grade.as_str().into(),
            reason: reason.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "facet": self.facet,
            "grade": self.grade,
            "reason": self.reason,
            "schema": "connector.arc.facet_denial.v1",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutonomyVolume {
    pub facets: AutonomyFacets,
    pub digest: String,
    pub effective_claim: bool,
    pub honesty: String,
}

impl AutonomyVolume {
    pub fn from_facets(facets: AutonomyFacets) -> Self {
        let grades = facets.iter_grades();
        let any_observed = grades.iter().any(|(_, g)| *g == EnforcementGrade::Observed);
        let effective_axes: Vec<_> = grades
            .iter()
            .filter(|(_, g)| g.counts_for_effective_a())
            .collect();
        // G1 honesty: Observed-only cannot shrink / market Effective A.
        let effective_claim = !effective_axes.is_empty() && !any_observed;
        let body = json!({
            "facets": facets.to_json(),
            "effective_only": effective_axes.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        });
        let digest =
            format!("{:x}", Sha256::digest(serde_json::to_vec(&body).unwrap_or_default()));
        Self {
            facets,
            digest,
            effective_claim,
            honesty: if any_observed {
                "lab_partial: Observed facets present — do not market as Effective A".into()
            } else {
                "effective_a: all facets Enforced/Effective".into()
            },
        }
    }

    /// Effective \(\mathcal{A}\) = meet of facets with grade ≥ Enforced (Observed excluded).
    pub fn effective_meet(facets: &AutonomyFacets) -> Self {
        let mut meet = AutonomyFacets::default();
        let take = |ax: &Option<FacetAxis>| {
            ax.as_ref()
                .filter(|a| a.grade.counts_for_effective_a())
                .cloned()
        };
        meet.c_capability = take(&facets.c_capability);
        meet.g_grants = take(&facets.g_grants);
        meet.d_ifc = take(&facets.d_ifc);
        meet.i_irreversibility = take(&facets.i_irreversibility);
        meet.t_temporal = take(&facets.t_temporal);
        meet.q_budgets = take(&facets.q_budgets);
        meet.p_posture = take(&facets.p_posture);
        meet.n_topology = take(&facets.n_topology);
        let grades = meet.iter_grades();
        let effective_claim = !grades.is_empty()
            && grades
                .iter()
                .all(|(_, g)| g.counts_for_effective_a());
        let body = json!({ "effective_meet": meet.to_json() });
        let digest =
            format!("{:x}", Sha256::digest(serde_json::to_vec(&body).unwrap_or_default()));
        Self {
            facets: meet,
            digest,
            effective_claim,
            honesty: if effective_claim {
                "effective_a: meet of Enforced/Effective facets only".into()
            } else {
                "effective_a: empty or incomplete — Observed facets do not shrink claim".into()
            },
        }
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_partial_not_effective_claim() {
        let v = AutonomyVolume::from_facets(AutonomyFacets::lab_partial_v0());
        assert!(!v.effective_claim);
        assert!(v.honesty.contains("lab_partial"));
    }

    #[test]
    fn child_amplify_refused() {
        let parent = AutonomyFacets::lab_partial_v0();
        let mut child = parent.clone();
        if let Some(ref mut g) = child.g_grants {
            g.digest = "amplified".into();
            g.encoding = json!({"wider": true});
        }
        assert!(parent.meet_child(&child).is_err());
    }

    #[test]
    fn child_same_ok() {
        let parent = AutonomyFacets::lab_partial_v0();
        let child = parent.clone();
        assert!(parent.meet_child(&child).is_ok());
    }

    #[test]
    fn dit_enforced_in_effective_meet() {
        let f = AutonomyFacets::lab_partial_v0().with_dit_enforced();
        let meet = AutonomyVolume::effective_meet(&f);
        assert!(meet.facets.d_ifc.is_some());
        assert!(meet.facets.i_irreversibility.is_some());
        assert!(meet.facets.t_temporal.is_some());
        assert!(meet.effective_claim);
        let full = AutonomyVolume::from_facets(f);
        assert!(!full.effective_claim);
    }

    #[test]
    fn cgqp_enforced_n_still_observed() {
        let f = AutonomyFacets::lab_partial_v0()
            .with_dit_enforced()
            .with_cgqp_enforced();
        let meet = AutonomyVolume::effective_meet(&f);
        assert!(meet.effective_claim);
        assert!(meet.facets.c_capability.is_some());
        assert_eq!(
            f.n_topology.as_ref().unwrap().grade,
            EnforcementGrade::Observed
        );
        let full = AutonomyVolume::from_facets(f);
        assert!(!full.effective_claim); // N Observed keeps lab_partial honesty
    }

    #[test]
    fn observed_cannot_shrink_effective_claim() {
        let only_obs = AutonomyFacets::lab_partial_v0();
        let meet = AutonomyVolume::effective_meet(&only_obs);
        assert!(!meet.effective_claim);
        assert!(meet.facets.iter_grades().is_empty());
    }

    #[test]
    fn facet_denial_names_axis() {
        let d = FacetDenial::new("D", EnforcementGrade::Enforced, "IFC write-down");
        assert_eq!(d.to_json()["facet"], "D");
        assert_eq!(d.to_json()["grade"], "enforced");
    }
}

//! Surface Engine — The unified orchestrator
//!
//! This is the main entry point for SOE. It combines all components:
//! - CID-based content addressing
//! - Receipt/proof chains
//! - Trust tiers
//! - Time-travel queries
//! - Governance/policy
//! - Streaming
//! - Metrics
//! - Kernel integration

use super::cid::{SurfaceCid, AddressedSurface, SurfaceCache};
use super::export::{ExportFormat, Exporter};
use super::renderer::{JsonRenderer, Renderer, TerminalRenderer};
use super::receipt::{SurfaceReceipt, ReceiptChain, TimeContext};
use super::roles::{RedactionLevel, Redactor, Role, ValueType};
use super::tiers::{TrustTier, TierVerification, TieredSurface};
use super::time::{SurfaceTimeSelector, TimedSurfaceQuery, ResolvedTimeRange};
use super::governance::{SurfaceGovernance, SurfaceAccessRequest, GovernanceResult, PolicyDecision};
use super::stream::{SurfaceBus, SurfaceEvent, SurfaceEventType, SurfaceEventPayload};
use super::metrics::{SurfaceMetrics, RenderTimer, metrics};
use super::kernel::{KernelBridge, KernelData, KernelQuery, KernelQueryType};
use super::pagination::{FilterOp, FilterValue, PageInfo, Query};
use std::fmt;
use super::{
    contract::{Judgment, Signal, SignalIcon, SurfaceContract},
    document::{ComplianceState, EvidenceItem, EvidencePosture, EvidenceStatus, ExecutionState, Finding, HealthState, KeyValueItem, LinkAction, ListItem, ResourceKind, ResourceLink, SectionContent, SectionKind, Severity, StatItem, StateVector, SubjectIdentity, SurfaceAction, SurfaceBadge, SurfaceDocument, SurfaceFooter, SurfaceHeader, SurfaceMeta, SurfaceSection, SurfaceType, SurfaceView, TimelineEvent, TraceSpan, TrustComponents, TrustScore, TrustState},
    package::{ComplianceBadge, ComplianceStatus, ConfidenceLevel, ConfidenceLine, CostLine, DecisionDeepSections, DecisionForensicSections, DecisionLine, DecisionMeta, DecisionSurfacePackage, NextAction, ProofLine, ProofStatus},
    translator::{StandardTranslator, Translator},
};

/// The Surface Output Engine — unified orchestrator
pub struct SurfaceEngine {
    cache: SurfaceCache,
    receipts: ReceiptChain,
    governance: SurfaceGovernance,
    bus: SurfaceBus,
    kernel: KernelBridge,
    translator: StandardTranslator,
    config: EngineConfig,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub cache_enabled: bool,
    pub cache_size: usize,
    pub governance_enabled: bool,
    pub receipts_enabled: bool,
    pub streaming_enabled: bool,
    pub default_ttl_ms: u64,
    /// When true, reject renders that fail `SurfaceContract::validate` (Surface Contract Standard).
    pub enforce_surface_contract: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            cache_enabled: true,
            cache_size: 1000,
            governance_enabled: true,
            receipts_enabled: true,
            streaming_enabled: true,
            default_ttl_ms: 60_000,
            enforce_surface_contract: true,
        }
    }
}

/// Request to render a surface
#[derive(Debug, Clone)]
pub struct RenderRequest {
    pub surface_type: SurfaceType,
    pub view: SurfaceView,
    pub subject_id: String,
    pub actor: String,
    pub role: Role,
    pub time: SurfaceTimeSelector,
    pub namespace: Option<String>,
    pub export_format: Option<ExportFormat>,
    pub query: Option<Query>,
}

impl RenderRequest {
    pub fn new(surface_type: SurfaceType, subject_id: &str, actor: &str, role: Role) -> Self {
        Self {
            surface_type,
            view: role.default_view(),
            subject_id: subject_id.to_string(),
            actor: actor.to_string(),
            role,
            time: SurfaceTimeSelector::Now,
            namespace: None,
            export_format: None,
            query: None,
        }
    }

    pub fn view(mut self, view: SurfaceView) -> Self { self.view = view; self }
    pub fn time(mut self, time: SurfaceTimeSelector) -> Self { self.time = time; self }
    pub fn namespace(mut self, ns: &str) -> Self { self.namespace = Some(ns.to_string()); self }
    pub fn export(mut self, format: ExportFormat) -> Self { self.export_format = Some(format); self }
    pub fn query(mut self, query: Query) -> Self { self.query = Some(query); self }
}

/// The result of a surface rendering operation.
#[derive(Debug, Clone)]
pub struct RenderResult {
    /// Validated mandatory contract (Surface Contract Standard) for this render.
    pub contract: SurfaceContract,
    /// Applied query (pagination/filter/search), if any.
    pub query: Option<Query>,
    /// Pagination metadata for the primary list section after filtering.
    pub page_info: Option<PageInfo>,
    /// The semantic decision package, which is the primary user-facing output.
    pub package: Option<DecisionSurfacePackage>,
    /// The tiered, addressed surface containing the full document and trust info.
    pub surface: TieredSurface<AddressedSurface>,
    /// The receipt for this rendering operation.
    pub receipt: Option<SurfaceReceipt>,
    /// The result of the governance evaluation.
    pub governance: GovernanceResult,
    /// Whether the result was served from cache.
    pub from_cache: bool,
    /// The time taken to render the surface, in milliseconds.
    pub render_time_ms: u64,
}

impl RenderResult {
    pub fn document(&self) -> &SurfaceDocument {
        &self.surface.data.document
    }

    pub fn package(&self) -> Option<&DecisionSurfacePackage> {
        self.package.as_ref()
    }

    pub fn cid(&self) -> &SurfaceCid {
        &self.surface.data.cid
    }

    pub fn tier(&self) -> TrustTier {
        self.surface.effective_tier()
    }

    pub fn to_terminal(&self) -> String {
        let renderer = TerminalRenderer::new();
        match (self.package(), self.document().meta.view) {
            (Some(package), SurfaceView::Summary) | (Some(package), SurfaceView::Exec) => renderer.render_decision_card(package),
            _ => renderer.render(self.document()),
        }
    }

    pub fn to_json(&self) -> String {
        self.to_json_with_meta(None, None)
    }

    /// Produce the canonical SOE JSON envelope with an optional `_meta` block.
    ///
    /// Callers (HTTP handlers, CLI) pass `surface_type` and `caller_role` so the
    /// envelope is self-describing for log aggregation and operator tooling.
    pub fn to_json_with_meta(
        &self,
        surface_type: Option<&str>,
        caller_role: Option<&str>,
    ) -> String {
        #[derive(serde::Serialize)]
        struct SurfaceMeta2 {
            version: &'static str,
            generated_at: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            surface_type: Option<String>,
            view: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            caller_role: Option<String>,
            render_ms: u64,
            from_cache: bool,
            cid: String,
        }

        #[derive(serde::Serialize)]
        struct JsonSurfaceOutput<'a> {
            _meta: SurfaceMeta2,
            surface_contract: &'a SurfaceContract,
            #[serde(skip_serializing_if = "Option::is_none")]
            query: Option<&'a Query>,
            #[serde(skip_serializing_if = "Option::is_none")]
            page_info: Option<&'a PageInfo>,
            #[serde(skip_serializing_if = "Option::is_none")]
            decision_package: Option<&'a DecisionSurfacePackage>,
            document: &'a SurfaceDocument,
        }

        let view_str = match self.document().meta.view {
            SurfaceView::Summary => "summary",
            SurfaceView::Ops => "ops",
            SurfaceView::Forensic => "forensic",
            SurfaceView::Exec => "exec",
        };

        let renderer = JsonRenderer;
        let legacy = match self.package() {
            Some(package) => renderer.render_package(package),
            None => renderer.render(self.document()),
        };

        let envelope = JsonSurfaceOutput {
            _meta: SurfaceMeta2 {
                version: env!("CARGO_PKG_VERSION"),
                generated_at: chrono::Utc::now().to_rfc3339(),
                surface_type: surface_type.map(|s| s.to_string()),
                view: view_str.to_string(),
                caller_role: caller_role.map(|s| s.to_string()),
                render_ms: self.render_time_ms,
                from_cache: self.from_cache,
                cid: self.cid().hash.clone(),
            },
            surface_contract: &self.contract,
            query: self.query.as_ref(),
            page_info: self.page_info.as_ref(),
            decision_package: self.package.as_ref(),
            document: self.document(),
        };
        serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| legacy)
    }

    pub fn export(&self, format: ExportFormat) -> String {
        Exporter::export(self.document(), format)
    }
}

/// Error from render operation
#[derive(Debug, Clone)]
pub enum RenderError {
    PolicyDenied(GovernanceResult),
    SubjectNotFound(String),
    TimeRangeInvalid(String),
    KernelError(String),
    InternalError(String),
    /// Output did not satisfy `SurfaceContract::validate` (enterprise / Surface Contract Standard).
    ContractViolation { errors: Vec<String>, warnings: Vec<String> },
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied(g) => write!(f, "policy denied ({:?})", g.decision),
            Self::SubjectNotFound(s) => write!(f, "subject not found: {s}"),
            Self::TimeRangeInvalid(s) => write!(f, "invalid time range: {s}"),
            Self::KernelError(s) => write!(f, "kernel error: {s}"),
            Self::InternalError(s) => write!(f, "internal error: {s}"),
            Self::ContractViolation { errors, warnings } => {
                write!(f, "surface contract violation")?;
                if !errors.is_empty() {
                    write!(f, ": {}", errors.join("; "))?;
                }
                if !warnings.is_empty() {
                    write!(f, " [warnings: {}]", warnings.join("; "))?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for RenderError {}

impl Default for SurfaceEngine {
    fn default() -> Self { Self::new(EngineConfig::default()) }
}

impl SurfaceEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            cache: SurfaceCache::new(config.cache_size),
            receipts: ReceiptChain::new(),
            governance: SurfaceGovernance::new(),
            bus: SurfaceBus::new(1000),
            kernel: KernelBridge::mock(),
            translator: StandardTranslator::new(),
            config,
        }
    }

    /// Create a live engine that queries real platform API data.
    /// `api_base` should be the base URL, e.g. "http://localhost:9091".
    pub fn live(api_base: &str) -> Self {
        let config = EngineConfig::default();
        Self {
            cache: SurfaceCache::new(config.cache_size),
            receipts: ReceiptChain::new(),
            governance: SurfaceGovernance::new(),
            bus: SurfaceBus::new(1000),
            kernel: KernelBridge::live(api_base),
            translator: StandardTranslator::new(),
            config,
        }
    }

    /// Render a surface with full pipeline
    pub fn render(&mut self, request: RenderRequest) -> Result<RenderResult, RenderError> {
        let timer = RenderTimer::start();

        // 1. Governance check
        let gov_request = SurfaceAccessRequest {
            actor: request.actor.clone(),
            role: request.role,
            surface_type: request.surface_type,
            view: request.view,
            subject_id: request.subject_id.clone(),
            namespace: request.namespace.clone(),
            time_travel: !matches!(request.time, SurfaceTimeSelector::Now),
            export_format: request.export_format.map(|f| format!("{:?}", f)),
        };

        let gov_result = if self.config.governance_enabled {
            self.governance.evaluate(&gov_request)
        } else {
            GovernanceResult {
                decision: PolicyDecision::Allow,
                violations: vec![],
                redaction_level: None,
                requires_approval: false,
                approver: None,
            }
        };

        if gov_result.is_denied() {
            metrics().record_policy_denial();
            return Err(RenderError::PolicyDenied(gov_result));
        }

        // 2. Resolve time
        let now = chrono::Utc::now().timestamp_millis();
        let resolved_time = request.time.resolve(now);
        if resolved_time.is_time_travel {
            metrics().record_time_travel();
        }

        // 3. Check cache
        let _cache_key = format!("{}:{}:{:?}:{}", request.subject_id, request.surface_type as u8, request.view, resolved_time.start);
        // For simplicity, we'll generate fresh each time but track cache metrics
        metrics().record_cache_miss();

        // 4. Query kernel for data
        let kernel_query = KernelQuery {
            subject_id: request.subject_id.clone(),
            query_type: Self::surface_to_kernel_query(request.surface_type),
            time_context: Some(TimeContext {
                selector: request.time.display(),
                resolved_start: resolved_time.start,
                resolved_end: resolved_time.end,
                is_time_travel: resolved_time.is_time_travel,
            }),
            namespace: request.namespace.clone(),
            // BUG-48: honour request pagination limit instead of hardcoded 100
            limit: Some(request.query.as_ref().map(|q| q.page.page_size).unwrap_or(100)),
        };
        let kernel_result = self.kernel.query(kernel_query);

        // BUG-50: For multi-source surfaces, run a supplementary AuditEntries query and
        // merge its sections so Explain/Inspect have both state and audit data in one render.
        let supplementary_sections = if matches!(request.surface_type, SurfaceType::Explain | SurfaceType::Inspect) {
            let supp_query = KernelQuery {
                subject_id: request.subject_id.clone(),
                query_type: KernelQueryType::AuditEntries,
                time_context: None,
                namespace: request.namespace.clone(),
                limit: Some(20),
            };
            let supp_result = self.kernel.query(supp_query);
            self.kernel.to_sections(&supp_result)
        } else {
            vec![]
        };

        // 5. Build surface document
        let mut sections = self.kernel.to_sections(&kernel_result);
        sections.extend(supplementary_sections);
        let document = self.build_document(&request, &resolved_time, sections, &kernel_result.data);
        let document = Self::apply_role_filters(&request, &gov_result, document);
        let (document, page_info) = Self::apply_query_to_document(document, request.query.as_ref());
        let contract = self.build_contract(&request, &document, &kernel_result.data);
        if self.config.enforce_surface_contract {
            let validation = contract.validate();
            if !validation.valid {
                metrics().record_error();
                return Err(RenderError::ContractViolation {
                    errors: validation
                        .errors
                        .iter()
                        .map(|e| format!("{}: {}", e.field, e.message))
                        .collect(),
                    warnings: validation
                        .warnings
                        .iter()
                        .map(|w| format!("{}: {}", w.field, w.message))
                        .collect(),
                });
            }
        }
        let package_doc_cid = SurfaceCid::from_document(&document);
        let package = self.build_decision_package(&request, &contract, &package_doc_cid, &document, &kernel_result.data)?;

        // 6. Create addressed surface with CID
        let addressed = AddressedSurface::new(document).with_ttl(self.config.default_ttl_ms);
        let cid = addressed.cid.clone();

        // 7. Create tiered surface
        let tiered = TieredSurface::new(addressed, kernel_result.tier.clone())
            .with_sources(vec![kernel_result.source.trust_tier()]);

        // 8. Create receipt
        let receipt = if self.config.receipts_enabled {
            let r = SurfaceReceipt::new(
                cid.clone(),
                request.surface_type,
                request.view,
                &request.subject_id,
                &request.actor,
                &format!("{:?}", request.role),
                timer.elapsed_ms(),
            ).with_time_context(TimeContext {
                selector: request.time.display(),
                resolved_start: resolved_time.start,
                resolved_end: resolved_time.end,
                is_time_travel: resolved_time.is_time_travel,
            });
            self.receipts.append(r.clone());
            metrics().record_receipt();
            Some(r)
        } else {
            None
        };

        // 9. Emit stream event
        if self.config.streaming_enabled {
            self.bus.publish(SurfaceEvent::new(
                SurfaceEventType::Info,
                &request.subject_id,
                SurfaceEventPayload::Text(format!("Surface rendered: {}", cid.short())),
            ));
            metrics().record_stream_event();
        }

        let render_time = timer.finish();

        Ok(RenderResult {
            contract,
            query: request.query.clone(),
            page_info,
            package: Some(package),
            surface: tiered,
            receipt,
            governance: gov_result,
            from_cache: false,
            render_time_ms: render_time,
        })
    }

    fn surface_to_kernel_query(st: SurfaceType) -> KernelQueryType {
        match st {
            // BUG-27: Review should use AgentHealth for real error_rate/health_score data
            SurfaceType::Agent | SurfaceType::Health | SurfaceType::Review => KernelQueryType::AgentHealth,
            SurfaceType::Debug | SurfaceType::Trace => KernelQueryType::AgentTrace,
            SurfaceType::Audit => KernelQueryType::AuditEntries,
            SurfaceType::Books => KernelQueryType::JournalEntries,
            SurfaceType::Memory => KernelQueryType::MemoryPackets,
            SurfaceType::Proof => KernelQueryType::EvidenceChain,
            _ => KernelQueryType::AgentState,
        }
    }

    fn surface_type_label(st: SurfaceType) -> &'static str {
        match st {
            SurfaceType::Explain  => "Explain",
            SurfaceType::Inspect  => "Inspect",
            SurfaceType::Review   => "Review",
            SurfaceType::Proof    => "Proof",
            SurfaceType::Audit    => "Audit",
            SurfaceType::Health   => "Health",
            SurfaceType::Trace    => "Trace",
            SurfaceType::Memory   => "Memory",
            SurfaceType::Monitor  => "Monitor",
            SurfaceType::Compliance => "Compliance",
            SurfaceType::Knowledge => "Knowledge",
            SurfaceType::Policy   => "Policy",
            SurfaceType::Tool     => "Tool",
            SurfaceType::Contract => "Contract",
            SurfaceType::Books    => "Books",
            SurfaceType::Debug    => "Debug",
            SurfaceType::Agent    => "Agent",
        }
    }

    fn build_document(&self, request: &RenderRequest, time: &ResolvedTimeRange, sections: Vec<SurfaceSection>, kernel_data: &KernelData) -> SurfaceDocument {
        let state = Self::state_from_kernel_data(request.surface_type, kernel_data);
        let human_name = Self::humanize_subject_id(&request.subject_id);
        let mut subject = SubjectIdentity::new(
            Self::surface_to_resource_kind(request.surface_type),
            &request.subject_id,
        );
        // Use humanized short name in the box instead of "kind/full-uuid"
        subject.display = human_name.clone();
        let badges = Self::badges_for_request(request, time, kernel_data);
        // For Explain surface: secondary query for audit entries to populate Recent Execution
        let secondary_kernel_result = if request.surface_type == SurfaceType::Explain {
            let audit_query = KernelQuery {
                subject_id: request.subject_id.clone(),
                query_type: KernelQueryType::AuditEntries,
                time_context: None,
                namespace: request.namespace.clone(),
                limit: Some(10),
            };
            Some(self.kernel.query(audit_query))
        } else {
            None
        };
        let secondary_data = secondary_kernel_result.as_ref().map(|r| &r.data);

        // For decision subjects (dec_): fetch EvidenceChain so footer gets real receipt count/hash
        let evidence_result = if request.subject_id.starts_with("dec_") && !matches!(kernel_data, KernelData::EvidenceChain { .. }) {
            let evidence_query = KernelQuery {
                subject_id: request.subject_id.clone(),
                query_type: KernelQueryType::EvidenceChain,
                time_context: None,
                namespace: request.namespace.clone(),
                limit: None,
            };
            let r = self.kernel.query(evidence_query);
            if matches!(r.data, KernelData::Empty) { None } else { Some(r) }
        } else {
            None
        };
        let evidence_data = evidence_result.as_ref().map(|r| &r.data);

        let sections = Self::surface_sections_for_request(request, sections, kernel_data, secondary_data);
        let actions = Self::actions_for_request(request);

        let summary = self.generate_judgment_text_from_data(request, kernel_data);

        // Merge evidence chain data into footer when available from tertiary query
        let (footer_root_hash, footer_verified, footer_receipt_count, footer_chain_valid) =
            if let Some(ev) = evidence_data {
                (
                    Self::root_hash_from_data(ev),
                    Self::verified_from_data(ev),
                    Self::receipt_count_from_data(request.surface_type, ev),
                    {
                        let count = Self::receipt_count_from_data(request.surface_type, ev);
                        // Empty chain (0 receipts) is valid; only invalid if receipts exist and fail verification
                        count == 0 || matches!(ev, KernelData::EvidenceChain { verified: true, .. })
                    },
                )
            } else {
                (
                    Self::root_hash_from_data(kernel_data),
                    Self::verified_from_data(kernel_data),
                    Self::receipt_count_from_data(request.surface_type, kernel_data),
                    {
                        let count = Self::receipt_count_from_data(request.surface_type, kernel_data);
                        // Empty chain is valid; only check verification when receipts exist
                        count == 0 || match kernel_data {
                            KernelData::EvidenceChain { verified, .. } => *verified,
                            _ => self.receipts.verify() || self.receipts.is_empty(),
                        }
                    },
                )
            };

        SurfaceDocument {
            meta: SurfaceMeta {
                surface_type: request.surface_type,
                view: request.view,
                generated_at: chrono::Utc::now().timestamp_millis(),
            },
            header: SurfaceHeader {
                title: format!("{}: {}", Self::surface_type_label(request.surface_type), human_name),
                subject,
                state,
                badges,
                time_range: if time.is_time_travel { Some(time.display()) } else { None },
            },
            summary: Some(summary),
            sections,
            actions,
            footer: Some(SurfaceFooter {
                root_hash: footer_root_hash,
                verified: footer_verified,
                receipt_count: footer_receipt_count,
                chain_valid: footer_chain_valid,
                timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            }),
        }
    }

    fn build_contract(&self, request: &RenderRequest, doc: &SurfaceDocument, kernel_data: &KernelData) -> SurfaceContract {
        let evidence = doc.footer.as_ref().map(|footer| EvidencePosture {
            status: if footer.verified && footer.chain_valid {
                EvidenceStatus::Complete
            } else if footer.verified {
                EvidenceStatus::Partial
            } else {
                EvidenceStatus::Missing
            },
            receipt_count: footer.receipt_count as usize,
            verified: footer.verified,
            chain_intact: footer.chain_valid,
            completeness: if footer.verified && footer.chain_valid {
                1.0
            } else if footer.verified {
                // BUG-25: ratio based on receipt depth; cap at 0.95 until chain confirmed intact
                (footer.receipt_count as f64 / 10.0).min(0.95).max(0.35)
            } else {
                // No verification — scale by receipt existence
                if footer.receipt_count > 0 { 0.15 } else { 0.0 }
            },
            root_hash: footer.root_hash.clone(),
        }).unwrap_or(EvidencePosture {
            status: EvidenceStatus::Missing,
            receipt_count: 0,
            verified: false,
            chain_intact: false,
            completeness: 0.0,
            root_hash: None,
        });

        let judgment_text = doc.summary.clone().unwrap_or_else(|| format!("{:?} ready", request.surface_type));
        let severity = Self::severity_for_state(&doc.header.state);
        let signals = Self::signals_from_document(doc, kernel_data, &request.subject_id);

        SurfaceContract {
            subject: doc.header.subject.clone(),
            state: doc.header.state.clone(),
            judgment: Judgment { text: judgment_text, severity },
            signals,
            actions: doc.actions.clone(),
            evidence,
            trust: Self::trust_from_document(doc, kernel_data),
        }
    }

    /// Builds the semantic `DecisionSurfacePackage` from a validated `SurfaceContract`.
    fn build_decision_package(
        &self,
        request: &RenderRequest,
        contract: &SurfaceContract,
        doc_cid: &SurfaceCid,
        doc: &SurfaceDocument,
        kernel_data: &KernelData,
    ) -> Result<DecisionSurfacePackage, RenderError> {
        let why = self.translator.translate_why(&contract, doc);
        let risk = self.translator.translate_risk(&contract, doc);

        let proof_status = if contract.evidence.verified && contract.evidence.chain_intact {
            ProofStatus::Verified
        } else if contract.evidence.verified {
            ProofStatus::Incomplete
        } else {
            ProofStatus::Unverified
        };

        let proof_summary = match proof_status {
            ProofStatus::Verified => format!("Verified · {} receipts · chain intact", contract.evidence.receipt_count),
            ProofStatus::Incomplete => format!("Verified · {} receipts · chain needs review", contract.evidence.receipt_count),
            ProofStatus::Tampered => "Evidence tampered".to_string(),
            ProofStatus::Unverified => "Unverified evidence chain".to_string(),
        };

        // Derive compliance framework label from namespace/subject hints or kernel data
        let compliance_label: String = {
            let ns = request.namespace.as_deref().unwrap_or("");
            let sid = &request.subject_id;
            let ns_lower = format!("{} {}", ns, sid).to_lowercase();
            if ns_lower.contains("hipaa") || ns_lower.contains("phi") {
                "HIPAA".into()
            } else if ns_lower.contains("soc2") || ns_lower.contains("soc-2") {
                "SOC 2".into()
            } else if ns_lower.contains("gdpr") {
                "GDPR".into()
            } else if ns_lower.contains("pci") {
                "PCI DSS".into()
            } else {
                match request.surface_type {
                    SurfaceType::Audit => "Audit policy".into(),
                    SurfaceType::Proof => "Evidence integrity".into(),
                    _ => "Security baseline".into(),
                }
            }
        };
        let compliance = match contract.state.compliance {
            ComplianceState::Compliant => vec![ComplianceBadge { standard: compliance_label.into(), status: ComplianceStatus::Pass }],
            ComplianceState::Partial => vec![ComplianceBadge { standard: compliance_label.into(), status: ComplianceStatus::Warn }],
            ComplianceState::NonCompliant => vec![ComplianceBadge { standard: format!("{} — violation detected", compliance_label), status: ComplianceStatus::Fail }],
            ComplianceState::Unknown => vec![ComplianceBadge { standard: "Compliance posture unknown".into(), status: ComplianceStatus::Warn }],
        };

        let cost = if request.surface_type == SurfaceType::Monitor {
            if let KernelData::AgentState { total_cost_usd, total_tokens, tool_calls, .. } = kernel_data {
                if *total_cost_usd > 0.0 || *total_tokens > 0 {
                    Some(CostLine {
                        amount_usd: *total_cost_usd,
                        change_summary: Some(format!("{} operations · {} tokens", tool_calls, total_tokens)),
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let confidence_score = (contract.trust.score as f64 / 100.0).clamp(0.0, 1.0);
        let confidence = Some(ConfidenceLine {
            score: confidence_score,
            level: if confidence_score >= 0.85 {
                ConfidenceLevel::High
            } else if confidence_score >= 0.60 {
                ConfidenceLevel::Medium
            } else {
                ConfidenceLevel::Low
            },
        });

        let next = contract.actions.iter().map(|action| NextAction {
            label: action.label.clone(),
            command: action.command.clone(),
            primary: action.primary,
        }).collect::<Vec<_>>();

        let package_cid = format!("pkg:{}", doc_cid);

        let deep = if matches!(request.view, SurfaceView::Ops) {
            Some(DecisionDeepSections { sections: doc.sections.clone() })
        } else {
            None
        };

        let forensic = if matches!(request.view, SurfaceView::Forensic) {
            Some(DecisionForensicSections { sections: doc.sections.clone() })
        } else {
            None
        };

        Ok(DecisionSurfacePackage {
            subject: contract.subject.clone(),
            decision: DecisionLine {
                outcome: contract.judgment.text.clone(),
            },
            why,
            risk,
            compliance,
            proof: ProofLine {
                status: proof_status,
                summary: proof_summary,
            },
            cost,
            next,
            confidence,
            meta: DecisionMeta {
                timestamp: doc.meta.generated_at,
                package_cid,
                source_document_cid: doc_cid.to_string(),
            },
            deep,
            forensic,
        })
    }

    fn trust_from_document(doc: &SurfaceDocument, kernel_data: &KernelData) -> TrustScore {
        let footer = doc.footer.as_ref();
        let verified = footer.map(|f| f.verified && f.chain_valid).unwrap_or(false);
        // d1: evidence chain verified (0-20)
        let d1: u8 = if verified { 20 } else if footer.map(|f| f.verified).unwrap_or(false) { 10 } else { 0 };
        // d2: receipt depth (0-20)
        let receipt_count = footer.map(|f| f.receipt_count).unwrap_or(0);
        let d2: u8 = ((receipt_count as f64 / 10.0).min(1.0) * 20.0) as u8;
        // d3: health state (0-25)
        let d3: u8 = match doc.header.state.health {
            HealthState::Healthy => 25,
            HealthState::Degraded => 14,
            HealthState::Unhealthy => 4,
            _ => 10,
        };
        // d4: compliance state (0-20)
        let d4: u8 = match doc.header.state.compliance {
            ComplianceState::Compliant => 20,
            ComplianceState::Partial => 12,
            ComplianceState::NonCompliant => 2,
            ComplianceState::Unknown => 8,
        };
        // d5: kernel signal (0-15)
        let d5: u8 = match kernel_data {
            KernelData::AgentHealth { error_rate, .. } => ((1.0 - error_rate) * 15.0) as u8,
            KernelData::AgentState { status, .. } => match status.as_str() {
                "running" | "active" | "healthy" => 15,
                "idle" | "completed" | "done" => 12,
                "degraded" => 8,
                "paused" | "suspended" => 6,
                "blocked" | "budget_exceeded" => 3,
                "failed" | "error" => 0,
                _ => 8,
            },
            _ => 8,
        };
        let score = (d1 + d2 + d3 + d4 + d5).min(100);
        TrustScore::with_components(score, TrustComponents {
            integrity: Some(d1 + d2),
            provenance: Some(d3),
            policy: Some(d4 + d5),
        })
    }

    fn state_from_kernel_data(surface_type: SurfaceType, kernel_data: &KernelData) -> StateVector {
        let _ = surface_type;
        match kernel_data {
            KernelData::AgentState { status, .. } => {
                let execution = if status.starts_with("decision:") {
                    if status.contains("blocked") || status.contains("denied") || status.contains("rejected") {
                        ExecutionState::Blocked
                    } else {
                        ExecutionState::Completed
                    }
                } else {
                    match status.as_str() {
                        "running" | "active" | "healthy" => ExecutionState::Active,
                        "idle" | "inactive" => ExecutionState::Idle,
                        "paused" | "suspended" => ExecutionState::Paused,
                        "failed" | "error" => ExecutionState::Failed,
                        "blocked" | "budget_exceeded" => ExecutionState::Blocked,
                        "completed" | "done" => ExecutionState::Completed,
                        _ => ExecutionState::Idle,
                    }
                };
                let health = match status.as_str() {
                    "running" | "active" | "healthy" | "idle" | "completed" | "done" => HealthState::Healthy,
                    "degraded" => HealthState::Degraded,
                    "failed" | "error" | "budget_exceeded" => HealthState::Unhealthy,
                    _ if status.starts_with("decision:") => HealthState::Healthy,
                    _ => HealthState::Unknown,
                };
                let compliance = if status.starts_with("decision:") && (status.contains("blocked") || status.contains("denied")) {
                    ComplianceState::NonCompliant
                } else {
                    match status.as_str() {
                        "blocked" => ComplianceState::NonCompliant,
                        "paused" | "suspended" | "degraded" => ComplianceState::Partial,
                        _ => ComplianceState::Compliant,
                    }
                };
                let trust = match (execution, health) {
                    (ExecutionState::Failed, _) => TrustState::Broken,
                    (ExecutionState::Blocked, _) | (_, HealthState::Unhealthy) => TrustState::Degraded,
                    (_, HealthState::Degraded) | (ExecutionState::Paused, _) => TrustState::Partial,
                    _ => TrustState::Verified,
                };
                StateVector { execution, trust, health, compliance }
            }
            KernelData::AgentHealth { health_score, error_rate, .. } => {
                let health = if *health_score >= 80 { HealthState::Healthy }
                    else if *health_score >= 50 { HealthState::Degraded }
                    else { HealthState::Unhealthy };
                let execution = if *error_rate > 0.5 { ExecutionState::Failed } else { ExecutionState::Active };
                let compliance = if *health_score >= 80 { ComplianceState::Compliant }
                    else if *health_score >= 50 { ComplianceState::Partial }
                    else { ComplianceState::NonCompliant };
                let trust = match health {
                    HealthState::Healthy => TrustState::Verified,
                    HealthState::Degraded => TrustState::Partial,
                    _ => TrustState::Degraded,
                };
                StateVector { execution, trust, health, compliance }
            }
            KernelData::EvidenceChain { verified, .. } => {
                let trust = if *verified { TrustState::Verified } else { TrustState::Broken };
                let compliance = if *verified { ComplianceState::Compliant } else { ComplianceState::NonCompliant };
                StateVector { execution: ExecutionState::Completed, trust, health: HealthState::Healthy, compliance }
            }
            KernelData::AuditEntries(entries) => {
                let has_failures = entries.iter().any(|e| {
                    e.outcome.contains("fail") || e.outcome.contains("blocked") || e.outcome.contains("denied")
                });
                StateVector {
                    execution: if has_failures { ExecutionState::Failed } else { ExecutionState::Active },
                    trust: if has_failures { TrustState::Partial } else { TrustState::Verified },
                    health: HealthState::Healthy,
                    compliance: ComplianceState::Compliant,
                }
            }
            KernelData::JournalEntries(entries) => {
                let has_failures = entries.iter().any(|e| {
                    e.outcome.contains("fail") || e.outcome.contains("blocked") || e.outcome.contains("denied") || e.outcome.contains("error")
                });
                if has_failures {
                    StateVector {
                        execution: ExecutionState::Failed,
                        trust: TrustState::Partial,
                        health: HealthState::Degraded,
                        compliance: ComplianceState::Partial,
                    }
                } else {
                    StateVector::active_verified()
                }
            }
            KernelData::MemoryPackets(_) => StateVector::active_verified(),
            KernelData::CompliancePosture { compliant, partial, .. } => {
                let compliance = if *compliant { ComplianceState::Compliant }
                    else if *partial { ComplianceState::Partial }
                    else { ComplianceState::NonCompliant };
                StateVector {
                    execution: ExecutionState::Active,
                    trust: if *compliant { TrustState::Verified } else { TrustState::Partial },
                    health: HealthState::Healthy,
                    compliance,
                }
            }
            KernelData::Unavailable { .. } => StateVector {
                execution: ExecutionState::Idle,
                trust: TrustState::Unknown,
                health: HealthState::Unknown,
                compliance: ComplianceState::Unknown,
            },
            KernelData::Empty => StateVector {
                execution: ExecutionState::Idle,
                trust: TrustState::Unknown,
                health: HealthState::Unknown,
                compliance: ComplianceState::Unknown,
            },
        }
    }

    fn badges_for_request(request: &RenderRequest, time: &ResolvedTimeRange, kernel_data: &KernelData) -> Vec<SurfaceBadge> {
        let mut badges = vec![
            SurfaceBadge {
                label: "View".into(),
                value: format!("{:?}", request.view),
                severity: Severity::Info,
            },
            SurfaceBadge {
                label: "Time".into(),
                value: if time.is_time_travel { "HISTORICAL" } else { "LIVE" }.into(),
                severity: if time.is_time_travel { Severity::Warn } else { Severity::Ok },
            },
        ];

        match request.surface_type {
            SurfaceType::Explain => {
                let status = if let KernelData::AgentState { status, .. } = kernel_data {
                    status.clone()
                } else { "unknown".into() };
                let sev = if status == "healthy" || status == "running" { Severity::Ok } else { Severity::Warn };
                badges.push(SurfaceBadge { label: "Status".into(), value: status, severity: sev });
                let (cap_value, cap_sev) = match kernel_data {
                    KernelData::AgentState { status, .. } if matches!(status.as_str(), "blocked" | "budget_exceeded" | "suspended" | "failed" | "error") =>
                        ("Restricted", Severity::Warn),
                    KernelData::AgentState { .. } => ("Active", Severity::Ok),
                    _ => ("Unknown", Severity::Info),
                };
                badges.push(SurfaceBadge { label: "Capabilities".into(), value: cap_value.into(), severity: cap_sev });
            }
            SurfaceType::Review => {
                let (risk_label, risk_sev) = Self::risk_from_kernel_data(kernel_data);
                badges.push(SurfaceBadge { label: "Risk".into(), value: risk_label, severity: risk_sev });
            }
            SurfaceType::Proof => {
                let receipt_count = Self::receipt_count_from_data(request.surface_type, kernel_data);
                let (proof_label, proof_sev) = if let KernelData::EvidenceChain { verified, .. } = kernel_data {
                    if *verified { ("Verified".to_string(), Severity::Ok) } else { ("Unverified".to_string(), Severity::Warn) }
                } else { ("Unknown".to_string(), Severity::Info) };
                badges.push(SurfaceBadge { label: "Proof".into(), value: proof_label, severity: proof_sev });
                badges.push(SurfaceBadge { label: "Receipts".into(), value: receipt_count.to_string(), severity: Severity::Info });
            }
            SurfaceType::Monitor => {
                if let KernelData::AgentState { total_tokens, total_cost_usd, .. } = kernel_data {
                    let tokens_str = if *total_tokens > 0 { format!("{}", total_tokens) } else { "0".into() };
                    let cost_str = if *total_cost_usd > 0.0 { format!("${:.0}", total_cost_usd) } else { "$0".into() };
                    let cost_sev = if *total_cost_usd > 100.0 { Severity::Warn } else { Severity::Info };
                    badges.push(SurfaceBadge { label: "Tokens".into(), value: tokens_str, severity: Severity::Info });
                    badges.push(SurfaceBadge { label: "Cost".into(), value: cost_str, severity: cost_sev });
                } else {
                    badges.push(SurfaceBadge { label: "Cost".into(), value: "run connectorctl cost".into(), severity: Severity::Info });
                }
            }
            _ => {}
        }

        badges
    }

    fn risk_from_kernel_data(kernel_data: &KernelData) -> (String, Severity) {
        match kernel_data {
            KernelData::AgentHealth { health_score, .. } => {
                if *health_score >= 80 { ("Low".into(), Severity::Ok) }
                else if *health_score >= 60 { ("Medium".into(), Severity::Warn) }
                else { ("High".into(), Severity::Risk) }
            }
            KernelData::AgentState { status, .. } => {
                match status.as_str() {
                    "degraded" | "budget_exceeded" => ("High".into(), Severity::Risk),
                    "paused" | "suspended" => ("Medium".into(), Severity::Warn),
                    _ => ("Low".into(), Severity::Ok),
                }
            }
            KernelData::CompliancePosture { compliant, partial, .. } => {
                if *compliant { ("Low".into(), Severity::Ok) }
                else if *partial { ("Medium".into(), Severity::Warn) }
                else { ("High — non-compliant".into(), Severity::Risk) }
            }
            KernelData::Unavailable { .. } | KernelData::Empty => ("Unknown — data unavailable".into(), Severity::Warn),
            _ => ("Unknown".into(), Severity::Info),
        }
    }

    fn root_hash_from_data(kernel_data: &KernelData) -> Option<String> {
        if let KernelData::EvidenceChain { root_hash, .. } = kernel_data {
            if !root_hash.is_empty() && root_hash != "sha256:mock" {
                return Some(if root_hash.starts_with("sha256:") {
                    root_hash.clone()
                } else {
                    format!("sha256:{}", root_hash)
                });
            }
        }
        None
    }

    fn verified_from_data(kernel_data: &KernelData) -> bool {
        matches!(kernel_data, KernelData::EvidenceChain { verified: true, .. })
    }

    fn receipt_count_from_data(surface_type: SurfaceType, kernel_data: &KernelData) -> u32 {
        match kernel_data {
            KernelData::EvidenceChain { chain_length, .. } => (*chain_length).min(u32::MAX as u64) as u32,
            KernelData::AuditEntries(entries) => entries.len() as u32,
            _ => 0,
        }
    }

    fn surface_sections_for_request(request: &RenderRequest, kernel_sections: Vec<SurfaceSection>, kernel_data: &KernelData, secondary_data: Option<&KernelData>) -> Vec<SurfaceSection> {
        let mut sections = match (request.surface_type, request.view) {
            (SurfaceType::Explain, _) => {
                let (status, tool_calls, uptime_str, last_ts, capabilities) = match kernel_data {
                    KernelData::AgentState { status, tool_calls, uptime_ms, last_activity, capabilities, .. } => (
                        status.clone(),
                        tool_calls.to_string(),
                        if *uptime_ms > 0 { format!("{}h {}m", uptime_ms / 3_600_000, (uptime_ms % 3_600_000) / 60_000) } else { "just started".into() },
                        chrono::DateTime::from_timestamp_millis(*last_activity)
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_else(|| "unknown".into()),
                        capabilities.clone(),
                    ),
                    _ => ("unknown".into(), "0".into(), "unknown".into(), "-".into(), vec![]),
                };
                let exec_link = if tool_calls != "0" {
                    Some(ResourceLink::trace(&format!("run-{}", request.subject_id)))
                } else { None };
                // Build Recent Execution from real audit entries if available
                let exec_events: Vec<TimelineEvent> = if let Some(KernelData::AuditEntries(entries)) = secondary_data {
                    if entries.is_empty() {
                        vec![TimelineEvent {
                            timestamp: last_ts,
                            event_type: "no-history".into(),
                            message: "No execution history yet".into(),
                            severity: Severity::Info,
                            link: None,
                        }]
                    } else {
                        entries.iter().take(5).map(|entry| {
                            let ts = chrono::DateTime::from_timestamp_millis(entry.timestamp)
                                .map(|dt| dt.format("%H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| "unknown".into());
                            let sev = if entry.outcome.contains("fail") || entry.outcome.contains("error") || entry.outcome.contains("blocked") || entry.outcome.contains("denied") {
                                Severity::Risk
                            } else if entry.outcome.contains("warn") || entry.outcome.contains("degraded") {
                                Severity::Warn
                            } else {
                                Severity::Ok
                            };
                            TimelineEvent {
                                timestamp: ts,
                                event_type: entry.operation.clone(),
                                message: format!("{} → {}", entry.operation, entry.outcome),
                                severity: sev,
                                link: Some(ResourceLink::trace(&format!("run-{}", request.subject_id))),
                            }
                        }).collect()
                    }
                } else {
                    // No secondary audit data — show last_activity timestamp as single event
                    vec![TimelineEvent {
                        timestamp: last_ts,
                        event_type: "last-seen".into(),
                        message: format!("agent {} last active", request.subject_id),
                        severity: Severity::Ok,
                        link: Some(ResourceLink::trace(&format!("run-{}", request.subject_id))),
                    }]
                };
                vec![
                    SurfaceSection {
                        title: "Agent Status".into(),
                        kind: SectionKind::StatsGrid,
                        content: SectionContent::Stats(vec![
                            StatItem { label: "Proper Name".into(), value: Self::humanize_subject_id(&request.subject_id), link: None },
                            StatItem { label: "Status".into(), value: status, link: None },
                            StatItem { label: "Uptime".into(), value: uptime_str, link: None },
                            StatItem { label: "Total Operations".into(), value: tool_calls, link: exec_link },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Capabilities".into(),
                        kind: SectionKind::List,
                        content: SectionContent::List(if capabilities.is_empty() {
                            vec![ListItem { text: "Capabilities not reported by agent manifest".into(), link: None }]
                        } else {
                            capabilities.iter().map(|cap| ListItem { text: cap.clone(), link: None }).collect()
                        }),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Recent Execution".into(),
                        kind: SectionKind::Timeline,
                        content: SectionContent::Timeline(exec_events),
                        collapsed: false,
                    },
                ]
            },
            (SurfaceType::Review, _) => {
                let (risk_label, risk_sev) = Self::risk_from_kernel_data(kernel_data);
                let (status_label, impact_label, action_taken, what_it_did, why_it_did_it, guardrail) = match kernel_data {
                    KernelData::AgentState { status, tool_calls, .. } => {
                        let impact = match status.as_str() {
                            "degraded" => "Degraded execution path".into(),
                            "budget_exceeded" => "Token budget exhausted — execution halted".into(),
                            "paused" | "suspended" => "Agent paused by operator or policy".into(),
                            "blocked" => "Execution blocked by guard pipeline".into(),
                            "failed" | "error" => "Agent reported execution failure".into(),
                            _ if status.starts_with("decision:") => {
                                if status.contains("blocked") || status.contains("denied") {
                                    "Decision blocked — action was denied".into()
                                } else {
                                    "Decision recorded — action completed".into()
                                }
                            }
                            _ => format!("{} operations completed", tool_calls),
                        };
                        let action = match status.as_str() {
                            "blocked" | "budget_exceeded" => "Halted",
                            "paused" | "suspended" => "Paused",
                            "failed" | "error" => "Failed",
                            _ if status.starts_with("decision:") && (status.contains("blocked") || status.contains("denied")) => "Denied",
                            _ => "Allowed",
                        };
                        let why = if status.starts_with("decision:") {
                            let parts: Vec<&str> = status.splitn(3, '|').collect();
                            parts.get(2).map(|s| s.trim_start_matches("action=").to_string())
                                .unwrap_or_else(|| format!("Status: {}", status))
                        } else {
                            format!("Agent status is '{}' per kernel state", status)
                        };
                        let guard = if status == "blocked" || (status.starts_with("decision:") && status.contains("blocked")) {
                            "Guard pipeline blocked this action"
                        } else if status == "budget_exceeded" {
                            "Token budget policy enforced"
                        } else {
                            "Operational policy applied"
                        };
                        (status.clone(), impact, action, status.clone(), why, guard.to_string())
                    }
                    KernelData::AgentHealth { error_rate, health_score, .. } => {
                        let status_str = if *error_rate < 0.05 { "healthy" } else { "degraded" };
                        let impact = format!("{:.1}% error rate — health score {}/100", error_rate * 100.0, health_score);
                        let action = if *error_rate > 0.2 { "Degraded" } else { "Allowed" };
                        (status_str.into(), impact, action, format!("Health score: {}/100", health_score),
                            format!("Error rate {:.1}% observed", error_rate * 100.0), "Health threshold policy".into())
                    }
                    _ => ("unknown".into(), "No kernel data available".into(), "Unknown",
                          "No data".into(), "Data unavailable".into(), "Policy unavailable".into()),
                };
                let recommendations: Vec<ListItem> = match (status_label.as_str(), risk_label.as_str()) {
                    (s, _) if s == "budget_exceeded" => vec![
                        ListItem { text: "Review and increase token budget".into(), link: Some(ResourceLink::inspect(ResourceKind::Agent, &request.subject_id)) },
                        ListItem { text: "Inspect cost statement".into(), link: None },
                        ListItem { text: format!("connectorctl cost {} --statement", request.subject_id), link: None },
                    ],
                    (s, _) if s == "paused" || s == "suspended" => vec![
                        ListItem { text: "Resume agent execution".into(), link: Some(ResourceLink::inspect(ResourceKind::Agent, &request.subject_id)) },
                        ListItem { text: "Review pause reason in audit trail".into(), link: Some(ResourceLink::verify(ResourceKind::Audit, &request.subject_id)) },
                    ],
                    (s, _) if s == "blocked" || (s.starts_with("decision:") && s.contains("blocked")) => vec![
                        ListItem { text: "Review guard pipeline block reason".into(), link: Some(ResourceLink::trace(&format!("run-{}", request.subject_id))) },
                        ListItem { text: "Inspect security policy".into(), link: None },
                        ListItem { text: "File security incident if unexpected".into(), link: None },
                    ],
                    (_, r) if r == "High" => vec![
                        ListItem { text: "Investigate immediately — high risk agent".into(), link: Some(ResourceLink::inspect(ResourceKind::Agent, &request.subject_id)) },
                        ListItem { text: "Prove the evidence chain".into(), link: Some(ResourceLink::verify(ResourceKind::Proof, &request.subject_id)) },
                        ListItem { text: "Consider suspending agent pending review".into(), link: None },
                    ],
                    (_, r) if r == "Medium" => vec![
                        ListItem { text: "Review recent operations".into(), link: Some(ResourceLink::trace(&format!("run-{}", request.subject_id))) },
                        ListItem { text: "Prove the evidence chain".into(), link: Some(ResourceLink::verify(ResourceKind::Proof, &request.subject_id)) },
                    ],
                    _ => vec![
                        ListItem { text: "No action required — agent operating normally".into(), link: None },
                        ListItem { text: "Inspect for full details".into(), link: Some(ResourceLink::inspect(ResourceKind::Agent, &request.subject_id)) },
                    ],
                };
                vec![
                    SurfaceSection {
                        title: "Risk Status".into(),
                        kind: SectionKind::StatsGrid,
                        content: SectionContent::Stats(vec![
                            StatItem { label: "Risk".into(), value: risk_label.to_uppercase(), link: None },
                            StatItem { label: "Agent Status".into(), value: status_label, link: None },
                            StatItem { label: "Action Taken".into(), value: action_taken.into(), link: None },
                            StatItem { label: "Impact".into(), value: impact_label, link: None },
                        StatItem { label: "Scope".into(), value: request.namespace.as_deref().map(|ns| format!("Namespace: {}", ns)).unwrap_or_else(|| "Single agent".into()), link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Why It Acted".into(),
                        kind: SectionKind::KeyValueTable,
                        content: SectionContent::KeyValue(vec![
                            KeyValueItem { key: "What it did".into(), value: what_it_did, link: None },
                            KeyValueItem { key: "Why it did it".into(), value: why_it_did_it, link: None },
                            KeyValueItem { key: "Guardrail".into(), value: guardrail, link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Recommended Action".into(),
                        kind: SectionKind::List,
                        content: SectionContent::List(recommendations),
                        collapsed: false,
                    },
                ]
            },
            (SurfaceType::Proof, _) => {
                let (verified_str, chain_str, receipt_count, root_hash) = match kernel_data {
                    KernelData::EvidenceChain { verified, chain_length, root_hash, .. } => (
                        if *verified { "VERIFIED" } else { "UNVERIFIED" },
                        if *verified { "INTACT" } else { "BROKEN" },
                        chain_length.to_string(),
                        root_hash.clone(),
                    ),
                    _ => ("UNKNOWN", "UNKNOWN", "0".into(), format!("{}-chain", request.subject_id)),
                };
                let completeness = match kernel_data {
                    KernelData::EvidenceChain { chain_length, receipts, .. } => {
                        if verified_str == "VERIFIED" {
                            "100%".into()
                        } else {
                            let expected = receipts.len().max(*chain_length as usize).max(1);
                            format!("{:.0}%", (receipts.len() as f64 / expected as f64 * 100.0).min(100.0))
                        }
                    }
                    _ => if verified_str == "VERIFIED" { "100%".into() } else { "incomplete".into() },
                };
                vec![
                    SurfaceSection {
                        title: "Proof Status".into(),
                        kind: SectionKind::StatsGrid,
                        content: SectionContent::Stats(vec![
                            StatItem { label: "Verification".into(), value: verified_str.into(), link: None },
                            StatItem { label: "Receipts".into(), value: receipt_count, link: None },
                            StatItem { label: "Chain".into(), value: chain_str.into(), link: None },
                            StatItem { label: "Root Hash".into(), value: format!("sha256:{}", &root_hash[..20.min(root_hash.len())]), link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Proving".into(),
                        kind: SectionKind::KeyValueTable,
                        content: SectionContent::KeyValue(vec![
                            KeyValueItem { key: "Subject".into(), value: Self::humanize_subject_id(&request.subject_id), link: None },
                            KeyValueItem { key: "Evidence Completeness".into(), value: completeness.into(), link: None },
                            KeyValueItem { key: "Receipt Chain".into(), value: if root_hash.is_empty() { "unavailable".into() } else { format!("sha256:{}", &root_hash[..20.min(root_hash.len())]) }, link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Evidence".into(),
                        kind: SectionKind::List,
                        content: SectionContent::List({
                            // BUG-41: real receipt entries from EvidenceChain
                            let mut items: Vec<ListItem> = if let KernelData::EvidenceChain { receipts, .. } = kernel_data {
                                receipts.iter().take(20).map(|r| ListItem {
                                    text: format!("Receipt: sha256:{}", &r[..20.min(r.len())]),
                                    link: Some(ResourceLink::verify(ResourceKind::Receipt, &request.subject_id)),
                                }).collect()
                            } else { vec![] };
                            if items.is_empty() {
                                items.push(ListItem { text: "Receipt chain".into(), link: Some(ResourceLink::verify(ResourceKind::Receipt, &request.subject_id)) });
                            }
                            items.push(ListItem { text: "Execution trace".into(), link: Some(ResourceLink::trace(&format!("run-{}", request.subject_id))) });
                            items
                        }),
                        collapsed: false,
                    },
                ]
            },
            (SurfaceType::Monitor, SurfaceView::Ops) => {
                let (tokens_str, cost_str, avg_day_str, per_ktok_str) = match kernel_data {
                    KernelData::AgentState { total_tokens, total_cost_usd, uptime_ms, .. } => {
                        let uptime_days = (*uptime_ms as f64 / 86_400_000.0).max(1.0);
                        let avg_day = if *total_cost_usd > 0.0 { format!("${:.2}", total_cost_usd / uptime_days) } else { "$0.00".into() };
                        let per_k = if *total_tokens > 0 { format!("${:.4}", total_cost_usd / (*total_tokens as f64 / 1000.0)) } else { "$0.00".into() };
                        (format!("{}", total_tokens), format!("${:.2}", total_cost_usd), avg_day, per_k)
                    }
                    _ => ("0".into(), "$0.00".into(), "$0.00".into(), "$0.00".into()),
                };
                vec![
                    Self::cost_summary_section(&request.subject_id, kernel_data),
                    SurfaceSection {
                        title: "Monthly Rollup".into(),
                        kind: SectionKind::KeyValueTable,
                        content: SectionContent::KeyValue(vec![
                            KeyValueItem { key: "Total Tokens".into(), value: tokens_str, link: None },
                            KeyValueItem { key: "Total Cost".into(), value: cost_str, link: None },
                            KeyValueItem { key: "Average / day".into(), value: avg_day_str, link: None },
                            KeyValueItem { key: "Average / 1K tokens".into(), value: per_ktok_str, link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Statement Link".into(),
                        kind: SectionKind::Links,
                        content: SectionContent::Links(vec![Self::cost_statement_link(&request.subject_id)]),
                        collapsed: false,
                    },
                ]
            },
            (SurfaceType::Monitor, _) => vec![
                Self::cost_summary_section(&request.subject_id, kernel_data),
                SurfaceSection {
                    title: "Statement Link".into(),
                    kind: SectionKind::Links,
                    content: SectionContent::Links(vec![Self::cost_statement_link(&request.subject_id)]),
                    collapsed: false,
                },
            ],
            (SurfaceType::Inspect, _) => {
                let (status, uptime_str, memory_mb, tool_calls, cost_str, capabilities) = match kernel_data {
                    KernelData::AgentState { status, uptime_ms, memory_used, memory_packets, tool_calls, total_cost_usd, capabilities, .. } => (
                        status.clone(),
                        if *uptime_ms > 0 { format!("{}h {}m", uptime_ms / 3_600_000, (uptime_ms % 3_600_000) / 60_000) } else { "just started".into() },
                        if *memory_packets > 0 {
                            format!("{} packets", memory_packets)
                        } else if *memory_used >= 1_048_576 {
                            format!("{:.1} MB", *memory_used as f64 / 1_048_576.0)
                        } else if *memory_used > 0 {
                            format!("{:.1} KB", *memory_used as f64 / 1024.0)
                        } else {
                            "-".into()
                        },
                        tool_calls.to_string(),
                        if *total_cost_usd > 0.0 { format!("${:.4}", total_cost_usd) } else { "$0.0000".into() },
                        capabilities.clone(),
                    ),
                    _ => ("unknown".into(), "unknown".into(), "-".into(), "0".into(), "$0.0000".into(), vec![]),
                };
                vec![
                    SurfaceSection {
                        title: "Identity".into(),
                        kind: SectionKind::KeyValueTable,
                        content: SectionContent::KeyValue(vec![
                            KeyValueItem { key: "Agent ID".into(), value: request.subject_id.clone(), link: None },
                            KeyValueItem { key: "Display Name".into(), value: Self::humanize_subject_id(&request.subject_id), link: None },
                            KeyValueItem { key: "Kind".into(), value: "Agent".into(), link: None },
                            KeyValueItem { key: "Status".into(), value: status, link: None },
                            KeyValueItem { key: "Uptime".into(), value: uptime_str, link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Resource Usage".into(),
                        kind: SectionKind::StatsGrid,
                        content: SectionContent::Stats(vec![
                            StatItem { label: "Memory".into(), value: memory_mb, link: None },
                            StatItem { label: "Operations".into(), value: tool_calls, link: Some(ResourceLink::trace(&format!("run-{}", request.subject_id))) },
                            StatItem { label: "Cost".into(), value: cost_str, link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Capabilities".into(),
                        kind: SectionKind::List,
                        content: SectionContent::List(if capabilities.is_empty() {
                            vec![ListItem { text: "Capabilities not reported by agent manifest".into(), link: None }]
                        } else {
                            capabilities.iter().map(|cap| ListItem { text: cap.clone(), link: None }).collect()
                        }),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Related".into(),
                        kind: SectionKind::Links,
                        content: SectionContent::Links(vec![
                            ResourceLink::verify(ResourceKind::Proof, &request.subject_id),
                            ResourceLink::trace(&format!("run-{}", request.subject_id)),
                            ResourceLink::inspect(ResourceKind::Audit, &request.subject_id),
                        ]),
                        collapsed: false,
                    },
                ]
            },
            (SurfaceType::Memory, _) => {
                let packets = match kernel_data {
                    KernelData::MemoryPackets(pkts) => pkts.as_slice(),
                    _ => &[],
                };
                let total = packets.len();
                let types: Vec<String> = {
                    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
                    for p in packets { *seen.entry(p.packet_type.as_str()).or_insert(0) += 1; }
                    seen.iter().map(|(k, v)| format!("{}: {}", k, v)).collect()
                };
                let type_summary = if types.is_empty() { "none".into() } else { types.join(", ") };
                let newest_ts = packets.iter().map(|p| p.timestamp).max().unwrap_or(0);
                let newest_str = if newest_ts > 0 {
                    chrono::DateTime::from_timestamp_millis(newest_ts)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| newest_ts.to_string())
                } else { "unknown".into() };
                vec![
                    SurfaceSection {
                        title: "Memory Summary".into(),
                        kind: SectionKind::StatsGrid,
                        content: SectionContent::Stats(vec![
                            StatItem { label: "Total Packets".into(), value: total.to_string(), link: None },
                            StatItem { label: "Packet Types".into(), value: type_summary, link: None },
                            StatItem { label: "Newest".into(), value: newest_str, link: None },
                            StatItem { label: "Subject".into(), value: Self::humanize_subject_id(&request.subject_id), link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Memory Packets".into(),
                        kind: SectionKind::List,
                        content: SectionContent::List(if packets.is_empty() {
                            vec![ListItem { text: "No memory packets found for this agent".into(), link: None }]
                        } else {
                            packets.iter().take(50).map(|p| {
                                let ts = chrono::DateTime::from_timestamp_millis(p.timestamp)
                                    .map(|dt| dt.format("%H:%M:%S").to_string())
                                    .unwrap_or_else(|| "?".into());
                                ListItem {
                                    text: format!("[{}] {} — {} ({})", ts, p.packet_type, p.preview, p.tier),
                                    link: None,
                                }
                            }).collect()
                        }),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Memory Context".into(),
                        kind: SectionKind::KeyValueTable,
                        content: SectionContent::KeyValue(vec![
                            KeyValueItem { key: "Agent".into(), value: Self::humanize_subject_id(&request.subject_id), link: None },
                            KeyValueItem { key: "Query".into(), value: "connectorctl trace agent <id> --memory".into(), link: None },
                            KeyValueItem { key: "Full proof".into(), value: format!("connectorctl prove {}", request.subject_id), link: None },
                        ]),
                        collapsed: false,
                    },
                ]
            },
            (SurfaceType::Trace, _) => {
                // BUG-49: Trace surface — real execution context sections
                let (span_count, last_op, first_ts, last_ts) = match kernel_data {
                    KernelData::AuditEntries(entries) => {
                        let n = entries.len();
                        let last = entries.last().map(|e| e.operation.as_str()).unwrap_or("none").to_string();
                        let first_t = entries.first().map(|e| e.timestamp).unwrap_or(0);
                        let last_t = entries.last().map(|e| e.timestamp).unwrap_or(0);
                        (n, last, first_t, last_t)
                    }
                    _ => (0, "no trace data".into(), 0, 0),
                };
                let duration_ms = if last_ts > first_ts { last_ts - first_ts } else { 0 };
                let duration_str = if duration_ms > 0 { format!("{} ms", duration_ms) } else { "unknown".into() };
                vec![
                    SurfaceSection {
                        title: "Execution Summary".into(),
                        kind: SectionKind::StatsGrid,
                        content: SectionContent::Stats(vec![
                            StatItem { label: "Spans".into(), value: span_count.to_string(), link: None },
                            StatItem { label: "Duration".into(), value: duration_str, link: None },
                            StatItem { label: "Last Operation".into(), value: last_op, link: None },
                            StatItem { label: "Subject".into(), value: Self::humanize_subject_id(&request.subject_id), link: None },
                        ]),
                        collapsed: false,
                    },
                    SurfaceSection {
                        title: "Trace Context".into(),
                        kind: SectionKind::KeyValueTable,
                        content: SectionContent::KeyValue(vec![
                            KeyValueItem { key: "Contract".into(), value: format!("connectorctl prove {}", request.subject_id), link: None },
                            KeyValueItem { key: "Guard Pipeline".into(), value: "Review audit trail for blocked operations".into(), link: None },
                            KeyValueItem { key: "Policy".into(), value: "connectorctl risk".into(), link: None },
                        ]),
                        collapsed: false,
                    },
                ]
            },
            _ => vec![],
        };

        // BUG-33: Explain surface already builds its own Agent Status + Recent Execution sections
        // — do NOT append raw kernel_sections which would create duplicates
        let skip_kernel = matches!(request.surface_type, SurfaceType::Explain | SurfaceType::Inspect);
        if !matches!(request.view, SurfaceView::Summary) && !skip_kernel {
            sections.extend(kernel_sections);
        }

        sections
    }

    fn actions_for_request(request: &RenderRequest) -> Vec<SurfaceAction> {
        match request.surface_type {
            SurfaceType::Explain => vec![
                SurfaceAction { label: "Inspect".into(), description: "Open the detailed agent view".into(), command: format!("connectorctl inspect {}", request.subject_id), primary: true },
                SurfaceAction { label: "Trace".into(), description: "Show the latest execution trace".into(), command: format!("connectorctl trace {}", request.subject_id), primary: false },
            ],
            SurfaceType::Review => vec![
                SurfaceAction { label: "Inspect".into(), description: "Inspect current state before approval".into(), command: format!("connectorctl inspect {}", request.subject_id), primary: true },
                SurfaceAction { label: "Prove".into(), description: "Verify the evidence chain".into(), command: format!("connectorctl prove {}", request.subject_id), primary: false },
            ],
            SurfaceType::Proof => vec![
                SurfaceAction { label: "Verify".into(), description: "Review proof and receipts".into(), command: format!("connectorctl prove {}", request.subject_id), primary: true },
                SurfaceAction { label: "Trace".into(), description: "Trace the linked execution".into(), command: format!("connectorctl trace {}", request.subject_id), primary: false },
            ],
            SurfaceType::Monitor => vec![
                SurfaceAction { label: "Open cost statement".into(), description: "View per-call cost entries".into(), command: format!("connectorctl cost {} --statement", request.subject_id), primary: true },
                SurfaceAction { label: "Inspect".into(), description: "Inspect the monitored agent".into(), command: format!("connectorctl inspect {}", request.subject_id), primary: false },
            ],
            _ => vec![SurfaceAction {
                label: "Open".into(),
                description: format!("Open the primary {} view", Self::command_name_for_surface(request.surface_type)),
                command: format!("connectorctl {} {}", Self::command_name_for_surface(request.surface_type), request.subject_id),
                primary: true,
            }],
        }
    }

    fn apply_query_to_document(
        mut document: SurfaceDocument,
        query: Option<&Query>,
    ) -> (SurfaceDocument, Option<PageInfo>) {
        let Some(query) = query else {
            return (document, None);
        };

        let mut page_info: Option<PageInfo> = None;
        for section in &mut document.sections {
            let info = match &mut section.content {
                SectionContent::Timeline(items) => Self::apply_query_to_timeline(items, query),
                SectionContent::Findings(items) => Self::apply_query_to_findings(items, query),
                SectionContent::List(items) => Self::apply_query_to_list(items, query),
                SectionContent::Evidence(items) => Self::apply_query_to_evidence(items, query),
                SectionContent::Links(items) => Self::apply_query_to_links(items, query),
                _ => None,
            };
            if page_info.is_none() {
                page_info = info;
            }
        }

        let page_info = page_info.or_else(|| Some(Self::page_info_for(query, 0)));
        if let Some(info) = &page_info {
            document.sections.push(Self::query_summary_section(query, info));
        }
        (document, page_info)
    }

    fn apply_query_to_timeline(
        items: &mut Vec<TimelineEvent>,
        query: &Query,
    ) -> Option<PageInfo> {
        let mut filtered = items.clone();
        filtered.retain(|item| {
            Self::matches_search(
                query,
                &[
                    ("timestamp", item.timestamp.as_str()),
                    ("event_type", item.event_type.as_str()),
                    ("message", item.message.as_str()),
                    ("severity", Self::severity_token(item.severity)),
                ],
            ) && Self::matches_filters(
                query,
                &[
                    ("timestamp", item.timestamp.as_str()),
                    ("event_type", item.event_type.as_str()),
                    ("message", item.message.as_str()),
                    ("severity", Self::severity_token(item.severity)),
                ],
            )
        });
        Self::sort_by_query(&mut filtered, query, |field, item| match field {
            "timestamp" => item.timestamp.clone(),
            "event_type" => item.event_type.clone(),
            "severity" => Self::severity_token(item.severity).to_string(),
            _ => item.message.clone(),
        });
        let info = Self::page_info_for(query, filtered.len());
        *items = Self::page_slice(filtered, &info);
        Some(info)
    }

    fn apply_query_to_findings(items: &mut Vec<Finding>, query: &Query) -> Option<PageInfo> {
        let mut filtered = items.clone();
        filtered.retain(|item| {
            Self::matches_search(
                query,
                &[
                    ("code", item.code.as_str()),
                    ("message", item.message.as_str()),
                    ("severity", Self::severity_token(item.severity)),
                ],
            ) && Self::matches_filters(
                query,
                &[
                    ("code", item.code.as_str()),
                    ("message", item.message.as_str()),
                    ("severity", Self::severity_token(item.severity)),
                ],
            )
        });
        Self::sort_by_query(&mut filtered, query, |field, item| match field {
            "code" => item.code.clone(),
            "severity" => Self::severity_token(item.severity).to_string(),
            _ => item.message.clone(),
        });
        let info = Self::page_info_for(query, filtered.len());
        *items = Self::page_slice(filtered, &info);
        Some(info)
    }

    fn apply_query_to_list(items: &mut Vec<ListItem>, query: &Query) -> Option<PageInfo> {
        let mut filtered = items.clone();
        filtered.retain(|item| {
            Self::matches_search(query, &[("text", item.text.as_str())])
                && Self::matches_filters(query, &[("text", item.text.as_str())])
        });
        Self::sort_by_query(&mut filtered, query, |_field, item| item.text.clone());
        let info = Self::page_info_for(query, filtered.len());
        *items = Self::page_slice(filtered, &info);
        Some(info)
    }

    fn apply_query_to_evidence(items: &mut Vec<EvidenceItem>, query: &Query) -> Option<PageInfo> {
        let mut filtered = items.clone();
        filtered.retain(|item| {
            Self::matches_search(
                query,
                &[
                    ("evidence_type", item.evidence_type.as_str()),
                    ("cid", item.cid.as_str()),
                    ("verified", if item.verified { "true" } else { "false" }),
                ],
            ) && Self::matches_filters(
                query,
                &[
                    ("evidence_type", item.evidence_type.as_str()),
                    ("cid", item.cid.as_str()),
                    ("verified", if item.verified { "true" } else { "false" }),
                ],
            )
        });
        Self::sort_by_query(&mut filtered, query, |field, item| match field {
            "cid" => item.cid.clone(),
            "verified" => if item.verified { "true".into() } else { "false".into() },
            _ => item.evidence_type.clone(),
        });
        let info = Self::page_info_for(query, filtered.len());
        *items = Self::page_slice(filtered, &info);
        Some(info)
    }

    fn apply_query_to_links(items: &mut Vec<ResourceLink>, query: &Query) -> Option<PageInfo> {
        let mut filtered = items.clone();
        filtered.retain(|item| {
            Self::matches_search(
                query,
                &[
                    ("label", item.label.as_str()),
                    ("command", item.command.as_str()),
                    ("id", item.id.as_str()),
                ],
            ) && Self::matches_filters(
                query,
                &[
                    ("label", item.label.as_str()),
                    ("command", item.command.as_str()),
                    ("id", item.id.as_str()),
                ],
            )
        });
        Self::sort_by_query(&mut filtered, query, |field, item| match field {
            "command" => item.command.clone(),
            "id" => item.id.clone(),
            _ => item.label.clone(),
        });
        let info = Self::page_info_for(query, filtered.len());
        *items = Self::page_slice(filtered, &info);
        Some(info)
    }

    fn query_summary_section(query: &Query, info: &PageInfo) -> SurfaceSection {
        let filters = if query.filters.is_empty() {
            "none".to_string()
        } else {
            query.filters
                .iter()
                .map(|f| format!("{}{:?}", f.field, f.op))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let sort = if query.sort.is_empty() {
            "none".to_string()
        } else {
            query.sort
                .iter()
                .map(|s| format!("{}:{:?}", s.field, s.direction))
                .collect::<Vec<_>>()
                .join(", ")
        };
        SurfaceSection {
            title: "Query Context".into(),
            kind: SectionKind::KeyValueTable,
            content: SectionContent::KeyValue(vec![
                KeyValueItem { key: "Results".into(), value: info.display(), link: None },
                KeyValueItem { key: "Pages".into(), value: info.page_links(), link: None },
                KeyValueItem {
                    key: "Search".into(),
                    value: query.search.as_ref().map(|q| q.query.clone()).unwrap_or_else(|| "none".into()),
                    link: None,
                },
                KeyValueItem { key: "Filters".into(), value: filters, link: None },
                KeyValueItem { key: "Sort".into(), value: sort, link: None },
            ]),
            collapsed: false,
        }
    }

    fn page_info_for(query: &Query, total_items: usize) -> PageInfo {
        let page = query.page.page.max(1);
        let page_size = query.page.page_size.max(1);
        let mut info = PageInfo::new(page, page_size, total_items);
        if info.has_next {
            info.next_cursor = Some(format!("page:{}", page + 1));
        }
        info
    }

    fn page_slice<T: Clone>(items: Vec<T>, info: &PageInfo) -> Vec<T> {
        let start = (info.page.saturating_sub(1)) * info.page_size;
        items.into_iter().skip(start).take(info.page_size).collect()
    }

    fn matches_search(query: &Query, fields: &[(&str, &str)]) -> bool {
        let Some(search) = &query.search else {
            return true;
        };
        let needle = search.query.to_ascii_lowercase();
        if search.fields.is_empty() {
            fields
                .iter()
                .any(|(_, value)| value.to_ascii_lowercase().contains(&needle))
        } else {
            fields.iter().any(|(field, value)| {
                search.fields.iter().any(|wanted| wanted.eq_ignore_ascii_case(field))
                    && value.to_ascii_lowercase().contains(&needle)
            })
        }
    }

    fn matches_filters(query: &Query, fields: &[(&str, &str)]) -> bool {
        query.filters.iter().all(|filter| {
            let Some((_, actual)) = fields
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(&filter.field))
            else {
                return false;
            };
            Self::filter_matches_value(actual, filter)
        })
    }

    fn filter_matches_value(actual: &str, filter: &super::pagination::Filter) -> bool {
        match (&filter.op, &filter.value) {
            (FilterOp::Eq, FilterValue::String(expected)) => actual.eq_ignore_ascii_case(expected),
            (FilterOp::Ne, FilterValue::String(expected)) => !actual.eq_ignore_ascii_case(expected),
            (FilterOp::Contains, FilterValue::String(expected)) => {
                actual.to_ascii_lowercase().contains(&expected.to_ascii_lowercase())
            }
            (FilterOp::StartsWith, FilterValue::String(expected)) => {
                actual.to_ascii_lowercase().starts_with(&expected.to_ascii_lowercase())
            }
            (FilterOp::EndsWith, FilterValue::String(expected)) => {
                actual.to_ascii_lowercase().ends_with(&expected.to_ascii_lowercase())
            }
            (FilterOp::In, FilterValue::List(expected)) => {
                expected.iter().any(|value| actual.eq_ignore_ascii_case(value))
            }
            (FilterOp::NotIn, FilterValue::List(expected)) => {
                expected.iter().all(|value| !actual.eq_ignore_ascii_case(value))
            }
            (FilterOp::Eq, FilterValue::Bool(expected)) => actual.eq_ignore_ascii_case(&expected.to_string()),
            (FilterOp::Ne, FilterValue::Bool(expected)) => !actual.eq_ignore_ascii_case(&expected.to_string()),
            (op, FilterValue::Number(expected)) => {
                let actual = actual.parse::<f64>().ok();
                match (op, actual) {
                    (FilterOp::Eq, Some(actual)) => (actual - expected).abs() < f64::EPSILON,
                    (FilterOp::Ne, Some(actual)) => (actual - expected).abs() >= f64::EPSILON,
                    (FilterOp::Gt, Some(actual)) => actual > *expected,
                    (FilterOp::Gte, Some(actual)) => actual >= *expected,
                    (FilterOp::Lt, Some(actual)) => actual < *expected,
                    (FilterOp::Lte, Some(actual)) => actual <= *expected,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn sort_by_query<T, F>(items: &mut [T], query: &Query, key_fn: F)
    where
        F: Fn(&str, &T) -> String,
    {
        let Some(sort) = query.sort.first() else {
            return;
        };
        let field = sort.field.as_str();
        items.sort_by(|left, right| {
            let left_key = key_fn(field, left);
            let right_key = key_fn(field, right);
            match sort.direction {
                super::pagination::SortDirection::Asc => left_key.cmp(&right_key),
                super::pagination::SortDirection::Desc => right_key.cmp(&left_key),
            }
        });
    }

    fn severity_token(severity: Severity) -> &'static str {
        match severity {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Risk => "risk",
            Severity::Critical => "critical",
        }
    }

    fn apply_role_filters(
        request: &RenderRequest,
        governance: &GovernanceResult,
        mut document: SurfaceDocument,
    ) -> SurfaceDocument {
        let redaction_level =
            Self::effective_redaction_level(request.role, governance.redaction_level.as_deref());
        let redactor = Redactor::new(redaction_level);

        document.header.subject.uid = redactor.redact(
            document.header.subject.effective_uid(),
            ValueType::InternalId,
        );
        document.header.subject.proof =
            redactor.redact(&document.header.subject.proof, ValueType::InternalId);

        if let Some(footer) = &mut document.footer {
            if let Some(root_hash) = &footer.root_hash {
                footer.root_hash = Some(redactor.redact(root_hash, ValueType::Hash));
            }
        }

        document.sections = document
            .sections
            .into_iter()
            .filter_map(|mut section| {
                Self::sanitize_section_for_role(&mut section, request.role, &redactor)
                    .then_some(section)
            })
            .collect();

        document
            .actions
            .retain(|action| Self::role_can_use_command(request.role, &action.command));

        if document.actions.is_empty() {
            let fallback_command = format!(
                "connectorctl {} {}",
                Self::command_name_for_surface(request.surface_type),
                document.header.subject.inspect
            );
            if Self::role_can_use_command(request.role, &fallback_command) {
                document.actions.push(SurfaceAction {
                    label: "Open".into(),
                    description: format!(
                        "Open the allowed {} view",
                        Self::command_name_for_surface(request.surface_type)
                    ),
                    command: fallback_command,
                    primary: true,
                });
            }
        } else if !document.actions.iter().any(|action| action.primary) {
            if let Some(first) = document.actions.first_mut() {
                first.primary = true;
            }
        }

        if !matches!(redaction_level, RedactionLevel::None) {
            document.header.badges.push(SurfaceBadge {
                label: "Redaction".into(),
                value: format!("{:?}", redaction_level).to_uppercase(),
                severity: Severity::Warn,
            });
        }

        document
    }

    fn sanitize_section_for_role(
        section: &mut SurfaceSection,
        role: Role,
        redactor: &Redactor,
    ) -> bool {
        if matches!(section.kind, SectionKind::Trace | SectionKind::RawData)
            && !role.can_access(SurfaceView::Forensic)
        {
            return false;
        }

        match &mut section.content {
            SectionContent::Stats(items) => {
                for item in items.iter_mut() {
                    item.value = Self::redact_labeled_value(&item.label, &item.value, redactor);
                    if let Some(link) = &mut item.link {
                        if !Self::sanitize_link_for_role(link, role) {
                            item.link = None;
                        }
                    }
                }
            }
            SectionContent::KeyValue(items) => {
                for item in items.iter_mut() {
                    item.value = Self::redact_labeled_value(&item.key, &item.value, redactor);
                    if let Some(link) = &mut item.link {
                        if !Self::sanitize_link_for_role(link, role) {
                            item.link = None;
                        }
                    }
                }
            }
            SectionContent::Timeline(events) => {
                for event in events.iter_mut() {
                    if let Some(link) = &mut event.link {
                        if !Self::sanitize_link_for_role(link, role) {
                            event.link = None;
                        }
                    }
                }
            }
            SectionContent::Findings(findings) => {
                for finding in findings.iter_mut() {
                    if let Some(link) = &mut finding.link {
                        if !Self::sanitize_link_for_role(link, role) {
                            finding.link = None;
                        }
                    }
                }
            }
            SectionContent::List(items) => {
                for item in items.iter_mut() {
                    if let Some(link) = &mut item.link {
                        if !Self::sanitize_link_for_role(link, role) {
                            item.link = None;
                        }
                    }
                }
            }
            SectionContent::Evidence(items) => {
                for item in items.iter_mut() {
                    item.cid = redactor.redact(&item.cid, ValueType::Hash);
                    if !Self::sanitize_link_for_role(&mut item.link, role) {
                        return false;
                    }
                }
            }
            SectionContent::Trace(spans) => {
                for span in spans.iter_mut() {
                    if let Some(link) = &mut span.link {
                        if !Self::sanitize_link_for_role(link, role) {
                            span.link = None;
                        }
                    }
                }
            }
            SectionContent::RawData(blob) => {
                blob.preview = redactor.redact(&blob.preview, ValueType::Other);
            }
            SectionContent::Links(links) => {
                links.retain_mut(|link| Self::sanitize_link_for_role(link, role));
                if links.is_empty() {
                    return false;
                }
            }
            SectionContent::Narrative(text) => {
                *text = redactor.redact(text, ValueType::Other);
            }
        }

        true
    }

    fn sanitize_link_for_role(link: &mut ResourceLink, role: Role) -> bool {
        if !Self::role_can_follow_link(role, link) {
            return false;
        }
        true
    }

    fn role_can_follow_link(role: Role, link: &ResourceLink) -> bool {
        match link.action {
            LinkAction::Forensic | LinkAction::Raw | LinkAction::Trace => {
                role.can_access(SurfaceView::Forensic)
            }
            LinkAction::Inspect | LinkAction::Cat => role.can_access(SurfaceView::Ops),
            LinkAction::Verify => true,
        }
    }

    fn role_can_use_command(role: Role, command: &str) -> bool {
        let normalized = command.trim().to_ascii_lowercase();
        if normalized.starts_with("connectorctl trace ") {
            role.can_access(SurfaceView::Forensic)
        } else if normalized.starts_with("connectorctl inspect ")
            || normalized.starts_with("connectorctl debug ")
            || normalized.starts_with("connectorctl health ")
            || normalized.contains(" --statement")
        {
            role.can_access(SurfaceView::Ops)
        } else {
            true
        }
    }

    fn effective_redaction_level(role: Role, policy_level: Option<&str>) -> RedactionLevel {
        let role_level = role.redaction_level();
        let policy_level = match policy_level.map(|value| value.to_ascii_lowercase()) {
            Some(level) if level == "maximum" => RedactionLevel::Maximum,
            Some(level) if level == "strict" => RedactionLevel::Strict,
            Some(level) if level == "standard" => RedactionLevel::Standard,
            _ => RedactionLevel::None,
        };
        Self::strictest_redaction(role_level, policy_level)
    }

    fn strictest_redaction(left: RedactionLevel, right: RedactionLevel) -> RedactionLevel {
        use RedactionLevel::*;
        match (left, right) {
            (Maximum, _) | (_, Maximum) => Maximum,
            (Strict, _) | (_, Strict) => Strict,
            (Standard, _) | (_, Standard) => Standard,
            _ => None,
        }
    }

    fn redact_labeled_value(label: &str, value: &str, redactor: &Redactor) -> String {
        let label = label.to_ascii_lowercase();
        let value_type = if label.contains("ssn") {
            ValueType::Ssn
        } else if label.contains("email") {
            ValueType::Email
        } else if label.contains("phone") {
            ValueType::Phone
        } else if label.contains("patient") {
            ValueType::PatientId
        } else if label.contains("hash") || label.contains("root") || label.contains("cid") {
            ValueType::Hash
        } else if label.contains("proof") || label.contains("uid") || label.contains("internal") {
            ValueType::InternalId
        } else {
            ValueType::Other
        };
        redactor.redact(value, value_type)
    }

    fn cost_summary_section(subject_id: &str, kernel_data: &KernelData) -> SurfaceSection {
        let (tokens_str, cost_str) = match kernel_data {
            KernelData::AgentState { total_tokens, total_cost_usd, .. } => (
                format!("{}", total_tokens),
                format!("${:.2}", total_cost_usd),
            ),
            _ => ("0".into(), "$0.00".into()),
        };
        SurfaceSection {
            title: "Cost Summary".into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(vec![
                StatItem { label: "Agent".into(), value: Self::humanize_subject_id(subject_id), link: None },
                StatItem { label: "Tokens Used".into(), value: tokens_str, link: None },
                StatItem { label: "Total Cost".into(), value: cost_str, link: None },
            ]),
            collapsed: false,
        }
    }

    fn cost_statement_link(subject_id: &str) -> ResourceLink {
        ResourceLink {
            label: "[open cost statement]".into(),
            resource_type: ResourceKind::Agent,
            id: subject_id.into(),
            command: format!("connectorctl cost {} --statement", subject_id),
            url: Some(format!("/ui/agent/{}/costs", subject_id)),
            action: LinkAction::Inspect,
        }
    }


    /// Parse a raw `decision:{outcome} | agent={pid} | action={act} target={tgt}` status
    /// string into a clean judgment line for the Explain surface.
    fn format_decision_judgment(status: &str, uptime_ms: &u64) -> String {
        // Normalise delimiters: API may use "|" or " | "
        let normalised = status.replace(" | ", "|");
        let outcome_raw = normalised.trim_start_matches("decision:")
            .split('|').next().unwrap_or("recorded").trim();
        let outcome_upper = match outcome_raw {
            "blocked" | "denied" | "rejected" => "BLOCKED",
            "allowed" | "approved" => "ALLOWED",
            other => other,
        };
        let agent = normalised.split("agent=").nth(1)
            .map(|s| s.split('|').next().unwrap_or(s).trim())
            .unwrap_or("unknown");
        let agent_short = &agent[..agent.len().min(24)];
        let action = normalised.split("action=").nth(1)
            .map(|s| s.split('|').next().unwrap_or(s).trim())
            .unwrap_or("unknown");
        let age_h = uptime_ms / 3_600_000;
        let age_m = (uptime_ms % 3_600_000) / 60_000;
        let age_str = if age_h > 0 {
            format!("{}h {}m ago", age_h, age_m)
        } else if age_m > 0 {
            format!("{}m ago", age_m)
        } else {
            "just now".to_string()
        };
        format!("{} — {} | agent {} | recorded {}", outcome_upper, action, agent_short, age_str)
    }

    fn humanize_subject_id(subject_id: &str) -> String {
        // Known prefixes that carry a UUID or long hex ID — display cleanly, don't mangle
        let typed_prefixes: &[(&str, &str)] = &[
            ("dec_",    "Decision"),
            ("agent_",  "Agent"),
            ("prf_",    "Proof"),
            ("run_",    "Run"),
            ("rcpt_",   "Receipt"),
            ("pkg_",    "Package"),
            ("evt_",    "Event"),
            ("cell_",   "Cell"),
        ];
        for (prefix, kind) in typed_prefixes {
            if subject_id.starts_with(prefix) {
                let suffix = &subject_id[prefix.len()..];
                // UUID or long hex: keep first 8 chars for readability
                if suffix.len() >= 8 && suffix.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                    let short = &suffix[..8];
                    return format!("{} {}", kind, short);
                }
                // Short readable suffix — humanize normally below
                break;
            }
        }
        // UUID with no known prefix: show as-is
        let looks_like_uuid = subject_id.len() == 36
            && subject_id.chars().enumerate().all(|(i, c)| {
                if i == 8 || i == 13 || i == 18 || i == 23 { c == '-' }
                else { c.is_ascii_hexdigit() }
            });
        if looks_like_uuid {
            return format!("Record {}", &subject_id[..8]);
        }

        // Human-readable ID (e.g. "claims-triage-001") — split and capitalise
        subject_id
            .split(|c| c == '-' || c == '_')
            .filter(|part| !part.is_empty())
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Generate judgment text using already-fetched kernel data (avoids a second API call).
    fn generate_judgment_text_from_data(&self, request: &RenderRequest, data: &KernelData) -> String {
        let name = Self::humanize_subject_id(&request.subject_id);
        match request.surface_type {
            SurfaceType::Explain => {
                if let KernelData::AgentState { status, tool_calls, uptime_ms, .. } = data {
                    // Decision record: parse "decision:{outcome}|agent={pid}|action={act} target={tgt}"
                    if status.starts_with("decision:") {
                        return Self::format_decision_judgment(status, uptime_ms);
                    }
                    let uptime_h = uptime_ms / 3_600_000;
                    let uptime_m = (uptime_ms % 3_600_000) / 60_000;
                    let status_label = match status.as_str() {
                        "running" | "healthy" | "active" => "Running",
                        "degraded" => "Degraded",
                        "budget_exceeded" => "Budget Exceeded",
                        "paused" | "suspended" => "Paused",
                        "inactive" => "Inactive",
                        other => other,
                    };
                    if *tool_calls == 0 {
                        format!("{}: {} | no operations yet | active {}h {}m",
                            name, status_label, uptime_h, uptime_m)
                    } else {
                        format!("{}: {} | {} operation{} | active {}h {}m",
                            name, status_label, tool_calls,
                            if *tool_calls == 1 { "" } else { "s" },
                            uptime_h, uptime_m)
                    }
                } else {
                    format!("{} — not found in registry", name)
                }
            }
            SurfaceType::Review => {
                let (risk, _) = Self::risk_from_kernel_data(data);
                match data {
                    KernelData::AgentHealth { health_score, .. } =>
                        format!("{}: {} risk (health: {}/100)", name, risk, health_score),
                    KernelData::AgentState { status, .. } =>
                        format!("{}: {} risk | status={}", name, risk, status),
                    _ => format!("{} — review data not available", name),
                }
            }
            SurfaceType::Proof => {
                if let KernelData::EvidenceChain { verified, chain_length, root_hash, .. } = data {
                    let status = if *verified { "verified" } else { "unverified" };
                    format!("{}: {} | {} receipts | root={}", name, status, chain_length, &root_hash[..20.min(root_hash.len())])
                } else {
                    format!("{} — evidence chain not available", name)
                }
            }
            SurfaceType::Monitor => {
                if let KernelData::AgentState { tool_calls, total_cost_usd, total_tokens, .. } = data {
                    format!("{}: {} operations | {} tokens | ${:.2} total cost", name, tool_calls, total_tokens, total_cost_usd)
                } else {
                    format!("{} — cost data not available", name)
                }
            }
            SurfaceType::Agent => {
                if let KernelData::AgentState { status, uptime_ms, memory_used, memory_packets, total_tokens, .. } = data {
                    // Prefer packet count from kernel API; else byte estimate (BUG-44 / BUG-SOE-11)
                    let mem_str = if *memory_packets > 0 {
                        format!("{} packets", memory_packets)
                    } else if *memory_used >= 1_000_000 {
                        format!("{} MB", memory_used / 1_000_000)
                    } else if *total_tokens > 0 && *memory_used > 0 {
                        format!("~{} KB", memory_used / 1_000)
                    } else {
                        "mem n/a".into()
                    };
                    format!("{}: {} | {}h uptime | {}", name, status, uptime_ms / 3_600_000, mem_str)
                } else {
                    format!("{} — state not available", name)
                }
            }
            SurfaceType::Health => {
                if let KernelData::AgentHealth { health_score, .. } = data {
                    let status = if *health_score >= 80 { "healthy" } else if *health_score >= 60 { "degraded" } else { "unhealthy" };
                    format!("{}: {} (score: {})", name, status, health_score)
                } else {
                    format!("{} — health metrics not available", name)
                }
            }
            SurfaceType::Audit => {
                if let KernelData::AuditEntries(entries) = data {
                    format!("{}: {} audit entries", name, entries.len())
                } else {
                    format!("{} — audit data not available", name)
                }
            }
            SurfaceType::Books => {
                if let KernelData::JournalEntries(entries) = data {
                    format!("{}: {} journal entries", name, entries.len())
                } else {
                    format!("{} — journal not available", name)
                }
            }
            _ => {
                match data {
                    KernelData::AgentState { status, .. } => format!("{}: status={}", name, status),
                    KernelData::CompliancePosture { compliant, framework, findings_count, .. } => {
                        let status = if *compliant { "compliant" } else { "non-compliant" };
                        format!("{}: {} ({}, {} findings)", name, status, framework, findings_count)
                    }
                    KernelData::Unavailable { reason } => format!("{} — {}", name, reason),
                    KernelData::Empty => format!("{} — data unavailable (API unreachable or subject not found)", name),
                    _ => format!("{} — no data for this surface type", name),
                }
            }
        }
    }

    /// DEPRECATED: Old hardcoded mock text - kept for reference, DO NOT USE
    #[allow(dead_code)]
    fn _deprecated_hardcoded_judgment_text(request: &RenderRequest) -> String {
        // This was the hardcoded mock text that returned fake placeholder data.
        // Replaced by generate_judgment_text() which queries real kernel data.
        let _name = Self::humanize_subject_id(&request.subject_id);
        "DEPRECATED - use generate_judgment_text()".to_string()
    }

    fn command_name_for_surface(surface_type: SurfaceType) -> &'static str {
        match surface_type {
            SurfaceType::Explain => "explain",
            SurfaceType::Review => "risk",
            SurfaceType::Proof => "prove",
            SurfaceType::Monitor => "cost",
            SurfaceType::Inspect => "inspect",
            SurfaceType::Trace => "trace",
            SurfaceType::Health => "health",
            _ => "inspect",
        }
    }

    fn signals_from_document(doc: &SurfaceDocument, kernel_data: &KernelData, subject_id: &str) -> Vec<Signal> {
        let mut signals = vec![];

        // Decision-subject signal: parse block reason from decision status
        if subject_id.starts_with("dec_") {
            if let KernelData::AgentState { status, .. } = kernel_data {
                if status.starts_with("decision:") && (status.contains("blocked") || status.contains("denied")) {
                    let reason = status.splitn(4, '|').nth(2)
                        .unwrap_or("guard pipeline");
                    signals.push(Signal {
                        icon: SignalIcon::Cross,
                        text: format!("Decision blocked by {}", reason.trim()),
                        link: None,
                    });
                } else if status.starts_with("decision:") {
                    signals.push(Signal {
                        icon: SignalIcon::Check,
                        text: "Decision approved and executed".into(),
                        link: None,
                    });
                }
            }
        }

        // Evidence chain signal
        let footer_verified = doc.footer.as_ref().map(|f| f.verified).unwrap_or(false);
        let chain_valid = doc.footer.as_ref().map(|f| f.chain_valid).unwrap_or(false);
        signals.push(Signal {
            icon: if footer_verified && chain_valid { SignalIcon::Check }
                  else if footer_verified { SignalIcon::Warning }
                  else { SignalIcon::Warning },
            text: if footer_verified && chain_valid { "Evidence verified — chain intact".into() }
                  else if footer_verified { "Evidence verified — chain needs review".into() }
                  else { "Evidence not verified".into() },
            link: None,
        });

        // Health signal — BUG-03: Unhealthy → Cross not Warning
        signals.push(Signal {
            icon: match doc.header.state.health {
                HealthState::Healthy => SignalIcon::Check,
                HealthState::Degraded => SignalIcon::Warning,
                HealthState::Unhealthy => SignalIcon::Cross,
                _ => SignalIcon::Info,
            },
            text: format!("Health: {}", doc.header.state.health.as_str()),
            link: None,
        });

        // Compliance signal
        signals.push(Signal {
            icon: match doc.header.state.compliance {
                ComplianceState::Compliant => SignalIcon::Check,
                ComplianceState::Partial => SignalIcon::Warning,
                ComplianceState::NonCompliant => SignalIcon::Cross,
                ComplianceState::Unknown => SignalIcon::Info,
            },
            text: format!("Compliance: {}", doc.header.state.compliance.as_str()),
            link: None,
        });

        if doc.meta.view == SurfaceView::Forensic {
            signals.push(Signal {
                icon: SignalIcon::Info,
                text: "Forensic review requested".into(),
                link: None,
            });
        }

        signals
    }

    fn severity_for_state(state: &StateVector) -> Severity {
        match state.health {
            super::document::HealthState::Unhealthy => Severity::Critical,
            super::document::HealthState::Degraded => Severity::Warn,
            _ => match state.compliance {
                ComplianceState::NonCompliant => Severity::Risk,
                ComplianceState::Partial => Severity::Warn,
                _ => Severity::Ok,
            },
        }
    }

    fn surface_to_resource_kind(st: SurfaceType) -> ResourceKind {
        match st {
            SurfaceType::Agent | SurfaceType::Debug | SurfaceType::Health | SurfaceType::Trace => ResourceKind::Agent,
            SurfaceType::Memory => ResourceKind::Memory,
            SurfaceType::Knowledge => ResourceKind::Knowledge,
            SurfaceType::Audit | SurfaceType::Books => ResourceKind::Audit,
            SurfaceType::Policy | SurfaceType::Compliance => ResourceKind::Policy,
            SurfaceType::Tool => ResourceKind::Tool,
            SurfaceType::Contract => ResourceKind::Contract,
            SurfaceType::Proof => ResourceKind::Proof,
            _ => ResourceKind::Agent,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════════

    pub fn receipts(&self) -> &ReceiptChain { &self.receipts }
    pub fn cache(&self) -> &SurfaceCache { &self.cache }
    pub fn bus(&self) -> &SurfaceBus { &self.bus }
    pub fn governance(&self) -> &SurfaceGovernance { &self.governance }

    pub fn subscribe(&self) -> super::stream::SurfaceSubscriber {
        self.bus.subscribe()
    }

    pub fn metrics_snapshot(&self) -> super::metrics::MetricsSnapshot {
        metrics().snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::time::SurfaceDuration;

    #[test]
    fn test_engine_render() {
        let mut engine = SurfaceEngine::default();
        let request = RenderRequest::new(SurfaceType::Agent, "test-001", "user-1", Role::Developer);
        let result = engine.render(request).unwrap();

        assert!(!result.cid().hash.is_empty());
        assert!(result.receipt.is_some());
        assert!(result.governance.is_allowed());
        let v = result.contract.validate();
        assert!(v.valid, "render path must emit a valid SurfaceContract: {:?}", v.errors);
        assert!(result.contract.signals.len() >= 3);

        let json = result.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("to_json must be valid JSON");
        assert!(parsed.get("surface_contract").is_some());
        assert!(parsed.get("decision_package").is_some() || parsed.get("document").is_some());
    }

    #[test]
    fn test_engine_role_filters_exec_actions_and_redacts_ids() {
        let mut engine = SurfaceEngine::default();
        let request =
            RenderRequest::new(SurfaceType::Explain, "claims-review-001", "user-1", Role::Executive)
                .view(SurfaceView::Summary);
        let result = engine.render(request).unwrap();

        assert!(result
            .document()
            .actions
            .iter()
            .all(|action| !action.command.starts_with("connectorctl inspect ")));
        assert!(result
            .document()
            .actions
            .iter()
            .all(|action| !action.command.starts_with("connectorctl trace ")));
        assert!(result
            .document()
            .actions
            .iter()
            .any(|action| action.command.starts_with("connectorctl explain ")));
        assert_eq!(result.contract.subject.uid, "id_████");
        assert_eq!(result.contract.subject.proof, "id_████");
        assert!(result
            .document()
            .header
            .badges
            .iter()
            .any(|badge| badge.label == "Redaction"));
    }

    #[test]
    fn test_engine_role_filters_forensic_links_for_operator() {
        let mut engine = SurfaceEngine::default();
        let request =
            RenderRequest::new(SurfaceType::Explain, "claims-review-001", "user-1", Role::Operator)
                .view(SurfaceView::Summary);
        let result = engine.render(request).unwrap();

        assert!(result
            .document()
            .actions
            .iter()
            .all(|action| !action.command.starts_with("connectorctl trace ")));

        let has_trace_links = result.document().sections.iter().any(|section| match &section.content {
            SectionContent::Stats(items) => items.iter().any(|item| {
                item.link
                    .as_ref()
                    .map(|link| matches!(link.action, LinkAction::Trace))
                    .unwrap_or(false)
            }),
            SectionContent::Timeline(events) => events.iter().any(|event| {
                event.link
                    .as_ref()
                    .map(|link| matches!(link.action, LinkAction::Trace))
                    .unwrap_or(false)
            }),
            _ => false,
        });
        assert!(!has_trace_links, "operator summary should not expose forensic trace links");
    }

    #[test]
    fn test_engine_query_pagination_and_search() {
        let mut engine = SurfaceEngine::default();
        let query = Query::new()
            .search(super::super::pagination::SearchQuery::new("policy"))
            .paginate(1, 1);
        let request =
            RenderRequest::new(SurfaceType::Explain, "claims-review-001", "user-1", Role::Developer)
                .view(SurfaceView::Summary)
                .query(query);
        let result = engine.render(request).unwrap();

        let capabilities = result
            .document()
            .sections
            .iter()
            .find(|section| section.title == "Capabilities")
            .expect("capabilities section should exist");
        match &capabilities.content {
            SectionContent::List(items) => {
                assert_eq!(items.len(), 1);
                assert!(items[0].text.contains("policy"));
            }
            other => panic!("unexpected section type: {:?}", other),
        }

        let info = result.page_info.as_ref().expect("page info should exist");
        assert_eq!(info.page, 1);
        assert_eq!(info.page_size, 1);
        let json = result.to_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("query json should be valid JSON");
        assert!(parsed.get("page_info").is_some());
        assert!(parsed.get("query").is_some());
    }

    #[test]
    fn test_engine_policy_denial() {
        let mut engine = SurfaceEngine::default();
        let request = RenderRequest::new(SurfaceType::Agent, "test-001", "user-1", Role::Operator)
            .view(SurfaceView::Forensic);
        let result = engine.render(request);
        
        assert!(matches!(result, Err(RenderError::PolicyDenied(_))));
    }

    #[test]
    fn test_engine_time_travel() {
        let mut engine = SurfaceEngine::default();
        let request = RenderRequest::new(SurfaceType::Agent, "test-001", "user-1", Role::Developer)
            .time(SurfaceTimeSelector::Last(SurfaceDuration::hours(1)));
        let result = engine.render(request).unwrap();
        
        assert!(result.receipt.as_ref().unwrap().time_context.as_ref().unwrap().is_time_travel);
    }

    #[test]
    fn test_engine_receipts() {
        let mut engine = SurfaceEngine::default();
        
        for i in 0..3 {
            let request = RenderRequest::new(SurfaceType::Agent, &format!("test-{}", i), "user-1", Role::Developer);
            engine.render(request).unwrap();
        }
        
        assert_eq!(engine.receipts().len(), 3);
        assert!(engine.receipts().verify());
    }

    #[test]
    fn smoke_all_surface_types_produce_valid_contract_and_meta() {
        let all_types = [
            SurfaceType::Agent,
            SurfaceType::Audit,
            SurfaceType::Memory,
            SurfaceType::Knowledge,
            SurfaceType::Policy,
            SurfaceType::Tool,
            SurfaceType::Contract,
            SurfaceType::Proof,
            SurfaceType::Compliance,
            SurfaceType::Health,
            SurfaceType::Books,
            SurfaceType::Debug,
            SurfaceType::Trace,
            SurfaceType::Inspect,
            SurfaceType::Review,
            SurfaceType::Explain,
            SurfaceType::Monitor,
        ];

        for st in &all_types {
            let mut engine = SurfaceEngine::default();
            let request = RenderRequest::new(*st, "smoke-subject", "smoke-actor", Role::Developer);
            let result = engine.render(request).unwrap_or_else(|e| {
                panic!("SurfaceType::{:?} failed to render: {}", st, e);
            });

            let v = result.contract.validate();
            assert!(
                v.valid,
                "SurfaceType::{:?} contract invalid: {:?}",
                st, v.errors
            );
            assert!(
                result.contract.signals.len() >= 3,
                "SurfaceType::{:?} has {} signals (need ≥3)",
                st,
                result.contract.signals.len()
            );

            let type_token = format!("{:?}", st).to_ascii_lowercase();
            let json_str = result.to_json_with_meta(Some(&type_token), Some("developer"));
            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_else(|e| {
                panic!("SurfaceType::{:?} produced invalid JSON: {}", st, e);
            });

            let meta = parsed.get("_meta").unwrap_or_else(|| {
                panic!("SurfaceType::{:?} JSON missing _meta block", st);
            });
            assert!(meta.get("version").is_some(), "{:?}: _meta.version missing", st);
            assert!(meta.get("generated_at").is_some(), "{:?}: _meta.generated_at missing", st);
            assert_eq!(
                meta.get("view").and_then(|v| v.as_str()),
                Some("ops"),
                "{:?}: _meta.view wrong",
                st
            );
            assert_eq!(
                meta.get("caller_role").and_then(|v| v.as_str()),
                Some("developer"),
                "{:?}: _meta.caller_role wrong",
                st
            );
            assert!(meta.get("cid").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false), "{:?}: _meta.cid empty", st);
            assert!(parsed.get("surface_contract").is_some(), "{:?}: surface_contract missing", st);
            assert!(parsed.get("document").is_some(), "{:?}: document missing", st);
        }
    }
}

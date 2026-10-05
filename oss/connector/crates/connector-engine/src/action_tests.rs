#[cfg(test)]
mod tests {
    use crate::action::*;

    // ─── Layer 0: Minimal (anyone) ───────────────────────────────

    #[test]
    fn test_layer0_search() {
        let a = Action::new("search")
            .describe("Search the web")
            .param("query", Param::String, "What to search for")
            .build();
        assert_eq!(a.name, "search");
        assert_eq!(a.params.len(), 1);
        assert!(a.params[0].required);
        assert!(!a.rules.require_approval);
        assert!(a.domain.is_none());
    }

    #[test]
    fn test_layer0_screen_click() {
        let a = Action::new("screen.click")
            .describe("Click at screen coordinates")
            .param("x", Param::Integer, "X coordinate")
            .param("y", Param::Integer, "Y coordinate")
            .build();
        assert_eq!(a.domain.as_deref(), Some("screen"));
        assert_eq!(a.operation.as_deref(), Some("click"));
        assert_eq!(a.params.len(), 2);
    }

    #[test]
    fn test_layer0_robot_move() {
        let a = Action::new("robot.move")
            .describe("Move robot arm to position")
            .param("x", Param::Float, "X mm")
            .param("y", Param::Float, "Y mm")
            .param("z", Param::Float, "Z mm")
            .param("speed", Param::Float, "Speed mm/s")
            .build();
        assert_eq!(a.domain.as_deref(), Some("robot"));
        assert_eq!(a.operation.as_deref(), Some("move"));
        assert_eq!(a.params.len(), 4);
    }

    #[test]
    fn test_layer0_terminal_execute() {
        let a = Action::new("terminal.execute")
            .describe("Execute a shell command")
            .param("command", Param::String, "Command to run")
            .optional("timeout", Param::Integer, "Timeout in seconds", serde_json::json!(30))
            .build();
        assert_eq!(a.params.len(), 2);
        assert!(a.params[0].required);
        assert!(!a.params[1].required);
        assert_eq!(a.params[1].default, Some(serde_json::json!(30)));
    }

    #[test]
    fn test_layer0_browser_navigate() {
        let a = Action::new("browser.navigate")
            .describe("Navigate to URL")
            .param("url", Param::String, "URL to navigate to")
            .build();
        assert_eq!(a.domain.as_deref(), Some("browser"));
        assert_eq!(a.operation.as_deref(), Some("navigate"));
    }

    #[test]
    fn test_layer0_file_read() {
        let a = Action::new("fs.read")
            .describe("Read a file")
            .param("path", Param::String, "File path")
            .returns(Param::String)
            .idempotent()
            .build();
        assert!(a.rules.idempotent);
        assert_eq!(a.returns, Some(Param::String));
    }

    // ─── Layer 2: Enterprise ─────────────────────────────────────

    #[test]
    fn test_layer2_hospital_prescribe() {
        let a = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication")
            .target("pharmacy_system")
            .param("patient_id", Param::String, "Patient ID")
            .param("medication", Param::String, "Drug name")
            .param("dosage", Param::String, "Dosage")
            .param("frequency", Param::Enum(vec!["once".into(), "daily".into(), "bid".into(), "tid".into()]), "How often")
            .returns(Param::Object)
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing"])
            .rate_limit(10)
            .compliance(&["hipaa", "fda"])
            .timeout_ms(30_000)
            .build();

        assert_eq!(a.target.as_deref(), Some("pharmacy_system"));
        assert_eq!(a.domain.as_deref(), Some("pharmacy"));
        assert_eq!(a.params.len(), 4);
        assert!(a.rules.require_approval);
        assert_eq!(a.rules.data_classification.as_deref(), Some("phi"));
        assert_eq!(a.rules.allowed_roles, vec!["doctor"]);
        assert_eq!(a.rules.denied_roles, vec!["nurse", "billing"]);
        assert_eq!(a.rules.rate_limit, Some(10));
        assert_eq!(a.rules.compliance, vec!["hipaa", "fda"]);
    }

    #[test]
    fn test_layer2_military_two_person() {
        let a = Action::new("weapons.arm")
            .describe("Arm weapon system")
            .target("weapons_controller")
            .param("system_id", Param::String, "Weapon system ID")
            .param("auth_code", Param::String, "Authorization code")
            .data_class("top_secret")
            .require_approval()
            .two_person()
            .allowed_roles(&["commander", "weapons_officer"])
            .compliance(&["dod_5220"])
            .build();

        assert!(a.rules.two_person);
        assert!(a.needs_approval());
        assert_eq!(a.rules.data_classification.as_deref(), Some("top_secret"));
    }

    #[test]
    fn test_layer2_finance_transfer() {
        let a = Action::new("account.transfer")
            .describe("Transfer funds between accounts")
            .param("from_account", Param::String, "Source account")
            .param("to_account", Param::String, "Destination account")
            .param("amount", Param::Float, "Amount in USD")
            .param("currency", Param::Enum(vec!["USD".into(), "EUR".into(), "GBP".into()]), "Currency")
            .data_class("pii")
            .require_approval()
            .compliance(&["soc2", "pci_dss"])
            .reversible()
            .build();

        assert!(a.rules.reversible);
        assert!(a.rules.require_approval);
        assert_eq!(a.rules.compliance, vec!["soc2", "pci_dss"]);
    }

    #[test]
    fn test_layer2_industrial_valve() {
        let a = Action::new("valve.set_position")
            .describe("Set valve position")
            .target("valve_controller")
            .constrained_param("position_pct", Param::Float, "Position 0-100%", ParamConstraints {
                min: Some(0.0), max: Some(100.0), ..Default::default()
            })
            .constrained_param("speed", Param::Float, "Opening speed deg/s", ParamConstraints {
                min: Some(0.1), max: Some(10.0), ..Default::default()
            })
            .interlock("position_pct change rate < 5%/s when pressure > 80bar")
            .compliance(&["iec_61511"])
            .build();

        assert!(a.rules.interlock.is_some());
        assert!(a.params[0].constraints.is_some());
        assert_eq!(a.params[0].constraints.as_ref().unwrap().max, Some(100.0));
    }

    // ─── Safety Constraints ──────────────────────────────────────

    #[test]
    fn test_constraint_validation_pass() {
        let a = Action::new("robot.move")
            .describe("Move")
            .constrained_param("speed", Param::Float, "Speed", ParamConstraints {
                min: Some(0.0), max: Some(500.0), ..Default::default()
            })
            .build();

        let mut ctx = ActionContext::new();
        ctx.set("speed", serde_json::json!(250.0));
        assert!(a.validate_params(&ctx).is_ok());
    }

    #[test]
    fn test_constraint_validation_above_max() {
        let a = Action::new("robot.move")
            .describe("Move")
            .constrained_param("speed", Param::Float, "Speed", ParamConstraints {
                min: Some(0.0), max: Some(500.0), ..Default::default()
            })
            .build();

        let mut ctx = ActionContext::new();
        ctx.set("speed", serde_json::json!(600.0));
        let err = a.validate_params(&ctx).unwrap_err();
        assert!(err.contains("above maximum"));
    }

    #[test]
    fn test_constraint_validation_below_min() {
        let a = Action::new("motor.set_speed")
            .describe("Set motor speed")
            .constrained_param("rpm", Param::Float, "RPM", ParamConstraints {
                min: Some(100.0), max: Some(3000.0), ..Default::default()
            })
            .build();

        let mut ctx = ActionContext::new();
        ctx.set("rpm", serde_json::json!(50.0));
        let err = a.validate_params(&ctx).unwrap_err();
        assert!(err.contains("below minimum"));
    }

    #[test]
    fn test_constraint_string_length() {
        let a = Action::new("send_message")
            .describe("Send a message")
            .constrained_param("text", Param::String, "Message", ParamConstraints {
                max_length: Some(10), ..Default::default()
            })
            .build();

        let mut ctx = ActionContext::new();
        ctx.set("text", serde_json::json!("short"));
        assert!(a.validate_params(&ctx).is_ok());

        ctx.set("text", serde_json::json!("this is way too long"));
        assert!(a.validate_params(&ctx).is_err());
    }

    #[test]
    fn test_missing_required_param() {
        let a = Action::new("search")
            .describe("Search")
            .param("query", Param::String, "Query")
            .build();

        let ctx = ActionContext::new();
        let err = a.validate_params(&ctx).unwrap_err();
        assert!(err.contains("Missing required parameter"));
    }

    // ─── RBAC ────────────────────────────────────────────────────

    #[test]
    fn test_rbac_allowed() {
        let a = Action::new("prescribe")
            .describe("Prescribe")
            .allowed_roles(&["doctor"])
            .denied_roles(&["billing", "admin"])
            .build();

        assert!(a.is_role_allowed("doctor"));
        assert!(!a.is_role_allowed("billing"));
        assert!(!a.is_role_allowed("admin"));
        assert!(!a.is_role_allowed("nurse")); // not in allowed
    }

    #[test]
    fn test_rbac_no_restrictions() {
        let a = Action::new("search").describe("Search").build();
        assert!(a.is_role_allowed("anyone"));
        assert!(a.is_role_allowed("doctor"));
    }

    #[test]
    fn test_rbac_deny_only() {
        let a = Action::new("read_logs")
            .describe("Read logs")
            .denied_roles(&["intern"])
            .build();

        assert!(a.is_role_allowed("admin"));
        assert!(a.is_role_allowed("doctor"));
        assert!(!a.is_role_allowed("intern"));
    }

    // ─── JSON Schema Export ──────────────────────────────────────

    #[test]
    fn test_json_schema_basic() {
        let a = Action::new("search")
            .describe("Search the web")
            .param("query", Param::String, "Query")
            .param("limit", Param::Integer, "Max results")
            .build();

        let s = a.to_json_schema();
        assert_eq!(s["type"], "function");
        assert_eq!(s["function"]["name"], "search");
        assert_eq!(s["function"]["parameters"]["properties"]["query"]["type"], "string");
        assert_eq!(s["function"]["parameters"]["properties"]["limit"]["type"], "integer");
        let req = s["function"]["parameters"]["required"].as_array().unwrap();
        assert!(req.contains(&serde_json::json!("query")));
    }

    #[test]
    fn test_json_schema_enum() {
        let a = Action::new("classify")
            .describe("Classify urgency")
            .param("level", Param::Enum(vec!["low".into(), "medium".into(), "high".into(), "critical".into()]), "Level")
            .build();

        let s = a.to_json_schema();
        let level = &s["function"]["parameters"]["properties"]["level"];
        assert_eq!(level["type"], "string");
        assert_eq!(level["enum"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_json_schema_array() {
        let a = Action::new("check_interactions")
            .describe("Check drug interactions")
            .param("medications", Param::Array(Box::new(Param::String)), "Medications")
            .build();

        let s = a.to_json_schema();
        let meds = &s["function"]["parameters"]["properties"]["medications"];
        assert_eq!(meds["type"], "array");
        assert_eq!(meds["items"]["type"], "string");
    }

    #[test]
    fn test_json_schema_constraints_in_output() {
        let a = Action::new("robot.move")
            .describe("Move")
            .constrained_param("speed", Param::Float, "Speed", ParamConstraints {
                min: Some(0.0), max: Some(500.0), ..Default::default()
            })
            .build();

        let s = a.to_json_schema();
        let speed = &s["function"]["parameters"]["properties"]["speed"];
        assert_eq!(speed["minimum"], 0.0);
        assert_eq!(speed["maximum"], 500.0);
    }

    #[test]
    fn test_json_schema_optional_not_required() {
        let a = Action::new("search")
            .describe("Search")
            .param("query", Param::String, "Query")
            .optional("limit", Param::Integer, "Max", serde_json::json!(10))
            .build();

        let s = a.to_json_schema();
        let req = s["function"]["parameters"]["required"].as_array().unwrap();
        assert_eq!(req.len(), 1);
        assert!(req.contains(&serde_json::json!("query")));
    }

    // ─── Kernel ToolBinding Export ────────────────────────────────

    #[test]
    fn test_tool_binding_export() {
        let a = Action::new("ehr.read")
            .describe("Read EHR")
            .data_class("phi")
            .require_approval()
            .build();

        let b = a.to_tool_binding("ns:hospital");
        assert_eq!(b["tool_id"], "ehr.read");
        assert_eq!(b["namespace_path"], "ns:hospital/actions/ehr");
        assert_eq!(b["data_classification"], "phi");
        assert_eq!(b["requires_approval"], true);
    }

    // ─── AAPI Kriya Export ───────────────────────────────────────

    #[test]
    fn test_kriya_export() {
        let a = Action::new("pharmacy.prescribe")
            .describe("Prescribe")
            .effect(EffectType::Create)
            .build();

        let k = a.to_kriya();
        assert_eq!(k["action"], "pharmacy.prescribe");
        assert_eq!(k["domain"], "pharmacy");
        assert_eq!(k["verb"], "prescribe");
        assert_eq!(k["expected_effect"], "create");
        assert_eq!(k["idempotent"], false);
    }

    #[test]
    fn test_kriya_idempotent() {
        let a = Action::new("ehr.read")
            .describe("Read EHR")
            .idempotent()
            .build();

        let k = a.to_kriya();
        assert_eq!(k["expected_effect"], "none");
        assert_eq!(k["idempotent"], true);
    }

    // ─── ActionContext ───────────────────────────────────────────

    #[test]
    fn test_context_from_json() {
        let json = serde_json::json!({"patient_id": "P-123", "section": "vitals", "count": 5, "active": true});
        let ctx = ActionContext::from_json(&json);
        assert_eq!(ctx.get_str("patient_id"), Some("P-123"));
        assert_eq!(ctx.get_str("section"), Some("vitals"));
        assert_eq!(ctx.get_i64("count"), Some(5));
        assert_eq!(ctx.get_bool("active"), Some(true));
    }

    #[test]
    fn test_context_agent_metadata() {
        let mut ctx = ActionContext::new();
        ctx.agent_id = Some("agent:doctor-1".into());
        ctx.role = Some("doctor".into());
        ctx.set("query", serde_json::json!("test"));
        assert_eq!(ctx.agent_id.as_deref(), Some("agent:doctor-1"));
        assert_eq!(ctx.role.as_deref(), Some("doctor"));
    }

    // ─── ActionResult ────────────────────────────────────────────

    #[test]
    fn test_result_constructors() {
        assert!(ActionResult::text("ok").is_success());
        assert!(ActionResult::json(serde_json::json!({"ok": true})).is_success());
        assert!(!ActionResult::error("E001", "fail").is_success());
        assert!(!ActionResult::pending("admin", "needs review").is_success());
        assert!(!ActionResult::feedback(0.5, "halfway").is_success());
    }

    #[test]
    fn test_result_display() {
        let s = format!("{}", ActionResult::text("done"));
        assert!(s.contains("✅"));
        let s = format!("{}", ActionResult::error("E001", "fail"));
        assert!(s.contains("💥") && s.contains("E001"));
        let s = format!("{}", ActionResult::pending("admin", "review"));
        assert!(s.contains("⏳"));
        let s = format!("{}", ActionResult::feedback(0.75, "progress"));
        assert!(s.contains("75%"));
    }

    // ─── Display ─────────────────────────────────────────────────

    #[test]
    fn test_action_display() {
        let a = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication")
            .target("pharmacy_system")
            .param("patient_id", Param::String, "Patient ID")
            .data_class("phi")
            .require_approval()
            .two_person()
            .build();

        let d = format!("{}", a);
        assert!(d.contains("pharmacy.prescribe"));
        assert!(d.contains("pharmacy_system"));
        assert!(d.contains("Prescribe medication"));
        assert!(d.contains("🔐"));
        assert!(d.contains("👥"));
        assert!(d.contains("phi"));
    }

    // ─── Feedback Channel (ROS2-inspired) ────────────────────────

    #[test]
    fn test_feedback_params() {
        let a = Action::new("robot.move")
            .describe("Move robot arm")
            .param("x", Param::Float, "Target X")
            .param("y", Param::Float, "Target Y")
            .param("z", Param::Float, "Target Z")
            .feedback_param("current_x", Param::Float, "Current X position")
            .feedback_param("current_y", Param::Float, "Current Y position")
            .feedback_param("current_z", Param::Float, "Current Z position")
            .feedback_param("percent_complete", Param::Float, "Progress 0-1")
            .build();

        assert_eq!(a.params.len(), 3);
        assert_eq!(a.feedback.len(), 4);
        assert_eq!(a.feedback[3].name, "percent_complete");
    }

    // ─── Full Domain Suites ──────────────────────────────────────

    #[test]
    fn test_suite_computer_control() {
        let click = Action::new("screen.click").describe("Click").param("x", Param::Integer, "X").param("y", Param::Integer, "Y").build();
        let type_text = Action::new("screen.type").describe("Type text").param("text", Param::String, "Text").build();
        let scroll = Action::new("screen.scroll").describe("Scroll").param("direction", Param::Enum(vec!["up".into(), "down".into()]), "Dir").param("amount", Param::Integer, "Pixels").build();
        let screenshot = Action::new("screen.screenshot").describe("Take screenshot").returns(Param::Binary).idempotent().build();

        assert_eq!(click.domain.as_deref(), Some("screen"));
        assert_eq!(type_text.operation.as_deref(), Some("type"));
        assert_eq!(scroll.params.len(), 2);
        assert!(screenshot.rules.idempotent);

        // All export to valid JSON Schema
        for a in &[&click, &type_text, &scroll, &screenshot] {
            let s = a.to_json_schema();
            assert_eq!(s["type"], "function");
            assert!(s["function"]["name"].as_str().unwrap().starts_with("screen."));
        }
    }

    #[test]
    fn test_suite_hospital() {
        let triage = Action::new("triage.classify")
            .describe("Classify patient urgency")
            .param("symptoms", Param::String, "Symptoms")
            .param("age", Param::Integer, "Age")
            .returns(Param::Enum(vec!["ESI-1".into(), "ESI-2".into(), "ESI-3".into(), "ESI-4".into(), "ESI-5".into()]))
            .compliance(&["hipaa"])
            .build();

        let read_ehr = Action::new("ehr.read")
            .describe("Read patient EHR")
            .param("patient_id", Param::String, "Patient ID")
            .param("section", Param::Enum(vec!["vitals".into(), "labs".into(), "notes".into()]), "Section")
            .data_class("phi")
            .allowed_roles(&["doctor", "nurse"])
            .idempotent()
            .build();

        let prescribe = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication")
            .param("patient_id", Param::String, "Patient ID")
            .param("medication", Param::String, "Medication")
            .param("dosage", Param::String, "Dosage")
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing", "admin"])
            .compliance(&["hipaa", "fda"])
            .build();

        // Verify exports
        assert!(triage.to_json_schema()["function"]["name"] == "triage.classify");
        assert!(read_ehr.to_tool_binding("ns:hospital")["data_classification"] == "phi");
        assert!(prescribe.to_kriya()["domain"] == "pharmacy");

        // Verify RBAC
        assert!(prescribe.is_role_allowed("doctor"));
        assert!(!prescribe.is_role_allowed("nurse"));
        assert!(!prescribe.is_role_allowed("billing"));
        assert!(read_ehr.is_role_allowed("nurse"));
    }

    #[test]
    fn test_suite_robotics() {
        let move_arm = Action::new("robot.move")
            .describe("Move arm")
            .target("ur5e_arm")
            .constrained_param("x", Param::Float, "X mm", ParamConstraints { min: Some(-500.0), max: Some(500.0), ..Default::default() })
            .constrained_param("y", Param::Float, "Y mm", ParamConstraints { min: Some(-500.0), max: Some(500.0), ..Default::default() })
            .constrained_param("z", Param::Float, "Z mm", ParamConstraints { min: Some(0.0), max: Some(800.0), ..Default::default() })
            .constrained_param("speed", Param::Float, "Speed mm/s", ParamConstraints { min: Some(1.0), max: Some(250.0), ..Default::default() })
            .feedback_param("current_x", Param::Float, "Current X")
            .feedback_param("current_y", Param::Float, "Current Y")
            .feedback_param("current_z", Param::Float, "Current Z")
            .feedback_param("progress", Param::Float, "0-1 progress")
            .interlock("speed < 50 when z < 10")
            .build();

        assert_eq!(move_arm.target.as_deref(), Some("ur5e_arm"));
        assert_eq!(move_arm.params.len(), 4);
        assert_eq!(move_arm.feedback.len(), 4);
        assert!(move_arm.rules.interlock.is_some());

        // Valid params
        let mut ctx = ActionContext::new();
        ctx.set("x", serde_json::json!(100.0));
        ctx.set("y", serde_json::json!(-200.0));
        ctx.set("z", serde_json::json!(300.0));
        ctx.set("speed", serde_json::json!(100.0));
        assert!(move_arm.validate_params(&ctx).is_ok());

        // Out of range
        ctx.set("z", serde_json::json!(900.0));
        assert!(move_arm.validate_params(&ctx).is_err());

        // Schema includes constraints
        let s = move_arm.to_json_schema();
        let speed = &s["function"]["parameters"]["properties"]["speed"];
        assert_eq!(speed["minimum"], 1.0);
        assert_eq!(speed["maximum"], 250.0);
    }

    #[test]
    fn test_suite_industrial() {
        let valve = Action::new("valve.open")
            .describe("Open valve")
            .target("valve_v42")
            .constrained_param("position_pct", Param::Float, "Position 0-100%", ParamConstraints { min: Some(0.0), max: Some(100.0), ..Default::default() })
            .interlock("rate_of_change < 5%/s when pressure > 80bar")
            .compliance(&["iec_61511"])
            .require_approval()
            .build();

        let motor = Action::new("motor.set_speed")
            .describe("Set motor speed")
            .target("motor_m7")
            .constrained_param("rpm", Param::Float, "RPM", ParamConstraints { min: Some(0.0), max: Some(3600.0), ..Default::default() })
            .param("direction", Param::Enum(vec!["cw".into(), "ccw".into()]), "Direction")
            .build();

        assert!(valve.needs_approval());
        assert!(!motor.needs_approval());
        assert_eq!(motor.params.len(), 2);
    }

    // ═══════════════════════════════════════════════════════════════
    // AAPI ABSORPTION TESTS — prove every Vakya capability is mapped
    // ═══════════════════════════════════════════════════════════════

    // --- V3 Kriya: EffectType (absorbs EffectBucket) ─────────────

    #[test]
    fn test_aapi_effect_type() {
        let read = Action::new("ehr.read").describe("Read EHR").effect(EffectType::Read).idempotent().build();
        let write = Action::new("ehr.write").describe("Write EHR").effect(EffectType::Update).build();
        let create = Action::new("patient.create").describe("Create patient").effect(EffectType::Create).build();
        let delete = Action::new("record.delete").describe("Delete record").effect(EffectType::Delete).build();
        let send = Action::new("email.send").describe("Send email").effect(EffectType::External).build();

        assert_eq!(read.rules.effect, EffectType::Read);
        assert!(!read.rules.effect.is_mutating());
        assert!(write.rules.effect.is_mutating());
        assert!(create.rules.effect.is_mutating());
        assert!(delete.rules.effect.is_mutating());
        assert!(send.rules.effect.is_mutating());

        // Kriya export uses EffectType
        assert_eq!(read.to_kriya()["expected_effect"], "read");
        assert_eq!(write.to_kriya()["expected_effect"], "update");
        assert_eq!(create.to_kriya()["expected_effect"], "create");
        assert_eq!(delete.to_kriya()["expected_effect"], "delete");
        assert_eq!(send.to_kriya()["expected_effect"], "external");
    }

    // --- V7 Adhikarana: scopes (absorbs Adhikarana.scopes) ───────

    #[test]
    fn test_aapi_scopes() {
        let a = Action::new("ehr.read").describe("Read EHR")
            .scopes(&["read:patient", "read:vitals"])
            .build();

        assert_eq!(a.rules.scopes, vec!["read:patient", "read:vitals"]);

        let adh = a.to_adhikarana();
        let scopes = adh["scopes"].as_array().unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&serde_json::json!("read:patient")));
    }

    // --- V7 Adhikarana: environment (absorbs AuthorityContext) ────

    #[test]
    fn test_aapi_environment() {
        let a = Action::new("deploy.release").describe("Deploy to production")
            .environment("production")
            .build();

        assert_eq!(a.rules.environment.as_deref(), Some("production"));

        let adh = a.to_adhikarana();
        assert_eq!(adh["context"]["environment"], "production");
    }

    // --- V7 Adhikarana: jurisdiction (absorbs ComplianceContext) ──

    #[test]
    fn test_aapi_jurisdiction() {
        let a = Action::new("data.process").describe("Process personal data")
            .jurisdiction("EU")
            .compliance(&["gdpr"])
            .data_class("pii")
            .retention_days(2555) // 7 years
            .build();

        assert_eq!(a.rules.jurisdiction.as_deref(), Some("EU"));
        assert_eq!(a.rules.retention_days, Some(2555));

        let comp = a.to_compliance().unwrap();
        assert_eq!(comp["jurisdiction"], "EU");
        assert_eq!(comp["retention_days"], 2555);
        assert!(comp["regulations"].as_array().unwrap().contains(&serde_json::json!("gdpr")));
    }

    // --- V7 Adhikarana: execution constraints ─────────────────────

    #[test]
    fn test_aapi_execution_constraints() {
        let a = Action::new("llm.generate").describe("Generate text")
            .max_tokens(4096)
            .max_cost(0.10)
            .max_chain_depth(5)
            .timeout_ms(60_000)
            .data_class("internal")
            .require_approval()
            .build();

        let adh = a.to_adhikarana();
        let ec = &adh["execution_constraints"];
        assert_eq!(ec["max_tokens"], 4096);
        assert_eq!(ec["max_cost_usd"], 0.10);
        assert_eq!(ec["max_tool_calls"], 5);
        assert_eq!(ec["max_execution_ms"], 60_000);
        assert_eq!(ec["data_classification"], "internal");
        assert_eq!(ec["requires_approval"], true);
    }

    // --- V7 Adhikarana: approval lane ─────────────────────────────

    #[test]
    fn test_aapi_approval_lanes() {
        let none = Action::new("search").describe("Search").build();
        let sync = Action::new("prescribe").describe("Prescribe").require_approval().build();
        let multi = Action::new("launch").describe("Launch").require_approval().two_person().build();

        assert_eq!(none.to_adhikarana()["approval_lane"], "none");
        assert_eq!(sync.to_adhikarana()["approval_lane"], "sync");
        assert_eq!(multi.to_adhikarana()["approval_lane"], "multi_party");
    }

    // --- V8 Pratyaya: postconditions ─────────────────────────────

    #[test]
    fn test_aapi_postconditions() {
        let a = Action::new("pharmacy.prescribe").describe("Prescribe medication")
            .postcondition("Prescription record created", Some("$.prescription_id != null"))
            .postcondition("Drug interaction check passed", Some("$.interactions.length == 0"))
            .rollback(RollbackStrategy::HumanReview)
            .build();

        assert_eq!(a.rules.postconditions.len(), 2);
        assert_eq!(a.rules.postconditions[0].description, "Prescription record created");
        assert_eq!(a.rules.postconditions[0].assertion.as_deref(), Some("$.prescription_id != null"));
        assert!(a.rules.postconditions[0].required);
        assert_eq!(a.rules.rollback, RollbackStrategy::HumanReview);

        let pratyaya = a.to_pratyaya().unwrap();
        assert_eq!(pratyaya["postconditions"].as_array().unwrap().len(), 2);
        assert_eq!(pratyaya["rollback"], "human_review");
        assert_eq!(pratyaya["allow_partial"], false);
    }

    #[test]
    fn test_aapi_pratyaya_none_when_empty() {
        let a = Action::new("search").describe("Search").build();
        assert!(a.to_pratyaya().is_none());
    }

    // --- V8 Pratyaya: rollback strategies ────────────────────────

    #[test]
    fn test_aapi_rollback_strategies() {
        let auto = Action::new("a").describe("a").rollback(RollbackStrategy::AutoReverse).build();
        let retry = Action::new("b").describe("b").rollback(RollbackStrategy::Retry { max_retries: 3, backoff_ms: 1000 }).build();
        let accept = Action::new("c").describe("c").rollback(RollbackStrategy::AcceptAndLog).build();

        assert_eq!(auto.to_pratyaya().unwrap()["rollback"], "auto_reverse");
        assert_eq!(retry.to_pratyaya().unwrap()["rollback"], "retry");
        assert_eq!(accept.to_pratyaya().unwrap()["rollback"], "accept_failure");
    }

    #[test]
    fn test_aapi_allow_partial() {
        let a = Action::new("batch.process").describe("Batch process")
            .postcondition("At least 80% processed", Some("$.processed_pct >= 0.8"))
            .allow_partial()
            .build();

        assert!(a.rules.allow_partial);
        assert_eq!(a.to_pratyaya().unwrap()["allow_partial"], true);
    }

    // --- VakyaMeta.compliance: full ComplianceContext ─────────────

    #[test]
    fn test_aapi_compliance_context() {
        let a = Action::new("ehr.read").describe("Read EHR")
            .data_class("phi")
            .compliance(&["hipaa", "soc2"])
            .retention_days(2555)
            .jurisdiction("US")
            .require_approval()
            .build();

        let comp = a.to_compliance().unwrap();
        assert_eq!(comp["data_classification"], "phi");
        assert!(comp["regulations"].as_array().unwrap().contains(&serde_json::json!("hipaa")));
        assert!(comp["regulations"].as_array().unwrap().contains(&serde_json::json!("soc2")));
        assert_eq!(comp["retention_days"], 2555);
        assert_eq!(comp["jurisdiction"], "US");
        assert_eq!(comp["requires_human_review"], true);
    }

    #[test]
    fn test_aapi_compliance_none_when_empty() {
        let a = Action::new("search").describe("Search").build();
        assert!(a.to_compliance().is_none());
    }

    // --- Full AAPI absorption: hospital prescription ─────────────

    #[test]
    fn test_full_aapi_absorption_hospital() {
        let prescribe = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication to patient")
            .target("pharmacy_system")
            // Params
            .param("patient_id", Param::String, "Patient ID")
            .param("medication", Param::String, "Drug name")
            .param("dosage", Param::String, "Dosage")
            // V3 Kriya
            .effect(EffectType::Create)
            // V7 Adhikarana: authorization
            .require_approval()
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing"])
            .scopes(&["write:prescription", "read:patient"])
            // V7 Adhikarana: execution constraints
            .data_class("phi")
            .rate_limit(10)
            .max_cost(1.00)
            .max_tokens(2048)
            .max_chain_depth(3)
            .timeout_ms(30_000)
            // V7 Adhikarana: context
            .environment("production")
            .jurisdiction("US")
            // V8 Pratyaya: postconditions
            .postcondition("Prescription created", Some("$.rx_id != null"))
            .postcondition("No drug interactions", Some("$.interactions == []"))
            .rollback(RollbackStrategy::HumanReview)
            // Compliance
            .compliance(&["hipaa", "fda"])
            .retention_days(2555)
            .build();

        // Verify all AAPI exports work
        let kriya = prescribe.to_kriya();
        assert_eq!(kriya["domain"], "pharmacy");
        assert_eq!(kriya["verb"], "prescribe");
        assert_eq!(kriya["expected_effect"], "create");

        let adh = prescribe.to_adhikarana();
        assert_eq!(adh["approval_lane"], "sync");
        assert_eq!(adh["scopes"].as_array().unwrap().len(), 2);
        assert_eq!(adh["context"]["environment"], "production");
        assert_eq!(adh["execution_constraints"]["max_tokens"], 2048);
        assert_eq!(adh["execution_constraints"]["max_tool_calls"], 3);

        let pratyaya = prescribe.to_pratyaya().unwrap();
        assert_eq!(pratyaya["postconditions"].as_array().unwrap().len(), 2);
        assert_eq!(pratyaya["rollback"], "human_review");

        let comp = prescribe.to_compliance().unwrap();
        assert_eq!(comp["jurisdiction"], "US");
        assert_eq!(comp["retention_days"], 2555);

        // JSON Schema still works for LLMs
        let schema = prescribe.to_json_schema();
        assert_eq!(schema["function"]["name"], "pharmacy.prescribe");

        // Kernel ToolBinding still works
        let binding = prescribe.to_tool_binding("ns:hospital");
        assert_eq!(binding["data_classification"], "phi");

        // RBAC still works
        assert!(prescribe.is_role_allowed("doctor"));
        assert!(!prescribe.is_role_allowed("nurse"));
    }

    // --- Full AAPI absorption: military drone ────────────────────

    #[test]
    fn test_full_aapi_absorption_military() {
        let strike = Action::new("drone.strike")
            .describe("Execute precision strike")
            .target("mq9_reaper")
            // Params with safety constraints
            .constrained_param("lat", Param::Float, "Latitude", ParamConstraints { min: Some(-90.0), max: Some(90.0), ..Default::default() })
            .constrained_param("lon", Param::Float, "Longitude", ParamConstraints { min: Some(-180.0), max: Some(180.0), ..Default::default() })
            // V3 Kriya
            .effect(EffectType::External)
            // V7 Adhikarana
            .require_approval()
            .two_person()
            .allowed_roles(&["commander", "weapons_officer"])
            .scopes(&["weapons:engage"])
            .data_class("top_secret")
            .environment("operational")
            .max_chain_depth(1) // no chaining
            .timeout_ms(120_000)
            // V8 Pratyaya
            .postcondition("Target confirmed destroyed", Some("$.bda.confirmed == true"))
            .rollback(RollbackStrategy::HumanReview)
            // Compliance
            .compliance(&["dod_5220", "loac"])
            .retention_days(36500) // 100 years
            .jurisdiction("US")
            .build();

        assert!(strike.needs_approval());
        assert!(strike.rules.two_person);
        assert_eq!(strike.rules.effect, EffectType::External);

        let adh = strike.to_adhikarana();
        assert_eq!(adh["approval_lane"], "multi_party");
        assert_eq!(adh["execution_constraints"]["max_tool_calls"], 1);

        let pratyaya = strike.to_pratyaya().unwrap();
        assert_eq!(pratyaya["postconditions"].as_array().unwrap().len(), 1);

        let comp = strike.to_compliance().unwrap();
        assert_eq!(comp["retention_days"], 36500);
    }

    // --- Full AAPI absorption: financial transaction ─────────────

    #[test]
    fn test_full_aapi_absorption_finance() {
        let transfer = Action::new("account.transfer")
            .describe("Transfer funds")
            .param("from", Param::String, "Source account")
            .param("to", Param::String, "Destination account")
            .param("amount", Param::Float, "Amount")
            .param("currency", Param::Enum(vec!["USD".into(), "EUR".into(), "GBP".into()]), "Currency")
            .effect(EffectType::Update)
            .require_approval()
            .data_class("pii")
            .compliance(&["soc2", "pci_dss", "finra"])
            .retention_days(2555)
            .jurisdiction("US")
            .environment("production")
            .scopes(&["write:account", "read:balance"])
            .postcondition("Balance updated", Some("$.new_balance >= 0"))
            .postcondition("Transaction logged", Some("$.tx_id != null"))
            .rollback(RollbackStrategy::AutoReverse)
            .reversible()
            .build();

        assert!(transfer.rules.reversible);
        assert_eq!(transfer.rules.effect, EffectType::Update);
        assert_eq!(transfer.to_pratyaya().unwrap()["rollback"], "auto_reverse");
        assert_eq!(transfer.to_compliance().unwrap()["regulations"].as_array().unwrap().len(), 3);
    }
}

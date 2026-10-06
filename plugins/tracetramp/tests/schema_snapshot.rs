#![cfg(feature = "schema-snapshot")]

#[test]
fn snapshot_providers_shape() {
    let _ = sqlx::query!(
        r#"
        SELECT id, tenant_id, name, api_base, provider_type, is_active
        FROM providers
        LIMIT 1
        "#
    );
}

#[test]
fn snapshot_workflow_runs_shape() {
    let _ = sqlx::query!(
        r#"
        SELECT id, workflow_id, tenant_id, status, input, output, step_results, current_step
        FROM workflow_runs
        LIMIT 1
        "#
    );
}

#[test]
fn snapshot_tools_shape() {
    let _ = sqlx::query!(
        r#"
        SELECT id, tenant_id, name, description, tool_type, definition, is_active
        FROM tools
        LIMIT 1
        "#
    );
}

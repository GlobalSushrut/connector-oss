//! Restart policy for WitnessCtl rows.
//!
//! A normal start clears every public table except the migration ledger.
//! Production keeps those rows by setting `WITNESSCTL_KEEP_RECORDS=1`
//! or `CONNECTOR_KEEP_RECORDS=1`.

pub fn flag_on(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

/// Production keeps rows only when one of these flags is on.
pub fn keep_records(service_flag: Option<&str>, shared_flag: Option<&str>) -> bool {
    flag_on(service_flag) || flag_on(shared_flag)
}

pub const CLEAR_PUBLIC_TABLES_SQL: &str = r#"
DO $$
DECLARE stmt text;
BEGIN
  SELECT 'TRUNCATE TABLE '
      || string_agg(format('%I.%I', schemaname, tablename), ', ')
      || ' RESTART IDENTITY CASCADE'
    INTO stmt
  FROM pg_tables
  WHERE schemaname = 'public'
    AND tablename <> '_sqlx_migrations';
  IF stmt IS NOT NULL THEN
    EXECUTE stmt;
  END IF;
END $$;
"#;

pub async fn clear_public_tables(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(CLEAR_PUBLIC_TABLES_SQL).execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::keep_records;

    #[test]
    fn a_normal_restart_does_not_keep_records() {
        assert!(!keep_records(None, None));
        assert!(!keep_records(Some("0"), Some("false")));
    }

    #[test]
    fn production_can_keep_records() {
        assert!(keep_records(Some("1"), None));
        assert!(keep_records(None, Some("on")));
    }
}

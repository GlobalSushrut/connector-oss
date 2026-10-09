//! Helpers for converting rust_decimal::Decimal ↔ f64 at sqlx boundaries.
//! sqlx 0.7 does not have a rust_decimal feature; we bind/get as f64.

use rust_decimal::Decimal;

pub fn to_f64(d: Decimal) -> f64 {
    rust_decimal::prelude::ToPrimitive::to_f64(&d).unwrap_or(0.0)
}

pub fn from_f64(v: f64) -> Decimal {
    Decimal::try_from(v).unwrap_or_default()
}

/// Get a NUMERIC column as Decimal via f64.
pub fn get_decimal(row: &sqlx::postgres::PgRow, col: &str) -> Decimal {
    use sqlx::Row;
    from_f64(row.try_get::<f64, _>(col).unwrap_or(0.0))
}

/// Get an optional NUMERIC column as Option<Decimal>.
pub fn get_decimal_opt(row: &sqlx::postgres::PgRow, col: &str) -> Option<Decimal> {
    use sqlx::Row;
    row.try_get::<Option<f64>, _>(col).ok().flatten().map(from_f64)
}

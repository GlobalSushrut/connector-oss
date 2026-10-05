//! `GET /api/v1/substrate/admission/matrix`

use axum::extract::State;
use axum::Json;
use serde_json::Value;

use crate::{
    operator::honesty::operator_envelope,
    state::SharedState,
};

pub async fn get_admission_matrix(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(crate::substrate::admission_matrix::admission_matrix_json()))
}

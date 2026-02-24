//! Error types for vac-route.

use thiserror::Error;

/// Errors from the routing layer.
#[derive(Debug, Error)]
pub enum RouteError {
    #[error("No cells available in the ring")]
    NoCells,

    #[error("Cell not found: {0}")]
    CellNotFound(String),

    #[error("Cell already registered: {0}")]
    CellAlreadyRegistered(String),
}

pub type RouteResult<T> = Result<T, RouteError>;

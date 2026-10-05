//! Ring-1 edge: bind `X-Connector-Execution-Quantum` to the request task before handlers run.

use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

pub async fn ring1_quantum_middleware(req: Request<Body>, next: Next) -> Response {
    let quantum = crate::kernel::docklock::extract_quantum_id(req.headers());
    crate::kernel::ring1_context::scope(quantum, async move { next.run(req).await }).await
}

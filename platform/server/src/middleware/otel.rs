use axum::http::{HeaderMap, Request};
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use tracing_opentelemetry::OpenTelemetrySpanExt;

struct HeaderExtractor<'a>(&'a HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

pub async fn trace_context_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let incoming_traceparent = req.headers().get("traceparent").cloned();
    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });

    let span = tracing::info_span!(
        "http.request",
        traceparent = incoming_traceparent
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    );
    span.set_parent(parent_context);
    let _guard = span.enter();

    let mut response = next.run(req).await;
    if let Some(traceparent) = incoming_traceparent {
        response.headers_mut().insert("traceparent", traceparent);
    }
    response
}

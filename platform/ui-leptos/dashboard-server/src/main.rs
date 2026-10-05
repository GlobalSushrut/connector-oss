//! Static file server for `cargo leptos serve` during dashboard development.
//! Writes a CSR `index.html` shell then serves `target/site` (same pattern as
//! leptos-rs/start-csr).

use std::path::PathBuf;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use leptos::logging::log;
use leptos::prelude::*;
use tower::ServiceExt;
use tower_http::services::ServeDir;

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
                <title>"Connector"</title>
                <link rel="icon" type="image/svg+xml" href="/favicon.svg"/>
                <link rel="stylesheet" href="/tailwind.out.css"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options=options.clone()/>
            </head>
            <body class="bg-zinc-950 text-zinc-50 antialiased">
                <div id="root"></div>
            </body>
        </html>
    }
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).expect("logger");
    let conf = get_configuration(None).expect("leptos configuration");
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;

    let index_path = PathBuf::from(&*leptos_options.site_root).join("index.html");
    tokio::fs::write(index_path, shell(leptos_options.clone()).to_html())
        .await
        .expect("write index.html");

    let app = Router::new()
        .route("/", get(file_and_error_handler))
        .fallback(file_and_error_handler)
        .with_state(leptos_options);

    log!("connector-ui dev server listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn file_and_error_handler(
    uri: Uri,
    State(options): State<LeptosOptions>,
) -> Response {
    let root = options.site_root.clone();
    match get_static_file(uri.clone(), &root).await {
        Ok(res) => res.into_response(),
        Err(_) => get_static_file(Uri::from_static("/index.html"), &root)
            .await
            .expect("index.html missing")
            .into_response(),
    }
}

async fn get_static_file(uri: Uri, root: &str) -> Result<Response<Body>, (StatusCode, String)> {
    let req = Request::builder()
        .uri(uri.clone())
        .body(Body::empty())
        .unwrap();
    match ServeDir::new(root).oneshot(req).await {
        Ok(res) => Ok(res.map(Body::new)),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("static file error: {err}"),
        )),
    }
}

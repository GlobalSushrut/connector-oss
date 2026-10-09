mod admin_auth;
mod cors;
mod keys;
mod routes;
mod store;
mod types;
mod persist;
mod database;
mod rpc_token;
mod rpc_auth;
mod surveillance;
mod payment;
mod webhooks;
mod dunning;
mod portal;
mod pilots;
mod pilot_api;

use axum::{middleware, Router, routing::{get, post}};
use std::sync::{Arc, Mutex};
use tower_http::services::{ServeDir, ServeFile};

#[tokio::main]
async fn main() {
    routes::init_start_time();

    // ── Data directory ────────────────────────────────────────────────────────
    let data_dir = std::env::var("CONNECTOR_LICENSE_DATA_DIR")
        .unwrap_or_else(|_| "./data".into());

    // ── Ed25519 signing keypair — MUST persist across restarts ───────────────
    let key_dir = std::env::var("CONNECTOR_KEY_DIR")
        .unwrap_or_else(|_| format!("{}/keys", data_dir));
    let signing_key = keys::SigningKeys::load_or_generate(&key_dir);

    // ── RPC HMAC secret — persisted to data/keys/rpc.secret ──────────────────
    let rpc_secret = rpc_token::RpcTokenManager::load_or_generate_secret(&data_dir);
    let mut token_manager = rpc_token::RpcTokenManager::new(rpc_secret);

    // ── Postgres connection ────────────────────────────────────────────────────
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| panic!("[main] DATABASE_URL must be set"));
    let db = persist::Db::connect(&database_url).await;
    eprintln!("[main] Postgres ready");

    // ── Bootstrap in-memory stores from Postgres ──────────────────────────────
    let mut license_store = store::LicenseStore::new();
    for key in db.load_all_keys().await { license_store.insert_key(key); }
    for act in db.load_all_activations().await { license_store.insert_activation(act); }
    eprintln!("[main] Loaded {} keys, {} activations", license_store.total_keys(), license_store.total_activations());

    let mut surveillance_db = database::SurveillanceDb::new();
    for c in db.load_all_customers().await { surveillance_db.upsert_customer(c); }
    for i in db.load_all_instances().await { surveillance_db.upsert_instance(i); }
    eprintln!("[main] Loaded {} customers, {} instances", surveillance_db.total_customers(), surveillance_db.total_instances());

    let issuances = db.load_all_issuances().await;
    eprintln!("[main] Loaded {} binary issuances", issuances.len());

    let revoked = db.load_revoked_token_ids().await;
    token_manager.load_revoked(revoked);

    // ── Dunning store — bootstrapped from Postgres customer records ───────────
    let mut dunning_store = dunning::DunningStore::new();
    for c in db.load_all_customers().await {
        let rec = dunning::DunningRecord::new(
            c.customer_id.clone(), c.email.clone(), c.name.clone(),
            "Community".into(),
        );
        dunning_store.upsert(rec);
    }

    // ── Portal users — bootstrapped from Postgres ─────────────────────────────
    portal::bootstrap_portal_users_pg(&db).await;

    let email_sender = dunning::EmailSender::from_env();
    if email_sender.is_configured() {
        eprintln!("[main] Email sender configured (SendGrid/SMTP)");
    } else {
        eprintln!("[main] Email sender NOT configured — set SENDGRID_API_KEY or CONNECTOR_SMTP_URL");
    }

    let state = Arc::new(AppState {
        store:           Mutex::new(license_store),
        signing_key,
        surveillance_db: Mutex::new(surveillance_db),
        db,
        issuances:       Mutex::new(issuances),
        token_manager:   Mutex::new(token_manager),
        dunning:         Mutex::new(dunning_store),
        email_sender,
    });

    // ── Admin UI static files ─────────────────────────────────────────────────
    let admin_dir = std::env::var("CONNECTOR_ADMIN_UI_DIR")
        .unwrap_or_else(|_| "./ui-leptos/admin/dist".into());
    let www_dir = std::env::var("CONNECTOR_WWW_DIR")
        .unwrap_or_else(|_| "./ui-leptos/www/dist".into());
    
    let admin_spa = ServeDir::new(&admin_dir)
        .fallback(ServeFile::new(format!("{}/index.html", admin_dir)));
    let portal_spa = ServeDir::new(&www_dir)
        .fallback(ServeFile::new(format!("{}/index.html", www_dir)));

    let app = Router::new()
        // ── License key management ────────────────────────────────────────────
        .route("/api/v1/keys/issue",        post(routes::issue_key))
        .route("/api/v1/keys/validate",     post(routes::validate_key))
        .route("/api/v1/keys/revoke",       post(routes::revoke_key))
        .route("/api/v1/keys/license-file", post(routes::generate_license_file))
        .route("/api/v1/keys/{key_id}",     get(routes::get_key))
        .route("/api/v1/keys",              get(routes::list_keys))
        .route("/api/v1/public-key",        get(routes::public_key))

        // ── Binary issuances (per-download unique DAO identity) ───────────────
        .route("/api/v1/issuances",           post(rpc_auth::create_issuance))
        .route("/api/v1/issuances/{binary_id}", get(rpc_auth::get_issuance))

        // ── RPC auth — binary token exchange (Vault AppRole pattern) ─────────
        .route("/rpc/v1/auth",   post(rpc_auth::rpc_auth))
        .route("/rpc/v1/renew",  post(rpc_auth::rpc_renew))
        .route("/rpc/v1/revoke", post(rpc_auth::rpc_revoke))
        .route("/rpc/v1/verify", get(rpc_auth::rpc_verify))

        // ── Legacy activation endpoints ───────────────────────────────────────
        .route("/api/v1/activate",   post(routes::activate))
        .route("/api/v1/deactivate", post(routes::deactivate))
        .route("/api/v1/heartbeat",  post(routes::heartbeat))

        // ── Usage reporting ───────────────────────────────────────────────────
        .route("/api/v1/usage/report",        post(routes::usage_report))
        .route("/api/v1/usage/{instance_id}", get(routes::usage_history))

        // ── Stripe webhooks ───────────────────────────────────────────────────
        .route("/webhooks/stripe", post(routes::stripe_webhook))

        // ── Admin auth (exempt from key middleware — IS the login endpoint) ──
        .route("/api/v1/admin/auth",      post(admin_auth::admin_login))

        // ── Admin ─────────────────────────────────────────────────────────────
        .route("/api/v1/admin/stats",     get(routes::admin_stats))
        .route("/api/v1/admin/instances", get(routes::list_instances))

        // ── Payment ───────────────────────────────────────────────────────────
        .route("/api/v1/payment/checkout",    post(payment::create_checkout))
        .route("/api/v1/payment/prices",      get(payment::list_prices))
        .route("/api/v1/payment/portal",      post(payment::customer_portal))
        .route("/api/v1/payment/revenue",     get(payment::revenue_dashboard))
        .route("/api/v1/payment/trial-config", get(payment::trial_config))
        .route("/api/v1/payment/prorate",      post(payment::calculate_proration))
        .route("/api/v1/payment/tax-config",   get(payment::tax_config))
        .route("/api/v1/payment/invoice-pdf",  post(payment::invoice_pdf))

        // ── Legacy RPC phone-home (still supported) ───────────────────────────
        .route("/rpc/v1/checkin",   post(surveillance::rpc_checkin))
        .route("/rpc/v1/heartbeat", post(surveillance::rpc_heartbeat))
        .route("/rpc/v1/usage",     post(surveillance::rpc_usage))

        // ── Surveillance admin ────────────────────────────────────────────────
        .route("/api/v1/surveillance/dashboard",  get(surveillance::dashboard))
        .route("/api/v1/surveillance/instances",  get(surveillance::list_tracked_instances))
        .route("/api/v1/surveillance/customers",  get(surveillance::list_customers))
        .route("/api/v1/surveillance/kill",       post(surveillance::kill_instance))
        .route("/api/v1/surveillance/degrade",    post(surveillance::degrade_instance))
        .route("/api/v1/surveillance/block-binary", post(surveillance::block_binary))
        .route("/api/v1/surveillance/events",     get(surveillance::event_log))

        // ── Portal auth (customer-facing website) ───────────────────────────
        .route("/api/v1/portal/register",       post(portal::register))
        .route("/api/v1/portal/login",          post(portal::login))
        .route("/api/v1/portal/me",             get(portal::me))
        .route("/api/v1/portal/totp/setup",     post(portal::totp_setup))
        .route("/api/v1/portal/totp/verify",    post(portal::totp_verify))
        .route("/api/v1/portal/api-keys",       post(portal::create_api_key))
        .route("/api/v1/portal/api-keys",       get(portal::list_api_keys))
        .route("/api/v1/portal/api-keys/{id}",  axum::routing::delete(portal::revoke_api_key))
        .route("/api/v1/portal/profile",        axum::routing::patch(portal::update_profile))
        .route("/api/v1/portal/change-password",post(portal::change_password))
        .route("/auth/token",                   post(portal::api_key_to_token))

        // ── Dunning & customer admin ──────────────────────────────────────────
        .route("/api/v1/admin/dunning",         get(portal::dunning_dashboard))
        .route("/api/v1/admin/customers/{id}/suspend", post(portal::admin_suspend))
        .route("/api/v1/admin/customers/{id}/restore", post(portal::admin_restore))
        .route("/api/v1/admin/customers/{id}/message", post(portal::admin_message))
        .route("/api/v1/admin/customers",       get(portal::admin_list_customers))

        // ── Pilot Grants (Admin) ──────────────────────────────────────────────
        .route("/api/v1/admin/pilots",          post(pilot_api::create_pilot))
        .route("/api/v1/admin/pilots",          get(pilot_api::list_pilots))
        .route("/api/v1/admin/pilots/{grant_id}", get(pilot_api::get_pilot))
        .route("/api/v1/admin/pilots/{grant_id}", axum::routing::delete(pilot_api::expire_pilot))
        .route("/api/v1/admin/pilots/{grant_id}/revoke", post(pilot_api::revoke_pilot))
        .route("/api/v1/admin/customers/{customer_id}/pilots", get(pilot_api::get_customer_pilots))

        // ── Pilot Grants (Customer Portal) ────────────────────────────────────
        .route("/api/v1/portal/pilot",          get(pilot_api::my_pilot_status))
        .route("/api/v1/portal/entitlement",    get(pilot_api::my_entitlement))

        // ── Health ────────────────────────────────────────────────────────────
        .route("/health", get(routes::health))

        .nest_service("/admin", admin_spa)
        .fallback_service(portal_spa)  // Portal at root for public access
        .layer(middleware::from_fn(admin_auth::admin_auth_middleware))
        .layer(cors::cors_layer())
        .with_state(state);

    let addr = std::env::var("CONNECTOR_LICENSE_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:4100".into());

    println!("╔══════════════════════════════════════════╗");
    println!("║  Connector License Server                ║");
    println!("╠══════════════════════════════════════════╣");
    eprintln!("connector-license-server listening on {}", addr);
    eprintln!("  Portal UI:     /           (from {})", www_dir);
    eprintln!("  Admin UI:      /admin      (from {})", admin_dir);
    eprintln!("  RPC:           /rpc/v1/*");
    eprintln!("  Portal API:    /api/v1/portal/*");
    eprintln!("  Admin API:     /api/v1/admin/*");
    eprintln!("  Payment API:   /api/v1/payment/*");
    eprintln!("  Webhooks:      /webhooks/stripe");
    println!("╚══════════════════════════════════════════╝");

    let listener = tokio::net::TcpListener::bind(&addr).await
        .unwrap_or_else(|e| panic!("Cannot bind {}: {}", addr, e));
    axum::serve(listener, app).await.unwrap();
}

pub struct AppState {
    pub store:           Mutex<store::LicenseStore>,
    pub signing_key:     keys::SigningKeys,
    pub surveillance_db: Mutex<database::SurveillanceDb>,
    /// Postgres pool — cheaply cloneable, no Mutex needed.
    pub db:              persist::Db,
    /// In-memory list of per-download binary issuances (bootstrapped from Postgres).
    pub issuances:       Mutex<Vec<rpc_token::BinaryIssuance>>,
    /// RPC token manager: issues, validates, revokes short-lived HMAC tokens.
    pub token_manager:   Mutex<rpc_token::RpcTokenManager>,
    /// Dunning / payment recovery state machine.
    pub dunning:         Mutex<dunning::DunningStore>,
    /// Email sender (SendGrid / SMTP).
    pub email_sender:    dunning::EmailSender,
}

pub type SharedState = Arc<AppState>;

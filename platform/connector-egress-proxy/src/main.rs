//! Connector egress proxy — T2 TLS terminate at the Connector hop.
//!
//! Clients redirected by eBPF/nft land here. The proxy:
//! 1. Requires an HMAC channel ticket (`X-Connector-Egress-Ticket`).
//! 2. Terminates HTTPS CONNECT under a Connector CA leaf (MITM at Connector hop).
//! 3. Re-dials upstream with rustls and splices plaintext.
//!
//! Intentional Connector-hop TLS terminate — not unauthenticated public MITM.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hmac::{Hmac, Mac};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::ServerConfig;
use sha2::Sha256;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(name = "connector-egress-proxy")]
struct Cli {
    #[arg(long, env = "CONNECTOR_EGRESS_PROXY_LISTEN", default_value = "127.0.0.1:19090")]
    listen: SocketAddr,
    #[arg(long, env = "CONNECTOR_EGRESS_CHANNEL_HMAC_KEY")]
    hmac_key: Option<String>,
    #[arg(long, env = "CONNECTOR_EGRESS_TLS_TERMINATE", default_value_t = true)]
    tls_terminate: bool,
    #[arg(long, env = "CONNECTOR_EGRESS_CERT_DIR", default_value = "./data/egress-proxy-certs")]
    cert_dir: PathBuf,
}

struct CaBundle {
    cert: Certificate,
    key: KeyPair,
}

fn channel_secret(cli: &Cli) -> Vec<u8> {
    if let Some(ref s) = cli.hmac_key {
        if !s.trim().is_empty() {
            return s.as_bytes().to_vec();
        }
    }
    if let Ok(s) = std::env::var("CONNECTOR_AUDIT_HMAC_KEY") {
        if !s.trim().is_empty() {
            return s.into_bytes();
        }
    }
    b"connector-egress-channel-lab-fallback".to_vec()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn verify_ticket(secret: &[u8], ticket: &str) -> Result<(String, String, u16)> {
    let parts: Vec<&str> = ticket.trim().split('|').collect();
    if parts.len() != 6 || parts[0] != "cegress.v1" {
        return Err(anyhow!("ticket_malformed"));
    }
    let agent = parts[1].to_string();
    let host = parts[2].to_string();
    let port: u16 = parts[3].parse().context("ticket_port")?;
    let exp: u64 = parts[4].parse().context("ticket_exp")?;
    if now_secs() > exp {
        return Err(anyhow!("ticket_expired"));
    }
    let payload = format!("cegress.v1|{agent}|{host}|{port}|{exp}");
    let mut mac = HmacSha256::new_from_slice(secret).context("hmac")?;
    mac.update(payload.as_bytes());
    let expect = hex::encode(mac.finalize().into_bytes());
    if parts[5] != expect {
        return Err(anyhow!("ticket_sig"));
    }
    Ok((agent, host, port))
}

fn ensure_ca(cli: &Cli) -> Result<CaBundle> {
    fs::create_dir_all(&cli.cert_dir)?;
    let ca_cert_path = cli.cert_dir.join("ca.pem");
    let ca_key_path = cli.cert_dir.join("ca.key.pem");

    let mut params = CertificateParams::new(vec!["Connector Egress CA".into()])?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = if ca_key_path.is_file() {
        KeyPair::from_pem(&fs::read_to_string(&ca_key_path)?)?
    } else {
        let key = KeyPair::generate()?;
        fs::write(&ca_key_path, key.serialize_pem())?;
        key
    };
    let cert = params.self_signed(&key)?;
    if !ca_cert_path.is_file() {
        fs::write(&ca_cert_path, cert.pem())?;
        tracing::info!(path = %ca_cert_path.display(), "generated Connector egress CA");
    }
    Ok(CaBundle { cert, key })
}

fn leaf_server_config(ca: &CaBundle, host: &str) -> Result<Arc<ServerConfig>> {
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, host);
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca.cert, &ca.key)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

async fn read_http_head(
    stream: &mut TcpStream,
) -> Result<(String, Vec<(String, String)>)> {
    let mut reader = TokioBufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Ok((request_line, headers))
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn parse_host_port(target: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = target.rsplit_once(':') {
        Ok((
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            p.parse()?,
        ))
    } else {
        Ok((target.to_string(), 443))
    }
}

async fn dial_upstream_tls(
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut root = rustls::RootCertStore::empty();
    root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect((host, port)).await?;
    let name = ServerName::try_from(host.to_string()).context("sni")?;
    Ok(connector.connect(name, tcp).await?)
}

async fn handle_client(
    mut stream: TcpStream,
    secret: Arc<Vec<u8>>,
    ca: Arc<CaBundle>,
    tls_terminate: bool,
) -> Result<()> {
    let peer = stream.peer_addr().ok();
    let (req, headers) = read_http_head(&mut stream).await?;
    let parts: Vec<&str> = req.split_whitespace().collect();
    if parts.len() < 2 {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    }
    let method = parts[0];
    let target = parts[1];

    let ticket = header_get(&headers, "x-connector-egress-ticket")
        .or_else(|| {
            header_get(&headers, "proxy-authorization").and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
            })
        })
        .ok_or_else(|| anyhow!("missing_egress_ticket"))?;
    let (agent, ticket_host, ticket_port) = verify_ticket(&secret, ticket)?;

    if method != "CONNECT" {
        stream
            .write_all(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
            .await?;
        return Ok(());
    }

    let (host, port) = parse_host_port(target)?;
    if host != ticket_host || port != ticket_port {
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await?;
        return Err(anyhow!("ticket_target_mismatch"));
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    if tls_terminate && port == 443 {
        let cfg = leaf_server_config(&ca, &host)?;
        let acceptor = TlsAcceptor::from(cfg);
        let client_tls = acceptor.accept(stream).await.context("client tls")?;
        let upstream = dial_upstream_tls(&host, port).await?;
        let (mut ur, mut uw) = tokio::io::split(upstream);
        let (mut cr, mut cw) = tokio::io::split(client_tls);
        let a = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut uw).await;
        });
        let b = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut ur, &mut cw).await;
        });
        let _ = tokio::join!(a, b);
        tracing::info!(%agent, %host, port, ?peer, "tls_terminate_connect");
        return Ok(());
    }

    let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
    let (mut ur, mut uw) = upstream.split();
    let (mut cr, mut cw) = stream.split();
    tokio::try_join!(tokio::io::copy(&mut cr, &mut uw), tokio::io::copy(&mut ur, &mut cw))?;
    tracing::info!(%agent, %host, port, ?peer, "tcp_connect_splice");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let ca = Arc::new(ensure_ca(&cli)?);
    let secret = Arc::new(channel_secret(&cli));
    // Materialize a sample leaf for operators installing the CA in trust stores.
    let _ = leaf_server_config(&ca, "proxy.connector.local");
    let listener = TcpListener::bind(cli.listen).await?;
    tracing::info!(
        listen = %cli.listen,
        tls_terminate = cli.tls_terminate,
        ca = %cli.cert_dir.join("ca.pem").display(),
        "connector-egress-proxy listening (ticket required; TLS terminate at Connector hop)"
    );

    loop {
        let (sock, _) = listener.accept().await?;
        let secret = secret.clone();
        let ca = ca.clone();
        let tls_terminate = cli.tls_terminate;
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, secret, ca, tls_terminate).await {
                tracing::warn!("client: {e:#}");
            }
        });
    }
}

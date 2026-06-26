//! MPV MITM Proxy - HTTP/HTTPS proxy with connection pooling and TLS interception.
//!
//! A high-performance async HTTP proxy built with Tokio and Hyper.
//! Supports upstream proxy chaining (HTTP CONNECT and SOCKS5), connection pooling,
//! and dynamic TLS certificate generation for HTTPS interception.

mod certificate;
mod connect;
mod forward;
mod pool;
mod proxy;
mod range;
mod resume;
mod tls;
mod tunnel;
mod types;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

use crate::certificate::CertificateAuthority;
use crate::proxy::{handle_client, ProxyConfig};

macro_rules! arg_parse {
    ($args:expr, $flag:literal, $default:expr) => {
        $args.iter()
            .position(|a| a == $flag)
            .and_then(|i| $args.get(i + 1))
            .and_then(|p| p.parse().ok())
            .unwrap_or($default)
    };
}

fn init_tracing(verbose: bool) {
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_env("RUST_LOG")
    } else if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}

/// Write an error to the status file (if configured) so the Lua script can detect startup failures.
fn write_error_status(status_file: &Option<String>, msg: &str) {
    if let Some(path) = status_file {
        let _ = std::fs::write(path, format!("ERROR:{}\n", msg));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    info!("Parsing CLI arguments");

    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");

    if args.iter().any(|a| a == "init") {
        init_tracing(verbose);
        println!("INIT_OK");
        info!("INIT_OK");
        return Ok(());
    }

    init_tracing(verbose);

    // Parse status-file early so we can write errors to it if startup fails
    let status_file = args
        .iter()
        .position(|a| a == "--status-file")
        .and_then(|i| args.get(i + 1).cloned());

    info!("Installing TLS crypto provider");
    if let Err(_e) = rustls::crypto::ring::default_provider().install_default() {
        let msg = "Failed to install rustls crypto provider: provider already initialized";
        error!("{}", msg);
        write_error_status(&status_file, msg);
        return Err(msg.into());
    }

    let listen_port: u16 = arg_parse!(args, "--port", 12500);
    let auto_port = args.iter().any(|a| a == "--auto-port");
    let max_retries: u16 = arg_parse!(args, "--max-retries", 100);

    let upstream_proxy = args
        .iter()
        .position(|a| a == "--upstream")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| std::env::var("UPSTREAM_PROXY").ok())
        .filter(|s| !s.is_empty());

    // (status_file already parsed above)

    let direct_cdn = args.iter().any(|a| a == "--direct-cdn");
    let bypass_chunk_modification = args.iter().any(|a| a == "--bypass-chunk-modification");
    let disable_pooling = args.iter().any(|a| a == "--disable-pooling");
    let verify_tls = args.iter().any(|a| a == "--verify-tls");

    let proxy_auth_user = args
        .iter()
        .position(|a| a == "--proxy-auth-user")
        .and_then(|i| args.get(i + 1).cloned());
    let proxy_auth_pass = args
        .iter()
        .position(|a| a == "--proxy-auth-pass")
        .and_then(|i| args.get(i + 1).cloned());

    info!("Creating certificate authority");
    let ca = match CertificateAuthority::new() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            let msg = format!("Failed to create certificate authority: {}", e);
            error!("{}", msg);
            write_error_status(&status_file, &msg);
            return Err(e.into());
        }
    };

    if let Some(ref proxy) = upstream_proxy {
        info!("Creating proxy config with upstream proxy: {}", proxy);
    } else {
        info!("Creating proxy config (no upstream proxy)");
    }
    let config = ProxyConfig::new(upstream_proxy, ca, direct_cdn, bypass_chunk_modification, disable_pooling, verify_tls, proxy_auth_user, proxy_auth_pass);

    info!("Starting background tasks (pool cleanup)");
    let _cleanup_handle = config.start();

    let mut port = listen_port;
    let mut listener = None;
    let mut last_error: Option<String> = None;

    for attempt in 0..max_retries {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        debug!("Attempting to bind to port {} (attempt {}/{})", port, attempt + 1, max_retries);
        match TcpListener::bind(addr).await {
            Ok(l) => {
                info!("Successfully bound to port {}", port);
                listener = Some(l);
                break;
            }
            Err(e) => {
                let err_str = e.to_string();
                debug!("Failed to bind to port {}: {}", port, e);
                last_error = Some(err_str);
                if auto_port {
                    let next = port.saturating_add(1);
                    if next == 0 || next <= port {
                        error!("Port overflow at {}, cannot auto-increment further", port);
                        break;
                    }
                    port = next;
                    continue;
                }
                error!("Failed to bind to port {}: {}", port, e);
                let msg = format!("Failed to bind to port {}: {}", port, e);
                write_error_status(&status_file, &msg);
                return Err(msg.into());
            }
        }
    }

    let listener = match listener {
        Some(l) => l,
        None => {
            let msg = format!("Failed to bind to any port after {} attempts: {}", max_retries, last_error.unwrap_or_else(|| "unknown error".to_string()));
            error!("{}", msg);
            write_error_status(&status_file, &msg);
            return Err(msg.into());
        }
    };

    if let Some(ref path) = status_file {
        info!("Writing status file: {}", path);
        if let Err(e) = std::fs::write(path, format!("READY:{}\n", port)) {
            let msg = format!("Failed to write status file {}: {}", path, e);
            error!("{}", msg);
            write_error_status(&status_file, &msg);
            return Err(msg.into());
        }
    }
    println!("READY:{}", port);
    info!("Proxy ready on port {}", port);

    info!("Entering accept loop");
    loop {
        tokio::select! {
            Ok((stream, _)) = listener.accept() => {
                debug!("Accepted connection");
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let _ = handle_client(stream, config).await;
                });
            }
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    if let Some(ref path) = status_file {
        let _ = std::fs::remove_file(path);
    }

    info!("Proxy shutdown complete");
    Ok(())
}

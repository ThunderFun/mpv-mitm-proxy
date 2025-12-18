mod certificate;
mod proxy;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;

use crate::certificate::CertificateAuthority;
use crate::proxy::ProxyConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the ring crypto provider for rustls BEFORE any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");


    let args: Vec<String> = std::env::args().collect();

    let listen_port: u16 = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(12500);

    let upstream_proxy = args
        .iter()
        .position(|a| a == "--upstream")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| std::env::var("UPSTREAM_PROXY").ok())
        .filter(|s| !s.is_empty());


    let ca = Arc::new(CertificateAuthority::new()?);
    let config = Arc::new(ProxyConfig::new(upstream_proxy, ca));

    let addr = SocketAddr::from(([127, 0, 0, 1], listen_port));
    let listener = TcpListener::bind(addr).await?;

    println!("READY:{}", listen_port);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, client_addr)) => {
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            let _ = proxy::handle_client(stream, client_addr, config).await;
                        });
                    }
                    Err(_) => {}
                }
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}

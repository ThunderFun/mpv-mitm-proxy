//! HTTP CONNECT tunneling module.
//!
//! Provides support for HTTP CONNECT method used to establish TLS tunnels
//! through the proxy, enabling HTTPS traffic interception and forwarding.

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use url::Url;

use crate::pool::{empty_body, ProxyBody, ProxyResult};
use crate::proxy::{handle_proxy_error, ConnectionTarget, ProxyConfig, ProxyError};
use crate::forward::forward_request;

/// Handles HTTP CONNECT requests to establish a TLS tunnel.
pub async fn handle_connect(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> ProxyResult<Response<ProxyBody>> {
    let (host, port) = extract_host_port(req.uri())?;

    let host_clone = host.clone();
    let upgrade_fut = hyper::upgrade::on(req);

    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade_fut.await {
            let upgraded_io = TokioIo::new(upgraded);
            if let Err(_e) = handle_tunnel(upgraded_io, &host_clone, port, config).await {
                eprintln!("Tunnel error for {}:{}", host_clone, port);
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("valid response"))
}

/// Extracts host and port from a URI.
///
/// Parses the authority component of a URI to extract the hostname
/// and port number. Defaults to port 443 if not specified.
///
/// # Arguments
/// * `uri` - The URI to parse
///
/// # Returns
/// A tuple of (host, port) on success
#[inline]
pub fn extract_host_port(uri: &http::Uri) -> ProxyResult<(String, u16)> {
    let auth = uri.authority().ok_or_else(|| {
        ProxyError::InvalidUri(Cow::Owned(format!("Missing authority in URI: {}", uri)))
    })?;
    let url = Url::parse(&format!("https://{}", auth.as_str()))
        .map_err(|e| ProxyError::InvalidUri(Cow::Owned(e.to_string())))?;
    Ok((
        url.host_str().unwrap_or("").to_string(),
        url.port().unwrap_or(443),
    ))
}

/// Handles the upgraded TLS tunnel connection.
///
/// After a successful HTTP CONNECT, performs TLS handshake
/// and serves HTTP requests over the encrypted tunnel.
pub async fn handle_tunnel<I>(
    upgraded: I,
    host: &str,
    port: u16,
    config: Arc<ProxyConfig>,
) -> ProxyResult<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls_config = config
        .ca
        .get_server_config(host)
        .map_err(|e| ProxyError::Certificate(e.to_string()))?;

    let acceptor = TlsAcceptor::from(tls_config);
    let client_tls = acceptor.accept(upgraded).await?;
    let client_io = TokioIo::new(client_tls);
    let host_owned = host.to_string();

    let service = service_fn(move |req: Request<Incoming>| {
        let config = Arc::clone(&config);
        let target = ConnectionTarget {
            host: host_owned.clone(),
            port,
            is_tls: true,
        };
        async move {
            match forward_request(req, &target, config).await {
                Ok(resp) => Ok::<_, hyper::Error>(resp),
                Err(e) => Ok(handle_proxy_error(&e, true)),
            }
        }
    });

    let _ = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(client_io, service)
        .await;

    Ok(())
}

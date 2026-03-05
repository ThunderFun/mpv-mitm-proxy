use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use url::Url;

use crate::certificate::CertificateAuthority;
use crate::pool::{ConnectionPool, ProxyBody, ProxyResult};
use crate::tls::{root_certs, NoVerifier};

pub use crate::forward::handle_http;
pub use crate::tunnel::handle_connect;
pub use crate::pool::error_response;

#[inline]
pub fn configure_http1_builder(
    client: &mut hyper::client::conn::http1::Builder,
    server: &mut hyper::server::conn::http1::Builder,
) {
    client.preserve_header_case(true).title_case_headers(true);
    server.preserve_header_case(true).title_case_headers(true);
}

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),
    #[error("Invalid URI: {0}")]
    InvalidUri(Cow<'static, str>),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Certificate error: {0}")]
    Certificate(String),
    #[error("SOCKS error: {0}")]
    Socks(#[from] tokio_socks::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

#[derive(Clone, Copy, PartialEq)]
pub enum ProxyType {
    Socks5,
    Http,
}

pub struct ProxyConfig {
    pub upstream_proxy: Option<UpstreamProxy>,
    pub ca: Arc<CertificateAuthority>,
    tls_client_config: Arc<rustls::ClientConfig>,
    pub connection_pool: Arc<ConnectionPool>,
    client_http1_builder: hyper::client::conn::http1::Builder,
    server_http1_builder: hyper::server::conn::http1::Builder,
    pub direct_cdn: bool,
    pub bypass_chunk_modification: bool,
    pub disable_pooling: bool,
    _verify_tls: bool,
}

/// Upstream proxy configuration.
pub struct UpstreamProxy {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Target connection specification for proxy connections.
#[derive(Clone, Debug)]
pub struct ConnectionTarget {
    /// Target hostname or IP address
    pub host: String,
    /// Target port (e.g., 80 for HTTP, 443 for HTTPS)
    pub port: u16,
    /// Whether to use TLS encryption
    pub is_tls: bool,
}

impl ConnectionTarget {
    /// Returns the default port for the connection type
    pub fn default_port(&self) -> u16 {
        if self.is_tls { 443 } else { 80 }
    }
}

impl ProxyConfig {
    pub fn new(
        upstream_url: Option<String>,
        ca: Arc<CertificateAuthority>,
        direct_cdn: bool,
        bypass_chunk_modification: bool,
        disable_pooling: bool,
        verify_tls: bool,
    ) -> Arc<Self> {
        let upstream_proxy = upstream_url.and_then(|url_str| {
            let url = Url::parse(&url_str).ok()?;
            let scheme = url.scheme();
            let proxy_type = match scheme {
                "socks5" | "socks5h" => ProxyType::Socks5,
                "http" | "https" => ProxyType::Http,
                _ => return None,
            };
            let host = url.host_str()?.to_string();
            let port = url.port().unwrap_or(match proxy_type {
                ProxyType::Socks5 => 1080,
                ProxyType::Http => 8080,
            });
            let username = (!url.username().is_empty()).then(|| url.username().to_string());
            let password = url.password().map(ToString::to_string);

            Some(UpstreamProxy {
                proxy_type,
                host,
                port,
                username,
                password,
            })
        });

        let tls_client_config = if verify_tls {
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_certs())
                    .with_no_client_auth(),
            )
        } else {
            Arc::new(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth(),
            )
        };

        let connection_pool = Arc::new(ConnectionPool::new());

        let mut client_http1_builder = hyper::client::conn::http1::Builder::new();
        let mut server_http1_builder = hyper::server::conn::http1::Builder::new();
        configure_http1_builder(&mut client_http1_builder, &mut server_http1_builder);

        Arc::new(Self {
            upstream_proxy,
            ca,
            tls_client_config,
            connection_pool,
            client_http1_builder,
            server_http1_builder,
            direct_cdn,
            bypass_chunk_modification,
            disable_pooling,
            _verify_tls: verify_tls,
        })
    }

    /// Starts background tasks for this proxy configuration.
    /// Returns a JoinHandle for the pool cleanup task (if pooling is enabled).
    /// This should be called after creating the ProxyConfig to explicitly start background work.
    pub fn start(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        if self.disable_pooling {
            return None;
        }

        let pool_clone = Arc::clone(&self.connection_pool);
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                pool_clone.cleanup();
            }
        }))
    }

    #[inline]
    pub async fn connect(self: &Arc<Self>, host: &str, port: u16) -> ProxyResult<tokio::net::TcpStream> {
        use crate::connect::connect_via_proxy;

        let connect_fut = connect_via_proxy(self, host, port);

        match tokio::time::timeout(Duration::from_secs(10), connect_fut).await {
            Ok(res) => res,
            Err(_) => Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Connection to {}:{} timed out after 10s", host, port),
            ))),
        }
    }

    #[inline]
    async fn handshake_upstream<IO>(
        &self,
        io: IO,
    ) -> ProxyResult<(hyper::client::conn::http1::SendRequest<Incoming>, tokio::task::AbortHandle)>
    where
        IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        match self.client_http1_builder.handshake(io).await {
            Ok((sender, conn)) => {
                let handle = tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok((sender, handle.abort_handle()))
            }
            Err(e) => Err(ProxyError::Hyper(e)),
        }
    }

    pub async fn get_or_create_connection(
        self: &Arc<Self>,
        target: &ConnectionTarget,
    ) -> ProxyResult<(hyper::client::conn::http1::SendRequest<Incoming>, tokio::task::AbortHandle)> {
        // Try to reuse connection from pool only if pooling is enabled
        if !self.disable_pooling {
            while let Some((mut sender, abort_handle)) = self.connection_pool.get(&target.host, target.port, target.is_tls) {
                match sender.ready().await {
                    Ok(_) => return Ok((sender, abort_handle)),
                    Err(_) => {
                        abort_handle.abort();
                        continue;
                    }
                }
            }
        }

        let upstream_tcp = self.connect(&target.host, target.port).await?;

        if target.is_tls {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_client_config));
            let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| ProxyError::InvalidUri(Cow::Borrowed("Invalid server name")))?;
            let upstream_tls = connector.connect(server_name, upstream_tcp).await?;
            let upstream_io = TokioIo::new(upstream_tls);
            self.handshake_upstream(upstream_io).await
        } else {
            let upstream_io = TokioIo::new(upstream_tcp);
            self.handshake_upstream(upstream_io).await
        }
    }
}

// Consolidated error response handler
#[inline]
pub fn handle_proxy_error(e: &ProxyError, is_connect: bool) -> http::Response<ProxyBody> {
    let (status, msg) = match e {
        ProxyError::InvalidUri(_) => (StatusCode::BAD_REQUEST, "Invalid URI"),
        ProxyError::Io(_) | ProxyError::Socks(_) | ProxyError::Tls(_) => {
            (StatusCode::BAD_GATEWAY, "Upstream Error")
        }
        _ if is_connect => (StatusCode::BAD_GATEWAY, "Upstream Error"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error"),
    };
    error_response(status, msg)
}

pub async fn handle_client(
    stream: TcpStream,
    config: Arc<ProxyConfig>,
) -> ProxyResult<()> {
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let config_clone = Arc::clone(&config);
    let service = service_fn(move |req: Request<Incoming>| {
        let config = Arc::clone(&config_clone);
        let is_connect = req.method() == Method::CONNECT;
        async move {
            let result = if is_connect {
                handle_connect(req, config).await
            } else {
                handle_http(req, config).await
            };

            match result {
                Ok(resp) => Ok::<_, hyper::Error>(resp),
                Err(e) => Ok(handle_proxy_error(&e, is_connect)),
            }
        }
    });

    let _ = config
        .server_http1_builder
        .serve_connection(io, service)
        .with_upgrades()
        .await;

    Ok(())
}

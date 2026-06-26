use base64::Engine;
use http::{header::PROXY_AUTHORIZATION, header::PROXY_AUTHENTICATE, Method, Request, StatusCode};
use std::borrow::Cow;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, info};
use url::Url;

use crate::certificate::CertificateAuthority;
use crate::connect::connect_via_proxy;
use crate::forward::ConnectionProvider;
use crate::pool::{ConnectionPool, handle_proxy_error, error_response, ProxyBody};
use crate::tls::{root_certs, NoVerifier};

// Public API types - imported by consumers
pub use crate::types::{ConnectionConfig, ConnectionTarget, ProxyError, ProxyResult, ProxyType, UpstreamProxy};

// Internal handlers - not publicly re-exported
use crate::forward::handle_http;
use crate::tunnel::handle_connect;

#[inline]
pub fn configure_http1_builder(
    client: &mut hyper::client::conn::http1::Builder,
    server: &mut hyper::server::conn::http1::Builder,
) {
    client.preserve_header_case(true).title_case_headers(true);
    server.preserve_header_case(true).title_case_headers(true);
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
    /// Whether TLS certificate verification is enabled.
    /// Kept for potential future features like debug logging, CLI inspection,
    /// or runtime configuration changes.
    pub verify_tls: bool,
    /// Optional proxy authentication credentials.
    /// When set, every incoming request must include a valid Proxy-Authorization header.
    pub proxy_auth_user: Option<String>,
    pub proxy_auth_pass: Option<String>,
}

impl ConnectionProvider for ProxyConfig {
    async fn get_or_create_connection(
        &self,
        target: &ConnectionTarget,
    ) -> ProxyResult<(hyper::client::conn::http1::SendRequest<ProxyBody>, tokio::task::AbortHandle)> {
        if !self.disable_pooling {
            while let Some((mut sender, abort_handle)) = self.connection_pool.get(&target.host, target.port, target.is_tls) {
                match sender.ready().await {
                    Ok(_) => {
                        debug!("pool hit for {}:{}:{}", target.host, target.port, if target.is_tls { "tls" } else { "plain" });
                        return Ok((sender, abort_handle));
                    }
                    Err(_) => {
                        debug!("pool connection stale for {}:{}, discarding", target.host, target.port);
                        abort_handle.abort();
                        continue;
                    }
                }
            }
            debug!("pool miss for {}:{}:{}", target.host, target.port, if target.is_tls { "tls" } else { "plain" });
        }

        debug!("establishing new connection to {}:{}:{}", target.host, target.port, if target.is_tls { "tls" } else { "plain" });
        let conn_config = self.connection_config();
        let connect_fut = connect_via_proxy(&conn_config, &target.host, target.port);

        let upstream_tcp = match tokio::time::timeout(Duration::from_secs(10), connect_fut).await {
            Ok(res) => res?,
            Err(_) => return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Connection to {}:{} timed out after 10s", target.host, target.port),
            ))),
        };

        if target.is_tls {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_client_config));
            let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| ProxyError::InvalidUri(Cow::Borrowed("Invalid server name")))?;
            let upstream_tls = connector.connect(server_name, upstream_tcp).await?;
            debug!("TLS handshake completed with {}:{}", target.host, target.port);
            let upstream_io = TokioIo::new(upstream_tls);
            match self.client_http1_builder.handshake(upstream_io).await {
                Ok((sender, conn)) => {
                    let handle = tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    Ok((sender, handle.abort_handle()))
                }
                Err(e) => Err(ProxyError::Hyper(e)),
            }
        } else {
            let upstream_io = TokioIo::new(upstream_tcp);
            match self.client_http1_builder.handshake(upstream_io).await {
                Ok((sender, conn)) => {
                    let handle = tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    Ok((sender, handle.abort_handle()))
                }
                Err(e) => Err(ProxyError::Hyper(e)),
            }
        }
    }

    fn connection_pool(&self) -> Arc<ConnectionPool> {
        Arc::clone(&self.connection_pool)
    }

    fn bypass_chunk_modification(&self) -> bool {
        self.bypass_chunk_modification
    }

    fn disable_pooling(&self) -> bool {
        self.disable_pooling
    }

    fn ca(&self) -> Arc<crate::certificate::CertificateAuthority> {
        Arc::clone(&self.ca)
    }
}

impl ProxyConfig {
    /// Returns the connection configuration for this proxy.
    pub fn connection_config(&self) -> ConnectionConfig {
        ConnectionConfig {
            upstream_proxy: self.upstream_proxy.clone(),
            direct_cdn: self.direct_cdn,
            bypass_chunk_modification: self.bypass_chunk_modification,
            disable_pooling: self.disable_pooling,
            verify_tls: self.verify_tls,
        }
    }

    pub fn new(
        upstream_url: Option<String>,
        ca: Arc<CertificateAuthority>,
        direct_cdn: bool,
        bypass_chunk_modification: bool,
        disable_pooling: bool,
        verify_tls: bool,
        proxy_auth_user: Option<String>,
        proxy_auth_pass: Option<String>,
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
            info!("TLS verification mode: full verification");
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_certs())
                    .with_no_client_auth(),
            )
        } else {
            info!("TLS verification mode: NoVerifier (certificate verification disabled)");
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

        if let Some(ref proxy) = upstream_proxy {
            if proxy.username.is_some() {
                info!("ProxyConfig created with upstream proxy {}://****:****@{}:{}", match proxy.proxy_type { ProxyType::Socks5 => "socks5", ProxyType::Http => "http" }, proxy.host, proxy.port);
            } else {
                info!("ProxyConfig created with upstream proxy {}://{}:{}", match proxy.proxy_type { ProxyType::Socks5 => "socks5", ProxyType::Http => "http" }, proxy.host, proxy.port);
            }
        } else {
            info!("ProxyConfig created without upstream proxy");
        }

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
            verify_tls,
            proxy_auth_user,
            proxy_auth_pass,
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
        info!("starting connection pool cleanup task (interval: 30s)");
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                pool_clone.cleanup();
            }
        }))
    }
}

/// Check proxy authentication credentials from the Proxy-Authorization header.
fn check_proxy_auth(
    req: &Request<Incoming>,
    expected_user: &Option<String>,
    expected_pass: &Option<String>,
) -> bool {
    if expected_user.is_none() && expected_pass.is_none() {
        return true;
    }
    let Some(expected_user) = expected_user else { return false };
    let Some(expected_pass) = expected_pass else { return false };

    let auth_header = match req.headers().get(PROXY_AUTHORIZATION) {
        Some(h) => h,
        None => return false,
    };
    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let Some(space_pos) = auth_str.find(' ') else {
        return false;
    };
    if auth_str[..space_pos].to_ascii_lowercase() != "basic" {
        return false;
    }
    let credentials = &auth_str[space_pos + 1..];
    let decoded = match base64::engine::general_purpose::STANDARD.decode(credentials) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    let mut parts = decoded.splitn(2, ':');
    let user = parts.next().unwrap_or("");
    let pass = parts.next().unwrap_or("");

    user == expected_user && pass == expected_pass
}

pub async fn handle_client(
    stream: TcpStream,
    config: Arc<ProxyConfig>,
) -> ProxyResult<()> {
    let peer_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string());
    debug!("handle_client() called from {}", peer_addr);
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let config_clone = Arc::clone(&config);
    let service = service_fn(move |req: Request<Incoming>| {
        let config = Arc::clone(&config_clone);
        let is_connect = req.method() == Method::CONNECT;
        let peer_addr_value = peer_addr.clone();
        async move {
            // Enforce proxy authentication if configured
            if !check_proxy_auth(&req, &config.proxy_auth_user, &config.proxy_auth_pass) {
                info!("Proxy authentication failed from {}", peer_addr_value);
                let mut resp = error_response(
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    "Proxy Authentication Required",
                );
                resp.headers_mut().insert(PROXY_AUTHENTICATE, http::HeaderValue::from_static("Basic realm=\"proxy\""));
                return Ok::<_, hyper::Error>(resp);
            }

            let result = if is_connect {
                info!("dispatching handle_connect for {}:{}", req.uri().host().unwrap_or_default(), req.uri().port_u16().unwrap_or(443));
                handle_connect(req, config).await
            } else {
                debug!("dispatching handle_http {} {}", req.method(), req.uri());
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

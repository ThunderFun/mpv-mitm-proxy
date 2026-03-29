//! Common types shared across modules.
//!
//! This module contains types that need to be accessed by multiple modules
//! without creating circular dependencies.

use std::borrow::Cow;
use thiserror::Error;

/// Standard result type used throughout the proxy.
pub type ProxyResult<T> = Result<T, ProxyError>;

/// Errors that can occur in the proxy.
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
    Certificate(#[from] crate::certificate::CertError),
    #[error("SOCKS error: {0}")]
    Socks(#[from] tokio_socks::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
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

/// Type of upstream proxy.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ProxyType {
    Socks5,
    Http,
}

/// Upstream proxy configuration.
#[derive(Clone, Debug)]
pub struct UpstreamProxy {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Configuration for connection behavior.
/// This is a lightweight config struct that avoids circular dependencies
/// by not referencing pool or certificate types directly.
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub upstream_proxy: Option<UpstreamProxy>,
    pub direct_cdn: bool,
    /// Stored for potential future features like debug logging or CLI inspection.
    #[allow(dead_code)]
    pub bypass_chunk_modification: bool,
    /// Stored for potential future features like debug logging or CLI inspection.
    #[allow(dead_code)]
    pub disable_pooling: bool,
    /// Stored for potential future features like debug logging or CLI inspection.
    #[allow(dead_code)]
    pub verify_tls: bool,
}

impl ConnectionConfig {
    /// Returns the default port for a proxy type.
    #[allow(dead_code)]
    pub fn default_port(proxy_type: ProxyType) -> u16 {
        match proxy_type {
            ProxyType::Socks5 => 1080,
            ProxyType::Http => 8080,
        }
    }
}

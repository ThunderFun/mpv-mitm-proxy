//! Connection establishment module.
//!
//! Provides functions for establishing TCP connections to target hosts,
//! with support for direct connections, HTTP CONNECT proxies, and SOCKS5 proxies.
//!
//! Features:
//! - Automatic retry with exponential backoff for transient failures
//! - TCP keepalive for detecting dead/stale connections
//! - Support for HTTP CONNECT and SOCKS5 upstream proxies

use std::fmt::Write;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use tracing::{debug, warn};

use crate::types::{ConnectionConfig, ProxyError, ProxyType, UpstreamProxy};

const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF_BASE_MS: u64 = 250;
#[allow(dead_code)]
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Establishes a connection to the target host via an upstream proxy if configured.
/// Returns a TcpStream ready for use.
///
/// Automatically retries on transient failures (up to MAX_RETRIES times) with
/// exponential backoff to handle unreliable upstream proxies gracefully.
pub async fn connect_via_proxy(
    config: &ConnectionConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    let use_direct = config.direct_cdn && host.ends_with("googlevideo.com");

    match &config.upstream_proxy {
        Some(proxy) if !use_direct => {
            match proxy.proxy_type {
                ProxyType::Socks5 => {
                    debug!(method = "socks5", host, port, "connect_via_proxy called");
                    connect_via_socks5(proxy, host, port).await
                }
                ProxyType::Http => {
                    debug!(method = "http", host, port, "connect_via_proxy called");
                    connect_via_http_proxy_with_retry(proxy, host, port).await
                }
            }
        }
        _ => {
            debug!(method = "direct", host, port, "connect_via_proxy called");
            connect_direct_with_retry(host, port).await
        }
    }
}

/// Sets TCP keepalive options on a TcpStream.
///
/// Uses socket2 to enable keepalive with a 15-second idle timeout and
/// 3-second interval between probes. This helps detect dead connections
/// early, preventing mid-stream failures on unreliable proxies.
#[cfg(unix)]
fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    let fd = stream.as_raw_fd();
    let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(3));
    let result = sock.set_tcp_keepalive(&ka);
    let _ = sock.into_raw_fd(); // Prevent close
    result
}

#[cfg(windows)]
fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};
    let raw_socket = stream.as_raw_socket();
    let sock = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(3));
    let result = sock.set_tcp_keepalive(&ka);
    let _ = sock.into_raw_socket(); // Prevent close
    result
}

/// Computes the exponential backoff delay for a given retry attempt.
#[inline]
fn retry_backoff_ms(attempt: u32) -> u64 {
    RETRY_BACKOFF_BASE_MS.saturating_mul(2_u64.saturating_pow(attempt))
}

/// Connects directly to the target host with automatic retry on failure.
async fn connect_direct_with_retry(host: &str, port: u16) -> Result<TcpStream, ProxyError> {
    let mut last_error = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = retry_backoff_ms(attempt);
            debug!(host, port, attempt = attempt + 1, max = MAX_RETRIES, delay_ms = delay, "Retrying direct connection after backoff");
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        match connect_direct_once(host, port).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = Some(e);
                warn!(host, port, attempt = attempt + 1, max = MAX_RETRIES, error = %last_error.as_ref().unwrap(), "Direct connection attempt failed");
            }
        }
    }

    warn!(host, port, max = MAX_RETRIES, "All direct connection attempts exhausted");
    Err(last_error.unwrap())
}

/// Connects directly to the target host (single attempt, no retry).
async fn connect_direct_once(host: &str, port: u16) -> Result<TcpStream, ProxyError> {
    debug!(host, port, "Connecting directly");
    let stream = match TcpStream::connect(format!("{}:{}", host, port)).await {
        Ok(s) => {
            debug!(host, port, "Direct TCP connection established");
            s
        }
        Err(e) => {
            warn!(host, port, error = %e, "Direct connection failed");
            return Err(e.into());
        }
    };
    let _ = stream.set_nodelay(true);
    if let Err(e) = set_keepalive(&stream) {
        debug!(host, port, error = %e, "Failed to set TCP keepalive");
    }
    Ok(stream)
}

/// Connects via SOCKS5 proxy with automatic retry on failure.
async fn connect_via_socks5(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    let mut last_error = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = retry_backoff_ms(attempt);
            debug!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, attempt = attempt + 1, max = MAX_RETRIES, delay_ms = delay, "Retrying SOCKS5 connection after backoff");
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        match connect_via_socks5_once(proxy, host, port).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = Some(e);
                warn!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, attempt = attempt + 1, max = MAX_RETRIES, error = %last_error.as_ref().unwrap(), "SOCKS5 connection attempt failed");
            }
        }
    }

    warn!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, max = MAX_RETRIES, "All SOCKS5 connection attempts exhausted");
    Err(last_error.unwrap())
}

/// Connects via SOCKS5 proxy (single attempt, no retry).
async fn connect_via_socks5_once(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    debug!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, "Connecting via SOCKS5 proxy");
    let stream = match (&proxy.username, &proxy.password) {
        (Some(user), Some(pass)) => {
            Socks5Stream::connect_with_password(
                (proxy.host.as_str(), proxy.port),
                (host, port),
                user,
                pass,
            )
            .await
        }
        _ => {
            Socks5Stream::connect((proxy.host.as_str(), proxy.port), (host, port)).await
        }
    };
    let stream = match stream {
        Ok(s) => {
            debug!(host, port, "SOCKS5 connection established");
            s
        }
        Err(e) => {
            warn!(host, port, error = %e, "SOCKS5 connection failed");
            return Err(e.into());
        }
    };
    let tcp_stream = stream.into_inner();
    let _ = tcp_stream.set_nodelay(true);
    if let Err(e) = set_keepalive(&tcp_stream) {
        debug!(host, port, error = %e, "Failed to set TCP keepalive on SOCKS5 connection");
    }
    Ok(tcp_stream)
}

/// Connects via HTTP proxy using CONNECT method with automatic retry.
async fn connect_via_http_proxy_with_retry(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    let mut last_error = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = retry_backoff_ms(attempt);
            debug!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, attempt = attempt + 1, max = MAX_RETRIES, delay_ms = delay, "Retrying HTTP CONNECT after backoff");
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        match connect_via_http_proxy_once(proxy, host, port).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = Some(e);
                warn!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, attempt = attempt + 1, max = MAX_RETRIES, error = %last_error.as_ref().unwrap(), "HTTP CONNECT attempt failed");
            }
        }
    }

    warn!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, max = MAX_RETRIES, "All HTTP CONNECT attempts exhausted");
    Err(last_error.unwrap())
}

/// Connects via HTTP proxy using CONNECT method (single attempt, no retry).
async fn connect_via_http_proxy_once(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    debug!(proxy_host = %proxy.host, proxy_port = proxy.port, host, port, "Connecting via HTTP proxy");

    let mut tcp_stream = match TcpStream::connect(format!("{}:{}", proxy.host, proxy.port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(host = %proxy.host, port = proxy.port, error = %e, "HTTP proxy TCP connection failed");
            return Err(e.into());
        }
    };
    let _ = tcp_stream.set_nodelay(true);
    if let Err(e) = set_keepalive(&tcp_stream) {
        debug!(proxy_host = %proxy.host, proxy_port = proxy.port, error = %e, "Failed to set TCP keepalive on HTTP proxy connection");
    }

    let connect_req = build_http_connect_request(host, port, &proxy.username, &proxy.password);
    tcp_stream.write_all(connect_req.as_bytes()).await?;

    // Parse HTTP CONNECT response
    let mut buf = [0u8; 1024];
    let response_len = read_http_response(&mut tcp_stream, &mut buf).await?;

    // Check for successful response
    if !buf[..response_len].starts_with(b"HTTP/1.1 200") && !buf[..response_len].starts_with(b"HTTP/1.0 200") {
        let first_line = buf[..response_len].split(|&b| b == b'\n').next().unwrap_or(&[]);
        let status_line = String::from_utf8_lossy(first_line).trim().to_string();
        warn!(host, port, status = %status_line, "HTTP CONNECT failed");
        return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "HTTP proxy CONNECT failed: {}",
                status_line
            ),
        )));
    }

    debug!(host, port, status = 200, "HTTP CONNECT succeeded");
    Ok(tcp_stream)
}

/// Reads an HTTP response into the buffer, returning the total bytes read.
/// Searches for the \r\n\r\n terminator to detect end of headers.
async fn read_http_response(
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<usize, ProxyError> {
    use tokio::io::AsyncReadExt;

    let mut pos = 0;
    const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

    loop {
        let n = stream.read(&mut buf[pos..]).await?;
        if n == 0 {
            return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed connection during handshake",
            )));
        }
        pos += n;

        // Check for header terminator in the newly read portion
        if pos >= 4 {
            let search_start = pos.saturating_sub(n + 3);
            if buf[search_start..pos]
                .windows(4)
                .any(|w| w == HEADER_TERMINATOR)
            {
                return Ok(pos);
            }
        }

        if pos >= buf.len() {
            return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy response exceeds buffer size without valid terminator",
            )));
        }
    }
}

/// Builds an HTTP CONNECT request string.
pub fn build_http_connect_request(
    host: &str,
    port: u16,
    username: &Option<String>,
    password: &Option<String>,
) -> String {
    let mut req = String::with_capacity(256);
    let _ = write!(
        &mut req,
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
        host, port, host, port
    );

    if let (Some(user), Some(pass)) = (username, password) {
        use base64::Engine;
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        let _ = write!(&mut req, "Proxy-Authorization: Basic {}\r\n", credentials);
    }

    let _ = write!(&mut req, "Proxy-Connection: Keep-Alive\r\n\r\n");
    req
}

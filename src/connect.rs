//! Connection establishment module.
//!
//! Provides functions for establishing TCP connections to target hosts,
//! with support for direct connections, HTTP CONNECT proxies, and SOCKS5 proxies.

use std::fmt::Write;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use crate::types::{ConnectionConfig, ProxyError, ProxyType, UpstreamProxy};

/// Establishes a connection to the target host via an upstream proxy if configured.
/// Returns a TcpStream ready for use.
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
                    connect_via_socks5(proxy, host, port).await
                }
                ProxyType::Http => {
                    connect_via_http_proxy(proxy, host, port).await
                }
            }
        }
        _ => connect_direct(host, port).await,
    }
}

/// Connects directly to the target host.
async fn connect_direct(host: &str, port: u16) -> Result<TcpStream, ProxyError> {
    let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Connects via SOCKS5 proxy.
async fn connect_via_socks5(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    let stream = match (&proxy.username, &proxy.password) {
        (Some(user), Some(pass)) => {
            Socks5Stream::connect_with_password(
                (proxy.host.as_str(), proxy.port),
                (host, port),
                user,
                pass,
            )
            .await?
        }
        _ => {
            Socks5Stream::connect((proxy.host.as_str(), proxy.port), (host, port)).await?
        }
    };
    let tcp_stream = stream.into_inner();
    let _ = tcp_stream.set_nodelay(true);
    Ok(tcp_stream)
}

/// Connects via HTTP proxy using CONNECT method.
async fn connect_via_http_proxy(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    let mut tcp_stream = TcpStream::connect(format!("{}:{}", proxy.host, proxy.port)).await?;
    let _ = tcp_stream.set_nodelay(true);

    let connect_req = build_http_connect_request(host, port, &proxy.username, &proxy.password);
    tcp_stream.write_all(connect_req.as_bytes()).await?;

    // Parse HTTP CONNECT response
    let mut buf = [0u8; 1024];
    let response_len = read_http_response(&mut tcp_stream, &mut buf).await?;

    // Check for successful response
    if !buf[..response_len].starts_with(b"HTTP/1.1 200") && !buf[..response_len].starts_with(b"HTTP/1.0 200") {
        let first_line = buf[..response_len].split(|&b| b == b'\n').next().unwrap_or(&[]);
        return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "HTTP proxy CONNECT failed: {}",
                String::from_utf8_lossy(first_line).trim()
            ),
        )));
    }

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

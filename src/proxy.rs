use bytes::Bytes;
use http::{header::*, Method, Request, Response, StatusCode, Uri};
use http_body::{Body, Frame};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::server::conn::http1;
use dashmap::DashMap;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lru::LruCache;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::task::AbortHandle;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_socks::tcp::Socks5Stream;
use url::Url;

use crate::certificate::CertificateAuthority;

/// Load root certificates from the system for TLS verification.
fn root_certs() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();

    if let Some(e) = cert_result.errors.first() {
        eprintln!("Warning: some certificates failed to load: {}", e);
    }

    for cert in cert_result.certs {
        if let Err(e) = root_store.add(cert) {
            eprintln!("Warning: failed to add certificate: {}", e);
        }
    }

    root_store
}

#[inline]
fn configure_http1_builder(
    client: &mut hyper::client::conn::http1::Builder,
    server: &mut hyper::server::conn::http1::Builder,
) {
    client.preserve_header_case(true).title_case_headers(true);
    server.preserve_header_case(true).title_case_headers(true);
}

const CHUNK_SIZE: u64 = 10 * 1024 * 1024;
const CONNECTION_POOL_SIZE: usize = 100;
const CONNECTION_TTL: Duration = Duration::from_secs(60);

// Type aliases for repeated complex types
type ProxyBody = BoxBody<Bytes, hyper::Error>;
type ProxyResult<T> = Result<T, ProxyError>;

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
    #[error("SOCKS error: {0}")]
    Socks(#[from] tokio_socks::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

struct PooledConnection {
    sender: Option<SendRequest<Incoming>>,
    created_at: Instant,
    abort_handle: AbortHandle,
}

impl PooledConnection {
    fn is_valid(&self) -> bool {
        self.created_at.elapsed() < CONNECTION_TTL && self.sender.is_some()
    }

    fn take(mut self) -> Option<(SendRequest<Incoming>, AbortHandle)> {
        self.sender.take().map(|sender| {
            let handle = std::mem::replace(
                &mut self.abort_handle,
                tokio::task::spawn(async {}).abort_handle()
            );
            (sender, handle)
        })
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

type ConnKey = (String, u16, bool); // (host, port, is_tls)

struct ConnectionPool {
    pool: DashMap<ConnKey, Mutex<Vec<PooledConnection>>>,
    state: Mutex<(LruCache<ConnKey, ()>, usize)>,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            pool: DashMap::new(),
            state: Mutex::new((
                LruCache::new(std::num::NonZeroUsize::new(CONNECTION_POOL_SIZE).unwrap()),
                0,
            )),
        }
    }

    fn get(&self, host: &str, port: u16, is_tls: bool) -> Option<(SendRequest<Incoming>, AbortHandle)> {
        let key: ConnKey = (host.to_string(), port, is_tls);

        loop {
            let conn_option = self.pool.get(&key).and_then(|entry| {
                let mut conns = entry.value().lock();
                conns.pop()
            });

            if let Some(conn) = conn_option {
                let mut state = self.state.lock();
                state.1 = state.1.saturating_sub(1);
                state.0.put(key.clone(), ());
                drop(state);

                if conn.is_valid() {
                    if let Some(result) = conn.take() {
                        return Some(result);
                    }
                }
                continue;
            }
            break;
        }
        None
    }

    fn put(&self, host: String, port: u16, is_tls: bool, sender: SendRequest<Incoming>, abort_handle: AbortHandle) {
        let key: ConnKey = (host, port, is_tls);

        {
            let mut state = self.state.lock();
            if state.1 >= CONNECTION_POOL_SIZE {
                if let Some((old_key, _)) = state.0.pop_lru() {
                    if let Some((_, conns_mutex)) = self.pool.remove(&old_key) {
                        let removed_count = conns_mutex.lock().len();
                        state.1 = state.1.saturating_sub(removed_count);
                    }
                }
            }

            if state.1 >= CONNECTION_POOL_SIZE {
                abort_handle.abort();
                return;
            }

            state.1 += 1;
            state.0.put(key.clone(), ());
        }

        let entry = self.pool.entry(key).or_insert_with(|| Mutex::new(Vec::with_capacity(4)));
        entry.value().lock().push(PooledConnection {
            sender: Some(sender),
            created_at: Instant::now(),
            abort_handle,
        });
    }

    fn cleanup(&self) {
        let mut total_removed = 0;
        self.pool.retain(|_key, conns_mutex| {
            let mut conns = conns_mutex.lock();
            let before = conns.len();
            conns.retain(|conn| conn.is_valid());
            let after = conns.len();
            total_removed += before - after;

            after != 0
        });

        if total_removed > 0 {
            let mut state = self.state.lock();
            state.1 = state.1.saturating_sub(total_removed);
        }
    }
}

struct BodyWithPoolReturn {
    inner: Incoming,
    pool: Arc<ConnectionPool>,
    host_port_tls: Option<(String, u16, bool)>,
    sender: Option<SendRequest<Incoming>>,
    abort_handle: Option<AbortHandle>,
}

impl BodyWithPoolReturn {
    fn new(
        inner: Incoming,
        pool: Arc<ConnectionPool>,
        host: String,
        port: u16,
        is_tls: bool,
        sender: SendRequest<Incoming>,
        abort_handle: AbortHandle,
    ) -> Self {
        Self {
            inner,
            pool,
            host_port_tls: Some((host, port, is_tls)),
            sender: Some(sender),
            abort_handle: Some(abort_handle),
        }
    }

    fn return_to_pool(&mut self) {
        if let (Some(sender), Some((host, port, is_tls)), Some(abort_handle)) =
            (self.sender.take(), self.host_port_tls.take(), self.abort_handle.take())
        {
            self.pool.put(host, port, is_tls, sender, abort_handle);
        }
    }
}

impl Body for BodyWithPoolReturn {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let inner = Pin::new(&mut self.inner);
        match inner.poll_frame(cx) {
            Poll::Ready(None) => {
                self.return_to_pool();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                self.sender.take();
                if let Some(handle) = self.abort_handle.take() {
                    handle.abort();
                }
                Poll::Ready(Some(Err(e)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for BodyWithPoolReturn {
    fn drop(&mut self) {
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ProxyType {
    Socks5,
    Http,
}

pub struct ProxyConfig {
    upstream_proxy: Option<UpstreamProxy>,
    pub ca: Arc<CertificateAuthority>,
    tls_client_config: Arc<rustls::ClientConfig>,
    connection_pool: Arc<ConnectionPool>,
    client_http1_builder: hyper::client::conn::http1::Builder,
    server_http1_builder: hyper::server::conn::http1::Builder,
    direct_cdn: bool,
    pub bypass_chunk_modification: bool,
    #[allow(dead_code)]
    disable_pooling: bool,  // Kept for backward compatibility, ignored
    _verify_tls: bool,  // Stored for consistency, used during construction
}

struct UpstreamProxy {
    proxy_type: ProxyType,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
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

        // Spawn cleanup task
        let pool_clone = Arc::clone(&connection_pool);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                pool_clone.cleanup();
            }
        });

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

    #[inline]
    async fn connect(self: &Arc<Self>, host: &str, port: u16) -> ProxyResult<TcpStream> {
        let self_clone = Arc::clone(self);
        let host_owned = host.to_string();
        let connect_fut = async move {
            let use_direct = self_clone.direct_cdn && host_owned.ends_with("googlevideo.com");

            match &self_clone.upstream_proxy {
                Some(proxy) if !use_direct => {
                    let proxy_host = proxy.host.as_str();
                    let proxy_port = proxy.port;

                    match proxy.proxy_type {
                        ProxyType::Socks5 => {
                            let stream = match (&proxy.username, &proxy.password) {
                                (Some(user), Some(pass)) => {
                                    Socks5Stream::connect_with_password(
                                        (proxy_host, proxy_port),
                                        (host_owned.as_str(), port),
                                        user,
                                        pass,
                                    )
                                    .await?
                                }
                                _ => {
                                    Socks5Stream::connect((proxy_host, proxy_port), (host_owned.as_str(), port)).await?
                                }
                            };
                            let tcp_stream = stream.into_inner();
                            let _ = tcp_stream.set_nodelay(true);
                            Ok(tcp_stream)
                        }
                        ProxyType::Http => {
                            let mut tcp_stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)).await?;
                            let _ = tcp_stream.set_nodelay(true);

                            let connect_req = build_http_connect_request(&host_owned, port, &proxy.username, &proxy.password);

                            tcp_stream.write_all(connect_req.as_bytes()).await?;

                            let mut buf = [0u8; 1024];
                            let mut pos = 0;

                            loop {
                                let n = tcp_stream.read(&mut buf[pos..]).await?;
                                if n == 0 {
                                    return Err(ProxyError::Io(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "HTTP proxy closed connection during handshake",
                                    )));
                                }
                                pos += n;

                                static HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
                                if pos >= 4 {
                                    let search_start = pos.saturating_sub(n + 3);
                                    if buf[search_start..pos].windows(4).any(|w| w == HEADER_TERMINATOR) {
                                        break;
                                    }
                                }

                                if pos >= buf.len() {
                                    return Err(ProxyError::Io(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "HTTP proxy response exceeds buffer size without valid terminator",
                                    )));
                                }
                            }

                            if !buf[..pos].starts_with(b"HTTP/1.1 200") && !buf[..pos].starts_with(b"HTTP/1.0 200") {
                                let first_line = buf[..pos].split(|&b| b == b'\n').next().unwrap_or(&[]);
                                return Err(ProxyError::Io(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionRefused,
                                    format!("HTTP proxy CONNECT failed: {}", String::from_utf8_lossy(first_line).trim()),
                                )));
                            }

                            Ok(tcp_stream)
                        }
                    }
                }
                _ => {
                    let tcp_stream = TcpStream::connect(format!("{}:{}", host_owned, port)).await?;
                    let _ = tcp_stream.set_nodelay(true);
                    Ok(tcp_stream)
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(10), connect_fut).await {
            Ok(res) => res,
            Err(_) => Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Connection to {}:{} timed out after 10s", host, port),
            ))),
        }
    }

    // Helper function to perform HTTP/1 handshake and return sender with abort handle
    async fn handshake_upstream<IO>(
        &self,
        io: IO,
    ) -> ProxyResult<(SendRequest<Incoming>, AbortHandle)>
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

    async fn get_or_create_connection(
        self: &Arc<Self>,
        host_str: &str,
        port: u16,
        is_tls: bool,
    ) -> ProxyResult<(SendRequest<Incoming>, AbortHandle)> {
        while let Some((mut sender, abort_handle)) = self.connection_pool.get(host_str, port, is_tls) {
            match sender.ready().await {
                Ok(_) => return Ok((sender, abort_handle)),
                Err(_) => {
                    abort_handle.abort();
                    continue;
                }
            }
        }

        let upstream_tcp = self.connect(host_str, port).await?;

        if is_tls {
            let host = host_str.to_string();
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_client_config));
            let server_name = rustls::pki_types::ServerName::try_from(host)
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

// Helper function to build HTTP CONNECT request
#[inline]
fn build_http_connect_request(host: &str, port: u16, username: &Option<String>, password: &Option<String>) -> String {
    use std::fmt::Write;
    let mut req = String::with_capacity(256);
    let _ = write!(&mut req, "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n", host, port, host, port);

    if let (Some(user), Some(pass)) = (username, password) {
        use base64::Engine;
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        let _ = write!(&mut req, "Proxy-Authorization: Basic {}\r\n", credentials);
    }

    let _ = write!(&mut req, "Proxy-Connection: Keep-Alive\r\n\r\n");
    req
}

// Consolidated error response handler
#[inline]
fn handle_proxy_error(e: &ProxyError, is_connect: bool) -> Response<ProxyBody> {
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

#[inline]
fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[inline]
fn error_response(status: StatusCode, msg: &'static str) -> Response<ProxyBody> {
    let body = if msg.is_empty() {
        empty_body()
    } else {
        Full::new(Bytes::from_static(msg.as_bytes()))
            .map_err(|never| match never {})
            .boxed()
    };
    Response::builder()
        .status(status)
        .body(body)
        .expect("valid response")
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

async fn handle_connect(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> ProxyResult<Response<ProxyBody>> {
    let (host, port) = extract_host_port(req.uri())?;

    let host_clone = host.clone();
    let upgrade_fut = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => {
                let upgraded_io = TokioIo::new(upgraded);
                if let Err(_e) = handle_tunnel(upgraded_io, &host_clone, port, config).await {
                    eprintln!("Tunnel error for {}:{}", host_clone, port);
                }
            }
            Err(_) => {}
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("valid response"))
}

#[inline]
fn extract_host_port(uri: &Uri) -> ProxyResult<(String, u16)> {
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

async fn handle_tunnel<I>(
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
        .map_err(|e| ProxyError::Tls(rustls::Error::General(e.to_string())))?;

    let acceptor = TlsAcceptor::from(tls_config);
    let client_tls = acceptor.accept(upgraded).await?;
    let client_io = TokioIo::new(client_tls);
    let host_owned = host.to_string();

    let service = service_fn(move |req: Request<Incoming>| {
        let config = Arc::clone(&config);
        let host = host_owned.clone();
        async move {
            match forward_request(req, &host, port, true, config).await {
                Ok(resp) => Ok::<_, hyper::Error>(resp),
                Err(e) => Ok(handle_proxy_error(&e, true)),
            }
        }
    });

    let _ = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(client_io, service)
        .await;

    Ok(())
}

#[inline]
fn strip_hop_by_hop_headers<T>(req: &mut Request<T>) {
    let headers = req.headers_mut();
    headers.remove(CONNECTION);
    headers.remove("Proxy-Connection");
    headers.remove("Keep-Alive");
    headers.remove(UPGRADE);
    headers.remove("TE");
    headers.remove("Trailer");
    headers.remove(TRANSFER_ENCODING);
}

#[inline]
fn modify_request_headers<T>(req: &mut Request<T>, host: &str) -> bool {
    if !host.ends_with("googlevideo.com") {
        return false;
    }

    let range_header = match req.headers().get(RANGE) {
        Some(h) => h,
        None => return false,
    };

    let range_bytes = range_header.as_bytes();
    if range_bytes.len() < 8 || !range_bytes.starts_with(b"bytes=") || !range_bytes.ends_with(b"-") {
        return false;
    }

    let start_bytes = &range_bytes[6..range_bytes.len() - 1];
    if start_bytes.is_empty() || start_bytes.contains(&b'-') {
        return false;
    }

    let mut start_byte: u64 = 0;
    for &b in start_bytes {
        if !(b'0'..=b'9').contains(&b) {
            return false;
        }
        start_byte = match start_byte
            .checked_mul(10)
            .and_then(|n| n.checked_add((b - b'0') as u64))
        {
            Some(n) => n,
            None => return false,
        };
    }

    let new_end_byte = start_byte.saturating_add(CHUNK_SIZE - 1);

    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(b"bytes=");
    push_u64(&mut buf, start_byte);
    buf.push(b'-');
    push_u64(&mut buf, new_end_byte);

    let val = match http::HeaderValue::from_bytes(&buf) {
        Ok(v) => v,
        Err(_) => return false,
    };

    req.headers_mut().insert(RANGE, val);
    true
}

#[inline]
fn push_u64(buf: &mut Vec<u8>, n: u64) {
    let mut itoa_buf = itoa::Buffer::new();
    buf.extend_from_slice(itoa_buf.format(n).as_bytes());
}

async fn forward_request(
    mut req: Request<Incoming>,
    host: &str,
    port: u16,
    is_tls: bool,
    config: Arc<ProxyConfig>,
) -> ProxyResult<Response<ProxyBody>> {
    strip_hop_by_hop_headers(&mut req);

    if config.bypass_chunk_modification {
        if host.ends_with("googlevideo.com") {
            println!("[PROXY] Bypassing chunk modification for {}", host);
        }
    } else if modify_request_headers(&mut req, host) {
        println!("[PROXY] Modified Range header for {}", host);
    }

    let (mut sender, abort_handle) = config.get_or_create_connection(host, port, is_tls).await?;

    let default_port = if is_tls { 443 } else { 80 };
    let host_header = if port == default_port {
        http::HeaderValue::from_str(host)
    } else {
        http::HeaderValue::from_maybe_shared(format!("{}:{}", host, port))
    }
    .expect("valid host header");

    let (mut parts, body) = req.into_parts();

    if is_tls {
        let path_and_query = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        parts.uri = Uri::builder()
            .scheme("https")
            .authority(host_header.as_bytes())
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| ProxyError::InvalidUri(Cow::Owned(e.to_string())))?;
    }

    parts.headers.insert(HOST, host_header);

    let req = Request::from_parts(parts, body);
    let resp = match sender.send_request(req).await {
        Ok(resp) => resp,
        Err(e) => {
            // Connection is dead, don't return it to the pool
            abort_handle.abort();
            return Err(e.into());
        }
    };

    let (parts, incoming_body) = resp.into_parts();

    let can_reuse = parts.status != StatusCode::SWITCHING_PROTOCOLS
        && !matches!(
            parts.headers.get(CONNECTION),
            Some(v) if v.as_bytes().eq_ignore_ascii_case(b"close")
        );

    if can_reuse {
        let body = BodyWithPoolReturn::new(
            incoming_body,
            Arc::clone(&config.connection_pool),
            host.to_string(),
            port,
            is_tls,
            sender,
            abort_handle,
        );
        Ok(Response::from_parts(parts, body.boxed()))
    } else {
        abort_handle.abort();
        Ok(Response::from_parts(parts, incoming_body.map_err(|e| e).boxed()))
    }
}

async fn handle_http(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> ProxyResult<Response<ProxyBody>> {
    if (req.method() == Method::GET || req.method() == Method::HEAD) && req.uri().path() == "/" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(empty_body())
            .expect("valid response"));
    }

    let uri = req.uri();
    let host = uri
        .host()
        .map(|h| h.to_string())
        .ok_or_else(|| ProxyError::InvalidUri(Cow::Borrowed("Missing host")))?;
    let port = uri.port_u16().unwrap_or(80);

    forward_request(req, &host, port, false, config).await
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

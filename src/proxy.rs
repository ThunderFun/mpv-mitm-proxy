use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode, Uri};
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
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
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

const CHUNK_SIZE: u64 = 10 * 1024 * 1024; 
const CONNECTION_POOL_SIZE: usize = 100;
const CONNECTION_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_SIZE: usize = 256;
const DNS_CACHE_TTL: Duration = Duration::from_secs(300); 

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

#[derive(Hash, Eq, PartialEq, Clone)]
struct ConnKey {
    host: String,
    port: u16,
    is_tls: bool,
}

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
        let key = ConnKey {
            host: host.to_string(),
            port,
            is_tls,
        };

        if let Some(entry) = self.pool.get(&key) {
            let mut conns = entry.value().lock();
            while let Some(conn) = conns.pop() {
                let mut state = self.state.lock();
                state.1 = state.1.saturating_sub(1);
                state.0.put(key.clone(), ());

                if conn.is_valid() {
                    if let Some(result) = conn.take() {
                        return Some(result);
                    }
                }
            }
        }
        None
    }

    fn put(&self, host: String, port: u16, is_tls: bool, sender: SendRequest<Incoming>, abort_handle: AbortHandle) {
        let key = ConnKey { host, port, is_tls };
        
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

struct DnsCacheEntry {
    result: Result<Vec<IpAddr>, String>,
    expires_at: Instant,
    stale_at: Instant,
}

struct DnsCache {
    cache: Mutex<LruCache<String, Arc<DnsCacheEntry>>>,
    inflight: DashMap<String, tokio::sync::watch::Receiver<Option<Result<Vec<IpAddr>, String>>>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(DNS_CACHE_SIZE).unwrap(),
            )),
            inflight: DashMap::new(),
        }
    }

    fn get(&self, host: &str) -> (Option<Result<Vec<IpAddr>, String>>, bool) {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(host) {
            let now = Instant::now();
            if now < entry.expires_at {
                return (Some(entry.result.clone()), false);
            } else if now < entry.stale_at {
                return (Some(entry.result.clone()), true);
            }
            cache.pop(host);
        }
        (None, false)
    }

    fn put(&self, host: String, result: Result<Vec<IpAddr>, String>) {
        let now = Instant::now();
        let (ttl, stale_ttl) = if result.is_ok() {
            (DNS_CACHE_TTL, DNS_CACHE_TTL * 2)
        } else {
            (Duration::from_secs(30), Duration::from_secs(60)) 
        };

        let entry = Arc::new(DnsCacheEntry {
            result,
            expires_at: now + ttl,
            stale_at: now + stale_ttl,
        });
        self.cache.lock().put(host, entry);
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
    dns_cache: Arc<DnsCache>,
    client_http1_builder: hyper::client::conn::http1::Builder,
    server_http1_builder: hyper::server::conn::http1::Builder,
    direct_cdn: bool,
    pub bypass_chunk_modification: bool,
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

        let tls_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth(),
        );

        let connection_pool = Arc::new(ConnectionPool::new());
        let dns_cache = Arc::new(DnsCache::new());

        let mut client_http1_builder = hyper::client::conn::http1::Builder::new();
        client_http1_builder.preserve_header_case(true);
        client_http1_builder.title_case_headers(true);

        let mut server_http1_builder = hyper::server::conn::http1::Builder::new();
        server_http1_builder.preserve_header_case(true);
        server_http1_builder.title_case_headers(true);

        let pool_clone = Arc::clone(&connection_pool);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                pool_clone.cleanup();
            }
        });

        let config = Arc::new(Self {
            upstream_proxy,
            ca,
            tls_client_config,
            connection_pool,
            dns_cache,
            client_http1_builder,
            server_http1_builder,
            direct_cdn,
            bypass_chunk_modification,
        });

        let config_clone = Arc::clone(&config);
        tokio::spawn(async move {
            let domains = ["www.youtube.com", "youtube.com"];
            for domain in domains {
                let _ = config_clone.perform_dns_lookup(domain.to_string()).await;
            }
        });

        config
    }

    async fn resolve_host(self: &Arc<Self>, host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
        let (cached, is_stale) = self.dns_cache.get(host);
        
        if let Some(result) = cached {
            if is_stale {
                let self_clone = Arc::clone(self);
                let host_owned = host.to_string();
                tokio::spawn(async move {
                    let _ = self_clone.perform_dns_lookup(host_owned).await;
                });
            }
            return match result {
                Ok(ips) => Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()),
                Err(e) => Err(ProxyError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e))),
            };
        }

        let ips = self.perform_dns_lookup(host.to_string()).await?;
        Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }

    async fn perform_dns_lookup(&self, host: String) -> Result<Vec<IpAddr>, ProxyError> {
        use dashmap::mapref::entry::Entry;
        
        let rx = match self.dns_cache.inflight.entry(host.clone()) {
            Entry::Occupied(occ) => occ.get().clone(),
            Entry::Vacant(vac) => {
                let (tx, rx) = tokio::sync::watch::channel(None);
                vac.insert(rx.clone());
                
                let host_clone = host.clone();
                let dns_cache = Arc::clone(&self.dns_cache);
                tokio::spawn(async move {
                    let host_for_lookup = host_clone.clone();
                    let res: Result<Vec<IpAddr>, String> = tokio::task::spawn_blocking(move || {
                        (host_for_lookup.as_str(), 0u16)
                            .to_socket_addrs()
                            .map(|iter| {
                                let ips: Vec<IpAddr> = iter.map(|addr| addr.ip()).collect();
                                if ips.is_empty() {
                                    Err(format!("No addresses found for {}", host_for_lookup))
                                } else {
                                    Ok(ips)
                                }
                            })
                            .unwrap_or_else(|e| Err(e.to_string()))
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));

                    dns_cache.put(host_clone.clone(), res.clone());
                    let _ = tx.send(Some(res));
                    dns_cache.inflight.remove(&host_clone);
                });
                rx
            }
        };

        let mut rx = rx;
        loop {
            if let Some(res) = rx.borrow().clone() {
                return res.map_err(|e| ProxyError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e)));
            }
            if rx.changed().await.is_err() {
                return Err(ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "DNS lookup task dropped",
                )));
            }
        }
    }

    #[inline]
    async fn connect(self: &Arc<Self>, host: &str, port: u16) -> Result<TcpStream, ProxyError> {
        let self_clone = Arc::clone(self);
        let host_owned = host.to_string();
        let connect_fut = async move {
            let use_direct = self_clone.direct_cdn && host_owned.ends_with("googlevideo.com");
            
            match &self_clone.upstream_proxy {
                Some(proxy) if !use_direct => {
                    let proxy_addrs = self_clone.resolve_host(&proxy.host, proxy.port).await?;
                    
                    match proxy.proxy_type {
                        ProxyType::Socks5 => {
                            let stream = match (&proxy.username, &proxy.password) {
                                (Some(user), Some(pass)) => {
                                    Socks5Stream::connect_with_password(
                                        proxy_addrs.as_slice(),
                                        (host_owned.as_str(), port),
                                        user,
                                        pass,
                                    )
                                    .await?
                                }
                                _ => {
                                    Socks5Stream::connect(proxy_addrs.as_slice(), (host_owned.as_str(), port)).await?
                                }
                            };
                            let tcp_stream = stream.into_inner();
                            let _ = tcp_stream.set_nodelay(true);
                            Ok(tcp_stream)
                        }
                        ProxyType::Http => {
                            let mut tcp_stream = TcpStream::connect(proxy_addrs.as_slice()).await?;
                            let _ = tcp_stream.set_nodelay(true);

                            let connect_req = if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
                                use base64::Engine;
                                let credentials = base64::engine::general_purpose::STANDARD
                                    .encode(format!("{}:{}", user, pass));
                                format!(
                                    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Authorization: Basic {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                                    host_owned, port, host_owned, port, credentials
                                )
                            } else {
                                format!(
                                    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                                    host_owned, port, host_owned, port
                                )
                            };
                            
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
                                
                                if buf[..pos].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                
                                if pos == buf.len() {
                                    break; 
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
                    let addrs = self_clone.resolve_host(&host_owned, port).await?;
                    let tcp_stream = TcpStream::connect(addrs.as_slice()).await?;
                    let _ = tcp_stream.set_nodelay(true);
                    Ok(tcp_stream)
                }
            }
        };

        let res = match tokio::time::timeout(Duration::from_secs(10), connect_fut).await {
            Ok(res) => res,
            Err(_) => Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Connection to {}:{} timed out after 10s", host, port),
            ))),
        };

        res
    }

    async fn get_or_create_connection(
        self: &Arc<Self>,
        host_str: &str,
        port: u16,
        is_tls: bool,
    ) -> Result<(SendRequest<Incoming>, AbortHandle), ProxyError> {
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
}

#[inline]
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[inline]
fn error_response<E>(status: StatusCode, msg: &'static str) -> Response<BoxBody<Bytes, E>> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| -> E { match never {} })
        .boxed();
    Response::builder()
        .status(status)
        .body(body)
        .expect("valid response")
}

pub async fn handle_client(
    stream: TcpStream,
    _client_addr: SocketAddr,
    config: Arc<ProxyConfig>,
) -> Result<(), ProxyError> {
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let config_clone = Arc::clone(&config);
    let service = service_fn(move |req: Request<Incoming>| {
        let config = Arc::clone(&config_clone);
        async move {
            match handle_request(req, config).await {
                Ok(resp) => Ok::<_, hyper::Error>(resp),
                Err(e) => Ok(match e {
                    ProxyError::InvalidUri(_) => {
                        error_response(StatusCode::BAD_REQUEST, "Invalid URI")
                    }
                    ProxyError::Io(_) | ProxyError::Socks(_) | ProxyError::Tls(_) => {
                        error_response(StatusCode::BAD_GATEWAY, "Upstream Error")
                    }
                    _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Error"),
                }),
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

#[inline]
async fn handle_request(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    if req.method() == Method::CONNECT {
        handle_connect(req, config).await
    } else {
        handle_http(req, config).await
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    let (host, port) = extract_host_port(req.uri())?;

    let host_clone = host.clone();
    let upgrade_fut = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => {
                let upgraded_io = TokioIo::new(upgraded);
                if let Err(e) = handle_tunnel(upgraded_io, &host_clone, port, config).await {
                    eprintln!("Tunnel error for {}:{}: {}", host_clone, port, e);
                }
            }
            Err(e) => {
                eprintln!("Upgrade error for {}:{}: {}", host_clone, port, e);
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("valid response"))
}

#[inline]
fn extract_host_port(uri: &Uri) -> Result<(String, u16), ProxyError> {
    if let Some(host) = uri.host() {
        let port = uri.port_u16().unwrap_or(443);
        return Ok((host.to_string(), port));
    }

    if let Some(authority) = uri.authority() {
        let auth_str = authority.as_str();
        if auth_str.starts_with('[') {
            if let Some(end_bracket) = auth_str.find(']') {
                let host = &auth_str[1..end_bracket];
                let rest = &auth_str[end_bracket + 1..];
                if rest.starts_with(':') {
                    if let Ok(port) = rest[1..].parse::<u16>() {
                        return Ok((host.to_string(), port));
                    }
                }
                return Ok((host.to_string(), 443));
            }
        }

        if let Some(idx) = auth_str.rfind(':') {
            let (host, port_str) = auth_str.split_at(idx);
            if let Ok(port) = port_str[1..].parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
        return Ok((auth_str.to_string(), 443));
    }

    Err(ProxyError::InvalidUri(Cow::Owned(format!(
        "Missing host in URI: {}",
        uri
    ))))
}

async fn handle_tunnel<I>(
    upgraded: I,
    host: &str,
    port: u16,
    config: Arc<ProxyConfig>,
) -> Result<(), ProxyError>
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
                Err(e) => Ok(match e {
                    ProxyError::InvalidUri(_) => {
                        error_response(StatusCode::BAD_REQUEST, "Invalid URI")
                    }
                    _ => error_response(StatusCode::BAD_GATEWAY, "Upstream Error"),
                }),
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
    headers.remove(header::CONNECTION);
    headers.remove("Proxy-Connection");
    headers.remove("Keep-Alive");
    headers.remove(header::UPGRADE);
    headers.remove("TE");
    headers.remove("Trailer");
    headers.remove(header::TRANSFER_ENCODING);
}

#[inline]
fn modify_request_headers<T>(req: &mut Request<T>, host: &str) -> bool {
    if !host.ends_with("googlevideo.com") {
        return false;
    }

    let range_header = match req.headers().get(header::RANGE) {
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

    req.headers_mut().insert(header::RANGE, val);
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
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
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

    parts.headers.insert(header::HOST, host_header);

    let req = Request::from_parts(parts, body);
    let resp = match sender.send_request(req).await {
        Ok(resp) => resp,
        Err(e) => {
            abort_handle.abort();
            return Err(e.into());
        }
    };

    let (parts, incoming_body) = resp.into_parts();


    let can_reuse = parts.status != StatusCode::SWITCHING_PROTOCOLS
        && parts.headers
            .get(header::CONNECTION)
            .map(|v| !v.as_bytes().eq_ignore_ascii_case(b"close"))
            .unwrap_or(true);

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
        Ok(Response::from_parts(parts, body.map_err(|e| e).boxed()))
    } else {
        abort_handle.abort();
        Ok(Response::from_parts(
            parts,
            incoming_body.map_err(|e| e).boxed(),
        ))
    }
}

async fn handle_http(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
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

static SUPPORTED_SIG_SCHEMES: &[rustls::SignatureScheme] = &[
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
];

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
        SUPPORTED_SIG_SCHEMES.to_vec()
    }
}

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
use std::sync::atomic::{AtomicUsize, Ordering};
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
    abort_handle: Option<AbortHandle>,
}

impl PooledConnection {
    fn is_valid(&self) -> bool {
        self.created_at.elapsed() < CONNECTION_TTL
            && self.sender.is_some()
            && self.abort_handle.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }

    fn take(mut self) -> Option<(SendRequest<Incoming>, AbortHandle)> {
        match (self.sender.take(), self.abort_handle.take()) {
            (Some(sender), Some(handle)) => Some((sender, handle)),
            _ => None,
        }
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(h) = self.abort_handle.take() {
            h.abort();
        }
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
    state: Mutex<LruCache<ConnKey, usize>>,
    total: AtomicUsize,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            pool: DashMap::new(),
            state: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(CONNECTION_POOL_SIZE).unwrap(),
            )),
            total: AtomicUsize::new(0),
        }
    }

    fn get(&self, host: &str, port: u16, is_tls: bool) -> Option<(SendRequest<Incoming>, AbortHandle)> {
        let key = ConnKey { host: host.to_string(), port, is_tls };
        if let Some(entry) = self.pool.get(&key) {
            let mut conns = entry.value().lock();
            while let Some(conn) = conns.pop() {
                if conn.is_valid() {
                    if let Some(pair) = conn.take() {
                        self.total.fetch_sub(1, Ordering::SeqCst);
                        let mut state = self.state.lock();
                        let count = state.get(&key).copied().unwrap_or(1).saturating_sub(1);
                        if count == 0 {
                            state.pop(&key);
                        } else {
                            state.put(key.clone(), count);
                        }
                        return Some(pair);
                    }
                }
            }
        }
        None
    }

    fn put(&self, host: String, port: u16, is_tls: bool, sender: SendRequest<Incoming>, abort_handle: AbortHandle) {
        if self.total.load(Ordering::SeqCst) >= CONNECTION_POOL_SIZE {
            abort_handle.abort();
            return;
        }
        let key = ConnKey { host, port, is_tls };

        let entry = self.pool.entry(key.clone()).or_insert_with(|| Mutex::new(Vec::with_capacity(4)));
        entry.value().lock().push(PooledConnection {
            sender: Some(sender),
            created_at: Instant::now(),
            abort_handle: Some(abort_handle),
        });

        self.total.fetch_add(1, Ordering::SeqCst);

        let mut state = self.state.lock();
        let count = state.get(&key).copied().unwrap_or(0) + 1;
        state.put(key, count);
    }

    fn cleanup(&self) {
        let mut removed = 0usize;
        self.pool.retain(|_, conns_mutex| {
            let mut conns = conns_mutex.lock();
            let before = conns.len();
            conns.retain(|c| c.is_valid());
            let after = conns.len();
            removed += before - after;
            after != 0
        });
        if removed > 0 {
            self.total.fetch_sub(removed, Ordering::SeqCst);
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
            // Don't return to pool if the connection task has finished
            if abort_handle.is_finished() {
                return;
            }
            
            // Check if sender is still usable before returning to pool
            // If sender is closed, don't pool the connection
            if sender.is_closed() {
                abort_handle.abort();
                return;
            }
            
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
        // Only abort if the connection wasn't returned to pool
        // (sender is None means it was returned)
        if self.sender.is_some() {
            if let Some(handle) = self.abort_handle.take() {
                handle.abort();
            }
        }
    }
}

/// Body wrapper that aborts the connection task after the body is fully consumed.
/// This prevents truncating the response body when connections are not being pooled.
struct BodyWithAbortOnEnd {
    inner: Incoming,
    abort_handle: Option<AbortHandle>,
}

impl BodyWithAbortOnEnd {
    fn new(inner: Incoming, abort_handle: AbortHandle) -> Self {
        Self {
            inner,
            abort_handle: Some(abort_handle),
        }
    }

    fn abort(&mut self) {
        if let Some(h) = self.abort_handle.take() {
            h.abort();
        }
    }
}

impl Body for BodyWithAbortOnEnd {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let inner = Pin::new(&mut self.inner);
        match inner.poll_frame(cx) {
            Poll::Ready(None) => {
                self.abort();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                self.abort();
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

impl Drop for BodyWithAbortOnEnd {
    fn drop(&mut self) {
        self.abort();
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
            // Entry is fully expired, remove it
            cache.pop(host);
        }
        (None, false)
    }
    
    /// Remove a stale entry from the cache to force a fresh lookup
    fn remove(&self, host: &str) {
        let mut cache = self.cache.lock();
        cache.pop(host);
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
    pub debug: bool,
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
        debug: bool,
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
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                pool_clone.cleanup();
            }
        });
        // Store handle for potential graceful shutdown (currently runs until process exit)
        let _ = cleanup_handle;

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
            debug,
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
                // Use perform_dns_lookup which has proper inflight coordination
                // This prevents multiple concurrent stale refreshes for the same hostname
                let self_clone = Arc::clone(self);
                let host_owned = host.to_string();
                tokio::spawn(async move {
                    // perform_dns_lookup uses DashMap entry API to ensure only one
                    // lookup task is spawned per hostname
                    let result = self_clone.perform_dns_lookup(host_owned.clone()).await;
                    // If refresh failed, remove the stale entry to force fresh lookup next time
                    if result.is_err() {
                        self_clone.dns_cache.remove(&host_owned);
                    }
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
                    // Use a scope guard to ensure inflight entry is always cleaned up
                    let _cleanup = scopeguard::guard((dns_cache.clone(), host_clone.clone()), |(dc, h)| {
                        dc.inflight.remove(&h);
                    });
                    
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
                    // Send result before cleanup guard drops
                    let _ = tx.send(Some(res));
                    // Cleanup guard will remove inflight entry here
                });
                rx
            }
        };

        let mut rx = rx;
        loop {
            if let Some(res) = rx.borrow().clone() {
                return res.map_err(|e| ProxyError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e)));
            }
            let changed = tokio::time::timeout(Duration::from_secs(5), rx.changed()).await;
            match changed {
                Ok(Ok(_)) => continue,
                _ => {
                    self.dns_cache.inflight.remove(&host);
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "DNS lookup cancelled or timed out",
                    )));
                }
            }
        }
    }

    #[inline]
    async fn connect(self: &Arc<Self>, host: &str, port: u16) -> Result<TcpStream, ProxyError> {
        let self_clone = Arc::clone(self);
        let host_owned = host.to_string();
        
        if self_clone.debug {
            eprintln!("[PROXY DEBUG] Connecting to {}:{}", host_owned, port);
            eprintln!("[PROXY DEBUG] upstream_proxy is_none: {}", self_clone.upstream_proxy.is_none());
            eprintln!("[PROXY DEBUG] direct_cdn: {}", self_clone.direct_cdn);
        }

        let connect_fut = async move {
            let use_direct = self_clone.direct_cdn && host_owned.ends_with("googlevideo.com");
            
            if self_clone.debug {
                if use_direct {
                    eprintln!("[PROXY DEBUG] Using DIRECT connection for {} (direct_cdn=true and googlevideo.com)", host_owned);
                } else {
                    match &self_clone.upstream_proxy {
                        Some(proxy) => eprintln!("[PROXY DEBUG] Using {} proxy {}:{} for {}", 
                            match proxy.proxy_type { ProxyType::Socks5 => "SOCKS5", ProxyType::Http => "HTTP" },
                            proxy.host, proxy.port, host_owned),
                        None => eprintln!("[PROXY DEBUG] Using DIRECT connection for {} (no upstream proxy configured)", host_owned),
                    }
                }
            }
            
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
                            read_http_connect_status(&mut tcp_stream).await?;
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
        // Retry loop for pooled connections - but limit retries to avoid infinite loops
        let mut attempts = 0;
        const MAX_POOL_ATTEMPTS: u32 = 3;
        
        while attempts < MAX_POOL_ATTEMPTS {
            if let Some((mut sender, abort_handle)) = self.connection_pool.get(host_str, port, is_tls) {
                attempts += 1;
                
                // Check if connection is still usable with a timeout
                // ready() can hang if the connection is in a bad state
                match tokio::time::timeout(Duration::from_millis(100), sender.ready()).await {
                    Ok(Ok(_)) => {
                        // Additional check: verify the connection task is still running
                        if abort_handle.is_finished() {
                            // Connection task has finished - connection is dead
                            continue;
                        }
                        return Ok((sender, abort_handle));
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Connection is broken or timed out, abort and try next
                        abort_handle.abort();
                        continue;
                    }
                }
            } else {
                break; // No more pooled connections available
            }
        }

        let upstream_tcp = self.connect(host_str, port).await?;

        if is_tls {
            let host = host_str.to_string();
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_client_config));
            // Remove brackets from IPv6 for ServerName (SNI doesn't use brackets)
            let server_name_str = if host.starts_with('[') && host.ends_with(']') {
                &host[1..host.len()-1]
            } else {
                &host
            };
            let server_name = rustls::pki_types::ServerName::try_from(server_name_str.to_string())
                .map_err(|_| ProxyError::InvalidUri(Cow::Borrowed("Invalid server name")))?;
            let upstream_tls = match tokio::time::timeout(
                Duration::from_secs(10),
                connector.connect(server_name, upstream_tcp)
            ).await {
                Ok(res) => res?,
                Err(_) => return Err(ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("TLS handshake to {} timed out", host_str),
                ))),
            };
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

async fn read_http_connect_status(stream: &mut TcpStream) -> Result<(), ProxyError> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut tmp = [0u8; 512];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed connection during handshake",
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy response headers too large",
            )));
        }
    }

    let first_line = buf.split(|&b| b == b'\n').next().unwrap_or(&[]);
    if !first_line.starts_with(b"HTTP/1.1 200") && !first_line.starts_with(b"HTTP/1.0 200") {
        return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("HTTP proxy CONNECT failed: {}", String::from_utf8_lossy(first_line).trim()),
        )));
    }
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
        // Preserve IPv6 brackets in host for proper SNI and Host header usage
        return Ok((host.to_string(), port));
    }

    if let Some(authority) = uri.authority() {
        let auth_str = authority.as_str();
        if auth_str.starts_with('[') {
            // IPv6 address - must have closing bracket
            let end_bracket = auth_str.find(']').ok_or_else(|| {
                ProxyError::InvalidUri(Cow::Owned(format!(
                    "Invalid IPv6 address, missing closing bracket: {}",
                    uri
                )))
            })?;
            // Keep brackets for IPv6 addresses (required for Host header and SNI)
            let host = &auth_str[..=end_bracket];
            let rest = &auth_str[end_bracket + 1..];
            if rest.starts_with(':') {
                if let Ok(port) = rest[1..].parse::<u16>() {
                    return Ok((host.to_string(), port));
                }
            }
            return Ok((host.to_string(), 443));
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
        .get_server_config(host).await
        .map_err(|e| ProxyError::Tls(rustls::Error::General(e.to_string())))?;

    let acceptor = TlsAcceptor::from(tls_config);
    let client_tls = match tokio::time::timeout(
        Duration::from_secs(10),
        acceptor.accept(upgraded)
    ).await {
        Ok(res) => res?,
        Err(_) => return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TLS client handshake timed out",
        ))),
    };
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
fn parse_open_ended_range(start: &[u8]) -> Option<u64> {
    if start.is_empty() || start.contains(&b'-') {
        return None;
    }
    let mut n: u64 = 0;
    for &b in start {
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

#[inline]
fn modify_request_headers<T>(req: &mut Request<T>, host: &str) -> bool {
    if !host.ends_with("googlevideo.com") {
        return false;
    }
    let range_header = match req.headers().get(header::RANGE) {
        Some(h) => h.as_bytes(),
        None => return false,
    };
    if !range_header.starts_with(b"bytes=") {
        return false;
    }

    let range_spec = &range_header[6..];
    if range_spec.starts_with(b"-") {
        return false; // suffix range: don't touch
    }
    if !range_spec.ends_with(b"-") {
        return false; // already bounded or multi-range
    }

    let start_bytes = &range_spec[..range_spec.len() - 1];
    let start = match parse_open_ended_range(start_bytes) {
        Some(v) => v,
        None => return false,
    };

    let end = start.saturating_add(CHUNK_SIZE.saturating_sub(1));

    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(b"bytes=");
    push_u64(&mut buf, start);
    buf.push(b'-');
    push_u64(&mut buf, end);

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
    let req_wants_close = req
        .headers()
        .get(header::CONNECTION)
        .map(|v| v.as_bytes().eq_ignore_ascii_case(b"close"))
        .unwrap_or(false);

    strip_hop_by_hop_headers(&mut req);

    if config.bypass_chunk_modification {
        if host.ends_with("googlevideo.com") {
            if config.debug { println!("[PROXY] Bypassing chunk modification for {}", host); }
        }
    } else if modify_request_headers(&mut req, host) {
        if config.debug { println!("[PROXY] Modified Range header for {}", host); }
    }

    let (mut sender, abort_handle) = config.get_or_create_connection(host, port, is_tls).await?;

    let default_port = if is_tls { 443 } else { 80 };
    let host_header = if port == default_port {
        http::HeaderValue::from_str(host)
    } else {
        http::HeaderValue::from_str(&format!("{}:{}", host, port))
    }
    .map_err(|_| ProxyError::InvalidUri(Cow::Owned(format!("Invalid host header: {}:{}", host, port))))?;

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

    parts.headers.insert(header::HOST, host_header.clone());

    let req = Request::from_parts(parts, body);
    let resp = match sender.send_request(req).await {
        Ok(resp) => resp,
        Err(e) => {
            // Abort the connection - body doesn't need to be consumed
            // as the connection is being torn down anyway
            abort_handle.abort();
            return Err(e.into());
        }
    };

    let (parts, incoming_body) = resp.into_parts();

    let can_reuse = !req_wants_close
        && parts.status != StatusCode::SWITCHING_PROTOCOLS
        && !sender.is_closed()
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
        // Do NOT abort immediately; let the body stream out
        let body = BodyWithAbortOnEnd::new(incoming_body, abort_handle);
        Ok(Response::from_parts(parts, body.map_err(|e| e).boxed()))
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

use bytes::Bytes;
use dashmap::DashMap;
use http_body::{Body, Frame};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use lru::LruCache;
use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::task::AbortHandle;

use crate::proxy::ProxyError;

pub const CHUNK_SIZE: u64 = 10 * 1024 * 1024;
pub const CONNECTION_POOL_SIZE: usize = 100;
pub const CONNECTION_TTL: Duration = Duration::from_secs(60);

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;
pub type ProxyResult<T> = Result<T, ProxyError>;

pub struct PooledConnection {
    sender: Option<SendRequest<Incoming>>,
    created_at: Instant,
    abort_handle: AbortHandle,
}

impl PooledConnection {
    pub fn is_valid(&self) -> bool {
        self.created_at.elapsed() < CONNECTION_TTL && self.sender.is_some()
    }

    pub fn take(mut self) -> Option<(SendRequest<Incoming>, AbortHandle)> {
        self.sender.take().map(|sender| {
            let handle = std::mem::replace(
                &mut self.abort_handle,
                tokio::task::spawn(async {}).abort_handle(),
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

/// A connection pool for HTTP/HTTPS connections with LRU eviction and TTL-based expiration.
pub struct ConnectionPool {
    pool: DashMap<ConnKey, Mutex<Vec<PooledConnection>>>,
    state: Mutex<(LruCache<ConnKey, ()>, usize)>,
}

impl ConnectionPool {
    /// Creates a new empty connection pool.
    pub fn new() -> Self {
        Self {
            pool: DashMap::new(),
            state: Mutex::new((
                LruCache::new(std::num::NonZeroUsize::new(CONNECTION_POOL_SIZE).unwrap()),
                0,
            )),
        }
    }

    /// Retrieves a reusable connection for the given host/port/TLS combination.
    /// Returns None if no valid connection is available.
    pub fn get(
        &self,
        host: &str,
        port: u16,
        is_tls: bool,
    ) -> Option<(SendRequest<Incoming>, AbortHandle)> {
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

    /// Stores a connection in the pool for reuse.
    /// If the pool is at capacity, the oldest entry is evicted.
    pub fn put(
        &self,
        host: String,
        port: u16,
        is_tls: bool,
        sender: SendRequest<Incoming>,
        abort_handle: AbortHandle,
    ) {
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

        let entry = self
            .pool
            .entry(key)
            .or_insert_with(|| Mutex::new(Vec::with_capacity(4)));
        entry.value().lock().push(PooledConnection {
            sender: Some(sender),
            created_at: Instant::now(),
            abort_handle,
        });
    }

    /// Removes expired connections from the pool.
    /// Should be called periodically (e.g., every 30 seconds).
    pub fn cleanup(&self) {
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

/// A body wrapper that returns the connection to the pool when fully consumed.
pub struct BodyWithPoolReturn {
    inner: Incoming,
    pool: Arc<ConnectionPool>,
    target: Option<crate::proxy::ConnectionTarget>,
    sender: Option<SendRequest<Incoming>>,
    abort_handle: Option<AbortHandle>,
}

impl BodyWithPoolReturn {
    /// Creates a new BodyWithPoolReturn that will return the connection to the pool when dropped.
    pub fn new(
        inner: Incoming,
        pool: Arc<ConnectionPool>,
        target: crate::proxy::ConnectionTarget,
        sender: SendRequest<Incoming>,
        abort_handle: AbortHandle,
    ) -> Self {
        Self {
            inner,
            pool,
            target: Some(target),
            sender: Some(sender),
            abort_handle: Some(abort_handle),
        }
    }

    fn return_to_pool(&mut self) {
        if let (Some(sender), Some(target), Some(abort_handle)) = (
            self.sender.take(),
            self.target.take(),
            self.abort_handle.take(),
        ) {
            self.pool.put(target.host, target.port, target.is_tls, sender, abort_handle);
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

/// A body wrapper that keeps the abort_handle alive until the body is consumed.
/// Used when pooling is disabled to prevent the connection from being aborted prematurely.
pub struct BodyWithAbortHandle {
    inner: Incoming,
    abort_handle: Option<AbortHandle>,
}

impl BodyWithAbortHandle {
    /// Creates a new BodyWithAbortHandle that will abort the connection task on error
    /// or when dropped after the body is fully consumed.
    pub fn new(inner: Incoming, abort_handle: AbortHandle) -> Self {
        Self {
            inner,
            abort_handle: Some(abort_handle),
        }
    }
}

impl Body for BodyWithAbortHandle {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let inner = Pin::new(&mut self.inner);
        match inner.poll_frame(cx) {
            Poll::Ready(None) => {
                // Body fully consumed, abort the connection task
                if let Some(handle) = self.abort_handle.take() {
                    handle.abort();
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                // Error occurred, abort the connection task
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

impl Drop for BodyWithAbortHandle {
    fn drop(&mut self) {
        // Abort the connection task if not already aborted
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }
    }
}

pub fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn error_response(status: http::StatusCode, msg: &'static str) -> http::Response<ProxyBody> {
    let body = if msg.is_empty() {
        empty_body()
    } else {
        Full::new(Bytes::from_static(msg.as_bytes()))
            .map_err(|never| match never {})
            .boxed()
    };
    http::Response::builder()
        .status(status)
        .body(body)
        .expect("valid response")
}

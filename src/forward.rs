//! HTTP request forwarding module.
//!
//! Handles forwarding HTTP requests to upstream servers and managing
//! response body streaming with connection pool integration.

use http::{header::*, Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::borrow::Cow;
use std::sync::Arc;

use crate::pool::{BodyWithAbortHandle, BodyWithPoolReturn, empty_body, ProxyBody};
use crate::types::{ConnectionTarget, ProxyError, ProxyResult};
use crate::range::modify_youtube_range_headers;

/// Trait for types that can provide connections.
/// Used to break circular dependencies between proxy and forward modules.
pub trait ConnectionProvider: Send + Sync {
    /// Gets or creates a connection to the target.
    fn get_or_create_connection(
        &self,
        target: &ConnectionTarget,
    ) -> impl std::future::Future<Output = ProxyResult<(hyper::client::conn::http1::SendRequest<Incoming>, tokio::task::AbortHandle)>> + Send;

    /// Returns the connection pool.
    fn connection_pool(&self) -> Arc<crate::pool::ConnectionPool>;

    /// Whether chunk modification is bypassed.
    fn bypass_chunk_modification(&self) -> bool;

    /// Whether pooling is disabled.
    fn disable_pooling(&self) -> bool;

    /// Returns the certificate authority for TLS interception.
    fn ca(&self) -> Arc<crate::certificate::CertificateAuthority>;
}

/// Strips hop-by-hop headers that should not be forwarded.
///
/// Removes headers like Connection, Proxy-Connection, Keep-Alive, etc.
/// These headers are meant for the immediate connection and should not
/// be passed to the upstream server.
#[inline]
pub fn strip_hop_by_hop_headers<T>(req: &mut Request<T>) {
    let headers = req.headers_mut();
    headers.remove(CONNECTION);
    headers.remove("Proxy-Connection");
    headers.remove("Keep-Alive");
    headers.remove(UPGRADE);
    headers.remove("TE");
    headers.remove("Trailer");
    headers.remove(TRANSFER_ENCODING);
}

/// Forwards an HTTP request to the target and returns the response.
///
/// This function:
/// 1. Strips hop-by-hop headers
/// 2. Optionally modifies Range headers for YouTube optimization
/// 3. Obtains a connection to the target (from pool or new)
/// 4. Sends the request and returns the response
/// 5. Handles connection reuse for keep-alive
///
/// # Arguments
/// * `req` - The incoming HTTP request
/// * `target` - The target connection specification (host, port, TLS)
/// * `provider` - Something that can provide connections
pub async fn forward_request<P>(
    mut req: Request<Incoming>,
    target: &ConnectionTarget,
    provider: Arc<P>,
) -> ProxyResult<Response<ProxyBody>>
where
    P: ConnectionProvider,
{
    strip_hop_by_hop_headers(&mut req);

    if provider.bypass_chunk_modification() {
        if target.host.ends_with("googlevideo.com") {
            println!("[PROXY] Bypassing chunk modification for {}", target.host);
        }
    } else if modify_youtube_range_headers(&mut req, &target.host) {
        println!("[PROXY] Modified Range header for {}", target.host);
    }

    let (mut sender, abort_handle) = provider.get_or_create_connection(target).await?;

    let host_header = if target.port == target.default_port() {
        http::HeaderValue::from_str(&target.host)
    } else {
        http::HeaderValue::from_maybe_shared(format!("{}:{}", target.host, target.port))
    }
    .expect("valid host header");

    let (mut parts, body) = req.into_parts();

    if target.is_tls {
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

    if can_reuse && !provider.disable_pooling() {
        let body = BodyWithPoolReturn::new(
            incoming_body,
            provider.connection_pool(),
            target.clone(),
            sender,
            abort_handle,
        );
        Ok(Response::from_parts(parts, body.boxed()))
    } else {
        // Wrap body to keep abort_handle alive until body is consumed
        // This prevents the connection from being aborted prematurely
        let body = BodyWithAbortHandle::new(incoming_body, abort_handle);
        Ok(Response::from_parts(parts, body.boxed()))
    }
}

/// Handles plain HTTP (non-CONNECT) requests.
///
/// Handles GET/HEAD requests to the root path with a simple OK response.
/// For other requests, extracts the target from the URI and forwards the request.
///
/// # Arguments
/// * `req` - The incoming HTTP request
/// * `provider` - Something that can provide connections
pub async fn handle_http<P>(
    req: Request<Incoming>,
    provider: Arc<P>,
) -> ProxyResult<Response<ProxyBody>>
where
    P: ConnectionProvider,
{
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
    let target = ConnectionTarget { host, port, is_tls: false };

    forward_request(req, &target, provider).await
}

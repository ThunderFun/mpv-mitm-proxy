//! HTTP request forwarding module.
//!
//! Handles forwarding HTTP requests to upstream servers and managing
//! response body streaming.

use http::{header::*, Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::borrow::Cow;
use std::sync::Arc;

use tracing::debug;

use crate::pool::{BodyWithAbortHandle, BodyWithPoolReturn, empty_body, ProxyBody};
use crate::types::{ConnectionTarget, ProxyError, ProxyResult};
use crate::range::modify_youtube_range_headers;
use crate::resume::{response_range, ResumableBody};

/// Trait for types that can provide connections.
/// Used to break circular dependencies between proxy and forward modules.
pub trait ConnectionProvider: Send + Sync {
    /// Gets or creates a connection to the target.
    fn get_or_create_connection(
        &self,
        target: &ConnectionTarget,
    ) -> impl std::future::Future<Output = ProxyResult<(hyper::client::conn::http1::SendRequest<ProxyBody>, tokio::task::AbortHandle)>> + Send;

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
    headers.remove("Proxy-Authorization");
}

/// Forwards an HTTP request to the target and returns the response.
///
/// This function:
/// 1. Strips hop-by-hop headers
/// 2. Optionally modifies Range headers for YouTube stream delivery
/// 3. Obtains a connection to the target (from pool or new)
/// 4. Sends the request and returns the response
/// 5. Handles connection reuse for keep-alive
///
/// # Arguments
/// * `req` - The incoming HTTP request.
/// * `target` - The target connection specification (host, port, TLS).
/// * `provider` - The connection provider.
pub async fn forward_request<P>(
    mut req: Request<Incoming>,
    target: &ConnectionTarget,
    provider: Arc<P>,
) -> ProxyResult<Response<ProxyBody>>
where
    P: ConnectionProvider + 'static,
{
    strip_hop_by_hop_headers(&mut req);

    let req_method = req.method().clone();
    let req_uri = req.uri().clone();
    debug!(method = %req_method, uri = %req_uri, host = %target.host, "forward_request called");

    if provider.bypass_chunk_modification() {
        if target.host.ends_with("googlevideo.com") {
            debug!(host = %target.host, "Bypassing chunk modification");
        }
    } else if modify_youtube_range_headers(&mut req, &target.host) {
        debug!(host = %target.host, "Modified Range header for YouTube");
    }

    let (mut sender, abort_handle) = provider.get_or_create_connection(target).await?;
    debug!(host = %target.host, port = target.port, "Connection obtained");

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

    let req = Request::from_parts(parts, body.boxed());

    // Save the original request for potential mid-stream resume.
    let resume_method = req.method().clone();
    let resume_uri = req.uri().clone();
    let resume_headers = req.headers().clone();

    debug!(method = %req_method, uri = %req_uri, "Sending request");
    let resp = match send_request_with_retry(
        req,
        &mut sender,
        abort_handle.clone(),
        req_method.clone(),
        req_uri.clone(),
        target,
        Arc::clone(&provider),
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            abort_handle.abort();
            return Err(e);
        }
    };

    let (parts, incoming_body) = resp.into_parts();
    debug!(status = %parts.status.as_u16(), method = %req_method, uri = %req_uri, "Response received");

    let can_reuse = parts.status != StatusCode::SWITCHING_PROTOCOLS
        && !matches!(
            parts.headers.get(CONNECTION),
            Some(v) if v.as_bytes().eq_ignore_ascii_case(b"close")
        );

    // Attempt to use a resumable body for range responses. Retries truncated
    // segments so the client sees a complete stream even when the upstream
    // drops mid-body.
    if req_method == Method::GET {
        if let Some(rr) = response_range(&parts.headers) {
            debug!(
                host = %target.host,
                range_start = rr.start,
                range_end = rr.end,
                expected = rr.expected,
                "wrapping response in ResumableBody"
            );
            let body = ResumableBody::new(
                incoming_body,
                Arc::clone(&provider),
                target.clone(),
                resume_method,
                resume_uri,
                resume_headers,
                rr.start,
                rr.end,
                rr.expected,
                abort_handle,
            );
            return Ok(Response::from_parts(parts, body.boxed()));
        }
    }

    // Non-resumable response: use existing wrappers.
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
        // Wrap body to keep abort_handle alive until body is consumed.
        // This prevents the connection from being aborted prematurely.
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
/// * `req` - The incoming HTTP request.
/// * `provider` - The connection provider.
pub async fn handle_http<P>(
    req: Request<Incoming>,
    provider: Arc<P>,
) -> ProxyResult<Response<ProxyBody>>
where
    P: ConnectionProvider + 'static,
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
    debug!(method = %req.method(), uri = %uri, host = %host, "handle_http processing request");
    let target = ConnectionTarget { host, port, is_tls: false };

    forward_request(req, &target, provider).await
}

const MAX_SEND_RETRIES: u32 = 2;
const SEND_RETRY_BACKOFF_BASE_MS: u64 = 150;

/// Forwards a request and retries on connection-level errors for idempotent requests.
///
/// For GET/HEAD/OPTIONS requests with empty bodies, if the initial send_request fails
/// with a connection error, we discard the connection, establish a fresh one, and retry
/// up to `MAX_SEND_RETRIES` times with exponential backoff.
async fn send_request_with_retry<P>(
    req: Request<ProxyBody>,
    sender: &mut hyper::client::conn::http1::SendRequest<ProxyBody>,
    abort_handle: tokio::task::AbortHandle,
    req_method: Method,
    req_uri: Uri,
    target: &ConnectionTarget,
    provider: Arc<P>,
) -> ProxyResult<Response<hyper::body::Incoming>>
where
    P: ConnectionProvider,
{
    let mut last_error = None;
    let is_idempotent = matches!(req_method, Method::GET | Method::HEAD | Method::OPTIONS);

    // Destructure once so we can rebuild the request for each attempt
    // without moving `req` inside the loop (which would be a use-after-move).
    let (parts, body) = req.into_parts();
    let req_headers = parts.headers.clone();
    let mut first_req = Some(Request::from_parts(parts, body));

    for attempt in 0..=MAX_SEND_RETRIES {
        if attempt > 0 {
            let delay = SEND_RETRY_BACKOFF_BASE_MS.saturating_mul(2_u64.saturating_pow(attempt - 1));
            debug!(
                method = %req_method, uri = %req_uri, host = %target.host,
                attempt = attempt, max = MAX_SEND_RETRIES, delay_ms = delay,
                "send_request failed, retrying after backoff"
            );
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

            // Obtain a fresh connection for the retry.
            let (new_sender, new_abort_handle) = provider.get_or_create_connection(target).await?;
            *sender = new_sender;
            let _ = abort_handle;
            // The old abort_handle is dropped; new_abort_handle takes over below.

            // Rebuild the request with the same method/uri/headers but an empty body,
            // since we're only retrying idempotent empty-body requests.
            let mut new_req = Request::builder()
                .method(req_method.clone())
                .uri(req_uri.clone())
                .body(empty_body())
                .map_err(ProxyError::Http)?;
            *new_req.headers_mut() = req_headers.clone();
            match sender.send_request(new_req).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    new_abort_handle.abort();
                    last_error = Some(e);
                    continue;
                }
            }
        }

        let send_req = first_req.take().expect("first_req only used on attempt 0");
        match sender.send_request(send_req).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                // Only retry idempotent, empty-body requests on connection errors.
                let is_retryable = is_idempotent && is_retryable_error(&e);
                if !is_retryable || attempt >= MAX_SEND_RETRIES {
                    abort_handle.abort();
                    return Err(e.into());
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap().into())
}

/// Determines if a Hyper error is retryable (connection-level failure).
fn is_retryable_error(e: &hyper::Error) -> bool {
    if e.is_closed() {
        return true;
    }
    if e.is_incomplete_message() {
        return true;
    }
    // Connection reset, broken pipe, etc.
    use std::error::Error;
    if e.source().and_then(|s| s.downcast_ref::<std::io::Error>())
        .map(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
        .unwrap_or(false)
    {
        return true;
    }
    false
}

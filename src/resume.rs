//! Mid-stream truncation recovery for response bodies.
//!
//! When the upstream connection drops mid-stream (premature EOF or body error)
//! before the full Content-Length has been delivered, this module detects the
//! truncation, re-issues a range request for the missing bytes, and splices
//! the new segment onto the outgoing stream so the client sees a complete,
//! untruncated body.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::*;
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use tokio::task::AbortHandle;
use tracing::{debug, warn};

use crate::forward::ConnectionProvider;
use crate::pool::empty_body;
use crate::range::build_range_value;
use crate::types::ConnectionTarget;

/// Maximum number of mid-stream resume attempts before giving up.
const MAX_RESUME_RETRIES: u32 = 3;
/// Base backoff between resume attempts; doubled each retry.
const RESUME_BACKOFF_BASE_MS: u64 = 200;

/// Result of a successful resume: a new body segment to stream.
struct ResumeSegment {
    body: Incoming,
    abort_handle: AbortHandle,
}

/// Parsed `Content-Range: bytes START-END/TOTAL` header.
#[derive(Clone, Copy, Debug)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
}

/// Parses a `Content-Range` response header value.
///
/// Handles `bytes START-END/TOTAL` and `bytes START-END/*` formats.
pub fn parse_content_range(value: &[u8]) -> Option<ContentRange> {
    let s = std::str::from_utf8(value).ok()?;
    let s = s.strip_prefix("bytes ")?;
    let slash = s.find('/')?;
    let range_part = &s[..slash];
    let dash = range_part.find('-')?;
    let start: u64 = range_part[..dash].parse().ok()?;
    let end: u64 = range_part[dash + 1..].parse().ok()?;
    Some(ContentRange { start, end })
}

/// Parses a `Content-Length` header value as u64.
pub fn parse_content_length(value: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(value).ok()?;
    s.trim().parse().ok()
}

/// Parsed range information from a response, used to set up resume tracking.
pub struct ResponseRange {
    pub start: u64,
    pub end: u64,
    pub expected: u64,
}

/// Extracts the byte range from a response's headers.
///
/// Prefers `Content-Range` (always present on 206 responses); falls back to
/// `Content-Length` with start=0 for 200 responses.
pub fn response_range(headers: &HeaderMap) -> Option<ResponseRange> {
    if let Some(cr) = headers.get(CONTENT_RANGE) {
        if let Some(parsed) = parse_content_range(cr.as_bytes()) {
            let expected = parsed.end - parsed.start + 1;
            return Some(ResponseRange { start: parsed.start, end: parsed.end, expected });
        }
    }
    if let Some(cl) = headers.get(CONTENT_LENGTH) {
        if let Some(len) = parse_content_length(cl.as_bytes()) {
            if len > 0 {
                return Some(ResponseRange { start: 0, end: len - 1, expected: len });
            }
        }
    }
    None
}

/// A response body wrapper that transparently resumes after mid-stream truncation.
///
/// When the inner body returns a premature EOF or a body-level error before
/// the expected number of bytes have been delivered, `ResumableBody` opens a
/// new upstream connection, re-requests the missing byte range
/// (`bytes=next_byte-range_end`), and continues streaming from where it left off. The downstream client sees
/// one continuous, complete body.
pub struct ResumableBody<P: ConnectionProvider + 'static> {
    /// Current underlying body being streamed.
    inner: Incoming,
    /// Connection provider for obtaining fresh connections on resume.
    provider: Arc<P>,
    /// The upstream target (host, port, is_tls).
    target: ConnectionTarget,
    /// Request method (always GET for range requests).
    method: Method,
    /// Request URI (as sent to upstream, with scheme+authority for TLS).
    uri: Uri,
    /// Request headers (as sent to upstream; Range will be overridden on retry).
    headers: HeaderMap,
    /// Absolute start byte of the range being served.
    range_start: u64,
    /// Absolute end byte of the range being served (inclusive).
    range_end: u64,
    /// Total bytes this response body should deliver (end - start + 1).
    expected: u64,
    /// Bytes delivered to the client so far.
    delivered: u64,
    /// Abort handle for the current upstream connection task.
    abort_handle: Option<AbortHandle>,
    /// In-flight retry future, if resuming.
    /// Wrapped in `Mutex` so that the containing `ResumableBody` is `Sync`
    /// (required for `BodyExt::boxed()` -> `BoxBody`). `Mutex<T>` is `Sync`
    /// whenever `T: Send`, and the future is `Send`.
    retry_fut: Option<parking_lot::Mutex<Pin<Box<dyn Future<Output = Option<ResumeSegment>> + Send>>>>,
    /// Number of resume attempts made so far.
    retries: u32,
    /// Last error from the inner body (for surfacing on retry exhaustion).
    last_error: Option<hyper::Error>,
    /// Set when we're done streaming (either complete or gave up).
    done: bool,
}

impl<P: ConnectionProvider + 'static> ResumableBody<P> {
    pub fn new(
        inner: Incoming,
        provider: Arc<P>,
        target: ConnectionTarget,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        range_start: u64,
        range_end: u64,
        expected: u64,
        abort_handle: AbortHandle,
    ) -> Self {
        Self {
            inner,
            provider,
            target,
            method,
            uri,
            headers,
            range_start,
            range_end,
            expected,
            delivered: 0,
            abort_handle: Some(abort_handle),
            retry_fut: None,
            retries: 0,
            last_error: None,
            done: false,
        }
    }

    fn start_retry(&mut self) {
        self.retries += 1;
        let retries = self.retries;
        let next_byte = self.range_start + self.delivered;
        let range_end = self.range_end;
        let provider = Arc::clone(&self.provider);
        let target = self.target.clone();
        let method = self.method.clone();
        let uri = self.uri.clone();
        let mut headers = self.headers.clone();

        // Abort the current (broken) connection.
        if let Some(h) = self.abort_handle.take() {
            h.abort();
        }

        debug!(
            retries,
            next_byte,
            range_end,
            delivered = self.delivered,
            expected = self.expected,
            "starting mid-stream resume"
        );

        self.retry_fut = Some(parking_lot::Mutex::new(Box::pin(async move {
            let backoff = RESUME_BACKOFF_BASE_MS
                .saturating_mul(2u64.saturating_pow(retries.saturating_sub(1)));
            tokio::time::sleep(Duration::from_millis(backoff)).await;

            fetch_resume_segment(
                &provider, &target, &method, &uri, &mut headers,
                next_byte, range_end,
            )
            .await
        })));
    }

    fn abort_current(&mut self) {
        if let Some(h) = self.abort_handle.take() {
            h.abort();
        }
    }
}

impl<P: ConnectionProvider + 'static> Body for ResumableBody<P> {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;

        loop {
            if this.done {
                return Poll::Ready(None);
            }

            // Drive any in-flight retry future.
            if let Some(retry_mutex) = this.retry_fut.take() {
                let result = {
                    let mut guard = retry_mutex.lock();
                    guard.as_mut().poll(cx)
                };
                match result {
                    Poll::Pending => {
                        this.retry_fut = Some(retry_mutex);
                        return Poll::Pending;
                    }
                    Poll::Ready(Some(segment)) => {
                        this.inner = segment.body;
                        this.abort_handle = Some(segment.abort_handle);
                        debug!(retries = this.retries, "mid-stream resume succeeded, streaming new segment");
                        // Fall through to poll the new inner body.
                    }
                    Poll::Ready(None) => {
                        // Retry failed (connection error or unexpected response).
                        if this.retries >= MAX_RESUME_RETRIES {
                            warn!(
                                retries = this.retries,
                                delivered = this.delivered,
                                expected = this.expected,
                                "mid-stream resume retries exhausted"
                            );
                            this.done = true;
                            if let Some(e) = this.last_error.take() {
                                return Poll::Ready(Some(Err(e)));
                            }
                            return Poll::Ready(None);
                        }
                        this.start_retry();
                        continue;
                    }
                }
            }

            // Poll the current inner body.
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,

                Poll::Ready(Some(Err(e))) => {
                    // Body error mid-stream -> attempt resume.
                    warn!(
                        error = %e,
                        delivered = this.delivered,
                        expected = this.expected,
                        "body error mid-stream, attempting resume"
                    );
                    this.last_error = Some(e);
                    if this.retries >= MAX_RESUME_RETRIES {
                        this.done = true;
                        if let Some(e) = this.last_error.take() {
                            return Poll::Ready(Some(Err(e)));
                        }
                        return Poll::Ready(None);
                    }
                    this.start_retry();
                    continue;
                }

                Poll::Ready(None) => {
                    // EOF from current segment.
                    if this.delivered >= this.expected {
                        // Complete delivery.
                        this.done = true;
                        this.abort_current();
                        return Poll::Ready(None);
                    }
                    // Premature EOF -- truncation detected.
                    warn!(
                        delivered = this.delivered,
                        expected = this.expected,
                        "premature EOF (truncated), attempting resume"
                    );
                    if this.retries >= MAX_RESUME_RETRIES {
                        warn!("mid-stream resume retries exhausted");
                        this.done = true;
                        this.abort_current();
                        return Poll::Ready(None);
                    }
                    this.start_retry();
                    continue;
                }

                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        let n = data.len() as u64;
                        this.delivered += n;
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        let remaining = self.expected.saturating_sub(self.delivered);
        SizeHint::with_exact(remaining)
    }
}

impl<P: ConnectionProvider + 'static> Drop for ResumableBody<P> {
    fn drop(&mut self) {
        self.abort_current();
    }
}

/// Obtains a fresh connection and issues a range request for the missing tail
/// of a truncated stream. Returns `Some(ResumeSegment)` on success or `None`
/// if the connection/request/response was invalid.
async fn fetch_resume_segment<P: ConnectionProvider + 'static>(
    provider: &Arc<P>,
    target: &ConnectionTarget,
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    next_byte: u64,
    range_end: u64,
) -> Option<ResumeSegment> {
    let range_value = build_range_value(next_byte, Some(range_end))?;
    headers.insert(RANGE, range_value);

    let (mut sender, abort_handle) = provider.get_or_create_connection(target).await.ok()?;

    let mut req = Request::new(empty_body());
    *req.method_mut() = method.clone();
    *req.uri_mut() = uri.clone();
    *req.headers_mut() = headers.clone();

    let resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "resume range request failed");
            abort_handle.abort();
            return None;
        }
    };

    let status = resp.status();
    if status != StatusCode::PARTIAL_CONTENT && status != StatusCode::OK {
        warn!(status = %status, "resume request returned unexpected status");
        abort_handle.abort();
        return None;
    }

    // Validate that the response covers the expected range.
    if let Some(cr) = resp.headers().get(CONTENT_RANGE) {
        if let Some(parsed) = parse_content_range(cr.as_bytes()) {
            if parsed.start != next_byte {
                warn!(
                    expected_start = next_byte,
                    actual_start = parsed.start,
                    "resume Content-Range start mismatch"
                );
                abort_handle.abort();
                return None;
            }
        }
    }

    Some(ResumeSegment {
        body: resp.into_body(),
        abort_handle,
    })
}

//! Range header manipulation module.
//!
//! Provides functionality for parsing and modifying HTTP Range headers,
//! specifically optimized for streaming with fixed-size chunks.

use http::{header::RANGE, Request};

use crate::pool::CHUNK_SIZE;

/// Parses a byte range header value in the format "bytes=start-" (open-ended).
/// Returns Some(start_byte) on success, None if parsing fails or format is invalid.
pub fn parse_open_ended_range(range_bytes: &[u8]) -> Option<u64> {
    if range_bytes.len() < 8
        || !range_bytes.starts_with(b"bytes=")
        || !range_bytes.ends_with(b"-")
    {
        return None;
    }

    let start_bytes = &range_bytes[6..range_bytes.len() - 1];
    if start_bytes.is_empty() || start_bytes.contains(&b'-') {
        return None;
    }

    let mut start_byte: u64 = 0;
    for &b in start_bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        start_byte = match start_byte
            .checked_mul(10)
            .and_then(|n| n.checked_add((b - b'0') as u64))
        {
            Some(n) => n,
            None => return None,
        };
    }

    Some(start_byte)
}

/// Builds a closed byte range header value in the format "bytes=start-end".
pub fn build_range_header(start: u64, end: u64) -> Option<http::HeaderValue> {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(b"bytes=");
    push_u64(&mut buf, start);
    buf.push(b'-');
    push_u64(&mut buf, end);

    http::HeaderValue::from_bytes(&buf).ok()
}

/// Formats a u64 into a byte buffer.
#[inline]
pub fn push_u64(buf: &mut Vec<u8>, n: u64) {
    let mut itoa_buf = itoa::Buffer::new();
    buf.extend_from_slice(itoa_buf.format(n).as_bytes());
}

/// Modifies Range headers for YouTube (googlevideo.com) requests to optimize streaming.
/// Changes open-ended byte ranges (bytes=start-) to fixed-size chunks (bytes=start-end).
/// Returns true if the header was modified, false otherwise.
#[inline]
pub fn modify_youtube_range_headers<T>(req: &mut Request<T>, host: &str) -> bool {
    if !host.ends_with("googlevideo.com") {
        return false;
    }

    let range_header = match req.headers().get(RANGE) {
        Some(h) => h,
        None => return false,
    };

    let start_byte = match parse_open_ended_range(range_header.as_bytes()) {
        Some(start) => start,
        None => return false,
    };

    let new_end_byte = start_byte.saturating_add(CHUNK_SIZE - 1);

    let val = match build_range_header(start_byte, new_end_byte) {
        Some(v) => v,
        None => return false,
    };

    req.headers_mut().insert(RANGE, val);
    true
}

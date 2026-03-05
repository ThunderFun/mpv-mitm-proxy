// Re-exports for backwards compatibility
// These modules have been split for better organization:
// - tunnel: HTTP CONNECT handling and TLS tunneling
// - forward: HTTP request forwarding
// - range: Range header modification for streaming optimization

#![allow(unused_imports)]
pub use crate::forward::{forward_request, handle_http, strip_hop_by_hop_headers};
pub use crate::range::{modify_youtube_range_headers, parse_open_ended_range, build_range_header, push_u64};
pub use crate::tunnel::{handle_connect, handle_tunnel, extract_host_port};

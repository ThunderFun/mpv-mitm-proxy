# Rust MITM Proxy for mpv

A high-performance MITM proxy that enables seamless YouTube streaming in mpv, with optional support for upstream proxies and automatic stream optimization.

## Features

- **MITM Proxy**: Re-signs HTTPS traffic on the fly using an ephemeral internal CA.
- **Stream Optimization**: Transparently modifies specific request headers to ensure consistent stream delivery and compatibility with various network environments.
- **Optional Upstream Support**: Can connect to an upstream SOCKS5 proxy if needed.
- **mpv Integration**: Includes a Lua script for seamless integration with the mpv media player.
- **Performance**: Built with Rust and Tokio for high performance and low resource usage.

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable)
- [mpv](https://mpv.io/)
- (Optional) An upstream **SOCKS5** proxy (Note: HTTP/HTTPS upstream proxies are not supported)

## Installation

### 1. Build the Proxy

To build the proxy for your current platform:

```bash
cargo build --release
```

The binary will be located at `target/release/mpv-mitm-proxy`. For the Lua script to find it, you should either:
- Add the `target/release` directory to your system `PATH`.
- Move the `mpv-mitm-proxy` binary to a standard location like `/usr/local/bin/`.
- Place the binary in the same folder as the Lua script (see `mitm_rust_proxy.lua` for search logic).
- Edit `local script_dir = "[directory of mpv-mitm-proxy]"` in `mitm_rust_proxy.lua` to the directory of the binary.

### 2. Configure the Lua Script

Copy `mitm_rust_proxy.lua` to your mpv scripts directory (usually `~/.config/mpv/scripts/` on Linux/macOS or `%APPDATA%\mpv\scripts\` on Windows).

By default, the script is configured to use **no upstream proxy** (direct connection). You can modify this at the top of `mitm_rust_proxy.lua`:

- **To use an upstream proxy**: 
  ```lua
  local upstream_socks5_url = "socks5://127.0.0.1:1080"
  ```
- **To use NO upstream proxy** (direct connection): 
  ```lua
  local upstream_socks5_url = ""
  ```

Ensure the `proxy_binary` path or `find_binary` logic matches your system.

## Usage

The script automatically starts the proxy when you open a URL from supported domains (YouTube, etc.).

Press `Shift+P` (P) in mpv to check the proxy status.

## Security

The proxy utilizes an **ephemeral internal Certificate Authority (CA)** to re-sign traffic on the fly. This CA is generated in memory when the proxy starts and is not persisted to disk. This ensures that no sensitive CA keys are left behind on your system and provides a lightweight, secure approach for local traffic interception.

## License

MIT

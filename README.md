# Rust MITM Proxy for mpv

A high-performance MITM proxy that enables seamless YouTube streaming in mpv, with optional support for upstream proxies and automatic stream optimization.

## Features

- **MITM Proxy**: Re-signs HTTPS traffic on the fly using an ephemeral internal CA.
- **Stream Optimization**: Transparently modifies specific request headers to ensure consistent stream delivery and compatibility with various network environments.
- **Optional Upstream Support**: Can connect to an upstream HTTP/HTTPS/SOCKS5 proxy if needed.
- **Proxy Rotation**: Automatically rotates through a list of proxies when a "bot challenge" is detected.
- **Cooldown System**: Automatically puts blocked proxies on a 16-hour cooldown (configurable).
- **mpv Integration**: Includes a Lua script for seamless integration with the mpv media player.
- **Connection Pooling**: Efficiently reuses connections for improved performance and reduced latency.
- **Performance**: Built with Rust and Tokio for high performance and low resource usage.

## Prerequisites

- [mpv](https://mpv.io/)
- **Windows**: Visual C++ Redistributable (required for the pre-built binary)
- (Optional) One or more upstream proxies

## Installation

### 1. Download or Build

#### Download
Pre-built binaries are available from the [releases page](https://github.com/ThunderFun/mpv-mitm-proxy/releases).

#### Build
If you prefer to build from source, you will need [Rust](https://www.rust-lang.org/) (latest stable):
```bash
cargo build --release
```
The binary will be located at `target/release/mpv-mitm-proxy`.

### 2. Install to mpv

Create a new folder named `mpv-mitm-proxy` inside your mpv `scripts` directory:
- **Linux/macOS**: `~/.config/mpv/scripts/mpv-mitm-proxy/`
- **Windows**: `%APPDATA%\mpv\scripts\mpv-mitm-proxy\`

Place both the binary (`mpv-mitm-proxy` or `mpv-mitm-proxy.exe`) and the Lua script (`mitm_rust_proxy.lua`) into that folder.

## Configuration

### Proxy List (`proxies.txt`)
Create a `proxies.txt` file in the same directory as the script (included in release archives). Add one proxy URL per line. Supported proxy types: HTTP, HTTPS, and SOCKS5.
```text
socks5://127.0.0.1:1080
http://proxy.example.com:8080
https://proxy.example.com:8443
# Lines starting with # are ignored
```

### Script Options
The following options are defined in the Lua script with default values. You can modify them directly in `mitm_rust_proxy.lua`, or override them via `script-opts/mitm_rust_proxy.conf` or the command line:

| Option | Default | Description |
| :--- | :--- | :--- |
| `use_proxies` | `false` | Enable or disable the use of upstream proxies. |
| `proxy_rotation_enabled` | `false` | Enable proxy rotation when a proxy is blocked. |
| `cooldown_hours` | `16` | How long to block a proxy after a bot challenge. |
| `fallback_to_direct` | `false` | Use a direct connection if all proxies are blocked. |
| `direct_cdn` | `false` | Experimental: Use direct connection for CDN connections. |
| `ytdl_extractor_profile` | `android_vr` | YouTube extractor profile to use (`android_vr`, `ios_m3u8`, or `basic`). |
| `bypass_chunk_modification` | `false` | Disable chunk modification. |
| `verify_tls` | `false` | Verify TLS certificates from upstream servers. |
| `max_resolution` | `2160` | Maximum video resolution for the `ios_m3u8` extractor profile. |

Example command line usage:
```bash
mpv --script-opts=mitm_rust_proxy-use_proxies=no video_url
```

## Usage

The script automatically starts and configures the proxy whenever you open a URL that triggers `yt-dlp` in mpv.

- **Check Status**: Press `P` (Shift+p) in mpv to show the current proxy status, port, and upstream.

## Security

The proxy utilizes an **ephemeral internal Certificate Authority (CA)** to re-sign traffic on the fly. This CA is generated in memory when the proxy starts and is not persisted to disk. This ensures that no sensitive CA keys are left behind on your system and provides a lightweight, secure approach for local traffic interception.

## License

MIT

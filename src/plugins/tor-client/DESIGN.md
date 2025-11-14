# Arti Tor Client VPP Plugin - Design Document

## Overview

This plugin integrates the Arti Tor client (Rust implementation) into VPP as a native plugin, enabling VPP to route traffic through the Tor network for anonymity and censorship circumvention.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        VPP Core                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Session Layer│ -> │ Tor Plugin   │ -> │ IP Output    │  │
│  │ (SOCKS5)     │    │ (C + Rust)   │    │ (Tor Network)│  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ├─ C API (VPP Plugin Interface)
                              │
                       ┌──────▼──────────────────┐
                       │  Rust FFI Bridge        │
                       │  (libarti_vpp_ffi.so)   │
                       └──────┬──────────────────┘
                              │
                       ┌──────▼──────────────────┐
                       │  Arti Client Library    │
                       │  (async Rust runtime)   │
                       └─────────────────────────┘
                              │
                              ▼
                       Tor Network (Guards → Relays → Exit)
```

## Components

### 1. Rust FFI Library (`libarti_vpp_ffi`)

**Purpose**: Provide a C-compatible interface to arti-client

**Responsibilities**:
- Initialize Arti runtime (tokio)
- Manage Tor client lifecycle
- Create circuits and streams
- Handle async operations in separate thread
- Expose synchronous C API for VPP

**Key Functions**:
```c
// Initialize Arti with config directory
void* arti_init(const char *config_dir, const char *cache_dir);

// Create a new Tor stream to destination
int arti_connect(void *client, const char *addr, uint16_t port, void **stream);

// Send/receive data on stream
ssize_t arti_send(void *stream, const uint8_t *data, size_t len);
ssize_t arti_recv(void *stream, uint8_t *buf, size_t len);

// Close stream
void arti_close_stream(void *stream);

// Shutdown client
void arti_shutdown(void *client);
```

### 2. VPP Plugin (C)

**Purpose**: Integrate Arti into VPP's plugin architecture

**Files**:
- `tor_client.h/c` - Main plugin registration and state
- `tor_client.api` - Binary API definitions
- `tor_client_api.c` - API message handlers
- `tor_client_cli.c` - CLI commands
- `tor_socks5.c` - SOCKS5 protocol handler
- `CMakeLists.txt` - Build configuration

**VPP Integration Points**:
- **Session Layer**: Implement application protocol (SOCKS5 proxy)
- **Transport**: Bridge VPP sessions to Arti streams
- **Per-thread State**: Maintain Arti client instances
- **Event Loop**: Integrate with VPP's event system

### 3. Session/Application Protocol

**SOCKS5 Proxy Implementation**:
- Register as VPP application protocol
- Listen on configurable port (default: 9050)
- Handle SOCKS5 handshake
- Forward connections through Tor
- Bidirectional data transfer

**Flow**:
1. Client connects to VPP SOCKS5 port
2. SOCKS5 handshake (authentication, connect request)
3. Create Arti stream to destination
4. Proxy data bidirectionally
5. Handle connection teardown

## Configuration

### VPP CLI Commands

```bash
# Enable Tor client with SOCKS5 proxy
tor client enable port 9050

# Configure Tor directories
tor client config dir /var/lib/vpp/tor

# Show status
show tor status
show tor circuits

# Disable
tor client disable
```

### Config File

```
tor {
  enabled
  socks-port 9050
  config-dir /var/lib/vpp/tor
  cache-dir /var/cache/vpp/tor
}
```

## Build System

### Cargo.toml (Rust FFI Library)

```toml
[package]
name = "arti-vpp-ffi"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
arti-client = "1.0"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
```

### CMakeLists.txt (VPP Plugin)

```cmake
add_vpp_plugin(tor_client
  SOURCES
    tor_client.c
    tor_client_api.c
    tor_client_cli.c
    tor_socks5.c

  API_FILES
    tor_client.api

  LINK_LIBRARIES
    arti_vpp_ffi  # Rust FFI library
)
```

## Threading Model

**Arti Thread Pool**:
- Separate tokio runtime in background threads
- Handles all async Tor operations
- Communicates with VPP via thread-safe queues

**VPP Worker Threads**:
- Fast-path packet processing
- SOCKS5 protocol handling
- Enqueue requests to Arti threads
- Poll for completion

## Memory Management

**Rust Side**:
- Use `Box::into_raw()` / `Box::from_raw()` for FFI pointers
- Careful lifetime management
- No memory leaks across FFI boundary

**C Side**:
- VPP memory pools for packet buffers
- Reference counting for shared state
- Explicit cleanup on shutdown

## Security Considerations

1. **Isolation**: Arti runs in separate threads, crashes contained
2. **Resource Limits**: Connection limits, bandwidth throttling
3. **Configuration**: Secure defaults, sandboxing
4. **Logging**: Sanitized logs (no IP addresses in production)

## Performance Optimization

1. **Connection Pooling**: Reuse Tor circuits
2. **Buffer Management**: Zero-copy where possible
3. **Async Batching**: Group operations for efficiency
4. **Lock-free Queues**: Minimize contention between VPP and Arti threads

## Testing Strategy

1. **Unit Tests**: Rust FFI library
2. **Integration Tests**: VPP CLI commands
3. **Functional Tests**: SOCKS5 proxy with curl
4. **Performance Tests**: Throughput, latency benchmarks

## Deployment

```bash
# Build VPP with tor-client plugin
cd /home/user/vpp
./configure --enable-plugin tor_client
make rebuild

# Start VPP with Tor enabled
sudo vpp -c /etc/vpp/startup.conf

# In VPP CLI
vpp# tor client enable port 9050

# Test with curl
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

## Future Enhancements

1. **Pluggable Transports**: Obfuscation (obfs4, meek)
2. **Onion Services**: Hidden service support (.onion domains)
3. **Bridge Support**: Connect via bridges for censorship circumvention
4. **Multi-hop**: Custom circuit building
5. **API Extensions**: VPP Binary API for programmatic control
6. **Metrics**: Prometheus/statsd integration

## References

- Arti documentation: https://tpo.pages.torproject.net/core/arti/
- Arti client crate: https://docs.rs/arti-client/
- VPP plugin development: https://fd.io/docs/vpp/
- WireGuard plugin (reference): `/home/user/vpp/src/plugins/wireguard/`

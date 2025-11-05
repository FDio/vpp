# Arti Tor Client Plugin for VPP

A production-grade VPP plugin that integrates the Arti Tor client, providing SOCKS5 proxy functionality to route traffic through the Tor network for anonymity and censorship circumvention.

## Features

- **Full Arti Integration**: Leverages Arti 1.0+ Rust implementation of Tor
- **SOCKS5 Proxy**: RFC 1928 compliant SOCKS5 server integrated with VPP sessions
- **High Performance**: Zero-copy where possible, efficient async runtime integration
- **Production Ready**: Comprehensive error handling, thread safety, resource management
- **VPP Native**: Deep integration with VPP's session layer and packet processing
- **CLI Management**: Easy configuration via VPP CLI commands
- **Binary API**: Programmatic control via VPP Binary API

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
                       Tor Network
```

## Prerequisites

### System Requirements

- Linux (kernel 4.4+)
- x86_64 or ARM64 architecture
- 4GB+ RAM recommended
- 10GB+ disk space for Tor cache

### Build Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install -y \
    build-essential \
    cmake \
    rustc \
    cargo \
    libssl-dev \
    pkg-config

# Rust 1.86+ required
rustc --version

# If Rust is not installed or outdated:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Building

### Quick Build

```bash
# From VPP root directory
cd /path/to/vpp

# Configure with tor-client plugin
./configure --enable-plugin tor_client

# Build VPP with the plugin
make rebuild

# Or build just the plugin
make rebuild-tor_client
```

### Manual Build

```bash
# Build Rust FFI library first
cd src/plugins/tor-client/arti-ffi
cargo build --release

# Then build VPP plugin
cd ..
make rebuild
```

## Installation

```bash
# Install VPP with tor-client plugin
sudo make install

# Or install just the plugin
sudo make install-tor_client
```

## Configuration

### VPP Startup Configuration

Edit `/etc/vpp/startup.conf`:

```
plugins {
  plugin tor_client_plugin.so { enable }
}

tor {
  enabled
  socks-port 9050
  config-dir /var/lib/vpp/tor
  cache-dir /var/cache/vpp/tor
}
```

### Runtime Configuration (VPP CLI)

```bash
# Start VPP
sudo vpp

# In VPP CLI:
vpp# tor client enable port 9050
```

## Usage

### CLI Commands

```bash
# Enable Tor client
tor client enable [port <port>]

# Disable Tor client
tor client disable

# Show status and statistics
show tor status
show tor streams

# Test connection through Tor
test tor connect example.com 80
```

### Example: curl through VPP Tor Proxy

```bash
# With VPP Tor client running on port 9050:
curl --socks5 127.0.0.1:9050 https://check.torproject.org

# Check your Tor IP:
curl --socks5 127.0.0.1:9050 https://api.ipify.org
```

### Binary API

```python
# Python example using VPP API
from vpp_papi import VPPApiClient

vpp = VPPApiClient()
vpp.connect("tor_client")

# Enable Tor client
result = vpp.api.tor_client_enable_disable(
    enable=True,
    socks_port=9050
)

# Get statistics
stats = vpp.api.tor_client_get_stats()
print(f"Active streams: {stats.active_streams}")
print(f"Total bytes sent: {stats.total_bytes_sent}")
```

## Performance Tuning

### For High-Throughput Scenarios

```
tor {
  max-connections 10000
}

session {
  evt_qs_memfd_seg
  event-queue-length 32768
  preallocated-sessions 10000
}
```

### Memory Settings

```
unix {
  # Increase shared memory for many connections
  interactive
  cli-listen /run/vpp/cli.sock
  full-coredump
  log /var/log/vpp/vpp.log
}

buffers {
  buffers-per-numa 128000
}
```

## Security Considerations

1. **Firewall Rules**: Ensure only trusted clients can access SOCKS5 port
2. **Resource Limits**: Set appropriate `max-connections` to prevent DoS
3. **Logging**: Tor doesn't log destination IPs, but be careful with VPP debug logs
4. **Isolation**: Run VPP as dedicated user with minimal privileges
5. **Updates**: Keep Arti and VPP updated for security patches

### Recommended Firewall Rules

```bash
# Allow SOCKS5 only from localhost
sudo iptables -A INPUT -p tcp --dport 9050 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9050 -j DROP
```

## Monitoring

### Statistics

```bash
vpp# show tor status
Tor Client Statistics:
  Status: Enabled
  SOCKS5 Port: 9050
  Active Streams: 15
  Total Connections: 1234
  Total Bytes Sent: 12345678
  Total Bytes Received: 87654321
  Arti Version: arti-vpp-ffi 0.1.0

vpp# show tor streams
Active Tor Streams: 15

Index  Destination            Age        TX Bytes        RX Bytes
------  ---------------------  ----------  ---------------  ---------------
0      port 443               12.3s      1024            2048
1      port 80                5.7s       512             1024
...
```

### Logging

```bash
# Enable debug logging
vpp# set logging class tor_client level debug

# View logs
tail -f /var/log/vpp/vpp.log
```

## Troubleshooting

### Common Issues

#### Tor client fails to initialize

```bash
# Check permissions on Tor directories
sudo mkdir -p /var/lib/vpp/tor /var/cache/vpp/tor
sudo chown vpp:vpp /var/lib/vpp/tor /var/cache/vpp/tor
```

#### Connection failures

```bash
# Verify Tor is actually running
vpp# show tor status

# Test basic connectivity
vpp# test tor connect check.torproject.org 443

# Check VPP interfaces are up
vpp# show interface
```

#### Performance issues

```bash
# Check worker threads
vpp# show threads

# Monitor session usage
vpp# show session

# Check buffer allocation
vpp# show buffers
```

### Debug Mode

```bash
# Build in debug mode for verbose logging
cd src/plugins/tor-client/arti-ffi
./build.sh debug

cd ..
make rebuild
```

## Development

### Project Structure

```
tor-client/
├── DESIGN.md               # Detailed architecture document
├── README.md               # This file
├── CMakeLists.txt          # Build configuration
├── tor_client.h            # Main header
├── tor_client.c            # Plugin core
├── tor_client_api.c        # Binary API handlers
├── tor_client_cli.c        # CLI commands
├── tor_client.api          # API definitions
├── tor_socks5.c            # SOCKS5 implementation
└── arti-ffi/               # Rust FFI library
    ├── Cargo.toml
    ├── build.sh
    └── src/
        └── lib.rs          # Rust<->C FFI bindings
```

### Testing

```bash
# Run VPP tests
make test

# Run Rust tests
cd src/plugins/tor-client/arti-ffi
cargo test

# Integration test
cd /path/to/vpp
make test TEST=tor_client
```

### Contributing

1. Follow VPP coding standards
2. Add tests for new features
3. Update documentation
4. Ensure clean builds: `make rebuild`
5. Run tests: `make test`

## References

- [Arti Documentation](https://tpo.pages.torproject.net/core/arti/)
- [VPP Documentation](https://fd.io/docs/vpp/)
- [SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)
- [Tor Protocol Specification](https://spec.torproject.org/)

## License

Copyright (c) 2025 Internet Mastering & Company, Inc.

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## Support

For issues and questions:
- VPP plugin issues: Submit to VPP project
- Arti issues: https://gitlab.torproject.org/tpo/core/arti/-/issues
- Integration questions: Check DESIGN.md

## Changelog

### Version 0.1.0 (2025-11-05)

- Initial release
- Full Arti 1.3+ integration
- RFC 1928 compliant SOCKS5 proxy
- VPP session layer integration
- CLI and Binary API support
- Production-grade error handling
- Comprehensive documentation

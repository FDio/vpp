# WireGuard TCP Transport Implementation

## Overview

This document describes the implementation of TCP transport support for the WireGuard plugin in VPP. The goal is to allow WireGuard to tunnel its encrypted packets over TCP in addition to the standard UDP transport.

## Motivation

WireGuard traditionally uses UDP as its transport protocol. However, there are scenarios where TCP transport is beneficial:

1. **Firewall/NAT Traversal**: Some restrictive networks block UDP or perform deep packet inspection that identifies WireGuard traffic
2. **TCP-only Networks**: Some enterprise or cellular networks only allow TCP connections
3. **Censorship Circumvention**: TCP-based tunnels can help bypass censorship systems that block VPN protocols
4. **Amnezia WireGuard Compatibility**: This work complements the Amnezia WireGuard support being implemented by another agent

## Design Approach

### Transport Abstraction Layer

We've created a transport abstraction layer that allows WireGuard to support multiple transport protocols:

1. **Transport Type Enum** (`wireguard_transport.h`):
   - `WG_TRANSPORT_UDP` (0) - Standard UDP transport
   - `WG_TRANSPORT_TCP` (1) - TCP transport

2. **TCP Framing Protocol**:
   - Since TCP is stream-based, we need to delimit WireGuard messages
   - We use a simple 2-byte length prefix in network byte order
   - Format: `[2-byte length][WireGuard message]`
   - This is similar to approaches used by udp2raw and OpenVPN over TCP

3. **TCP State Management**:
   - Each peer maintains TCP connection state (`wg_tcp_state_t`)
   - Tracks sequence numbers, window sizes, and connection status
   - Uses a simplified stateless model suitable for encrypted tunnels

### Architecture Changes

#### Data Structures

1. **Interface (`wg_if_t`)**:
   - Added `wg_transport_type_t transport` field
   - Stores the transport protocol for the interface

2. **Peer Endpoint (`wg_peer_endpoint_t`)**:
   - Added `wg_transport_type_t transport` field
   - Each endpoint can use a different transport

3. **Peer (`wg_peer_t`)**:
   - Added `wg_tcp_state_t tcp_state` field
   - Stores TCP connection state when using TCP transport

#### API Changes

1. **VPP API** (`wireguard.api`):
   - Version bumped to 1.4.0
   - Added `wireguard_transport_type` enum
   - Added transport field to `wireguard_interface` typedef

2. **CLI**:
   - Updated `wireguard create` command
   - New syntax: `wireguard create ... [transport udp|tcp]`
   - Defaults to UDP for backward compatibility

3. **C API** (`wireguard_if.h`):
   - Updated `wg_if_create()` signature to accept transport parameter

### Header Structures

#### UDP Headers (Existing)
```c
typedef struct ip4_udp_header_t_ {
  ip4_header_t ip4;
  udp_header_t udp;
} ip4_udp_header_t;
```

#### TCP Headers (New)
```c
typedef struct ip4_tcp_header_t_ {
  ip4_header_t ip4;
  tcp_header_t tcp;
} ip4_tcp_header_t;

typedef struct ip4_tcp_wg_header_t_ {
  ip4_header_t ip4;
  tcp_header_t tcp;
  wg_tcp_frame_header_t frame;  // 2-byte length prefix
  /* WireGuard message follows */
} ip4_tcp_wg_header_t;
```

## Implementation Status

### Completed

✅ Transport abstraction layer design
✅ Header file with TCP structures and framing protocol
✅ Data structure updates (interface, peer, endpoint)
✅ API updates (VPP API, CLI, C API)
✅ Format functions for transport types
✅ Interface creation with transport parameter
✅ Basic infrastructure for TCP support

### Remaining Work

❌ TCP Input Nodes:
- Create `wg4_tcp_input_node` and `wg6_tcp_input_node`
- Implement TCP packet reception and de-framing
- Extract WireGuard messages from TCP stream
- Handle TCP connection state

❌ TCP Output Handling:
- Modify `wireguard_send.c` to build TCP headers
- Implement TCP framing (add 2-byte length prefix)
- Update rewrite generation for TCP transport
- Compute TCP checksums

❌ TCP Registration:
- Implement TCP port registration mechanism
- TCP connection management for peers
- Handle TCP handshake and state machine
- Connection teardown on peer removal

❌ Peer Management:
- Update `wg_peer_add()` to accept transport parameter
- Set peer endpoint transport type
- Initialize TCP state for TCP peers
- Update rewrite building logic

❌ Testing:
- Unit tests for TCP framing/deframing
- Integration tests for TCP transport
- Performance benchmarks
- Interoperability testing

## TCP vs UDP Differences

| Aspect | UDP | TCP |
|--------|-----|-----|
| Registration | `udp_register_dst_port()` | Custom input nodes (to be implemented) |
| Framing | Not needed (packet-based) | 2-byte length prefix required |
| State | Stateless | Connection state per peer |
| Headers | IP + UDP | IP + TCP + length prefix |
| Checksums | Optional (IPv4), mandatory (IPv6) | Always required |
| Ordering | Best effort | In-order delivery |
| Retransmission | WireGuard handles | TCP handles |

## Usage

### Creating a WireGuard Interface with UDP (Default)
```
vpp# wireguard create listen-port 51820 private-key <key> src 10.0.0.1
```

### Creating a WireGuard Interface with TCP
```
vpp# wireguard create listen-port 51820 private-key <key> src 10.0.0.1 transport tcp
```

**Note**: TCP transport is currently not fully functional and will return an error. The infrastructure is in place but requires implementation of TCP input/output nodes.

## Files Modified/Created

### Created:
- `src/plugins/wireguard/wireguard_transport.h` - Transport abstraction layer
- `src/plugins/wireguard/wireguard_transport.c` - Format functions
- `WIREGUARD_TCP_IMPLEMENTATION.md` - This document

### Modified:
- `src/plugins/wireguard/wireguard_if.h` - Added transport to interface
- `src/plugins/wireguard/wireguard_if.c` - Updated interface creation
- `src/plugins/wireguard/wireguard_peer.h` - Added transport to endpoint and TCP state
- `src/plugins/wireguard/wireguard_cli.c` - CLI transport parameter
- `src/plugins/wireguard/wireguard_api.c` - API handler updates
- `src/plugins/wireguard/wireguard.api` - API definition updates

## Implementation Approach

The implementation follows a phased approach:

### Phase 1: Infrastructure (COMPLETED)
- Transport abstraction layer
- Data structure updates
- API/CLI updates

### Phase 2: TCP I/O (TODO)
- TCP input node implementation
- TCP output and rewrite generation
- TCP framing/deframing logic

### Phase 3: Connection Management (TODO)
- TCP connection state machine
- Port registration and routing
- Connection establishment and teardown

### Phase 4: Testing & Optimization (TODO)
- Functional testing
- Performance optimization
- Documentation updates

## Technical Considerations

### TCP Connection Model

Unlike VPP's full TCP stack which uses the session layer, WireGuard's TCP transport uses a simplified model:

1. **No formal TCP handshake for WireGuard messages**: The TCP connection is used purely as a transport layer
2. **Sequence numbers tracked per-peer**: Each peer maintains its own TCP state
3. **No retransmission at WireGuard level**: TCP handles retransmission, WireGuard focuses on encryption
4. **No congestion control**: The tunnel itself handles backpressure

This approach keeps the implementation simple while providing TCP's benefits.

### Framing Protocol

The 2-byte length prefix allows for:
- Maximum message size: 65,535 bytes
- Efficient parsing: Read 2 bytes, then read N bytes
- Clear message boundaries in TCP stream

Example frame:
```
[0x00, 0x94] [WireGuard message of 148 bytes]
```

### Performance Implications

TCP transport will have different performance characteristics:

- **Latency**: Higher due to TCP acknowledgments
- **Throughput**: May be lower due to TCP overhead
- **CPU**: Higher due to TCP state management
- **Firewall Traversal**: Better in restrictive networks

## Future Enhancements

1. **TCP Options Support**: Implement TCP timestamps, window scaling for better performance
2. **Connection Pooling**: Reuse TCP connections for multiple WireGuard sessions
3. **Obfuscation**: Add TLS wrapping or HTTP obfuscation for deeper censorship resistance
4. **Dynamic Transport**: Auto-switch between UDP and TCP based on network conditions
5. **MPTCP Support**: Use Multipath TCP for improved reliability and performance

## References

- WireGuard Protocol: https://www.wireguard.com/protocol/
- VPP TCP Implementation: `src/vnet/tcp/`
- udp2raw: https://github.com/wangyu-/udp2raw
- Amnezia WireGuard: https://github.com/amnezia-vpn/amneziawg

## Notes

This implementation provides the foundation for TCP transport in WireGuard. The core infrastructure is complete, but the actual TCP I/O handlers need to be implemented to make it functional.

The design is intentionally modular to allow for future transport protocols (e.g., QUIC, HTTP/2) by extending the transport abstraction layer.

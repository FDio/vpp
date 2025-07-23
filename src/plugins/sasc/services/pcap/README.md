# SASC PCAP Service

The SASC PCAP service provides packet capture functionality for SASC (Session-Aware Service Chain) sessions. It can be used as a service in SASC service chains to capture packets for analysis and debugging.

## Features

- **Service Chain Integration**: Can be added to any SASC service chain
- **Protocol Agnostic**: Works with all protocols (TCP, UDP, ICMP, etc.)
- **Configurable Capture**: Set filename, packet limits, and capture parameters
- **CLI Management**: Start, stop, and monitor capture via CLI commands
- **Test Integration**: Automatic PCAP capture during test execution

## Usage

### As a SASC Service

Add the PCAP service to a SASC service chain:

```bash
# Add PCAP service to chain 1
set sasc services 1 sasc-pcap sasc-tcp-check

# Show current services
show sasc services
```

### CLI Commands

#### Start PCAP Capture

```bash
# Start capture with default settings
sasc pcap start

# Start capture with custom filename
sasc pcap start filename /tmp/my_capture.pcap

# Start capture with custom packet limit
sasc pcap start filename /tmp/my_capture.pcap max-packets 5000
```

#### Stop PCAP Capture

```bash
# Stop capture and write file
sasc pcap stop
```

#### Show PCAP Status

```bash
# Show current PCAP service status
show sasc pcap
```

### Test Integration

Run tests with automatic PCAP capture:

```bash
# Run a specific test with PCAP capture
test sasc run establishment pcap /tmp/test_capture.pcap

# Run all tests in a category with PCAP capture
test sasc category basic pcap /tmp/basic_tests.pcap

# Run all tests with PCAP capture
test sasc all pcap /tmp/all_tests.pcap
```

## Configuration

### Default Settings

- **Default filename**: `/tmp/sasc_pcap_<timestamp>.pcap`
- **Default packet limit**: 1000 packets
- **Packet type**: IP packets
- **Capture size**: Up to ETHERNET_MAX_PACKET_BYTES per packet

### Service Chain Configuration

The PCAP service can be configured in service chains:

```bash
# Create a service chain with PCAP
set sasc services 1 sasc-pcap sasc-tcp-check sasc-l4-lifecycle

# Apply the chain to a tenant
set sasc tenant 0 context-id 1 forward-chain 1 reverse-chain 1 miss-chain 0
```

## File Format

The PCAP service generates standard libpcap format files that can be opened with:

- Wireshark
- tcpdump
- tshark
- Any libpcap-compatible tool

## Statistics

The PCAP service tracks:

- **Packets processed**: Total packets that passed through the service
- **Packets captured**: Total packets written to PCAP file
- **Bytes captured**: Total bytes written to PCAP file
- **Current session**: Packets captured in current capture session

## Examples

### Basic Usage

```bash
# Start capture
sasc pcap start filename /tmp/debug.pcap max-packets 1000

# Run some traffic through SASC
# ... traffic flows ...

# Stop capture
sasc pcap stop

# Check status
show sasc pcap
```

### Test Debugging

```bash
# Run a test with PCAP capture for debugging
test sasc run retransmit_basic pcap /tmp/retransmit_debug.pcap

# Open in Wireshark for analysis
wireshark /tmp/retransmit_debug.pcap
```

### Service Chain Debugging

```bash
# Add PCAP to existing chain for debugging
set sasc services 1 sasc-pcap sasc-tcp-check

# Start capture
sasc pcap start filename /tmp/chain_debug.pcap

# Generate traffic
# ... traffic flows ...

# Stop capture and analyze
sasc pcap stop
```

## Implementation Details

### Service Node

The PCAP service is implemented as a VPP graph node (`sasc-pcap`) that:

1. Processes packets in the SASC service chain
2. Captures packet data to PCAP buffers
3. Writes PCAP files when capture limits are reached
4. Maintains statistics and state

### Integration Points

- **SASC Service Framework**: Registered as a service with `SASC_SERVICE_DEFINE`
- **VPP Graph**: Implements standard VPP node interface
- **PCAP Infrastructure**: Uses VPP's built-in PCAP support
- **CLI Framework**: Integrates with VPP CLI system

### Performance Considerations

- **Minimal Overhead**: PCAP capture only occurs when enabled
- **Configurable Limits**: Packet limits prevent excessive disk usage
- **Efficient Buffering**: Uses VPP's optimized PCAP buffering
- **Thread Safety**: Proper locking for multi-threaded operation
# SASC Packet Statistics Service

The SASC Packet Statistics service provides comprehensive packet-level measurements and analytics for SASC (Session-Aware Service Chain) sessions. It collects detailed statistics about packet sizes, timing, protocols, and flow characteristics.

## Features

- **Packet Size Histograms**: 16-bucket log2 histogram for packet size distribution
- **Inter-Packet Gap Histograms**: 16-bucket log2 histogram for inter-packet timing
- **Protocol Analysis**: TCP, UDP, ICMP, and other protocol statistics
- **Inter-Packet Timing**: Min, max, and average inter-packet arrival times
- **Rate Monitoring**: Current and peak packets/bytes per second
- **Burst Detection**: Automatic detection of packet bursts and idle periods
- **Flow Statistics**: Total packets, bytes, and flow duration
- **Session-Level Tracking**: Per-session statistics collection
- **CLI Interface**: Commands to view statistics and summaries

## Packet Size Buckets (Log2)

The service uses log2 buckets for packet size distribution, providing better resolution for smaller packet sizes:

- **1B**: 1 byte packets
- **2B**: 2 byte packets
- **4B**: 4 byte packets
- **8B**: 8 byte packets
- **16B**: 16 byte packets
- **32B**: 32 byte packets
- **64B**: 64 byte packets (typical ACK size)
- **128B**: 128 byte packets
- **256B**: 256 byte packets
- **512B**: 512 byte packets
- **1024B**: 1KB packets
- **2048B**: 2KB packets
- **4096B**: 4KB packets
- **8192B**: 8KB packets
- **16384B**: 16KB packets
- **32768B+**: 32KB and larger packets

This log2 approach provides better granularity for smaller packets while efficiently handling larger packet sizes.

## Inter-Packet Gap Buckets (Log2)

The service also uses log2 buckets for inter-packet gap timing distribution:

- **1μs**: 1 microsecond gaps
- **2μs**: 2 microsecond gaps
- **4μs**: 4 microsecond gaps
- **8μs**: 8 microsecond gaps
- **16μs**: 16 microsecond gaps
- **32μs**: 32 microsecond gaps
- **64μs**: 64 microsecond gaps
- **128μs**: 128 microsecond gaps
- **256μs**: 256 microsecond gaps
- **512μs**: 512 microsecond gaps
- **1ms**: 1 millisecond gaps
- **2ms**: 2 millisecond gaps
- **4ms**: 4 millisecond gaps
- **8ms**: 8 millisecond gaps
- **16ms**: 16 millisecond gaps
- **32ms+**: 32 millisecond and larger gaps

This provides insight into traffic patterns, burst behavior, and network latency characteristics.

## Usage

### As a SASC Service

Add the packet-stats service to a SASC service chain:

```bash
# Add packet-stats service to chain 4
set sasc services 4 sasc-l4-lifecycle sasc-tcp-check sasc-packet-stats sasc-pcap error-drop

# Show current services
show sasc services
```

### CLI Commands

#### Show Session Statistics

```bash
# Show packet statistics for a specific session
show sasc packet-stats session <session-index>

# Example output:
# Session 5 Packet Statistics:
# Total Packets: 150
# Total Bytes: 45000
# Flow Duration: 1234567890 ns
# Protocol Statistics:
#   TCP: 150 packets
#   UDP: 0 packets
#   ICMP: 0 packets
#   Other: 0 packets
# Packet Size Histogram (Log2 Bins):
#   64B: 50 packets
#   128B: 30 packets
#   256B: 20 packets
#   512B: 25 packets
#   1024B: 15 packets
#   1500B: 10 packets
# Inter-Packet Gap Histogram (Log2 Bins):
#   1ms: 45 gaps
#   2ms: 30 gaps
#   4ms: 25 gaps
#   8ms: 20 gaps
#   16ms: 15 gaps
#   32ms+: 10 gaps
# Inter-Packet Timing:
#   Min: 0.000100 seconds
#   Max: 0.050000 seconds
#   Avg: 0.010000 seconds
#   Samples: 149
# Rate Statistics:
#   Current: 100 packets/sec, 45000 bytes/sec
#   Peak: 150.0 packets/sec, 67500.0 bytes/sec
#   Bursts: 25 detected
#   Idle Periods: 3 detected
```

#### Show Summary Statistics

```bash
# Show summary of all packet statistics
show sasc packet-stats summary

# Example output:
# Packet Statistics Summary:
# Active Sessions: 25
# Total Packets: 3750
# Total Bytes: 1125000
# Protocol Distribution:
#   TCP: 3000 packets
#   UDP: 500 packets
#   ICMP: 200 packets
#   Other: 50 packets
```

## Statistics Collected

### Per-Session Statistics

- **Total Packets**: Number of packets processed for the session
- **Total Bytes**: Total bytes processed for the session
- **Flow Duration**: Duration of the flow in nanoseconds
- **Protocol Counts**: Number of packets by protocol type
- **Packet Size Histogram**: Distribution across 8 size buckets
- **Inter-Packet Timing**: Min, max, and average timing between packets

### Global Statistics

- **Active Sessions**: Number of sessions with packet statistics
- **Aggregate Counts**: Sum of all session statistics
- **Protocol Distribution**: Overall protocol breakdown

## Performance Considerations

- **Memory Usage**: Statistics are stored per-session in a sparse vector
- **CPU Overhead**: Minimal overhead for packet processing
- **Scalability**: Designed to handle thousands of concurrent sessions
- **Thread Safety**: Statistics are collected per-thread for optimal performance

## Integration

The packet-stats service integrates seamlessly with other SASC services:

- **L4-Lifecycle**: Works with session state management
- **TCP-Check**: Complements TCP-specific analysis
- **PCAP**: Can be used together for comprehensive packet analysis
- **Error-Drop**: Handles error conditions gracefully

## Use Cases

### Network Analysis
- Identify traffic patterns and anomalies
- Monitor protocol distribution
- Analyze packet size characteristics
- Track flow durations and timing

### Performance Monitoring
- Measure inter-packet timing for latency analysis
- Monitor packet size distribution for bandwidth optimization
- Track session activity levels
- Identify protocol-specific patterns

### Troubleshooting
- Debug packet processing issues
- Analyze traffic patterns during problems
- Monitor service chain performance
- Validate packet handling behavior

## Implementation Details

### Service Node
The packet-stats service is implemented as a VPP graph node (`sasc-packet-stats`) that:
1. Processes packets in the SASC service chain
2. Extracts packet metadata (size, protocol, timing)
3. Updates session-specific statistics
4. Maintains histograms and timing data

### Data Structures
- **Session Data**: Per-session statistics storage
- **Histogram Buckets**: 16-bucket log2 packet size distribution
- **Timing Data**: Inter-packet timing statistics
- **Protocol Counters**: Per-protocol packet counts

### Integration Points
- **SASC Service Framework**: Registered with `SASC_SERVICE_DEFINE`
- **VPP Graph**: Standard VPP node interface
- **CLI Framework**: VPP CLI integration
- **Session Management**: Integrates with SASC session tracking
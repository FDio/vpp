# GPCAPng Plugin for VPP

## Overview

The GPCAPng plugin provides functionality for capturing GENEVE tunneled packets (IPv4/IPv6) to PCAPng files. The plugin supports advanced filtering based on GENEVE headers, options, and 5-tuple information for both outer and inner packets. The plugin uses a destination-based output system where captured packets are written to configurable output destinations.

## Features

- Captures GENEVE tunnel traffic to PCAPng-format files
- Per-interface or global capture filters
- Multiple output destinations (file, gzip, igzip, HTTP)
- Filtering based on:
  - GENEVE header fields (version, option length, protocol, VNI)
  - GENEVE options with customizable data matching
  - 5-tuple filtering for both outer and inner headers (IPv4/IPv6)
- Support for named option definitions for user-friendly filtering
- Per-worker thread output contexts for efficient packet capture
- Real-time packet display from PCAPng files

## Architecture

The plugin uses a three-tier system:

1. **Destinations**: Configure where captured packets are written (files, compressed files, HTTP endpoints)
2. **Filters**: Define which packets to capture based on GENEVE and IP header criteria
3. **Output Assignment**: Connect filters to specific destinations

## CLI Commands

### Managing Output Destinations

Before capturing packets, you must configure at least one output destination.

#### Adding Destinations

```bash
gpcapng destination add name <name> {file <path> | gzip <path> | igzip <path> | http <url>}
```

**Examples:**
```bash
# Standard PCAPng file
vpp# gpcapng destination add name main-capture file /tmp/geneve_capture.pcapng
Added destination: main-capture : /tmp/geneve_capture.pcapng (index: 0)

# Gzip compressed file
vpp# gpcapng destination add name compressed-capture gzip /tmp/geneve_compressed.pcapng.gz
Added destination: compressed-capture : /tmp/geneve_compressed.pcapng.gz (index: 1)

# HTTP endpoint
vpp# gpcapng destination add name remote-capture http https://192.0.2.1/upload
Added destination: remote-capture : https://192.0.2.1/upload (index: 2)
```

#### Viewing Destinations

```bash
show gpcapng destination [name <name>]
```

**Example output:**
```bash
vpp# show gpcapng destination
GPCAPNG Destinations (total: 2):
Index  Name                 Type       Path/URL
-----  ----                 ----       --------
0      main-capture         file       /tmp/geneve_capture.pcapng
1      compressed-capture   gzip       /tmp/geneve_compressed.pcapng.gz
```

#### Deleting Destinations

```bash
gpcapng destination del name <name>
```

**Example:**
```bash
vpp# gpcapng destination del name compressed-capture
Deleted GPCAPNG destination: compressed-capture
```

### Managing Filters

#### Adding Filters

```bash
gpcapng filter name <filtername> [interface <interface> | global] [ver <ver>] [opt-len <len>] [protocol <proto>] [vni <vni>] [outer-ipv4 | outer-ipv6 | inner-ipv4 | inner-ipv6] [option <name> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]] [option-direct class <class> type <type> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]]
```

The filter command supports extensive criteria for matching packets:

- `name <filtername>`: **Required** - Unique name for the filter
- `interface <interface>`: Apply filter to specific interface
- `global`: Create a global filter applied to all interfaces
- `ver <ver>`: Match GENEVE version field
- `opt-len <len>`: Match GENEVE option length field
- `protocol <proto>`: Match GENEVE protocol field
- `vni <vni>`: Match GENEVE VNI (Virtual Network Identifier)

**5-tuple filtering for outer and inner headers:**

- `outer-ipv4`: Filter on outer IPv4 header with the following sub-options:
  - `src-ip <ip>[/<prefix>]`: Source IP with optional prefix
  - `dst-ip <ip>[/<prefix>]`: Destination IP with optional prefix
  - `src-port <port>`: Source port
  - `dst-port <port>`: Destination port
  - `proto <protocol>`: IP protocol (tcp, udp, icmp, or number)

- `outer-ipv6`: Filter on outer IPv6 header with the same sub-options

- `inner-ipv4`/`inner-ipv6`: Filter on inner IP header with the same sub-options

**GENEVE option filtering:**

- `option <name>`: Filter based on a registered option name
  - `any`: Match any value of this option (presence only)
  - `value [type] <data>`: Match specific option data (type can be raw, ipv4, ipv6, uint8, uint16, uint32, or string)
  - `mask <mask>`: Apply a mask when matching option data

- `option-direct class <class> type <type>`: Filter based on option class/type values directly
  - With same sub-options as named options

**Examples:**

Basic filter matching GENEVE version and VNI:
```bash
vpp# gpcapng filter name basic-filter interface GigabitEthernet0/1/0 ver 0 vni 100
Added GENEVE interface filter with ID: 123456789
```

Global filter with IPv4 5-tuple:
```bash
vpp# gpcapng filter name web-traffic global outer-ipv4 { src-ip 192.168.1.0/24 dst-ip 10.0.0.1 proto tcp dst-port 80 }
Added GENEVE global filter with ID: 987654321
```

Filter with option matching:
```bash
vpp# gpcapng filter name metadata-filter interface GigabitEthernet0/1/0 option vpp-metadata value uint32 42
Added GENEVE interface filter with ID: 456789123
```

#### Deleting Filters

```bash
gpcapng filter [interface <interface> | global] del id <filter_id>
```

**Example:**
```bash
vpp# gpcapng filter global del id 987654321
Deleted GENEVE global filter with ID: 987654321
```

### Assigning Filters to Destinations

By default, filters capture to the first destination (index 0). You can assign filters to specific destinations:

#### Set Filter Output Destination

```bash
gpcapng output set filter <filter_name> destination <dest_name>
```

**Example:**
```bash
vpp# gpcapng output set filter web-traffic destination compressed-capture
Set global filter 'web-traffic' output to destination 'compressed-capture' (index 1)
```

#### Stop Filter Output

```bash
gpcapng output stop filter <filter_name>
```

**Example:**
```bash
vpp# gpcapng output stop filter web-traffic
Stopped output for global filter 'web-traffic'
```

### Enabling/Disabling Capture

After configuring destinations and filters, enable capture on interfaces:

```bash
gpcapng capture interface <interface> [disable]
```

**Example:**
```bash
vpp# gpcapng capture interface GigabitEthernet0/1/0
GENEVE packet capture enabled on interface 1

vpp# gpcapng capture interface GigabitEthernet0/1/0 disable
GENEVE packet capture disabled on interface 1
```

### Option Management

#### Registering Custom Options

```bash
gpcapng register-option name <name> class <class> type <type> length <length> [data-type raw|ipv4|ipv6|uint8|uint16|uint32|string]
```

**Parameters:**
- `name`: Friendly name for the option
- `class`: GENEVE option class field (16-bit value)
- `type`: GENEVE option type field (8-bit value)
- `length`: Length in bytes of the option data
- `data-type`: Preferred data type for this option (defaults to raw)

**Example:**
```bash
vpp# gpcapng register-option name tenant-id class 0x0124 type 0x01 length 4 data-type uint32
Registered GENEVE option: name=tenant-id, class=0x124, type=0x1, length=4, data-type=uint32
```

### Display Commands

#### Show Registered Options

```bash
show gpcapng options
```

**Example output:**
```bash
vpp# show gpcapng options
Registered GENEVE options:
Name                 Class      Type       Length     Data Type
-------------------- ---------- ---------- ---------- ----------
vpp-metadata         0x123      1          8          string
legacy-oam           0xf0f      1          4          uint32
tenant-ip            0x124      2          4          ipv4
tenant-ipv6          0x124      3          16         ipv6
flow-id              0x125      1          4          uint32
app-id               0x125      2          2          uint16
service-tag          0x126      1          8          string
```

#### Show Active Filters

```bash
show gpcapng filters
```

**Example output:**
```bash
vpp# show gpcapng filters
GENEVE Capture Filters:

Global Filters:
  Filter Name: web-traffic
  Filter ID: 987654321
  Destination Output Index: 1
    Protocol: 0x0800
    Outer 5-tuple filter:
       IPv4:
      Src IP: 192.168.1.0/24
      Dst IP: 10.0.0.1
       Protocol: TCP (6)
         Dst Port(22): 80

Interface: GigabitEthernet0/1/0 (idx 1) - Capture enabled
  Filter Name: basic-filter
  Filter ID: 123456789
  Destination Output Index: 0
    Version: 0
    VNI: 100
  
  Filter Name: metadata-filter
  Filter ID: 456789123
  Destination Output Index: 0
    Option Filters:
      Option: vpp-metadata (class=0x123, type=0x1)
        Match Value: "42"
        Raw Bytes: 00 00 00 2a
```

#### Show Captured Packets

```bash
show gpcapng capture <filename> [max-packets <count>] [verbose]
```

This command displays packets captured in PCAPng files with detailed GENEVE parsing.

**Parameters:**
- `filename`: Path to the PCAPng file to display
- `max-packets <count>`: Optional maximum number of packets to display
- `verbose`: Optional flag to display additional PCAPng structure information

**Example output:**
```bash
vpp# show gpcapng capture /tmp/geneve_capture.pcapng

Packet #1: timestamp=1652938275612, len=142, interface=GigabitEthernet0/1/0 (1)
Ethernet: 00:50:56:ae:b2:3f -> 00:50:56:ae:cc:1d, type=0x0800
  IPv4: 192.168.10.5 -> 10.0.0.10, len=128, ttl=64, protocol=17
  UDP: src_port=52431, dst_port=6081 (GENEVE), len=108, checksum=0x1234
  GENEVE: ver=0, opt_len=0 (words), 0 (bytes), protocol=IPv4 (0x0800), VNI=100 (0x64)
      Inner IPv4: 192.168.1.5 -> 10.0.0.5, len=84, proto=6
      Inner TCP: src_port=53123, dst_port=80 (HTTP), flags=SYN

Packet #2: timestamp=1652938275614, len=142, interface=GigabitEthernet0/1/0 (1)
Ethernet: 00:50:56:ae:cc:1d -> 00:50:56:ae:b2:3f, type=0x0800
  IPv4: 10.0.0.10 -> 192.168.10.5, len=128, ttl=64, protocol=17
  UDP: src_port=6081 (GENEVE), dst_port=52431, len=108, checksum=0x5678
  GENEVE: ver=0, opt_len=0 (words), 0 (bytes), protocol=IPv4 (0x0800), VNI=100 (0x64)
      Inner IPv4: 10.0.0.5 -> 192.168.1.5, len=84, proto=6
      Inner TCP: src_port=80 (HTTP), dst_port=53123, flags=SYN,ACK

Total packets displayed: 2
```

## Pre-registered Options

The plugin comes with several pre-registered GENEVE options:

| Name          | Class    | Type | Length | Data Type |
|---------------|----------|------|--------|-----------|
| vpp-metadata  | 0x0123   | 0x01 | 8      | string    |
| legacy-oam    | 0x0F0F   | 0x01 | 4      | uint32    |
| tenant-ip     | 0x0124   | 0x02 | 4      | ipv4      |
| tenant-ipv6   | 0x0124   | 0x03 | 16     | ipv6      |
| flow-id       | 0x0125   | 0x01 | 4      | uint32    |
| app-id        | 0x0125   | 0x02 | 2      | uint16    |
| service-tag   | 0x0126   | 0x01 | 8      | string    |

You can use these option names directly in filter commands without needing to register them.

## Usage Workflow

1. **Configure Destinations**: Set up one or more output destinations where captured packets will be written
2. **Create Filters**: Define filters with specific matching criteria and assign names
3. **Assign Outputs**: Connect filters to appropriate destinations (optional - defaults to first destination)
4. **Enable Capture**: Enable packet capture on the desired interfaces
5. **Monitor**: Use show commands to verify configuration and view captured packets

## Performance Considerations

- The plugin operates at the VPP dataplane level with minimal performance impact
- Per-worker thread contexts ensure efficient packet processing
- Compressed output destinations (gzip/igzip) reduce storage requirements
- Global filters apply to all interfaces, while per-interface filters are more targeted
- HTTP destinations allow real-time streaming to remote collectors

## File Output

- Each worker thread creates its own output file with suffix `-<N>`, where N is the worker thread id.
- Files are in standard PCAPng format compatible with Wireshark and other analysis tools
- Compressed files use standard gzip compression for space efficiency

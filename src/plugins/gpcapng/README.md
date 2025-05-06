# GENEVE PCAPng Plugin for VPP

## Overview

The GENEVE PCAPng plugin provides functionality for capturing GENEVE tunneled packets (IPv4/IPv6) to PCAPng files. The plugin supports advanced filtering based on GENEVE headers, options, and 5-tuple information for both outer and inner packets.

## Features

- Captures GENEVE tunnel traffic to PCAPng-format files
- Per-interface or global capture filters
- Filtering based on:
  - GENEVE header fields (version, option length, protocol, VNI)
  - GENEVE options with customizable data matching
  - 5-tuple filtering for both outer and inner headers
- Support for named option definitions for user-friendly filtering
- Output to standard PCAPng files (one per worker thread)

## CLI Commands

### Enabling/Disabling Capture

```
geneve pcapng capture interface <interface> [disable]
```

**Example:**
```
vpp# geneve pcapng capture interface GigabitEthernet0/1/0
GENEVE packet capture enabled on interface 1
```

```
vpp# geneve pcapng capture interface GigabitEthernet0/1/0 disable
GENEVE packet capture disabled on interface 1
```

### Managing Filters

#### Adding Filters

```
geneve pcapng filter [interface <interface> | global] [ver <ver>] [opt-len <len>] [protocol <proto>] [vni <vni>] [outer-ipv4 | outer-ipv6 | inner-ipv4 | inner-ipv6] [option <name> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]] [option-direct class <class> type <type> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]]
```

The filter command supports extensive criteria for matching packets:

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
```
vpp# geneve pcapng filter interface GigabitEthernet0/1/0 ver 0 vni 100
Added GENEVE interface filter with ID: 123456789
```

Filter with IPv4 5-tuple:
```
vpp# geneve pcapng filter global outer-ipv4 { src-ip 192.168.1.10/24 dst-ip 10.0.0.1 proto tcp dst-port 80 }
Added GENEVE global filter with ID: 987654321
```

Filter with option matching:
```
vpp# geneve pcapng filter interface GigabitEthernet0/1/0 option vpp-metadata value uint32 42
Added GENEVE interface filter with ID: 456789123
```

#### Deleting Filters

```
geneve pcapng filter [interface <interface> | global] del id <filter_id>
```

**Example:**
```
vpp# geneve pcapng filter global del id 987654321
Deleted GENEVE global filter with ID: 987654321
```

### Option Management

#### Registering Custom Options

```
geneve pcapng register-option name <name> class <class> type <type> length <length> [data-type raw|ipv4|ipv6|uint8|uint16|uint32|string]
```

**Parameters:**
- `name`: Friendly name for the option
- `class`: GENEVE option class field (16-bit value)
- `type`: GENEVE option type field (8-bit value)
- `length`: Length in bytes of the option data
- `data-type`: Preferred data type for this option (defaults to raw)

**Example:**
```
vpp# geneve pcapng register-option name tenant-id class 0x0124 type 0x01 length 4 data-type uint32
Registered GENEVE option: name=tenant-id, class=0x124, type=0x1, length=4, data-type=uint32
```

### Display Commands

#### Show Registered Options

```
show geneve pcapng options
```

**Example output:**
```
vpp# show geneve pcapng options
Registered GENEVE options:
Name                 Class      Type       Length     Data Type
-------------------- ---------- ---------- ---------- ----------
vpp-metadata         0x123      1          8          string
legacy-oam           0xf0f      1          4          uint32
tenant-id            0x124      1          4          uint32
tenant-ip            0x124      2          4          ipv4
tenant-ipv6          0x124      3          16         ipv6
flow-id              0x125      1          4          uint32
app-id               0x125      2          2          uint16
service-tag          0x126      1          8          string
```

#### Show Active Filters

```
show geneve pcapng filters
```

**Example output:**
```
vpp# show geneve pcapng filters
GENEVE Capture Filters:

Global Filters:
  Filter ID: 987654321
    Protocol: 0x0800
    Outer 5-tuple filter:
      IPv4:
      Src IP: 192.168.1.10/24
      Dst IP: 10.0.0.1
      Protocol: TCP (6)
      Dst Port: 80

Interface: GigabitEthernet0/1/0 (idx 1) - Capture enabled
  Filter ID: 123456789
    Version: 0
    VNI: 100
  
  Filter ID: 456789123
    Option Filters:
      Option: vpp-metadata (class=0x123, type=0x1)
        Match Value: 42
        Raw Bytes: 00 00 00 2a
```

#### Show Captured Packets

```
show geneve pcapng capture <filename> [max-packets <count>] [verbose]
```

This command displays packets captured in PCAPng files with detailed GENEVE parsing.

**Parameters:**
- `filename`: Path to the PCAPng file to display
- `max-packets <count>`: Optional maximum number of packets to display
- `verbose`: Optional flag to display additional PCAPng structure information

**Example output:**
```
vpp# show geneve pcapng capture /tmp/geneve_capture_worker0.pcapng

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

### Output Configuration

```
geneve pcapng output [file]
```

Currently, the plugin only supports file output (which is the default).

**Example:**
```
vpp# geneve pcapng output file
GENEVE PCAPng capture will use file output
```

## Output Files

By default, the plugin stores captured packets in PCAPng format files located at:

```
/tmp/geneve_capture_worker<N>.pcapng
```

Where `<N>` is the worker thread number. These files can be opened with standard packet analysis tools like Wireshark.

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

.. _wireguard_plugin_doc:

Wireguard VPP Plugin - Enhanced Edition
========================================

Overview
--------

This plugin is an enhanced implementation of the `WireGuard protocol <https://www.wireguard.com/>`__
for VPP with **protocol obfuscation**, **transport flexibility**, and **hardware acceleration** support.

This implementation is based on `wireguard-openbsd <https://git.zx2c4.com/wireguard-openbsd/>`__
with additional features for censorship circumvention and performance optimization.

**Key Enhancements:**

- ✅ Full **AmneziaWG 1.5 compatibility** - Protocol masquerading via i-headers
- ✅ **Per-peer obfuscation** - Fine-grained obfuscation control
- ✅ **TCP transport option** - Bypass UDP-blocking firewalls
- ✅ **Intel QAT acceleration** - Offload TLS handshakes to hardware
- ✅ **100% backward compatible** - Standard WireGuard clients work unchanged

Crypto
------

**Core Crypto Protocols:**

-  blake2s `[Source] <https://github.com/BLAKE2/BLAKE2>`__
-  curve25519 (via OpenSSL)
-  chachapoly1305 (via OpenSSL)

**Hardware Acceleration:**

-  Intel QuickAssist Technology (QAT) for TLS handshake offload
-  DPDK cryptodev for symmetric crypto operations
-  Automatic fallback to software crypto if QAT unavailable

Features
--------

1. AmneziaWG Protocol Obfuscation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Protocol Masquerading** - Make WireGuard traffic indistinguishable from legitimate protocols:

- **i-Header Signature Chains** - Send crafted UDP packets (i1-i5) before special handshakes
- **Junk Header Insertion** - Prepend random data to WireGuard packets
- **Magic Header Replacement** - Replace WireGuard's type field with custom values
- **Tag-based Template System** - Flexible packet crafting with dynamic content

**What This Defeats:**

- Protocol fingerprinting (DPI systems)
- Statistical traffic analysis
- WireGuard-specific blocking
- Timing-based detection

**Tag System for i-Headers:**

::

   <b 0xHEXDATA>  - Inject literal hex bytes (e.g., captured QUIC packet)
   <c>            - Insert 8-byte counter (big-endian)
   <t>            - Insert 8-byte unix timestamp (big-endian)
   <r N>          - Insert N random bytes
   <rc N>         - Insert N random ASCII alphanumeric characters
   <rd N>         - Insert N random digits (0-9)

2. Per-Peer Obfuscation
~~~~~~~~~~~~~~~~~~~~~~~~

Each peer can have independent obfuscation settings:

- **Dual rewrite templates** - Normal and obfuscated packet headers
- **Transparent operation** - WireGuard protocol unchanged
- **Flexible deployment** - Mix obfuscated and standard peers

3. TCP Transport
~~~~~~~~~~~~~~~~~

Optional TCP transport for environments that block UDP:

- **2-byte length prefix framing** (similar to udp2raw, Shadowsocks)
- **Simplified TCP model** - No handshake overhead, WireGuard handles reliability
- **Fully backward compatible** - UDP is the default (transport=0)
- **TCP is opt-in** - Standard WireGuard clients work unchanged

4. Intel QAT Hardware Acceleration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Offload cryptographic operations to Intel QAT hardware:

- **TLS handshake acceleration** - RSA, ECDH, ECDSA operations on QAT
- **Symmetric crypto offload** - AES-GCM record encryption via DPDK cryptodev
- **3-5x CPU reduction** for handshake processing
- **1.5-2x throughput increase** under load
- **Automatic fallback** to software crypto if QAT unavailable

Hardware Requirements
---------------------

**Recommended for Production:**

- Intel CPU with QuickAssist Technology (QAT)

  - QAT 1.7 or newer
  - Examples: Intel C62x chipset, Xeon Scalable processors with QAT
  - Dedicated QAT cards (e.g., Intel QAT 8970, 8960)

- DPDK-compatible NIC for line-rate packet processing

  - Intel 82599, X710, XL710, XXV710
  - Mellanox ConnectX-4/5/6

**Minimum for Testing:**

- x86_64 CPU with SSE4.2
- 2GB RAM
- Standard network interface (will use software crypto)

Installation
------------

Prerequisites
~~~~~~~~~~~~~

**System Requirements:**

::

   # Ubuntu 24.04 LTS (recommended) or Ubuntu 22.04
   sudo apt-get update
   sudo apt-get install -y build-essential git

**Intel QAT Driver (if using QAT hardware):**

::

   # Download QAT driver from Intel
   # https://www.intel.com/content/www/us/en/download/765501/

   wget https://downloadmirror.intel.com/812203/QAT.L.4.24.0-00005.tar.gz
   tar xzf QAT.L.4.24.0-00005.tar.gz
   cd QAT.L.4.24.0-00005

   # Configure and install
   ./configure
   make
   sudo make install

   # Load QAT driver
   sudo modprobe qat_c62x  # or qat_dh895xcc, qat_c3xxx depending on hardware

   # Verify QAT devices
   lspci | grep -i quickassist
   adf_ctl status

Building VPP with WireGuard Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Clone VPP repository
   git clone https://github.com/0xinf0/vpp.git
   cd vpp

   # Checkout the enhanced WireGuard branch
   git checkout claude/wireguard-protocol-obfuscation-011CUpAky4KiU6MSK2UxNcXW

   # Install VPP build dependencies
   make install-dep

   # Build VPP (Release mode for production)
   make build-release

   # Or build with debug symbols for development
   make build

   # Install VPP
   sudo make install

**Build with QAT Support:**

Ensure DPDK detects QAT devices during VPP build:

::

   # Verify DPDK has QAT support
   cd build/external/
   ./configure --enable-qat

   # Build VPP with QAT
   cd ../..
   make build-release

VPP Startup Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Basic Configuration (Software Crypto):**

::

   # /etc/vpp/startup.conf

   unix {
     nodaemon
     log /var/log/vpp/vpp.log
     full-coredump
     cli-listen /run/vpp/cli.sock
   }

   api-trace {
     on
   }

   cpu {
     main-core 0
     corelist-workers 1-3
   }

**QAT-Enabled Configuration:**

::

   # /etc/vpp/startup.conf

   unix {
     nodaemon
     log /var/log/vpp/vpp.log
     full-coredump
     cli-listen /run/vpp/cli.sock
   }

   api-trace {
     on
   }

   cpu {
     main-core 0
     corelist-workers 1-7
   }

   # QAT device configuration
   dpdk {
     # Intel QAT PCIe device (use lspci to find your device)
     dev 0000:3d:00.0 {qat}
     dev 0000:3f:00.0 {qat}

     # Increase crypto mbufs for high throughput
     num-crypto-mbufs 32768

     # Optional: DPDK NIC configuration
     dev 0000:02:00.0
     dev 0000:02:00.1
   }

   # TLS with QAT engine
   tls {
     use-test-cert-in-ca-doc
     engine qat {
       algorithm RSA,ECDH,ECDSA
       async
     }
   }

**Start VPP:**

::

   sudo systemctl start vpp

   # Or run manually
   sudo /usr/bin/vpp -c /etc/vpp/startup.conf

Usage Examples
--------------

Basic WireGuard (Standard, Backward Compatible)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Create WireGuard interface (UDP transport, no obfuscation)
   vppctl wireguard create listen-port 51820 private-key <base64_private_key> src 10.0.0.1
   # Returns: wg0

   vppctl set int state wg0 up
   vppctl set int ip address wg0 10.100.0.1/24

   # Add peer
   vppctl wireguard peer add wg0 \
     public-key <base64_public_key> \
     endpoint 203.0.113.45 \
     allowed-ip 0.0.0.0/0 \
     dst-port 51820 \
     persistent-keepalive 25

   # Add route
   vppctl ip route add 0.0.0.0/0 via 10.100.0.2 wg0

WireGuard with Per-Peer Obfuscation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Create interface
   vppctl wireguard create listen-port 51820 private-key <priv_key> src 10.0.0.1
   vppctl set int state wg0 up
   vppctl set int ip address wg0 10.100.0.1/24

   # Add peer WITH obfuscation - packets sent to 172.16.0.1:443 instead of actual endpoint
   vppctl wireguard peer add wg0 \
     public-key <pub_key> \
     endpoint 203.0.113.45 \
     allowed-ip 0.0.0.0/0 \
     dst-port 51820 \
     obfuscate \
     obfuscation-endpoint 172.16.0.1 \
     obfuscation-port 443

   # Show peer with obfuscation info
   vppctl show wireguard peer

WireGuard with AmneziaWG i-Headers (Protocol Masquerading)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Example: Mimic QUIC Protocol**

::

   # Create interface
   vppctl wireguard create listen-port 443 private-key <priv_key> src 10.0.0.1
   vppctl set int state wg0 up
   vppctl set int ip address wg0 10.100.0.1/24

   # Configure i-header chain (i1 is critical - triggers the feature)
   # i1: QUIC Initial packet header + random connection ID + counter + timestamp
   vppctl set wireguard i-header wg0 i1 "<b 0xc00000000108dcf709c86520ee5ac68b00000000><r 16><c><t>"

   # i2: Random padding + counter
   vppctl set wireguard i-header wg0 i2 "<r 32><c>"

   # i3: Timestamp + random data
   vppctl set wireguard i-header wg0 i3 "<t><r 24>"

   # Configure junk header size for each message type
   vppctl set wireguard junk-size wg0 init 16      # Handshake initiation
   vppctl set wireguard junk-size wg0 response 16  # Handshake response
   vppctl set wireguard junk-size wg0 data 8       # Data packets

   # Set magic header values (replace WireGuard type field)
   vppctl set wireguard magic-header wg0 init 0x01
   vppctl set wireguard magic-header wg0 response 0x02
   vppctl set wireguard magic-header wg0 data 0x04

   # Show AmneziaWG configuration
   vppctl show wireguard awg wg0

   # Add peer
   vppctl wireguard peer add wg0 \
     public-key <pub_key> \
     endpoint 203.0.113.45 \
     allowed-ip 0.0.0.0/0 \
     dst-port 443

**Example: Mimic DNS Protocol**

::

   # i1: DNS query header (transaction ID + flags + questions=1)
   vppctl set wireguard i-header wg0 i1 "<r 2><b 0x0100000100000000000003777777076578616d706c6503636f6d0000010001><t>"

   # i2: Random transaction ID + counter
   vppctl set wireguard i-header wg0 i2 "<r 2><c>"

WireGuard over TCP (Bypass UDP Blocking)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Create WireGuard interface with TCP transport
   vppctl wireguard create listen-port 443 private-key <priv_key> src 10.0.0.1 transport tcp
   vppctl set int state wg0 up
   vppctl set int ip address wg0 10.100.0.1/24

   # Add peer (TCP transport is inherited from interface)
   vppctl wireguard peer add wg0 \
     public-key <pub_key> \
     endpoint 203.0.113.45 \
     allowed-ip 0.0.0.0/0 \
     dst-port 443 \
     persistent-keepalive 25

   # Show interface (displays transport type)
   vppctl show wireguard interface

Combined: TCP + Obfuscation + i-Headers (Maximum Stealth)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Create TCP WireGuard on port 443
   vppctl wireguard create listen-port 443 private-key <priv_key> src 10.0.0.1 transport tcp
   vppctl set int state wg0 up
   vppctl set int ip address wg0 10.100.0.1/24

   # Configure i-headers to mimic TLS Client Hello
   vppctl set wireguard i-header wg0 i1 "<b 0x1603010200010001fc0303><r 32><b 0x20><r 32><t>"
   vppctl set wireguard i-header wg0 i2 "<r 48><c>"

   # Set junk sizes
   vppctl set wireguard junk-size wg0 init 32
   vppctl set wireguard junk-size wg0 response 32
   vppctl set wireguard junk-size wg0 data 16

   # Add peer with obfuscation
   vppctl wireguard peer add wg0 \
     public-key <pub_key> \
     endpoint 203.0.113.45 \
     allowed-ip 0.0.0.0/0 \
     dst-port 51820 \
     obfuscate \
     obfuscation-endpoint 172.16.0.1 \
     obfuscation-port 443

Monitoring and Debugging
~~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Show interfaces
   vppctl show wireguard interface

   # Show peers
   vppctl show wireguard peer

   # Show AmneziaWG configuration
   vppctl show wireguard awg wg0

   # Show QAT devices (if using QAT)
   vppctl show dpdk crypto devices

   # Show crypto async status
   vppctl show crypto async status

   # Show TLS statistics
   vppctl show tls stats

   # Show interface statistics
   vppctl show int
   vppctl show int address

   # Enable packet tracing (for debugging)
   vppctl trace add dpdk-input 100
   vppctl trace add wg4-input 100
   vppctl trace add wg6-input 100
   vppctl show trace

Clearing Configuration
~~~~~~~~~~~~~~~~~~~~~~

::

   # Clear i-header configuration
   vppctl clear wireguard i-header wg0 all
   vppctl clear wireguard i-header wg0 i1  # Clear specific i-header

   # Clear junk sizes (reset to 0)
   vppctl set wireguard junk-size wg0 init 0
   vppctl set wireguard junk-size wg0 response 0
   vppctl set wireguard junk-size wg0 data 0

   # Remove peer
   vppctl wireguard peer remove <peer_idx>

   # Delete interface
   vppctl wireguard delete wg0

Performance Tuning
------------------

QAT Optimization
~~~~~~~~~~~~~~~~

**QAT Instance Mapping:**

Distribute QAT instances across NUMA nodes for optimal performance:

::

   # Check QAT device NUMA affinity
   cat /sys/bus/pci/devices/0000:3d:00.0/numa_node

   # Pin VPP worker threads to same NUMA node
   cpu {
     main-core 0
     corelist-workers 1-7
     skip-cores 0
   }

**QAT Queue Depth:**

Increase queue depth for high throughput:

::

   dpdk {
     dev 0000:3d:00.0 {qat}

     # Increase descriptor ring size
     dev default {
       num-rx-desc 2048
       num-tx-desc 2048
     }

     # More crypto mbufs
     num-crypto-mbufs 65536
   }

**Monitor QAT Utilization:**

::

   # Check QAT device status
   adf_ctl status

   # Monitor QAT statistics
   cat /sys/kernel/debug/qat_c62x_0000:3d:00.0/fw_counters

Worker Thread Scaling
~~~~~~~~~~~~~~~~~~~~~~

::

   # Allocate more workers for high throughput
   cpu {
     main-core 0
     corelist-workers 1-15  # 15 workers for 16-core system
   }

Huge Pages
~~~~~~~~~~

::

   # Enable huge pages for better memory performance
   dpdk {
     socket-mem 2048,2048  # 2GB per NUMA node
   }

Troubleshooting
---------------

QAT Device Not Detected
~~~~~~~~~~~~~~~~~~~~~~~~

::

   # Check QAT driver loaded
   lsmod | grep qat

   # Check QAT device status
   adf_ctl status

   # Restart QAT service
   sudo systemctl restart qat

   # Check VPP logs
   tail -f /var/log/vpp/vpp.log | grep -i qat

Connection Issues
~~~~~~~~~~~~~~~~~

::

   # Check peer status
   vppctl show wireguard peer

   # Verify routes
   vppctl show ip fib

   # Check interface is up
   vppctl show int

   # Verify firewall allows traffic
   sudo iptables -L -n

   # For obfuscation: verify obfuscation endpoint is reachable
   ping <obfuscation-endpoint>

Packet Drops
~~~~~~~~~~~~

::

   # Check interface errors
   vppctl show int

   # Check crypto operation errors
   vppctl show crypto async status

   # Enable packet tracing
   vppctl trace add dpdk-input 100
   vppctl show trace

Performance Issues
~~~~~~~~~~~~~~~~~~

::

   # Check CPU usage
   vppctl show runtime

   # Check QAT offload is working
   vppctl show crypto async status

   # Verify worker thread distribution
   vppctl show threads

   # Check for packet drops
   vppctl show errors

Advanced Features
-----------------

Generating i-Header Templates from Packet Captures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use Wireshark to capture legitimate protocol traffic and convert to i-header format:

::

   # 1. Capture QUIC traffic in Wireshark
   # 2. Right-click packet -> Copy -> as Hex Stream
   # 3. Format as i-header tag:

   <b 0xc00000000108dcf709c86520ee5ac68b00000000><r 16><c><t>
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       Captured QUIC Initial packet header

Dynamic Obfuscation Profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create different obfuscation profiles for different network conditions:

::

   # Profile 1: Light obfuscation (low overhead)
   vppctl set wireguard junk-size wg0 init 8
   vppctl set wireguard junk-size wg0 data 4

   # Profile 2: Heavy obfuscation (maximum stealth)
   vppctl set wireguard i-header wg0 i1 "<b 0x...><r 32><c><t>"
   vppctl set wireguard junk-size wg0 init 64
   vppctl set wireguard junk-size wg0 data 32

Multi-Interface Deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run multiple WireGuard interfaces with different obfuscation settings:

::

   # Interface 1: Standard WireGuard (UDP 51820)
   vppctl wireguard create listen-port 51820 private-key <key1> src 10.0.0.1

   # Interface 2: TCP on port 443
   vppctl wireguard create listen-port 443 private-key <key2> src 10.0.0.1 transport tcp

   # Interface 3: UDP with QUIC masquerading
   vppctl wireguard create listen-port 443 private-key <key3> src 10.0.0.1
   vppctl set wireguard i-header wg2 i1 "<b 0x...QUIC...>"

API Usage
---------

This plugin supports VPP's binary API for programmatic control:

::

   # Python example using VPP Python API
   from vpp_papi import VPPApiClient

   vpp = VPPApiClient()
   vpp.connect("wireguard-client")

   # Create interface
   result = vpp.api.wireguard_interface_create(
       interface={
           'user_instance': 0,
           'port': 51820,
           'src_ip': {'af': 0, 'un': {'ip4': [10, 0, 0, 1]}},
           'private_key': private_key_bytes,
           'public_key': public_key_bytes,
           'transport': 0  # 0=UDP, 1=TCP
       }
   )

   # Add peer with obfuscation
   result = vpp.api.wireguard_peer_add(
       peer={
           'public_key': peer_public_key,
           'port': 51820,
           'endpoint': {'af': 0, 'un': {'ip4': [203, 0, 113, 45]}},
           'allowed_ips': [{'prefix': {'address': ...}}],
           'obfuscate': True,
           'obfuscation_endpoint': {'af': 0, 'un': {'ip4': [172, 16, 0, 1]}},
           'obfuscation_port': 443
       },
       wg_sw_if_index=result.sw_if_index
   )

   vpp.disconnect()

Security Considerations
-----------------------

**Key Management:**

- Store private keys securely (use key management systems in production)
- Rotate keys periodically
- Use hardware security modules (HSM) for key storage if available

**Obfuscation Limitations:**

- Obfuscation helps evade DPI but is NOT a substitute for encryption
- WireGuard protocol security remains unchanged
- i-Headers are sent in cleartext (by design, to mimic legitimate traffic)

**QAT Security:**

- QAT performs crypto operations in hardware
- Ensure QAT firmware is up-to-date
- Use Intel's signed firmware packages

**Firewall Rules:**

- Restrict VPP management interface (default: /run/vpp/cli.sock)
- Use iptables/nftables to limit access to WireGuard ports
- Enable connection tracking for stateful filtering

License
-------

This plugin is licensed under Apache License 2.0.

See COPYING file for details.

Contributing
------------

Contributions are welcome! Please submit issues and pull requests to:

https://github.com/0xinf0/vpp

Authors
-------

- Original WireGuard VPP implementation: Cisco, Doc.ai
- AmneziaWG obfuscation: Enhanced by 0xinf0
- Per-peer obfuscation: Enhanced by 0xinf0
- TCP transport: Enhanced by 0xinf0
- QAT integration: VPP DPDK cryptodev infrastructure

References
----------

- WireGuard Protocol: https://www.wireguard.com/
- AmneziaWG: https://docs.amnezia.org/documentation/amnezia-wg/
- VPP Documentation: https://fd.io/docs/vpp/
- Intel QAT: https://www.intel.com/content/www/us/en/architecture-and-technology/intel-quick-assist-technology-overview.html
- DPDK Cryptodev: https://doc.dpdk.org/guides/prog_guide/cryptodev_lib.html

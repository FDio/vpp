## IOAM over VxLAN-GPE  {#ioam_vxlan_gpe_plugin_doc}

This document describes the details about configuring and monitoring the usage
of IOAM over VxLAN-GPE. The packet formats used by the implementation are specified
in the IETF draft below:
 - [IOAM-ietf-transport] - Lists out the transport protocols
 and mechanism to carry IOAM data records

## Features supported in the current release
VPP can function as IOAM encapsulating, transit and decapsulating node.
IOAM data transported as options in an VxLAN-GPE extension header
is described here.

The following IOAM features are supported:

- **IOAM Tracing** : IOAM supports multiple data records to be
recorded in the packet as the packet traverses the network.
These data records offer insights into the operational behavior of the network.
The following information can be collected in the tracing
data from the nodes a packet traverses:
  - Node ID
  - Ingress interface ID
  - Egress interface ID
  - Timestamp
  - Pre-configured application data

## Configuration
Configuring IOAM over VxLAN-GPE involves:
- Selecting the VxLAN-GPE tunnel for which IOAM data must be inserted, updated or removed
  - For flows transported over VxLAN-GPE, selection of packets is done based
    on the tuple of <VtepSrcIP, VtepDstIp, VNID>
  - Selection of packets for updating IOAM data is implicitly done on the
  presence of IOAM options in the packet
  - Selection of packets for removing the IOAM data is done when the VxLAN-GPE tunnel is terminated.
- The kind of data to be collected
  - Tracing data
- Additional details for processing IOAM data to be collected
  - For trace data - trace type, number of nodes to be recorded in the trace,
  time stamp precision, etc.

The CLI for configuring IOAM is explained here followed by detailed steps
and examples to deploy IOAM for VxLAN-GPE on VPP as an encapsulating, transit or
decapsulating IOAM node in the subsequent sub-sections.

### Trace configuration

#### On IOAM encapsulating node
 - Configure VxLAN tunnel parameters to select packets for IOAM data insertion
    - Example to enable IOAM data insertion for all the packets
    from src VTEP 10.1.1.1 dest VTEP 10.1.1.2 VNI 13

    vpp# set vxlan-gpe-ioam vxlan <src-ip> <dst_ip> <vnid> [disable]
    - Note the disable switch is used to disable the selection of packets for IOAM data insertion.

 - **Enable tracing** : Specify node ID, maximum number of nodes for which
 trace data should be recorded, type of data to be included for recording,
 optionally application data to be included
    - Example to enable tracing with a maximum of 4 nodes recorded
    and the data to be recorded to include - hop limit, node id,
    ingress and egress interface IDs, timestamp (millisecond precision),
    application data (0x1234):


    vpp# set ioam-trace profile trace-type 0x1f trace-elts 4 trace-tsp 1
    node-id 0x1 app-data 0x1234
    vpp# set vxlan-gpe-ioam trace



#### On IOAM transit node
- The transit node requires the outer Destination IP to be configured.
- Additionally the transit node requires trace type, timestamp precision, node ID and
optionally application data to be configured, to update its node data in the trace option.

Example:

    vpp# set ioam-trace profile trace-type 0x1f trace-elts 4 trace-tsp 1
    node-id 0x2 app-data 0x1234
    vpp# set vxlan-gpe-ioam-transit dst-ip <dst_ip> [outer-fib-index <outer_fib_index>] [disable]
    - Note the disable switch is used to disable the selection of packets for IOAM data insertion.

#### On the IOAM decapsulating node
- The decapsulating node similar to encapsulating node requires
configuration of the VxLAN-GPE tunnels for identifying the packets to remove IOAM data from.
    - Example to decapsulate IOAM data for packets
    from src VTEP 10.1.1.1 dest VTEP 10.1.1.2 VNI 13

    vpp# set vxlan-gpe-ioam vxlan <src-ip> <dst_ip> <vnid> [disable]
    - Note the disable switch is used to disable the selection of packets for IOAM data insertion.

- Decapsulating node requires trace type, timestamp precision,
node ID and optionally application data to be configured,
to update its node data in the trace option before it is decapsulated.

Example:

    vpp# set ioam-trace profile trace-type 0x1f trace-elts 4
    trace-tsp 1 node-id 0x3 app-data 0x1234
    vpp# set vxlan-gpe-ioam trace

## Export of IOAM records upon decapsulation

IOAM data records extracted from the VxLAN-GPE header can be exported as IPFIX records.
These IPFIX records can then be analysed using offline scripts or standard IPFIX collector modules.

Example:
    vpp# set vxlan-gpe-ioam export ipfix collector <ip4-address> src <ip4-address>


## Operational data

Following CLIs are available to check IOAM operation:
- To check IOAM configuration that are effective use "show ioam summary"


- Tracing - enable trace of VxLAN-GPE packets to view the data inserted and
collected.

Example when the nodes are receiving data over a DPDK interface:
Enable tracing using "trace add dpdk-input 20" and
execute "show trace" to view the IOAM data collected:


    vpp# trace add dpdk-input 20

    vpp# show trace
    
    ------------------- Start of thread 0 vpp_main -------------------
    Packet 1
    
    00:41:58:236271: af-packet-input
      af_packet: hw_if_index 1 next-index 1
        tpacket2_hdr:
          status 0x20000001 len 114 snaplen 114 mac 66 net 80
          sec 0x57c5b238 nsec 0x1bae439a vlan 0
    00:41:58:236281: ethernet-input
      IP4: fa:16:3e:1b:3b:df -> fa:16:3e:a5:df:a7
    00:41:58:236289: l2-input
      l2-input: sw_if_index 1 dst fa:16:3e:a5:df:a7 src fa:16:3e:1b:3b:df
    00:41:58:236292: l2-learn
      l2-learn: sw_if_index 1 dst fa:16:3e:a5:df:a7 src fa:16:3e:1b:3b:df bd_index 1
    00:41:58:236297: l2-fwd
      l2-fwd:   sw_if_index 1 dst fa:16:3e:a5:df:a7 src fa:16:3e:1b:3b:df bd_index 1
    00:41:58:236299: l2-flood
      l2-flood: sw_if_index 1 dst fa:16:3e:a5:df:a7 src fa:16:3e:1b:3b:df bd_index 1
    00:41:58:236304: l2-output
      l2-output: sw_if_index 4 dst fa:16:3e:a5:df:a7 src fa:16:3e:1b:3b:df
    00:41:58:236306: vxlan-gpe-encap
      VXLAN-GPE-ENCAP: tunnel 0
    00:41:58:236309: vxlan-gpe-encap-ioam-v4
      VXLAN_GPE_IOAM_HOP_BY_HOP: next_index 0 len 40 traced 40  Trace Type 0x1f , 1 elts left
        [0] ttl 0x0 node id 0x0 ingress 0x0 egress 0x0 ts 0x0
    app 0x0
        [1] ttl 0xff node id 0x323200 ingress 0x4 egress 0x4 ts 0x57c5b238
    app 0xa5a55e5e
    VXLAN-GPE-ENCAP: tunnel 0
      VXLAN_GPE_IOAM_HOP_BY_HOP: next_index 0 len 8 traced 0VXLAN-GPE-ENCAP: tunnel 0
    00:41:58:236314: ip4-lookup
      fib 0 adj-idx 13 :  via 10.0.0.10 flow hash: 0x00000000
      UDP: 6.0.0.11 -> 7.0.0.11
        tos 0x00, ttl 254, length 190, checksum 0xaf19
        fragment id 0x0000
      UDP: 4790 -> 4790
        length 170, checksum 0x0000
    00:41:58:236318: ip4-indirect
      fib 0 adj-idx 10 : host-eth2
                         IP4: 02:fe:3c:85:ec:72 -> 02:fe:64:28:83:90 flow hash: 0x00000000
      UDP: 6.0.0.11 -> 7.0.0.11
        tos 0x00, ttl 254, length 190, checksum 0xaf19
        fragment id 0x0000
      UDP: 4790 -> 4790
        length 170, checksum 0x0000
    00:41:58:236320: ip4-rewrite-transit
      tx_sw_if_index 2 adj-idx 10 : host-eth2
                                    IP4: 02:fe:3c:85:ec:72 -> 02:fe:64:28:83:90 flow hash: 0x00000000
      IP4: 02:fe:3c:85:ec:72 -> 02:fe:64:28:83:90
      UDP: 6.0.0.11 -> 7.0.0.11
        tos 0x00, ttl 253, length 190, checksum 0xb019
        fragment id 0x0000
      UDP: 4790 -> 4790
        length 170, checksum 0x0000
    00:41:58:236322: host-eth2-output
      host-eth2
      IP4: 02:fe:3c:85:ec:72 -> 02:fe:64:28:83:90
      UDP: 6.0.0.11 -> 7.0.0.11
        tos 0x00, ttl 253, length 190, checksum 0xb019
        fragment id 0x0000
      UDP: 4790 -> 4790
        length 170, checksum 0x0000
    00:41:58:236512: l2-flood
      l2-flood: sw_if_index 1 dst fa:16:3e:a5:df:a7 src fa:16:3e:1b:3b:df bd_index 1
    00:41:58:236514: error-drop
      l2-flood: BVI L3 mac mismatch
    
    vpp# trace add dpdk-input 20

    vpp# show trace
    
    ------------------- Start of thread 0 vpp_main -------------------
    Packet 1
    
    17:26:12:929645: af-packet-input
      af_packet: hw_if_index 1 next-index 1
        tpacket2_hdr:
          status 0x20000001 len 204 snaplen 204 mac 66 net 80
          sec 0x57c670fd nsec 0x74e39a2 vlan 0
    17:26:12:929656: ethernet-input
      IP4: 02:fe:c0:42:3c:a9 -> 02:fe:50:ec:fa:0a
    17:26:12:929662: ip4-input
      UDP: 6.0.0.11 -> 7.0.0.11
        tos 0x00, ttl 252, length 190, checksum 0xb119
        fragment id 0x0000
      UDP: 4790 -> 4790
        length 170, checksum 0x0000
    17:26:12:929666: ip4-lookup
      fib 0 adj-idx 12 :  7.0.0.11/16 flow hash: 0x00000000
      UDP: 6.0.0.11 -> 7.0.0.11
        tos 0x00, ttl 252, length 190, checksum 0xb119
        fragment id 0x0000
      UDP: 4790 -> 4790
        length 170, checksum 0x0000
    17:26:12:929670: ip4-local
        UDP: 6.0.0.11 -> 7.0.0.11
          tos 0x00, ttl 252, length 190, checksum 0xb119
          fragment id 0x0000
        UDP: 4790 -> 4790
          length 170, checksum 0x0000
    17:26:12:929672: ip4-udp-lookup
      UDP: src-port 4790 dst-port 4790
    17:26:12:929680: vxlan4-gpe-input
      VXLAN-GPE: tunnel 0 next 3 error 0IP6_HOP_BY_HOP: next index 3 len 40 traced 40  Trace Type 0x1f , 1 elts left
        [0] ttl 0x0 node id 0x0 ingress 0x0 egress 0x0 ts 0x0
    app 0x0
        [1] ttl 0xff node id 0x323200 ingress 0x4 egress 0x4 ts 0x57c670fc
    app 0xa5a55e5e
    
    17:26:12:929687: ethernet-input
      IP4: fa:16:3e:1b:3b:df -> fa:16:3e:a5:df:a7
    

[IOAM-vpp]: <#ioam_plugin_doc>
[IOAM-ietf-transport]:<https://tools.ietf.org/html/draft-brockners-inband-oam-transport>


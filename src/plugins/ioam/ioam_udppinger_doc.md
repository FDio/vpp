## UDP-Pinger for IPv6 with IOAM    {#ioam_udppinger_doc}

Traditionally to detect and isolate network faults, ping and traceroute 
are used. But in a complex network with large number of U/E-CMP being 
availble, it would be difficult to detect and isolate faults in the 
network. Also detecting loss/reordering/duplication of packets becomes 
much harder. [draft-lapukhov-dataplane-probe] uses active probes to 
solve the above mentioned problems. UDP-Pinger with IOAM, would combine 
[draft-lapukhov-dataplane-probe] with [IOAM-ietf-data] and 
[IOAM-ietf-transport] to provide a more sophisticated way for 
detection/isolation of network faults and enable network telemetry.

UDP-Pinger for IPv6 does:
- Crafts and sends Probe packets from source node to destination.
- Probe packet is an IPv6 packet with HBH header to collect IOAM data 
and UDP header followed by payload.
- UDP source and destination ports are varied to cover all possible 
paths in network as well as to simulate real application traffic.
- IOAM Trace option is used to record the path Probe packets take 
and also for measuring latency.
- IOAM E2E option is used to measure packet loss, reordering and 
duplicate packets.
- UDP payload follows packet format in [draft-lapukhov-dataplane-probe] 
and is used on source/destination nodes to identify Probe/Reply packets.
- Destination node on receiving Probe packet sends a reply back to source.
 Reply packet is formed by exchanging source and destination IP addresses 
and packet type in UDP payload.
- Source node on receiving Reply packet can trace packet Path and measure 
latency, packet loss, reordering, duplication.
- On detecting fault in network, Probe packets are sent with loopback 
flag set. On seeing loopback flag, each device in network along with 
forwarding the packet, also sends a copy back to source. With this 
Source node can corelate and detect the faulty node/link.

## Configuration
Following section describes how to enable UDP-Pinger on a VPP node.
Please note that IOAM configurations as mentioned in @subpage ioam_ipv6_doc 
have to be made prior to starting any of the below configurations.

### UDP-Pinger Enable/Disable
For configuring UDP-Pinger between two end-points, following parametrs 
need to be provided by using the CLI:

    set udp-ping src <local IPv6 address>  src-port-range <local port range> 
    dst <remote IPv6 address> dst-port-range <destination port range> 
    interval <time interval in sec> [fault-detect] [disable]

- src : IPv6 address of local node.
- src-port-range : Port range for source port in UDP header.
                   Syntax is <start_port>:<end_port>
- dst : IPv6 address of the destination node.
- dst-port-range : Port range for destination port in UDP header.
                   Syntax is <start_port>:<end_port>
- interval : Time interval in seconds for which Probe packets need to 
             be sent out.
- fault-detect : This is to enable IOAM loopback functionality on
                 detecting a failure and to detect faulty node/link.
- disable : Used for deleting a UDP-Ping flow.

Example:

    To create a UDP-Pinger session:
    set udp-ping src db00::1 src-port-range 5000:5002 dst db02::1 dst-port-range 6000:6002 interval 1 fault-detect

    To delete a UDP-Pinger session:
    set udp-ping src db00::1 src-port-range 5000:5002 dst db02::1 dst-port-range 6000:6002 interval 1 fault-detect disable

###  UDP-Pinger Data Export
For exporting network telemetry data extracted from UDP-Pinger sessions, 
below command is used. Data is exported as IP-Fix records.

    set udp-ping export-ipfix [disable]

    On enabling udp-ping export, UDP-Pinger data is exported as 
    IP-Fix record to IP-Fix collector address as configured in
    IP-Fix using the command:

    set ipfix exporter collector <Remote IP Address> src <Local IP address>

Following data is exported from UDP-Pinger:
- IOAM Trace information for each of UDP-Pinger flow
- Roundtrip Delay
- Packet loss count
- Reordered Packet count
- Duplicate Packet count

Example:

    To enable export:
    set ipfix exporter collector 172.16.1.254 src 172.16.1.229
    set udp-ping export-ipfix

    To disable export:
    set udp-ping export-ipfix disable

## Operational data
For checking the state of the UDP-Pinger sessions, below command can be used:

    show udp-ping summary

Command displays follwing for each UDP-Pinger session:
- IOAM Trace information for each of UDP-Pinger flow
- Roundtrip Delay
- Packet loss count
- Reordered Packet count
- Duplicate Packet count

Example:

    vpp#show udp-ping summary
    UDP-Ping data:
    Src: db00::1, Dst: db02::1
    Start src port: 5000, End src port: 5002
    Start dst port: 6000, End dst port: 6002
    Interval: 1
    
    Src Port - 5000, Dst Port - 6000, Flow CTX - 0
    Path State - Up
    Path Data:    
    pkt_sent : 400
    pkt_counter : 400
    bytes_counter : 458700
    Trace data: 
    pkt_sent : 400
    pkt_counter : 400
    bytes_counter : 45870
    Trace data: 
    path_map:
    
    node_id: 0x1, ingress_if: 1, egress_if: 2, state:UP
    node_id: 0x2, ingress_if: 0, egress_if: 2, state:UP
    node_id: 0x3, ingress_if: 3, egress_if: 0, state:UP
    node_id: 0x2, ingress_if: 4, egress_if: 9, state:UP
    node_id: 0x1, ingress_if: 10, egress_if: 0, state:UP
    pkt_counter: 400
    bytes_counter: 45870
    min_delay: 10
    max_delay: 50
    mean_delay: 15
    
    POT data: 
    sfc_validated_count : 0
    sfc_invalidated_count : 0
    
    Seqno Data:
    RX Packets        : 400
    Lost Packets      : 0
    Duplicate Packets : 0
    Reordered Packets : 0

    Src Port - 5000, Dst Port - 6001, Flow CTX - 1
    Path State - Down
    Path Data:    
    pkt_sent : 500
    pkt_counter : 400
    bytes_counter : 45870
    Trace data: 
    pkt_sent : 500
    pkt_counter : 400
    bytes_counter : 45870
    Trace data: 
    path_map:
    
    node_id: 0x1, ingress_if: 1, egress_if: 2, state:UP
    node_id: 0x2, ingress_if: 0, egress_if: 2, state:UP
    node_id: 0x3, ingress_if: 3, egress_if: 0, state:Down
    node_id: 0x2, ingress_if: 4, egress_if: 9, state:Down
    node_id: 0x1, ingress_if: 10, egress_if: 0, state:Down
    pkt_counter: 500
    bytes_counter: 45870
    min_delay: 50
    max_delay: 500
    mean_delay: 100
    
    POT data: 
    sfc_validated_count : 0
    sfc_invalidated_count : 0
    
    Seqno Data:
    RX Packets        : 400
    Lost Packets      : 100
    Duplicate Packets : 20
    Reordered Packets : 5

    <So on for other source/destination port combination>
    

[draft-lapukhov-dataplane-probe]:<https://tools.ietf.org/html/draft-lapukhov-dataplane-probe-01>
[IOAM-ietf-data]:<https://tools.ietf.org/html/draft-brockners-inband-oam-data-04>
[IOAM-ietf-transport]:<https://tools.ietf.org/html/draft-brockners-inband-oam-transport-03>


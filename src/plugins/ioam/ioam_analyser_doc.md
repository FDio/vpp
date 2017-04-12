## IOAM Analyser for IPv6    {#ioam_analyser_doc}

IOAM Analyser for IPv6 does 
- Analysing iOAM records and aggregating statistics
- Export the aggregated statistics over IP-FIX to external collector.

Following statistics are collected and exported per IOAM flow:
- All the Paths available for the flow : Collected using IOAM Trace.
- Delay
- POT data: No of packets In Policy and Out of Policy.
- Packet loss count
- Reordered Packet count
- Duplicate Packet count

This feature can work on IOAM decapsulating node or as a standalone external analyser.

## Configuration

Below command can be used to configure a VPP node as IOAM analyser:

    set ioam analyse [export-ipfix-collector] [disable] [listen-ipfix]

- export-ipfix-collector : This keyword instructs VPP to export the IOAM 
analysis data to be exported to an external collector via IP-Fix. Note 
that IP-Fix collector information has to be configured using the below 
command: 

    set ipfix exporter collector <Remote IP Address> src <Local IP address>

- listen-ipfix : This keyword instructs VPP node to listen to IP-Fix port
4739 to receive RAW IOAM records exported by using IOAM Export plugin and
analyse IOAM records.

- disable : This keyword is used to instruct VPP to stop analysing IOAM.

Example1 : To use VPP as IOAM Analyser on IOAM decapsulating node and export.

    set ipam analyse export-ipfix-collector
    set ipfix exporter collector 172.16.1.254 src 172.16.1.229

    Above commands when configured on a IOAM Decapsulating node will analyse 
    all the IOAM data before Decap, aggregate statistics and export them to
    node with IP address 172.16.1.254 via IP-Fix.

Example2 : To use VPP as a standalone IOAM Analyser and export.

    set ipam analyse export-ipfix-collector listen-ipfix
    set ipfix exporter collector 172.16.1.254 src 172.16.1.229

    Above commands when configured on a VPP node will listen on IP-Fix 
    port 4739 for IP-Fix records containing IOAM Raw data aggregate 
    statistics and export them to node with IP address 172.16.1.254 via IP-Fix.

## Operational data
For checking the operational data of VPP IOAM analyser below command needs to be used:

    show ioam analyse

Example:

    vpp# show ioam analyse
    iOAM Analyse Information:
    Flow Number: 1 
    pkt_sent : 400
    pkt_counter : 400
    bytes_counter : 458700
    Trace data: 
    pkt_sent : 400
    pkt_counter : 100
    bytes_counter : 458700
    Trace data: 
    path_map:
    
    node_id: 0x1, ingress_if: 1, egress_if: 2, state:UP
    node_id: 0x2, ingress_if: 0, egress_if: 2, state:UP
    node_id: 0x3, ingress_if: 3, egress_if: 0, state:UP
    pkt_counter: 200
    bytes_counter: 229350
    min_delay: 10
    max_delay: 50
    mean_delay: 15
    
    node_id: 0x1, ingress_if: 1, egress_if: 2, state:UP
    node_id: 0x4, ingress_if: 10, egress_if: 12, state:UP
    node_id: 0x3, ingress_if: 3, egress_if: 0, state:UP
    pkt_counter: 200
    bytes_counter: 229350
    min_delay: 19
    max_delay: 100
    mean_delay: 35
    
    POT data: 
    sfc_validated_count : 200
    sfc_invalidated_count : 200
    
    Seqno Data:
    RX Packets        : 400
    Lost Packets      : 0
    Duplicate Packets : 0
    Reordered Packets : 0
    

## VPP In-situ OAM over VxLAN-GPE (iOAM)    {#ioam_vxlan_gpe_plugin_doc}

VPP In-situ OAM [iOAM-vpp] is an implementation study to record operational
information in the packet while the packet traverses a path between
two points in the network.

This document describes the details about configuring and monitoring the usage
of iOAM over VxLAN-GPE. The packet formats used by the implementation are specified
in the IETF draft below:
 - [iOAM-ietf-transport] - Lists out the transport protocols
 and mechanism to carry iOAM data records

## Features supported in the current release
VPP can function as in-situ OAM encapsulating, transit and decapsulating node.
In this version of VPP in-situ OAM data is transported as options in an
VxLAN-GPE extension header. Hence in-situ OAM can be enabled for VxLAN-GPE traffic.

The following iOAM features are supported:

- **In-band OAM Tracing** : In-band OAM supports multiple data records to be
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
Configuring iOAM over VxLAN-GPE involves:
- Selecting the VxLAN-GPE tunnel for which iOAM data must be inserted, updated or removed
  - For flows transported over VxLAN-GPE, selection of packets is done based
    on the tuple of <VtepSrcIP, VtepDstIp, VNID>
  - Selection of packets for updating iOAM data is implicitly done on the
  presence of iOAM options in the packet
  - Selection of packets for removing the iOAM data is done when the VxLAN-GPE tunnel is terminated.
- The kind of data to be collected
  - Tracing data
- Additional details for processing iOAM data to be collected
  - For trace data - trace type, number of nodes to be recorded in the trace,
  time stamp precision, etc.

The CLI for configuring iOAM is explained here followed by detailed steps
and examples to deploy iOAM for VxLAN-GPE on VPP as an encapsulating, transit or
decapsulating iOAM node in the subsequent sub-sections.

### Trace configuration

#### On in-situ OAM encapsulating node
 - Configure VxLAN tunnel parameters to select packets for iOAM data insertion
    - Example to enable iOAM data insertion for all the packets
    from src VTEP 10.1.1.1 dest VTEP 10.1.1.2 VNI 13

    vpp# set vxlan-gpe-ioam vxlan <src-ip> <dst_ip> <vnid> [disable]
    - Note the disable switch is used to disable the selection of packets for iOAM data insertion.
    
 - **Enable tracing** : Specify node ID, maximum number of nodes for which
 trace data should be recorded, type of data to be included for recording,
 optionally application data to be included
    - Example to enable tracing with a maximum of 4 nodes recorded
    and the data to be recorded to include - hop limit, node id,
    ingress and egress interface IDs, timestamp (millisecond precision),
    application data (0x1234):


    vpp# set ioam rewrite trace-type 0x1f trace-elts 4 trace-tsp 1
    node-id 0x1 app-data 0x1234
    vpp# set vxlan-gpe-ioam trace



#### On in-situ OAM transit node
- The transit node requires the outer Destination IP to be configured.
- Additionally the transit node requires trace type, timestamp precision, node ID and
optionally application data to be configured, to update its node data in the trace option.

Example:  

    vpp# set ioam rewrite trace-type 0x1f trace-elts 4 trace-tsp 1  
    node-id 0x2 app-data 0x1234  
    vpp# set vxlan-gpe-ioam-transit dst-ip <dst_ip> [outer-fib-index <outer_fib_index>] [disable]
    - Note the disable switch is used to disable the selection of packets for iOAM data insertion.

#### On the In-band OAM decapsulating node
- The decapsulating node similar to encapsulating node requires
configuration of the VxLAN-GPE tunnels for identifying the packets to remove iOAM data from.
    - Example to decapsulate iOAM data for packets 
    from src VTEP 10.1.1.1 dest VTEP 10.1.1.2 VNI 13

    vpp# set vxlan-gpe-ioam vxlan <src-ip> <dst_ip> <vnid> [disable]
    - Note the disable switch is used to disable the selection of packets for iOAM data insertion.

- Decapsulating node requires trace type, timestamp precision,
node ID and optionally application data to be configured,
to update its node data in the trace option before it is decapsulated.

Example:  

    vpp# set ioam rewrite trace-type 0x1f trace-elts 4  
    trace-tsp 1 node-id 0x3 app-data 0x1234  
    vpp# set vxlan-gpe-ioam trace

## Export of iOAM records upon decapsulation

iOAM data records extracted from the VxLAN-GPE header can be exported as IPFIX records.
These IPFIX records can then be analysed using offline scripts or standard IPFIX collector modules.

Example:
    vpp# set vxlan-gpe-ioam export ipfix collector <ip4-address> src <ip4-address>"

[iOAM-vpp]: <#ioam_plugin_doc>
[iOAM-ietf-transport]:<https://tools.ietf.org/html/draft-brockners-inband-oam-transport>


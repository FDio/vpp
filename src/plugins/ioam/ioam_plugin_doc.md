## VPP Inband OAM (IOAM)    {#ioam_plugin_doc}

Inband OAM (IOAM) is an implementation study to record operational
information in the packet while the packet traverses a path between
two points in the network.

Overview of IOAM can be found in [IOAM-Devnet] page.
The following IETF drafts detail the motivation and mechanism for
recording operational information:
 - [IOAM-ietf-requirements] - Describes motivation and usecases for IOAM
 - [IOAM-ietf-data] - Describes data records that can be collected using IOAM
 - [IOAM-ietf-transport] - Lists out the transport protocols
 and mechanism to carry IOAM data records
 - [IOAM-ietf-proof-of-transit] - Describes the idea of Proof of Transit (POT)
 and mechanisms to operationalize the idea

## Terminology
IOAM is expected to be deployed in a specific domain rather
than on the overall Internet. The part of the network which employs IOAM
is referred to as **"IOAM-domain"**.
  
IOAM data is added to a packet on entering the IOAM-domain
and is removed from the packet when exiting the domain.
Within the IOAM-domain, network nodes that the packet traverses
may update the IOAM data records.

- The node which adds IOAM data to the packet is called the
**"IOAM encapsulating node"**.

- The node which removes the IOAM data is referred to as the
**"IOAM decapsulating node"**.

- Nodes within the domain which are aware of IOAM data and read
and/or write or process the IOAM data are called
**"IOAM transit nodes"**.

## Features supported in the current release
 
- VPP can function as IOAM encapsulating, transit and decapsulating node and collect:
  - IOAM Tracing information at each hop the packet traverses
  - Sequence number using IOAM Edge-to-Edge option to detect packet loss, duplicate, reordering
  - Proof of transit - to prove packet flow through a set of checkpoint nodes in the IOAM domain
- VPP can transport IOAM metadata for native IPv6 and VXLAN-GPE encapsulated packets
- At the IOAM decapsulating node the data captured can be exported as IPFIX records
- At the IOAM decapsulation node the data collected can be analysed and summary reported via IPFIX

Using the above IOAM features in VPP following solutions are available:
- IOAM based UDP pinger detailed description of this can be found @subpage ioam_udppinger_doc
- IOAM IPFIX Analyser detailed description of this can be found @subpage ioam_analyser_doc
- M-Anycast server using IOAM and SRv6 detailed description of this can be
  found @subpage ioam_manycast_doc


The following IOAM options are supported:

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
- **IOAM Proof of Transit (POT)**: Proof of transit IOAM data is
added to every packet for verifying that a packet traverses a specific
set of nodes.
IOAM data is updated at every node that is enabled with IOAM
proof of transit and is used to verify whether a packet traversed
all the specified nodes. When the verifier receives each packet,
it can validate whether the packet traversed the specified nodes.
- **IOAM sequence number**: IOAM defined Edge-to-Edge(E2E) Option is to carry data 
    that is added by the IOAM encapsulating node and interpreted by IOAM
   decapsulating node. Currently only sequence numbers use the IOAM Edge-to-Edge
   option.  In order to detect packet loss, packet reordering, or packet
   duplication in an IOAM-domain, sequence numbers can be added
   to packets

Configuration for deploying IOAM for IPv6 is explained in @subpage ioam_ipv6_doc
Configuration for deploying IOAM for VXLAN-GPE is explained in @subpage ioam_vxlan_gpe_plugin_doc

    

[IOAM-Devnet]: <https://github.com/ciscodevnet/IOAM>
[IOAM-ietf-requirements]:<https://tools.ietf.org/html/draft-brockners-inband-oam-requirements-03>
[IOAM-ietf-transport]:<https://tools.ietf.org/html/draft-brockners-inband-oam-transport-03>
[IOAM-ietf-data]:<https://tools.ietf.org/html/draft-brockners-inband-oam-data-04>
[IOAM-ietf-proof-of-transit]:<https://tools.ietf.org/html/draft-brockners-proof-of-transit-03>

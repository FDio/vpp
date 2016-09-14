## VPP Inband OAM (iOAM)    {#ioam_plugin_doc}

In-band OAM (iOAM) is an implementation study to record operational
information in the packet while the packet traverses a path between
two points in the network.

Overview of iOAM can be found in [iOAM-Devnet] page.
The following IETF drafts detail the motivation and mechanism for
recording operational information:
 - [iOAM-ietf-requirements] - Describes motivation and usecases for iOAM
 - [iOAM-ietf-data] - Describes data records that can be collected using iOAM
 - [iOAM-ietf-transport] - Lists out the transport protocols
 and mechanism to carry iOAM data records
 - [iOAM-ietf-proof-of-transit] - Describes the idea of Proof of Transit (POT)
 and mechanisms to operationalize the idea

## Terminology
In-band OAM is expected to be deployed in a specific domain rather
than on the overall Internet. The part of the network which employs in-band OAM
is referred to as **"in-band OAM-domain"**.

In-band OAM data is added to a packet on entering the in-band OAM-domain
and is removed from the packet when exiting the domain.
Within the in-band OAM-domain, network nodes that the packet traverses
may update the in-band OAM data records.

- The node which adds in-band OAM data to the packet is called the
**"in-band OAM encapsulating node"**.

- The node which removes the in-band OAM data is referred to as the
**"in-band OAM decapsulating node"**.

- Nodes within the domain which are aware of in-band OAM data and read
and/or write or process the in-band OAM data are called
**"in-band OAM transit nodes"**.

## Features supported in the current release
VPP can function as in-band OAM encapsulating, transit and decapsulating node.
In this version of VPP in-band OAM data is transported as options in an
IPv6 hop-by-hop extension header. Hence in-band OAM can be enabled
for IPv6 traffic.

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

- **In-band OAM Proof of Transit (POT)**: Proof of transit iOAM data is
added to every packet for verifying that a packet traverses a specific
set of nodes.
In-band OAM data is updated at every node that is enabled with iOAM
proof of transit and is used to verify whether a packet traversed
all the specified nodes. When the verifier receives each packet,
it can validate whether the packet traversed the specified nodes.


## Configuration
Configuring iOAM involves:
- Selecting the packets for which iOAM data must be inserted, updated or removed
  - Selection of packets for iOAM data insertion on iOAM encapsulating node.
  Selection of packets is done by 5-tuple based classification
  - Selection of packets for updating iOAM data is implicitly done on the
  presence of iOAM options in the packet
  - Selection of packets for removing the iOAM data is done on 5-tuple
  based classification
- The kind of data to be collected
  - Tracing data
  - Proof of transit
- Additional details for processing iOAM data to be collected
  - For trace data - trace type, number of nodes to be recorded in the trace,
  time stamp precision, etc.
  - For POT data - configuration of POT profile required to process the POT data

The CLI for configuring iOAM is explained here followed by detailed steps
and examples to deploy iOAM on VPP as an encapsulating, transit or
decapsulating iOAM node in the subsequent sub-sections.

VPP iOAM configuration for enabling trace and POT is as follows:

    set ioam rewrite trace-type <0x1f|0x7|0x9|0x11|0x19>
    trace-elts <number of trace elements> trace-tsp <0|1|2|3>
    node-id <node ID in hex> app-data <application data in hex> [pot]

A description of each of the options of the CLI follows:
- trace-type : An entry in the "Node data List" array of the trace option
can have different formats, following the needs of the a deployment.
For example: Some deployments might only be interested
in recording the node identifiers, whereas others might be interested
in recording node identifier and timestamp.
The following types are currently supported:
    - 0x1f : Node data to include hop limit (8 bits), node ID (24 bits),
    ingress and egress interface IDs (16 bits each), timestamp (32 bits),
    application data (32 bits)
    - 0x7 : Node data to include hop limit (8 bits), node ID (24 bits),
    ingress and egress interface IDs (16 bits each)
    - 0x9 : Node data to include hop limit (8 bits), node ID (24 bits),
    timestamp (32 bits)
    - 0x11: Node data to include hop limit (8 bits), node ID (24 bits),
    application data (32 bits)
    - 0x19: Node data to include hop limit (8 bits), node ID (24 bits),
    timestamp (32 bits), application data (32 bits)
- trace-elts : Defines the length of the node data array in the trace option.
- trace-tsp : Defines the timestamp precision to use with the enumerated value
              for precision as follows:
    - 0 : 32bits timestamp in seconds
    - 1 : 32bits timestamp in milliseconds
    - 2 : 32bits timestamp in microseconds
    - 3 : 32bits timestamp in nanoseconds
- node-id : Unique identifier for the node, included in the node ID
  field of the node data in trace option.
- app-data : The value configured here is included as is in
application data field of node data in trace option.
- pot : Enables POT option to be included in the iOAM options.

### Trace configuration

#### On in-band OAM encapsulating node
 - **Configure classifier and apply ACL** to select packets for
 iOAM data insertion
    - Example to enable iOAM data insertion for all the packets
    towards IPv6 address db06::06:

    vpp# classify table miss-next node ip6-lookup mask l3 ip6 dst
    
    vpp# classify session acl-hit-next node ip6-add-hop-by-hop
    table-index 0 match l3 ip6 dst db06::06
    
    vpp# set int input acl intfc GigabitEthernet0/0/0 ip6-table 0
    
 - **Enable tracing** : Specify node ID, maximum number of nodes for which
 trace data should be recorded, type of data to be included for recording,
 optionally application data to be included
    - Example to enable tracing with a maximum of 4 nodes recorded
    and the data to be recorded to include - hop limit, node id,
    ingress and egress interface IDs, timestamp (millisecond precision),
    application data (0x1234):


    vpp# set ioam rewrite trace-type 0x1f trace-elts 4 trace-tsp 1
    node-id 0x1 app-data 0x1234



#### On in-band OAM transit node
- The transit node requires trace type, timestamp precision, node ID and
optionally application data to be configured,
to update its node data in the trace option.

Example:  

    vpp# set ioam rewrite trace-type 0x1f trace-elts 4 trace-tsp 1  
    node-id 0x2 app-data 0x1234  

#### On the In-band OAM decapsulating node
- The decapsulating node similar to encapsulating node requires
**classification** of the packets to remove iOAM data from.
    - Example to decapsulate iOAM data for packets towards
    db06::06, configure classifier and enable it as an ACL as follows:


    vpp# classify table miss-next node ip6-lookup mask l3 ip6 dst

    vpp# classify session acl-hit-next node ip6-lookup table-index 0
    match l3 ip6 dst db06::06 opaque-index 100

    vpp# set int input acl intfc GigabitEthernet0/0/0 ip6-table 0


- Decapsulating node requires trace type, timestamp precision,
node ID and optionally application data to be configured,
to update its node data in the trace option before it is decapsulated.

Example:  

    vpp# set ioam rewrite trace-type 0x1f trace-elts 4  
    trace-tsp 1 node-id 0x3 app-data 0x1234  


### Proof of Transit configuration

For details on proof-of-transit,
see the IETF draft [iOAM-ietf-proof-of-transit].
To enable Proof of Transit all the nodes that participate
and hence are verified for transit need a proof of transit profile.
A script to generate a proof of transit profile as per the mechanism
described in [iOAM-ietf-proof-of-transit] will be available at [iOAM-Devnet].

The Proof of transit mechanism implemented here is based on
Shamir's Secret Sharing algorithm.
The overall algorithm uses two polynomials 
POLY-1 and POLY-2. The degree of polynomials depends on number of nodes
to be verified for transit.
POLY-1 is secret and constant. Each node gets a point on POLY-1
at setup-time and keeps it secret.
POLY-2 is public, random and per packet.
Each node is assigned a point on POLY-1 and POLY-2 with the same x index.
Each node derives its point on POLY-2 each time a packet arrives at it.
A node then contributes its points on POLY-1 and POLY-2 to construct
POLY-3 (POLY-3 = POLY-1 + POLY-2) using lagrange extrapolation and
forwards it towards the verifier by updating POT data in the packet.
The verifier constructs POLY-3 from the accumulated value from all the nodes
and its own points on POLY-1 and POLY-2 and verifies whether
POLY-3 = POLY-1 + POLY-2.  Only the verifier knows POLY-1.
The solution leverages finite field arithmetic in a field of size "prime number"
for reasons explained in description of Shamir's secret sharing algorithm.

Here is an explanation of POT profile list and profile configuration CLI to
realize the above mechanism.
It is best to use the script provided at [iOAM-Devnet] to generate
this configuration.
- **Create POT profile** : set pot profile name <string> id [0-1]  
[validator-key 0xu64] prime-number 0xu64 secret_share 0xu64  
lpc 0xu64 polynomial2 0xu64 bits-in-random [0-64]  
    - name : Profile list name.
    - id : Profile id, it can be 0 or 1.
    A maximum of two profiles can be configured per profile list.
    - validator-key : Secret key configured only on the
    verifier/decapsulating node used to compare and verify proof of transit.
    - prime-number : Prime number for finite field arithmetic as required by the
    proof of transit mechanism.
    - secret_share : Unique point for each node on the secret polynomial POLY-1.
    - lpc : Lagrange Polynomial Constant(LPC) calculated per node based on
    its point (x value used for evaluating the points on the polynomial)
    on the polynomial used in lagrange extrapolation
    for reconstructing polynomial (POLY-3).
    - polynomial2 : Is the pre-evaluated value of the point on
    2nd polynomial(POLY-2). This is unique for each node.
    It is pre-evaluated for all the coefficients of POLY-2 except
    for the constant part of the polynomial that changes per packet
    and is received as part of the POT data in the packet.
    - bits-in-random : To control the size of the random number to be
    generated. This number has to match the other numbers generated and used
    in the profile as per the algorithm.

- **Set a configured profile as active/in-use** :  
set pot profile-active name <string> ID [0-1]  
    - name : Name of the profile list to be used for computing
    POT data per packet.
    - ID : Identifier of the profile within the list to be used.

#### On In-band OAM encapsulating node
 - Configure the classifier and apply ACL to select packets for iOAM data insertion.
    - Example to enable iOAM data insertion for all the packet towards
    IPv6 address db06::06 -


    vpp# classify table miss-next node ip6-lookup mask l3 ip6 dst

    vpp# classify session acl-hit-next node
    ip6-add-hop-by-hop table-index 0 match l3 ip6 dst db06::06

    vpp# set int input acl intfc GigabitEthernet0/0/0 ip6-table 0


 - Configure the proof of transit profile list with profiles.
Each profile list referred to by a name can contain 2 profiles,
only one is in use for updating proof of transit data at any time.
    - Example profile list example with a profile generated from the
    script to verify transit through 3 nodes is:


    vpp# set pot profile name example id 0 prime-number 0x7fff0000fa884685
    secret_share 0x6c22eff0f45ec56d lpc 0x7fff0000fa884682
    polynomial2 0xffb543d4a9c bits-in-random 63

 - Enable one of the profiles from the configured profile list as active
 so that is will be used for calculating proof of transit

Example enable profile ID 0 from profile list example configured above:


    vpp# set pot profile-active name example ID 0


 - Enable POT option to be inserted


    vpp# set ioam rewrite pot


#### On in-band OAM transit node
 - Configure the proof of transit profile list with profiles for transit node.
Example:


    vpp# set pot profile name example id 0 prime-number 0x7fff0000fa884685
    secret_share 0x564cdbdec4eb625d lpc 0x1
    polynomial2 0x23f3a227186a bits-in-random 63

#### On in-band OAM decapsulating node / verifier
- The decapsulating node, similar to the encapsulating node requires
classification of the packets to remove iOAM data from.
    - Example to decapsulate iOAM data for packets towards db06::06
    configure classifier and enable it as an ACL as follows:


    vpp# classify table miss-next node ip6-lookup mask l3 ip6 dst

    vpp# classify session acl-hit-next node ip6-lookup table-index 0
    match l3 ip6 dst db06::06 opaque-index 100

    vpp# set int input acl intfc GigabitEthernet0/0/0 ip6-table 0

- To update and verify the proof of transit, POT profile list should be configured.
    - Example POT profile list configured as follows:

    vpp# set pot profile name example id 0 validate-key 0x7fff0000fa88465d
    prime-number 0x7fff0000fa884685 secret_share 0x7a08fbfc5b93116d lpc 0x3
    polynomial2 0x3ff738597ce bits-in-random 63

## Operational data

Following CLIs are available to check iOAM operation:
- To check iOAM configuration that are effective use "show ioam summary"  

Example:

    vpp# show ioam summary  
                  REWRITE FLOW CONFIGS - Not configured  
     HOP BY HOP OPTIONS - TRACE CONFIG -  
                            Trace Type : 0x1f (31)  
             Trace timestamp precision : 1 (Milliseconds)  
                    Num of trace nodes : 4  
                               Node-id : 0x2 (2)  
                              App Data : 0x1234 (4660)  
                            POT OPTION - 1 (Enabled)  
    Try 'show ioam pot and show pot profile' for more information  

- To find statistics about packets for which iOAM options were
added (encapsulating node) and removed (decapsulating node) execute
*show errors*

Example on encapsulating node:


    vpp# show error
       Count                    Node                  Reason
    1208804706                ip6-inacl               input ACL hits
    1208804706           ip6-add-hop-by-hop           Pkts w/ added ip6 hop-by-hop options
    
Example on decapsulating node:

    vpp# show error
       Count                    Node                  Reason
      69508569                ip6-inacl               input ACL hits
      69508569           ip6-pop-hop-by-hop           Pkts w/ removed ip6 hop-by-hop options

- To check the POT profiles use "show pot profile"

Example:

    vpp# show pot profile
    Profile list in use  : example
    POT Profile at index: 0
                     ID : 0
              Validator : False (0)
           Secret share : 0x564cdbdec4eb625d (6218586935324795485)
           Prime number : 0x7fff0000fa884685 (9223090566081300101)
    2nd polynomial(eval) : 0x23f3a227186a (39529304496234)
                     LPC : 0x1 (1)
               Bit mask : 0x7fffffffffffffff (9223372036854775807)
    Profile index in use: 0
    Pkts passed : 0x36 (54)

- To get statistics  of POT for packets use "show ioam pot"

Example at encapsulating or transit node:

    vpp# show ioam pot
     Pkts with ip6 hop-by-hop POT options - 54
     Pkts with ip6 hop-by-hop POT options but no profile set - 0
     Pkts with POT in Policy - 0
     Pkts with POT out of Policy - 0
    

Example at decapsulating/verification node:


    vpp# show ioam pot
     Pkts with ip6 hop-by-hop POT options - 54
     Pkts with ip6 hop-by-hop POT options but no profile set - 0
     Pkts with POT in Policy - 54
     Pkts with POT out of Policy - 0
    
- Tracing - enable trace of IPv6 packets to view the data inserted and
collected.

Example when the nodes are receiving data over a DPDK interface:
Enable tracing using "trace add dpdk-input 20" and
execute "show trace" to view the iOAM data collected:

  
    vpp# trace add dpdk-input 20  
      
    vpp# show trace
    
    ------------------- Start of thread 0 vpp_main -------------------  
    
    Packet 1  
      
    00:00:19:294697: dpdk-input  
      GigabitEthernetb/0/0 rx queue 0  
      buffer 0x10e6b: current data 0, length 214, free-list 0, totlen-nifb 0, trace 0x0  
      PKT MBUF: port 0, nb_segs 1, pkt_len 214  
        buf_len 2176, data_len 214, ol_flags 0x0, data_off 128, phys_addr 0xe9a35a00  
        packet_type 0x0  
      IP6: 00:50:56:9c:df:72 -> 00:50:56:9c:be:55  
      IP6_HOP_BY_HOP_OPTIONS: db05::2 -> db06::6  
        tos 0x00, flow label 0x0, hop limit 63, payload length 160  
    00:00:19:294737: ethernet-input  
      IP6: 00:50:56:9c:df:72 -> 00:50:56:9c:be:55  
    00:00:19:294753: ip6-input  
      IP6_HOP_BY_HOP_OPTIONS: db05::2 -> db06::6  
        tos 0x00, flow label 0x0, hop limit 63, payload length 160  
    00:00:19:294757: ip6-lookup  
      fib 0 adj-idx 15 : indirect via db05::2 flow hash: 0x00000000  
      IP6_HOP_BY_HOP_OPTIONS: db05::2 -> db06::6  
        tos 0x00, flow label 0x0, hop limit 63, payload length 160  
    00:00:19:294802: ip6-hop-by-hop  
      IP6_HOP_BY_HOP: next index 5 len 96 traced 96  Trace Type 0x1f , 1 elts left  
        [0] ttl 0x0 node ID 0x0 ingress 0x0 egress 0x0 ts 0x0  
    app 0x0  
        [1] ttl 0x3e node ID 0x3 ingress 0x1 egress 0x2 ts 0xb68c2213  
    app 0x1234  
        [2] ttl 0x3f node ID 0x2 ingress 0x1 egress 0x2 ts 0xb68c2204  
    app 0x1234  
        [3] ttl 0x40 node ID 0x1 ingress 0x5 egress 0x6 ts 0xb68c2200  
    app 0x1234  
        POT opt present  
             random = 0x577a916946071950, Cumulative = 0x10b46e78a35a392d, Index = 0x0  
    00:00:19:294810: ip6-rewrite  
      tx_sw_if_index 1 adj-idx 14 : GigabitEthernetb/0/0  
                                    IP6: 00:50:56:9c:be:55 -> 00:50:56:9c:df:72 flow hash: 0x00000000  
      IP6: 00:50:56:9c:be:55 -> 00:50:56:9c:df:72  
      IP6_HOP_BY_HOP_OPTIONS: db05::2 -> db06::6  
        tos 0x00, flow label 0x0, hop limit 62, payload length 160  
    00:00:19:294814: GigabitEthernetb/0/0-output  
      GigabitEthernetb/0/0  
      IP6: 00:50:56:9c:be:55 -> 00:50:56:9c:df:72  
      IP6_HOP_BY_HOP_OPTIONS: db05::2 -> db06::6  
        tos 0x00, flow label 0x0, hop limit 62, payload length 160  
    00:00:19:294820: GigabitEthernetb/0/0-tx    
      GigabitEthernetb/0/0 tx queue 0    
      buffer 0x10e6b: current data 0, length 214, free-list 0, totlen-nifb 0, trace 0x0    
      IP6: 00:50:56:9c:be:55 -> 00:50:56:9c:df:72
      
      IP6_HOP_BY_HOP_OPTIONS: db05::2 -> db06::6
      
        tos 0x00, flow label 0x0, hop limit 62, payload length 160  
    

[iOAM-Devnet]: <https://github.com/ciscodevnet/iOAM>
[iOAM-ietf-requirements]:<https://tools.ietf.org/html/draft-brockners-inband-oam-requirements-01>
[iOAM-ietf-transport]:<https://tools.ietf.org/html/draft-brockners-inband-oam-transport-01>
[iOAM-ietf-data]:<https://tools.ietf.org/html/draft-brockners-inband-oam-data-01>
[iOAM-ietf-proof-of-transit]:<https://tools.ietf.org/html/draft-brockners-proof-of-transit-01>

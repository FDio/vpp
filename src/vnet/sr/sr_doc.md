# SRv6: Segment Routing for IPv6    {#sr_doc}

This is a memo intended to contain documentation of the VPP SRv6 implementation
Everything that is not directly obvious should come here.
For any feedback on content that should be explained please mailto:pcamaril@cisco.com

## Segment Routing

Segment routing is a network technology focused on addressing the limitations of existing IP and Multiprotocol Label Switching (MPLS) networks in terms of simplicity, scale, and ease of operation. It is a foundation for application engineered routing as it prepares the networks for new business models where applications can control the network behavior.

Segment routing seeks the right balance between distributed intelligence and centralized optimization and programming. It was built for the software-defined networking (SDN) era.

Segment routing enhances packet forwarding behavior by enabling a network to transport unicast packets through a specific forwarding path, different from the normal path that a packet usually takes (IGP shortest path or BGP best path). This capability benefits many use cases, and one can build those specific paths based on application requirements.

Segment routing uses the source routing paradigm. A node, usually a router but also a switch, a trusted server, or a virtual forwarder running on a hypervisor, steers a packet through an ordered list of instructions, called segments. A segment can represent any instruction, topological or service-based. A segment can have a local semantic to a segment-routing node or global within a segment-routing network. Segment routing allows an operator to enforce a flow through any topological path and service chain while maintaining per-flow state only at the ingress node to the segment-routing network. Segment routing also supports equal-cost multipath (ECMP) by design.

Segment routing can operate with either an MPLS or an IPv6 data plane. All the currently available MPLS services, such as Layer 3 VPN (L3VPN), L2VPN (Virtual Private Wire Service [VPWS], Virtual Private LAN Services [VPLS], Ethernet VPN [E-VPN], and Provider Backbone Bridging Ethernet VPN [PBB-EVPN]), can run on top of a segment-routing transport network.

**The implementation of Segment Routing in VPP only covers the IPv6 data plane (SRv6).**

## Segment Routing terminology

* Segment Routing Header (SRH): IPv6 routing extension header of type 'Segment Routing'. (draft-ietf-6man-segment-routing-header-05)
* SegmentID (SID): is an IPv6 address.
* Segment List (SL) (SID List): is the sequence of SIDs that the packet will traverse.
* SR Policy: defines the SRH that will be applied to a packet. A packet steered into an SR policy may either receive the SRH by IPv6 header encapsulation (as recommended in draft-ietf-6man-rfc2460bis) or it could be inserted within an existing IPv6 header. An SR policy is uniquely identified by its Binding SID and associated with a weighted set of Segment Lists. In case several SID lists are defined, traffic steered into the policy is unevenly load-balanced among them according to their respective weights.
* Local SID: is a SID associated with a processing function on the local node, which may go from advancing to the next SID in the SRH, to complex user-defined behaviors. When a FIB lookup, either in the main FIB or in a specific VRF, returns a match on a local SID, the associated function is performed.
* BindingSID: a BindingSID is a SID (only one) associated one-one with an SR Policy. If a packet arrives with an IPv6 DA corresponding to a BindingSID, then the SR policy will be applied to such packet.

## Creating an SR LocalSID

A local SID is associated to a Segment Routing behavior -or function- on the current node.

The most basic behavior is called END. It simply activates the next SID in the current packet, by decrementing the Segments Left value and updating the IPv6 DA.

A local END SID is instantiated using the following CLI:

    sr localsid (del) address XX::YY behavior end

This creates a new entry in the main FIB for IPv6 address XX::YY. All packets whose IPv6 DA matches this FIB entry are redirected to the sr-localsid node, where they are processed as described above.

Other examples of local SIDs are the following:

    sr localsid (del) address XX::YY behavior end (psp)
    sr localsid (del) address XX::YY behavior end.x GE0/1/0 2001::a (psp)
    sr localsid (del) address XX::YY behavior end.dx6 GE0/1/0 2001::a
    sr localsid (del) address XX::YY behavior end.dx4 GE0/1/0 10.0.0.1
    sr localsid (del) address XX::YY behavior end.dx2 GigabitE0/11/0
    sr localsid (del) address XX::YY behavior end.dt6 5
    sr localsid (del) address XX::YY behavior end.dt6 5

Note that all of these behaviors match the specifications in **TODO REF NET PGM**. Please refer to this document for a detailed description of each behavior.

Help on the available local SID behaviors and their usage can be obtained with:
    
    help sr localsid

Alternatively they can be obtained using.

    show sr localsids behavior

The difference in between those two commands is that the first one will only display the SR LocalSID behaviors that are built-in VPP, while the latter will display those behaviors plus the ones added with the SR LocalSID Development Framework.


VPP keeps a 'My LocalSID Table' where it stores all the SR local SIDs instantiated as well as their parameters. Every time a new local SID is instantiated, a new entry is added to this table. In addition, counters for correctly and incorrectly processed traffic are maintained for each local SID. The counters store both the number of packets and bytes.

The contents of the 'My LocalSID Table' is shown with:

    vpp# show sr localsid
    SRv6 - My LocalSID Table:
    =========================
            Address:        c3::1
            Behavior:       DX6 (Endpoint with decapsulation and IPv6 cross-connect)
            Iface:          GigabitEthernet0/5/0
            Next hop:       b:c3::b
            Good traffic:   [51277 packets : 5332808 bytes]
            Bad traffic:    [0 packets : 0 bytes]
    --------------------

The traffic counters can be reset with:

    vpp# clear sr localsid counters

## Creating a SR Policy

An SR Policy is defined by a Binding SID and a weighted set of Segment Lists.

A new SR policy is created with a first SID list using:

    sr policy add bsid 2001::1 next A1:: next B1:: next C1:: (weight 5) (fib-table 3)

* The weight parameter is only used if more than one SID list is associated with the policy.
* The fib-table parameter specifies in which table (VRF) the Binding SID is to be installed.

An SR policy is deleted with:

    sr policy del bsid 2001::1
    sr policy del index 1

The existing SR policies are listed with:

    show sr policies

### Adding/Removing SID Lists from an SR policy

An additional SID list is associated with an existing SR policy with:

    sr policy mod bsid 2001::1 add sl next A2:: next B2:: next C2:: (weight 3)
    sr policy mod index 3      add sl next A2:: next B2:: next C2:: (weight 3)

Conversely, a SID list can be removed from an SR policy with:

    sr policy mod bsid 2001::1 del sl index 1
    sr policy mod index 3      del sl index 1

Note that this cannot be used to remove the last SID list of a policy.

The weight of a SID list can also be modified with:

    sr policy mod bsid 2001::1 mod sl index 1 weight 4
    sr policy mod index 3      mod sl index 1 weight 4

### SR Policies: Spray policies

Spray policies are a specific type of SR policies where the packet is replicated on all the SID lists, rather than load-balanced among them.

SID list weights are ignored with this type of policies.

A Spray policy is instantiated by appending the keyword **spray** to a regular SR policy command, as in:

    sr policy add bsid 2001::1 next A1:: next B1:: next C1:: spray

Spray policies are used for removing multicast state from a network core domain, and instead send a linear unicast copy to every access node. The last SID in each list accesses the multicast tree within the access node.  

### Encapsulation SR policies

In case the user decides to create an SR policy an IPv6 Source Address must be specified for the encapsulated traffic. In order to do so the user might use the following command:
    
    set sr encaps source addr XXXX::YYYY

## Steering packets into a SR Policy 

To steer packets in Transit into an SR policy (T.Insert, T.Encaps and T.Encaps.L2 behaviors), the user needs to create an 'sr steering policy'.

    sr steer l3 2001::/64 via sr policy index 1
    sr steer l3 2001::/64 via sr policy bsid cafe::1
    sr steer l3 2001::/64 via sr policy bsid cafe::1 fib-table 3
    sr steer l3 10.0.0.0/16 via sr policy bsid cafe::1
    sr steer l2 TenGE0/1/0 via sr policy bsid cafe::1

Disclaimer: The T.Encaps.L2 will steer L2 frames into an SR Policy. Notice that creating an SR steering policy for L2 frames will actually automatically *puts the interface into promiscous mode*.

## SR LocalSID development framework

One of the * 'key' * concepts about SRv6 is regarding network programmability. This is why an SRv6 LocalSID is associated with an specific function. 

However, the trully way to enable network programmability is allowing any developer **easily** create his own SRv6 LocalSID function. That is the reason why we have added some API calls such that any developer can code his own SRv6 LocalSID behaviors as plugins an add them to the running SRv6 code.

The principle is that the developer only codes the behavior -the graph node-. However all the FIB handling, SR LocalSID instantiation and so on are done by the VPP SRv6 code.

For more information please refer to the documentation *SRv6 Sample SR LocalSID plugin*.

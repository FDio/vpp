# SRv6: Segment Routing for IPv6    {#srv6_doc}

This is a memo intended to contain documentation of the VPP SRv6 implementation.
Everything that is not directly obvious should come here.
For any feedback on content that should be explained please mailto:pcamaril@cisco.com

## Segment Routing

Segment routing is a network technology focused on addressing the limitations of existing IP and Multiprotocol Label Switching (MPLS) networks in terms of simplicity, scale, and ease of operation. It is a foundation for application engineered routing as it prepares the networks for new business models where applications can control the network behavior.

Segment routing seeks the right balance between distributed intelligence and centralized optimization and programming. It was built for the software-defined networking (SDN) era.

Segment routing enhances packet forwarding behavior by enabling a network to transport unicast packets through a specific forwarding path, different from the normal path that a packet usually takes (IGP shortest path or BGP best path). This capability benefits many use cases, and one can build those specific paths based on application requirements.

Segment routing uses the source routing paradigm. A node, usually a router but also a switch, a trusted server, or a virtual forwarder running on a hypervisor, steers a packet through an ordered list of instructions, called segments. A segment can represent any instruction, topological or service-based. A segment can have a local semantic to a segment-routing node or global within a segment-routing network. Segment routing allows an operator to enforce a flow through any topological path and service chain while maintaining per-flow state only at the ingress node to the segment-routing network. Segment routing also supports equal-cost multipath (ECMP) by design.

Segment routing can operate with either an MPLS or an IPv6 data plane. All the currently available MPLS services, such as Layer 3 VPN (L3VPN), L2VPN (Virtual Private Wire Service [VPWS], Virtual Private LAN Services [VPLS], Ethernet VPN [E-VPN], and Provider Backbone Bridging Ethernet VPN [PBB-EVPN]), can run on top of a segment-routing transport network.

**The implementation of Segment Routing in VPP covers both the IPv6 data plane (SRv6) as well as the MPLS data plane (SR-MPLS). This page contains the SRv6 documentation.**

## Segment Routing terminology

* Segment Routing Header (SRH): IPv6 routing extension header of type 'Segment Routing'. (draft-ietf-6man-segment-routing-header-05)
* SegmentID (SID): is an IPv6 address.
* Segment List (SL) (SID List): is the sequence of SIDs that the packet will traverse.
* SR Policy: defines the SRH that will be applied to a packet. A packet steered into an SR policy may either receive the SRH by IPv6 header encapsulation (as recommended in draft-ietf-6man-rfc2460bis) or it could be inserted within an existing IPv6 header. An SR policy is uniquely identified by its Binding SID and associated with a weighted set of Segment Lists. In case several SID lists are defined, traffic steered into the policy is unevenly load-balanced among them according to their respective weights.
* Local SID: is a SID associated with a processing function on the local node, which may go from advancing to the next SID in the SRH, to complex user-defined behaviors. When a FIB lookup, either in the main FIB or in a specific VRF, returns a match on a local SID, the associated function is performed.
* BindingSID: a BindingSID is a SID (only one) associated one-one with an SR Policy. If a packet arrives with an IPv6 DA corresponding to a BindingSID, then the SR policy will be applied to such packet.

## SRv6 Features in VPP

The <a href="https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-network-programming/">SRv6 Network Programming (*draft-filsfils-spring-srv6-network-programming*)</a> defines the SRv6 architecture.

VPP supports the following SRv6 LocalSID functions: End, End.X, End.DX6, End.DT6, End.DX4, End.DT4, End.DX2, End.B6, End.B6.Encaps.

For further information and how to configure each specific function: @subpage srv6_localsid_doc


The <a href="https://datatracker.ietf.org/doc/draft-filsfils-spring-segment-routing-policy/">Segment Routing Policy (*draft-filsfils-spring-segment-routing-policy*)</a> defines SR Policies.

VPP supports SRv6 Policies with T.Insert and T.Encaps behaviors.

For further information on how to create SR Policies: @subpage srv6_policy_doc

For further information on how to steer traffic into SR Policies: @subpage srv6_steering_doc

## SRv6 LocalSID development framework

One of the *'key'* concepts about SRv6 is network programmability. This is why an SRv6 LocalSID is associated with an specific function. 

However, the trully way to enable network programmability is allowing any developer **easily** create his own SRv6 LocalSID function. That is the reason why we have added some API calls such that any developer can code his own SRv6 LocalSID behaviors as plugins an add them to the running SRv6 code.

The principle is that the developer only codes the behavior -the graph node-. However all the FIB handling, SR LocalSID instantiation and so on are done by the VPP SRv6 code.

For more information please refer to: @subpage srv6_plugin_doc

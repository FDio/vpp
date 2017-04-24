# SR-MPLS: Segment Routing for MPLS    {#srmpls_doc}

This is a memo intended to contain documentation of the VPP SR-MPLS implementation.
Everything that is not directly obvious should come here.
For any feedback on content that should be explained please mailto:pcamaril@cisco.com

## Segment Routing

Segment routing is a network technology focused on addressing the limitations of existing IP and Multiprotocol Label Switching (MPLS) networks in terms of simplicity, scale, and ease of operation. It is a foundation for application engineered routing as it prepares the networks for new business models where applications can control the network behavior.

Segment routing seeks the right balance between distributed intelligence and centralized optimization and programming. It was built for the software-defined networking (SDN) era.

Segment routing enhances packet forwarding behavior by enabling a network to transport unicast packets through a specific forwarding path, different from the normal path that a packet usually takes (IGP shortest path or BGP best path). This capability benefits many use cases, and one can build those specific paths based on application requirements.

Segment routing uses the source routing paradigm. A node, usually a router but also a switch, a trusted server, or a virtual forwarder running on a hypervisor, steers a packet through an ordered list of instructions, called segments. A segment can represent any instruction, topological or service-based. A segment can have a local semantic to a segment-routing node or global within a segment-routing network. Segment routing allows an operator to enforce a flow through any topological path and service chain while maintaining per-flow state only at the ingress node to the segment-routing network. Segment routing also supports equal-cost multipath (ECMP) by design.

Segment routing can operate with either an MPLS or an IPv6 data plane. All the currently available MPLS services, such as Layer 3 VPN (L3VPN), L2VPN (Virtual Private Wire Service [VPWS], Virtual Private LAN Services [VPLS], Ethernet VPN [E-VPN], and Provider Backbone Bridging Ethernet VPN [PBB-EVPN]), can run on top of a segment-routing transport network.

**The implementation of Segment Routing in VPP covers both the IPv6 data plane (SRv6) as well as the MPLS data plane (SR-MPLS). This page contains the SR-MPLS documentation.**

## Segment Routing terminology

* SegmentID (SID): is an MPLS label.
* Segment List (SL) (SID List): is the sequence of SIDs that the packet will traverse.
* SR Policy: is a set of candidate paths (SID list+weight). An SR policy is uniquely identified by its Binding SID and associated with a weighted set of Segment Lists. In case several SID lists are defined, traffic steered into the policy is unevenly load-balanced among them according to their respective weights.
* BindingSID: a BindingSID is a SID (only one) associated one-one with an SR Policy. If a packet arrives with MPLS label corresponding to a BindingSID, then the SR policy will be applied to such packet. (BindingSID is popped first.)

## SR-MPLS features in VPP

The SR-MPLS implementation is focused on the SR policies, as well on its steering. Others SR-MPLS features, such as for example AdjSIDs, can be achieved using the regular VPP MPLS implementation.

The <a href="https://datatracker.ietf.org/doc/draft-filsfils-spring-segment-routing-policy/">Segment Routing Policy (*draft-filsfils-spring-segment-routing-policy*)</a> defines SR Policies.

## Creating a SR Policy

An SR Policy is defined by a Binding SID and a weighted set of Segment Lists.

A new SR policy is created with a first SID list using:

    sr mpls policy add bsid 40001 next 16001 next 16002 next 16003 (weight 5)

* The weight parameter is only used if more than one SID list is associated with the policy.

An SR policy is deleted with:

    sr mpls policy del bsid 40001

The existing SR policies are listed with:

    show sr mpls policies

### Adding/Removing SID Lists from an SR policy

An additional SID list is associated with an existing SR policy with:

    sr mpls policy mod bsid 40001 add sl next 16001 next 16002 next 16003 (weight 3)

Conversely, a SID list can be removed from an SR policy with:

    sr mpls policy mod bsid 4001 del sl index 1

Note that this CLI cannot be used to remove the last SID list of a policy. Instead the SR policy delete CLI must be used.

The weight of a SID list can also be modified with:

    sr mpls policy mod bsid 40001 mod sl index 1 weight 4
    sr mpls policy mod index 1    mod sl index 1 weight 4

### SR Policies: Spray policies

Spray policies are a specific type of SR policies where the packet is replicated on all the SID lists, rather than load-balanced among them.

SID list weights are ignored with this type of policies.

A Spray policy is instantiated by appending the keyword **spray** to a regular SR-MPLS policy command, as in:

    sr mpls policy add bsid 40002 next 16001 next 16002 next 16003 spray

Spray policies are used for removing multicast state from a network core domain, and instead send a linear unicast copy to every access node. The last SID in each list accesses the multicast tree within the access node.  

## Steering packets into a SR Policy

To steer packets in Transit into an SR policy, the user needs to create an 'sr steering policy'.

    sr mpls steer l3 2001::/64 via sr policy bsid 40001
    sr mpls steer l3 2001::/64 via sr policy bsid 40001 fib-table 3
    sr mpls steer l3 10.0.0.0/16 via sr policy bsid 40001

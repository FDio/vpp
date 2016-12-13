# VPP Segment Routing for IPv6 (SRv6) implementation    {#sr_doc}

This is a memo intended to contain documentation of the VPP SRv6 implementation
Everything that is not directly obvious should come here.

## Segment Routing

Segment routing is a network technology focused on addressing the pain points of existing IP and Multiprotocol Label Switching (MPLS) networks in terms of simplicity, scale, and ease of operation. It’s a foundation for application engineered routing because it prepares the networks for new business models where applications can direct network behavior.

Segment routing seeks the right balance between distributed intelligence and centralized optimization and programming. It was built for the software-defined networking (SDN) era.

Segment routing enables enhanced packet forwarding behavior. It enables a network to transport unicast packets through a specific forwarding path, other than the normal shortest path that a packet usually takes. This capability benefits many use cases, and you can build those specific paths based on application requirements.

Segment routing uses the source routing paradigm. A node, usually a router but it can also be a switch, a trusted server, or a virtual forwarder running on a hypervisor, steers a packet through an ordered list of instructions, called segments. A segment can represent any instruction, topological or service-based. A segment can have a local semantic to a segment-routing node or global within a segment-routing network. Segment routing allows you to enforce a flow through any topological path and service chain while maintaining per-flow state only at the ingress node to the segment-routing network. To be aligned with modern IP networks, segment routing supports equal-cost multipath (ECMP) by design, and the forwarding within a segment-routing network uses all possible paths, when desired.

Segment routing can operate with either an MPLS or an IPv6 data plane. All the currently available MPLS services, such as Layer 3 VPN (L3VPN), L2VPN (Virtual Private Wire Service [VPWS], Virtual Private LAN Services [VPLS], Ethernet VPN [E-VPN], and Provider Backbone Bridging Ethernet VPN [PBB-EVPN]), can run on top of a segment-routing transport network.

The implementation of Segment Routing in VPP only covers the IPv6 data plane (SRv6).

## Segment Routing terminology

* Segment Routing Header (SRH): IPv6 extension header of type 'Routing Header' used for SRv6. (draft-ietf-6man-segment-routing-header-02)
* SegmentID (SID): is an IPv6 address.
* Segment List (SL) (SID List): is the set of IPv6 addresses that the packet will traverse
* BindingSID: a BindingSID is an IPv6 address (only one) associated to an SR Policy. If a packet arrives with an IPv6 DA corresponding to a BindingSID, then the SR policy will be applied to such packet.
* SR Policy: defines a Segment List that will be applied to a packet. Application can be done using IPv6 header encapsulation (as recommended by draft-ietf-6man-rfc2460bis-08) or using Segment Routing Header insertion. An SR Policy might contain one or several Segment Lists. In the latter case each SL will have a weight and there wECMP among them.
* SR LocalSID: A localSID is an IPv6 address Segment Routing enabled on the local node. It will be used for SR forwarding. A packet arriving with a Segment Routing header will not be processed unless the IPv6 DA is registered as a localSID. Each LocalSID has an associated functionality, that might go from plain Segment Routing processing to xconnect behaviors.

## Creating a SR LocalSID

A localsid is a SegmentID registered on the current node which is associated to a SR behavior. 

The most basic behavior is the End behavior. The End behavior means process the SRH, update the DA and if necessary remove the SRH'. This is achieved using the following CLI:
    sr localsid (del) locator XX:: function yy:yy (arguments zz:zz) behavior end

This will create a new entry in the FIB for IPv6 address XX::yy:yy:zz:zz. All packets that match this FIB entry will be redirected to the `sr-localsid` node. In this node the packets will be processed according to the behavior associated with that localsid, in this case only end procesing.

Other examples of localsids are the following:

    sr localsid (del) locator XX:: function yy:yy (arguments zz:zz) behavior end
    sr localsid (del) locator XX:: function yy:yy (arguments zz:zz) behavior l2 xconnect GigabitE0/11/0
    sr localsid (del) locator XX:: function yy:yy (arguments zz:zz) behavior l3 xconnect GE0/1/0 2001::a
    sr localsid (del) locator XX:: function yy:yy (arguments zz:zz) behavior vrf 5

To show all the SR localsids:

    show sr localsid

## Creating a SR Policy

A SR Policy is defined by a BindingSID and a list of Segment Lists with its corresponding weight each of them.

To create a SR Policy:

    sr policy add bsid 2001::1 next A1:: next B1:: next C1:: (weight 5) (fib-table 3)

* The weight parameter associates a weight to the Segment List. Notice that if the SR policy only contains one Segment List the weight is irrelevant.
* The fib-table parameter specifies in which FIB-table (VRF) to install the BindingSID.

To delete a SR Policy:

    sr policy del bsid 2001::1
    sr policy del index 1

To show all SR policies:

    show sr policies

### Adding/Removing SID Lists from a SR policy

To add another Segment List to an existing SR Policy:

    sr policy mod bsid 2001::1 add sl next A2:: next B2:: next C2:: (weight 3)
    sr policy mod index 3      add sl next A2:: next B2:: next C2:: (weight 3)

To remove an existing Segment List from an SR policy:

    sr policy mod bsid 2001::1 del sl index 1
    sr policy mod index 3      del sl index 1

To modify the weight of a Segment List:

    sr policy mod bsid 2001::1 mod sl index 1 weight 4
    sr policy mod index 3      mod sl index 1 weight 4

## Steering packets into a SR Policy 

## Counters

All the segment routing graph nodes have a rich set of counters. To view them type:

    show node counters

## Spray use-case

The Spray use-case is a different type of SR Policy that will replicate the packets accross all the different Segment Lists within the SR policy. 

The Spray use-case is useful for removing the multicast state from a network core domain, sending a linear unicast copy to every access node. The last segment of every Segment List will access the multicast tree within the access node.

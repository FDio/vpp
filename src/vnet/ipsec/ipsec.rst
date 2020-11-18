.. _ipsec:

.. toctree::

IP Security
===========

This is not a description on how IPSec works. Please read:

  - https://tools.ietf.org/html/rfc4301
  - https://tools.ietf.org/html/rfc4302
  - https://tools.ietf.org/html/rfc4303  


I would also suggest this:

  - https://wiki.strongswan.org/projects/strongswan/wiki/RouteBasedVPN


If you're interested in cryptography, I would recommend this excellent
introductory lecture series (there is also a book, but you'll have to
buy it, IMHO it's worth it):

  - https://www.youtube.com/channel/UC1usFRN4LCMcfIV7UjHNuQg/featured


IPSec VPNs come in two flavours; policy and route based, the
difference is how the Security Association (SA) is chosen.


Route Base VPNs
---------------

There are two aspects of a route based VPN; all packets to a
particular peer are encrypted by the same SA and routing
decides the peer to which to forward traffic (as routing always
does). Therefore, routing is choosing the SA. Of course the same must
be true in reverse, that all packets from a given peer are decrypted
with the same SA. Another way of expressing this is to say a peer is
'protected' by this SA (really a pair of SAs; one for rx and tx).

The 'standard' [#i1]_ way of representing this protected peer is by
using a point-to-point virtual interface to which the peer is
attached and the SA pair is associated. Prefixes
that require protection are routed through this virtual interface and
hence implicitly to the peer.

There are three components to the model:

- The SAs; An **ipsec_sa_t**, use the force, read the source.
- The virtual interface
- The protection - the association of the SAs to the interface.


The protection is represented by a **ipsec_tun_protect_t**. The "tun"
part comes from the fact that the protected interface is usually a
tunnel. IMO It would have been better if the author had not assumed
this [#i2]_.
The protection associates a single TX SA and up to four RX SAs to an
interface. Four is as many as can fit on one cache-line. Multiple RX
SAs mean that a peer can be using any SA in the set, this is
particularly useful during rekeying because it is not possible for the
peers to swap their RX and TX SAs at exactly the same moment in the
traffic stream. Instead they can add the new RX immediately, then swap
the TX after a short delay, then remove the old RX after another short
delay. This will minimize, if not eliminate, packet loss.

The virtual interface can be represented in two ways:

 - interface + encap + SA = (interface + encap) + SA = ipip-interface + SA transport mode

or

 - interface + encap + SA = interface + (encap + SA) = IPSec-interface + SA tunnel mode

It's a question of where you add the parenthesis, from the perspective
of the external user the effect is identical.

The IPSec interface serves as the encap-free interface to be used in
conjunction with an encap-describing tunnel mode SA. VPP supports both models.

A route based VPN could impose 0, 1 or 2 encaps. the support matrix for  these use cases is:

.. code-block:: console


         |  0  |  1  |  2  |
   --------------------------
   ipip  |  N  |  Y  |  Y  |
   ipsec |  P  |  Y  |  P  |
 
Where P = potentially.

Ipsec could potentially support 0 encap (i.e. transport mode) since
neither the interface nor the SA *requires* encap. However, for a
route based VPN to use transport mode is probably wrong since one
shouldn't use transport mode for transit traffic, since without encap
it is not guaranteed to return. IPSec could potentially support 2
encaps, but that would require the SA to describe both, something it
does not do at this time.

Internally the difference is that the mid-chain adjacency for the IPSec
interface has no associated encap (whereas for an ipip tunnel it
describes the peer). Consequently, features on the output arc see
packets without any encap. Since the protecting SAs are in tunnel
mode, they apply the encap. The mid-chain adj is stacked only once the
protecting SA is known, since only then is the peer known. Otherwise
the VLIB graph nodes used are the same:

.. code-block:: console

   (routing) --> ipX-michain --> espX-encrypt --> adj-midchain-tx --> (routing)

    where X = 4 or 6.


Some benefits to the ipsec interface:

- it is slightly more efficient since the encapsulating IP header has its checksum updated only once.
- even when the interface is admin up traffic cannot be sent to a peer
  unless the SA is available (since it's the SA that determines the
  encap). With ipip interfaces a client must use the admin state to
  prevent sending until the SA is available. 

The best recommendations I can make are:

- pick a model that supports your use case
- make sure any other features you wish to use are supported by the model
- choose the model that best fits your control plane's model.


Multi-point Interfaces
^^^^^^^^^^^^^^^^^^^^^^

As mentioned above route based VPNs protect all packets destined to
a given peer with the same SA pair. This protection was modelled using
a virtual p2p interface, so one could legitimately reason that
all traffic through the interface is protected with the SA pair or all
traffic to the peer is protected, since they are one in the
same. However, when we consider multi-point interfaces, we have to
think of protection applying to the peers on the link.

When using IPSec protection on a P2MP link the **ipsec_tun_protect_t**
will be specific to a particular peer (in the P2P case this peer is
the usual special all zero address).

All other aspects of using route based VPNs remains the same. The
routes are resolved via specific peers on the interface, i.e.

.. code-block:: console

  ip route add 10.0.0.0/8 via 192.168.1.1 mipip0


rather than

.. code-block:: console

  ip route add 10.0.0.0/8 via ipip0


but one should always use a next-hop on a multi-access interface, so
this is not a restriction.

The data-path is unchanged, in both P2P and P2MP case the SA to
use for TX comes from the adjacency, and for RX it's the SPI that
matches to the SA and interface.


Policy Based VPNs
-----------------

At the risk of stating the obvious, in a policy based VPN the SA is
chosen based on a specific IPSec policy. A policy describes what
attributes of the packets to match and what action to take if
matched. Actions are:

- bypass: Ignore it
- discard: Drop it
- protect: Either encrypt or decrypt with a specific SA

The 'resolve' action which (as per-RFC4301) states that an IKE session
should be initiated, is not supported.

Policies are stored in a security policy database (SPD). An SPD is
attached to an interface. Packets that ingress and egress the
interface are matched against the policies in the attached SPD.
This is IPSec as described in RFC4301.


.. rubric:: Footnotes:

.. [#i1] Standard in inverted commas because, at least to my
         knowledge, there is no official standard (RFC) that states it
         should be this way. It is probably this way because routers
         model/implement/restrict/etc IPSec as an interface
         input/output feature.
.. [#i2] That's a self criticism.


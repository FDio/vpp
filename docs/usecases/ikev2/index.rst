.. _ikev2:

IKEv2 with VPP
==============

This sections describes some of the ways to establish IKEv2 connection
between two VPP instances or VPP and strongSwan. It covers scenarios in
which VPP is the IKEv2 responder (and strongSwan initiator) and vice versa.

Child SA mode
-------------

VPP protects a tunnel interface with the negotiated child SA. Without
``udp-encap`` the SA has no tunnel flag and ESP follows the outer IP header
of that interface:

- ``ipip`` interface (created automatically when the profile has no
  ``tunnel`` interface): the ESP payload is IP, which is tunnel mode on the
  wire. VPP does not request transport mode and declines a request for it:
  the response does not include ``USE_TRANSPORT_MODE``.
- other interface set with ``ikev2 profile set <name> tunnel <interface>``,
  e.g. GRE: VPP requests transport mode with ``USE_TRANSPORT_MODE`` as the
  initiator and includes it in the response as the responder when the peer
  requests it (RFC 7296 section 1.3.1). When both messages carry the
  notification the ESP payload is the tunnel encapsulation (transport
  mode). Otherwise the child SA is installed in tunnel mode and the ESP
  payload is the tunnel packet with its outer IP header.

.. toctree::

    vpp_resp_sswan_init
    vpp_init_sswan_resp
    2_vpp

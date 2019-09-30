.. _Linux_control_plane:

.. toctree::

Linux Control Plane Integration
===============================

Overview
________

This plugin allows VPP to integrate with the Linux. The
general model is that Linux is the network stack, i.e. it has the
control plane protocols, like ARP, IPv6 ND/MLD, Ping, etc, and VPP
provides a SW based ASIC for forwarding.

Interfaces
__________

VPP owns the interfaces in the system; physical (.e.g PCI), quasi
physical (e.g. vhost), or virtual (e.g. tunnel). However,
for the Linux networking stack to function it needs a representation
of these interfaces; it needs a mirror image in the kernel. For this
mirror we use a Tap interface, if the VPP interface is multi-point, a
Tun if it's point-to-point. A physical and its mirror form an
interface 'pair'.

The host interface has two identities; the sw_if_index of the Tap and
the virtual interface index in the kernel. It may be in a Linux namespace.

The creation of the interface pairs is required from the control
plane. It can be statically configured in the VPP startup
configuration file. The intent here was to make the pair creation
explicit, rather than have VPP guess which of the interfaces it owns
require a mirror.

Configuration
_____________

Linux will send and receive packets on the mirrored tap/tun
interfaces.
Any configuration that is made on these Linux interfaces, is
automatically also applied on the corresponding physical interface in
VPP. This is possible by the plugin listening to the netlink messages
and applying the config. As a result all e.g. routes programmed in
Linux, will also be present in VPP's FIB.

Linux will own the [ARP/ND] nieghbour tables (which will be copied via
netlink to VPP also). This means that Linux will send packets with the
peer's MAC address in the rewrite to VPP. The receiving TAP interface
must therefore be in promiscuous mode.


Forwarding
__________

The basic principle is to x-connect traffic from a Linux host interface
(received on the Tap/Tun) to its paired the physical, and vice-versa.

Host to Physical
^^^^^^^^^^^^^^^^

All packets sent by the host, and received by VPP on a Tap/Tun should
be sent to its paired physical interface. However, they should be sent
with the same consequences as if they had originated from VPP,
i.e. they should be subject to all output features on the physical
interface. To achieve this there is a per-IP-address-family (AF) node
inserted in the per-AF input feature arc. The node must be per-AF,
since it must be a sibling of a start node for the ipX-output feature
arc. This node uses the packet's L2 rewrite to search for the
adjacency that VPP would have used to send this packet; this adjacency
is stored in the buffer's meta data so that it is available to all
output features. Then the packet is sent through the physical
interface's IP output feature arc.
All ARP packets are x-connected from the tap to the physical.

Physical to Host
^^^^^^^^^^^^^^^^

All ARP packets received on the physical are sent to the paired
Tap. This allows the Linux network stack to build the nieghbour table.

IP packets that are punted are sent to the host. They are sent on the
tap that is paired with the physical on which they were originally
received. The packet is sent on the Tap/Tun 'exactly' as it was
received (i.e. with the L2 rewrite) but post any translations that
input features may have made.


Recommendations
^^^^^^^^^^^^^^^

When using this plugin disable the ARP, ND, IGMP plugins; this is the
task for Linux.
Disable ping plugin, since Linux will now respond.

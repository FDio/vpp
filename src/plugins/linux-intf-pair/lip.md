.. _LIP:

Linux Interface Pairs
=====================

.. toctree::

Overview
________

Consider the following setup

               +----------+ +--------+
               | DHCP-srv | | IP-app |
               +----------+ +--------+
                     |           |
                     ------------- Linux
	                   |
                       +------+
                       | Tap0 |
                       +------+
                           |
  +----+   +--------+   +-----+   +-----------+
  | L2 | - | Vxlan0 | - | VPP | - | Ethernet0 |
  +----+   +--------+   +-----+   +-----------+
    |
  +----+
  | VM |
  +----+

There are applications running in Linux that need to receive packets. VPP is acting as a VxLAN tunnel endpoint (TEP) and decapsulated packets are sent into an L2 bridge domain onto which other VMs are also attached. Both the Linux apps and the TEP use the same IP address.

This means that on the Linux side one does:
  ifconfig tap0 10.0.0.1 netmask 255.255.255.0
and in VPP
  set interface ip address ethernet0 10.0.0.1/24

In this scenario both Ethernet0 and Tap0 need to receive packets destined to 10.0.0.1 and both need to be able to reach hosts in the 10.0.0/24 subnet, i.e. both need to be able to build an ARP table.

"Linux Interface Pair" offers a solution to this by pairing Tap0 with Ethernet0. If the system above was augmented with more Ethernet and Tap interfaces with different shared addresses more pairs could be created.

Once interfaces are paired the following occurs;
...
 1) packets from the tap interface are L2 cross connected onto the Ethernet. This means that the Linux side of the tap must have the same MAC address as the VPP side of the Ethernet (so that peers do not see the whole system as having two MAC addresses).
 2) packets received on the Ethernet that are 'passive' punted to the tap have their original L2 header restored. This allows a DHCP server to run on Linux, without this the server would only see the Tap MAC address of VPP and would thus not be able to authenticate peers based on MAC address.
 3) ARP responses received on the Ethernet interface are used to learn by VPP and sent to the tap. This allows both Linux OS and VPP to build ARP tables.
 4) ARP requests received on the Ethernet interface are responded to by VPP and not sent to the tap. This means the peer only receives one ARP response.
...




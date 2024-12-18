GRE Tunnel configure example
============================
This plugin provides a simple gre tunnel implements and support to teb, l3, mpls_unicast, erspan and nsp for gre.

1. Setting GRE L2(teb) tunnel example:
---------------------------------------

* vpp docking vpp network topology

.. image:: /_images/gre-two-vpp-teb.png


Local Linux netns configure
::

   ip netns add app1
   ip link add name veth_vpp type veth peer name veth_kernal_ns netns app1
   ip link set dev veth_vpp up

   ip netns exec app1 ip link set lo up
   ip netns exec app1 ip link set veth_kernal_ns up
   ip netns exec app1 ip addr add 2.2.2.1/24 dev veth_kernal_ns

Local vpp configure
::

   vppctl set interface ip address eth0 10.8.124.10/24
   vppctl set interface state eth0 up

   vppctl create gre tunnel src 10.8.124.10 dst 10.8.124.11 instance 1 teb
   vppctl set interface state gre1 up
   vppctl set int l2 bridge gre1 1

   vppctl create host-interface name veth_vpp
   vppctl set int state host-veth_vpp up
   vppctl set int l2 bridge host-veth_vpp 1

Peer Linux netns configure
::

   ip netns add app2
   ip link add name veth_vpp type veth peer name veth_kernal_ns netns app2
   ip link set dev veth_vpp up

   ip netns exec app2 ip link set lo up
   ip netns exec app2 ip link set veth_kernal_ns up
   ip netns exec app2 ip addr add 2.2.2.2/24 dev veth_kernal_ns

Peer vpp configure
::

   vppctl set interface ip address eth0 10.8.124.11/24
   vppctl set interface state eth0 up

   vppctl create gre tunnel src 10.8.124.11 dst 10.8.124.10 instance 1 teb
   vppctl set interface state gre2 up
   vppctl set int l2 bridge gre2 1

   vppctl create host-interface name veth_vpp
   vppctl set int state host-veth_vpp up
   vppctl set int l2 bridge host-veth_vpp 1


VXLAN Tunnel configure example
==============================
This is a simple example case for VLXAN Tunnel.

1. Setting VXLAN tunnel example:
---------------------------------------

* vpp docking vpp network topology

.. image:: /_images/vxlan_topology.png


Local Linux netns configure
::

	ip netns add app1
	ip link add name app1 type veth peer name veth_app1 netns app1
	ip link set dev app1 up

	ip netns exec app1 ip link set lo up
	ip netns exec app1 ip link set veth_app1 up
	ip netns exec app1 ip addr add 2.2.2.1/24 dev veth_app1

Local vpp configure
::

	vppctl set interface ip address eth0 10.8.124.10/24
	vppctl set interface state eth0 up

	vppctl create vxlan tunnel src 10.8.124.10 dst 10.8.124.11 vni 10
	vppctl set int l2 bridge vxlan_tunnel0 1

	vppctl create host-interface name app1
	vppctl set int state host-app1 up
	vppctl set int l2 bridge host-app1 1

Peer Linux netns configure
::

	ip netns add app2
	ip link add name app2 type veth peer name veth_app2 netns app2
	ip link set dev app2 up

	ip netns exec app2 ip link set lo up
	ip netns exec app2 ip link set veth_app2 up
	ip netns exec app2 ip addr add 2.2.2.2/24 dev veth_app2

Peer vpp configure
::

	vppctl set interface ip address eth0 10.8.124.11/24
	vppctl set interface state eth0 up

	vppctl create vxlan tunnel src 10.8.124.11 dst 10.8.124.10 vni 10
	vppctl set int l2 bridge vxlan_tunnel0 1

	vppctl create host-interface name app2
	vppctl set int state host-app2 up
	vppctl set int l2 bridge host-app2 1

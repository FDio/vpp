.. _Routing:

.. toctree::

Connecting the two Containers
_____________________________

Now for connecting these two linux containers to VPP and pinging between them.

Enter container *cone*, and check the current network configuration:

.. code-block:: console

    root@cone:/# ip -o a
    1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
    1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
    2: veth0    inet 10.0.3.253/24 brd 10.0.3.255 scope global dynamic veth0\       valid_lft 3326sec preferred_lft 3326sec
    2: veth0    inet6 fe80::216:3eff:fe8c:b710/64 scope link \       valid_lft forever preferred_lft forever
    3: veth_link1    inet6 fe80::9ce3:11ff:fe2e:8680/64 scope link \       valid_lft forever preferred_lft forever

You can see that there are three network interfaces, *lo, veth0*, and *veth_link1*.

Notice that *veth_link1* has no assigned IP.

Check if the interfaces are down or up:

.. code-block:: console

    root@cone:/# ip link
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    2: veth0@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether 00:16:3e:8c:b7:10 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    3: veth_link1@if24: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether 9e:e3:11:2e:86:80 brd ff:ff:ff:ff:ff:ff link-netnsid 0

.. _networkNote:

.. note::

    Take note of the network index for **veth_link1**. In our case, it 3, and its parent index (the host machine, not the containers) is 24, shown by **veth_link1@if24**. Yours will most likely be different, but **please take note of these index's**.

Make sure your loopback interface is up, and assign an IP and gateway to veth_link1.

.. code-block:: console

    root@cone:/# ip link set dev lo up
    root@cone:/# ip addr add 172.16.1.2/24 dev veth_link1
    root@cone:/# ip link set dev veth_link1 up
    root@cone:/# dhclient -r
    root@cone:/# ip route add default via 172.16.1.1 dev veth_link1

Here, the IP is 172.16.1.2/24 and the gateway is 172.16.1.1.

Run some commands to verify the changes:

.. code-block:: console

    root@cone:/# ip -o a
    1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
    1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
    2: veth0    inet6 fe80::216:3eff:fe8c:b710/64 scope link \       valid_lft forever preferred_lft forever
    3: veth_link1    inet 172.16.1.2/24 scope global veth_link1\       valid_lft forever preferred_lft forever
    3: veth_link1    inet6 fe80::9ce3:11ff:fe2e:8680/64 scope link \       valid_lft forever preferred_lft forever

    root@cone:/# ip route
    default via 172.16.1.1 dev veth_link1
    172.16.1.0/24 dev veth_link1 proto kernel scope link src 172.16.1.2


We see that the IP has been assigned, as well as our default gateway.

Now exit this container and repeat this process with container *ctwo*, except with IP 172.16.2.2/24 and gateway 172.16.2.1.


After that's done for *both* containers, exit from the container if you're in one:

.. code-block:: console

    root@ctwo:/# exit
    exit
    root@localhost:~#

In the machine running the containers, run **ip link** to see the host *veth* network interfaces, and their link with their respective *container veth's*.

.. code-block:: console

    root@localhost:~# ip link
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
        link/ether 00:15:5d:3b:5b:6b brd ff:ff:ff:ff:ff:ff
    18: lxcbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether 00:16:3e:00:00:00 brd ff:ff:ff:ff:ff:ff
    23: vethuoTaG8@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master lxcbr0 state UP mode DEFAULT group default qlen 1000
        link/ether fe:2e:0f:f8:74:45 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    24: vethy1GVZ8@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether fe:69:c8:c1:f7:40 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    25: vethYJFtBn@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master lxcbr0 state UP mode DEFAULT group default qlen 1000
        link/ether fe:25:b9:41:aa:70 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    26: vethpUBl88@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether fe:8f:2f:58:6f:10 brd ff:ff:ff:ff:ff:ff link-netnsid 1


Remember our network interface index 3 in *cone* from this :ref:`note <networkNote>`? We can see at the bottom the name of the 24th index **vethy1GVZ8@if3**. Keep note of this network interface name for the veth connected to *cone* (ex. vethy1GVZ8), and the other network interface name for *ctwo*.

With VPP in the host machine, show current VPP interfaces:

.. code-block:: console

    root@localhost:~# vppctl show inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
    local0                        0     down          0/0/0/0

Which should only output local0.

Based on the names of the network interfaces discussed previously, which are specific to my systems, we can create VPP host-interfaces:

.. code-block:: console

    root@localhost:~# vppctl create host-interface name vethy1GVZ8
    root@localhost:~# vppctl create host-interface name vethpUBl88

Verify they have been set up properly:

.. code-block:: console

    root@localhost:~# vppctl show inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
    host-vethpUBl88                   2     down         9000/0/0/0
    host-vethy1GVZ8                   1     down         9000/0/0/0
    local0                            0     down          0/0/0/0

Which should output *three network interfaces*, local0, and the other two host network interfaces linked to the container veth's.


Set their state to up:

.. code-block:: console

    root@localhost:~# vppctl set interface state host-vethy1GVZ8 up
    root@localhost:~# vppctl set interface state host-vethpUBl88 up

Verify they are now up:

.. code-block:: console

    root@localhost:~# vppctl show inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
    host-vethpUBl88               1      up          9000/0/0/0
    host-vethy1GVZ8               2      up          9000/0/0/0
    local0                        0     down          0/0/0/0


Add IP addresses for the other end of each veth link:

.. code-block:: console

    root@localhost:~# vppctl set interface ip address host-vethy1GVZ8 172.16.1.1/24
    root@localhost:~# vppctl set interface ip address host-vethpUBl88 172.16.2.1/24


Verify the addresses are set properly by looking at the L3 table:

.. code-block:: console

    root@localhost:~# vppctl show inter addr
    host-vethy1GVZ8 (up):
      L3 172.16.1.1/24
    host-vethpUBl88 (up):
      L3 172.16.2.1/24
    local0 (dn):

Or looking at the FIB by doing:

.. code-block:: console

    root@localhost:~# vppctl show ip fib
    ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto flowlabel ] epoch:0 flags:none locks:[default-route:1, ]
    0.0.0.0/0
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:1 buckets:1 uRPF:0 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    0.0.0.0/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:2 buckets:1 uRPF:1 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    172.16.1.0/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:10 buckets:1 uRPF:9 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    172.16.1.0/24
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:9 buckets:1 uRPF:8 to:[0:0]]
        [0] [@4]: ipv4-glean: [src:172.16.1.0/24] host-vethy1GVZ8: mtu:9000 next:1 flags:[] ffffffffffff02fe653aa3cc0806
    172.16.1.1/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:12 buckets:1 uRPF:13 to:[0:0]]
        [0] [@12]: dpo-receive: 172.16.1.1 on host-vethy1GVZ8
    172.16.1.255/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:11 buckets:1 uRPF:11 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    172.16.2.0/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:14 buckets:1 uRPF:15 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    172.16.2.0/24
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:13 buckets:1 uRPF:14 to:[0:0]]
        [0] [@4]: ipv4-glean: [src:172.16.2.0/24] host-vethpUBl88: mtu:9000 next:2 flags:[] ffffffffffff02fe7d8708ac0806
    172.16.2.1/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:16 buckets:1 uRPF:19 to:[0:0]]
        [0] [@12]: dpo-receive: 172.16.2.1 on host-vethpUBl88
    172.16.2.255/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:15 buckets:1 uRPF:17 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    224.0.0.0/4
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:4 buckets:1 uRPF:3 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    240.0.0.0/4
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:3 buckets:1 uRPF:2 to:[0:0]]
        [0] [@0]: dpo-drop ip4
    255.255.255.255/32
    unicast-ip4-chain
    [@0]: dpo-load-balance: [proto:ip4 index:5 buckets:1 uRPF:4 to:[0:0]]
        [0] [@0]: dpo-drop ip4

At long last you probably want to see some pings:

.. code-block:: console

    root@localhost:~# lxc-attach -n cone -- ping -c3 172.16.2.2
    PING 172.16.2.2 (172.16.2.2) 56(84) bytes of data.
    64 bytes from 172.16.2.2: icmp_seq=1 ttl=63 time=0.102 ms
    64 bytes from 172.16.2.2: icmp_seq=2 ttl=63 time=0.189 ms
    64 bytes from 172.16.2.2: icmp_seq=3 ttl=63 time=0.150 ms

    --- 172.16.2.2 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 1999ms
    rtt min/avg/max/mdev = 0.102/0.147/0.189/0.035 ms

    root@localhost:~# lxc-attach -n ctwo -- ping -c3 172.16.1.2
    PING 172.16.1.2 (172.16.1.2) 56(84) bytes of data.
    64 bytes from 172.16.1.2: icmp_seq=1 ttl=63 time=0.111 ms
    64 bytes from 172.16.1.2: icmp_seq=2 ttl=63 time=0.089 ms
    64 bytes from 172.16.1.2: icmp_seq=3 ttl=63 time=0.096 ms

    --- 172.16.1.2 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 1998ms
    rtt min/avg/max/mdev = 0.089/0.098/0.111/0.014 ms


Which should send/receive three packets for each command.

This is the end of this guide. Great work!

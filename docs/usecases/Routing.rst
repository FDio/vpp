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
    30: veth0    inet 10.0.3.157/24 brd 10.0.3.255 scope global veth0\       valid_lft forever preferred_lft forever
    30: veth0    inet6 fe80::216:3eff:fee2:d0ba/64 scope link \       valid_lft forever preferred_lft forever
    32: veth_link1    inet6 fe80::2c9d:83ff:fe33:37e/64 scope link \       valid_lft forever preferred_lft forever

You can see that there are three network interfaces, *lo, veth0*, and *veth_link1*.

Notice that *veth_link1* has no assigned IP.

Check if the interfaces are down or up:

.. code-block:: console

    root@cone:/# ip link
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    30: veth0@if31: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether 00:16:3e:e2:d0:ba brd ff:ff:ff:ff:ff:ff link-netnsid 0
    32: veth_link1@if33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether 2e:9d:83:33:03:7e brd ff:ff:ff:ff:ff:ff link-netnsid 0

.. _networkNote:

.. note::

    Take note of the network index for **veth_link1**. In our case, it 32, and its parent index (the host machine, not the containers) is 33, shown by **veth_link1@if33**. Yours will most likely be different, but **please take note of these index's**.

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
    30: veth0    inet6 fe80::216:3eff:fee2:d0ba/64 scope link \       valid_lft forever preferred_lft forever
    32: veth_link1    inet 172.16.1.2/24 scope global veth_link1\       valid_lft forever preferred_lft forever
    32: veth_link1    inet6 fe80::2c9d:83ff:fe33:37e/64 scope link \       valid_lft forever preferred_lft forever

    root@cone:/# route
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    default         172.16.1.1      0.0.0.0         UG    0      0        0 veth_link1
    172.16.1.0      *               255.255.255.0   U     0      0        0 veth_link1


We see that the IP has been assigned, as well as our default gateway.

Now exit this container and repeat this process with container *ctwo*, except with IP 172.16.2.2/24 and gateway 172.16.2.1.


After thats done for *both* containers, exit from the container if you're in one:

.. code-block:: console
    
    root@ctwo:/# exit
    exit
    root@localhost:~#

In the machine running the containers, run **ip link** to see the host *veth* network interfaces, and their link with their respective *container veth's*.

.. code-block:: console
    
    root@localhost:~# ip link
    1: lo: <LOOPBACK> mtu 65536 qdisc noqueue state DOWN mode DEFAULT group default qlen 1
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
        link/ether 08:00:27:33:82:8a brd ff:ff:ff:ff:ff:ff
    3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
        link/ether 08:00:27:d9:9f:ac brd ff:ff:ff:ff:ff:ff
    4: enp0s9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
        link/ether 08:00:27:78:84:9d brd ff:ff:ff:ff:ff:ff
    5: lxcbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether 00:16:3e:00:00:00 brd ff:ff:ff:ff:ff:ff
    19: veth0C2FL7@if18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master lxcbr0 state UP mode DEFAULT group default qlen 1000
        link/ether fe:0d:da:90:c1:65 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    21: veth8NA72P@if20: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether fe:1c:9e:01:9f:82 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    31: vethXQMY4C@if30: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master lxcbr0 state UP mode DEFAULT group default qlen 1000
        link/ether fe:9a:d9:29:40:bb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    33: vethQL7KOC@if32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
        link/ether fe:ed:89:54:47:a2 brd ff:ff:ff:ff:ff:ff link-netnsid 0


Remember our network interface index 32 in *cone* from this :ref:`note <networkNote>`? We can see at the bottom the name of the 33rd index **vethQL7KOC@if32**. Keep note of this network interface name for the veth connected to *cone* (ex. vethQL7KOC), and the other network interface name for *ctwo*.

With VPP in the host machine, show current VPP interfaces:

.. code-block:: console
    
    root@localhost:~# vppctl show inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
    local0                        0     down          0/0/0/0  

Which should only output local0.

Based on the names of the network interfaces discussed previously, which are specific to my systems, we can create VPP host-interfaces:

.. code-block:: console
    
    root@localhost:~# vppctl create host-interface name vethQL7K0C
    root@localhost:~# vppctl create host-interface name veth8NA72P

Verify they have been set up properly:

.. code-block:: console
    
    root@localhost:~# vppctl show inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
    host-vethQL7K0C               1     down         9000/0/0/0     
    host-veth8NA72P               2     down         9000/0/0/0     
    local0                        0     down          0/0/0/0   

Which should output *three network interfaces*, local0, and the other two host network interfaces linked to the container veth's.


Set their state to up:

.. code-block:: console
    
    root@localhost:~# vppctl set interface state host-vethQL7K0C up
    root@localhost:~# vppctl set interface state host-veth8NA72P up

Verify they are now up:

.. code-block:: console

    root@localhost:~# vppctl show inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
    host-vethQL7K0C               1      up          9000/0/0/0     
    host-veth8NA72P               2      up          9000/0/0/0     
    local0                        0     down          0/0/0/0   


Add IP addresses for the other end of each veth link:

.. code-block:: console
    
    root@localhost:~# vppctl set interface ip address host-vethQL7K0C 172.16.1.1/24
    root@localhost:~# vppctl set interface ip address host-veth8NA72P 172.16.2.1/24


Verify the addresses are set properly by looking at the L3 table:

.. code-block:: console

    root@localhost:~# vppctl show inter addr
    host-vethQL7K0C (up):
      L3 172.16.1.1/24
    host-veth8NA72P (up):
      L3 172.16.2.1/24
    local0 (dn):

Or looking at the FIB by doing:

.. code-block:: console
    
    root@localhost:~# vppctl show ip fib
    ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] locks:[src:plugin-hi:2, src:default-route:1, ]
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
        [0] [@4]: ipv4-glean: host-vethQL7K0C: mtu:9000 ffffffffffff02fec953f98c0806
    172.16.1.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [proto:ip4 index:12 buckets:1 uRPF:13 to:[0:0]]
        [0] [@2]: dpo-receive: 172.16.1.1 on host-vethQL7K0C
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
        [0] [@4]: ipv4-glean: host-veth8NA72P: mtu:9000 ffffffffffff02fe305400e80806
    172.16.2.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [proto:ip4 index:16 buckets:1 uRPF:19 to:[0:0]]
        [0] [@2]: dpo-receive: 172.16.2.1 on host-veth8NA72P
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


Which should send/recieve three packets for each command.

This is the end of this guide. Great work! 
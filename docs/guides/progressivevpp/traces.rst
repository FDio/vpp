.. _traces:

.. toctree::

Traces 
======

Basic Trace Commands
~~~~~~~~~~~~~~~~~~~~

Show trace buffer [max COUNT].

.. code-block:: console 

  vpp# show trace


Clear trace buffer and free memory.

.. code-block:: console 

  vpp# clear trace

filter trace output - include NODE COUNT | exclude NODE COUNT | none.

.. code-block:: console 

  vpp# trace filter <include NODE COUNT | exclude NODE COUNT | none>

Skills to be Learned
~~~~~~~~~~~~~~~~~~~~

#. Setup a 'trace'
#. View a 'trace'
#. Clear a 'trace'
#. Verify using ping from host
#. Ping from vpp
#. Examine Arp Table
#. Examine ip fib

Add Trace
~~~~~~~~~

.. code-block:: console 

  vpp# trace add af-packet-input 10

Ping from Host to FD.io VPP
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console 

  vpp# q
  $ ping -c 1 10.10.1.2
  PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
  64 bytes from 10.10.1.2: icmp_seq=1 ttl=64 time=0.283 ms

  --- 10.10.1.2 ping statistics ---
  1 packets transmitted, 1 received, 0% packet loss, time 0ms
  rtt min/avg/max/mdev = 0.283/0.283/0.283/0.000 ms

Examine Trace of ping from host to FD.io VPP 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console 

  # vppctl
  vpp# show trace
  ------------------- Start of thread 0 vpp_main -------------------
  Packet 1

  00:17:04:099260: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e370 nsec 0x3af2736f vlan 0 vlan_tpid 0
  00:17:04:099269: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:17:04:099285: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099290: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099296: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3f7c
      fragment id 0xe516, flags DONT_FRAGMENT
    ICMP echo_request checksum 0xc043
  00:17:04:099300: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099301: ip4-icmp-echo-request
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099303: ip4-load-balance
  fib 0 dpo-idx 13 flow hash: 0x00000000
  ICMP: 10.10.1.2 -> 10.10.1.1
    tos 0x00, ttl 64, length 84, checksum 0x4437
    fragment id 0xe05b, flags DONT_FRAGMENT
  ICMP echo_reply checksum 0xc843
  00:17:04:099305: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 1 : ipv4 via 10.10.1.1 host-vpp1out: mtu:9000 e20f1e59ecf702fed975d5b40800 flow hash: 0x00000000
  00000000: e20f1e59ecf702fed975d5b4080045000054e05b4000400144370a0a01020a0a
  00000020: 01010000c8437c92000170e3605b000000001c170f00000000001011
  00:17:04:099307: host-vpp1out-output
  host-vpp1out
  IP4: 02:fe:d9:75:d5:b4 -> e2:0f:1e:59:ec:f7
  ICMP: 10.10.1.2 -> 10.10.1.1
    tos 0x00, ttl 64, length 84, checksum 0x4437
    fragment id 0xe05b, flags DONT_FRAGMENT
  ICMP echo_reply checksum 0xc843

Clear trace buffer
~~~~~~~~~~~~~~~~~~

.. code-block:: console 

  vpp# clear trace

Ping from FD.io VPP to Host 
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console 

  vpp# ping 10.10.1.1
  64 bytes from 10.10.1.1: icmp_seq=1 ttl=64 time=.0789 ms
  64 bytes from 10.10.1.1: icmp_seq=2 ttl=64 time=.0619 ms
  64 bytes from 10.10.1.1: icmp_seq=3 ttl=64 time=.0519 ms
  64 bytes from 10.10.1.1: icmp_seq=4 ttl=64 time=.0514 ms
  64 bytes from 10.10.1.1: icmp_seq=5 ttl=64 time=.0526 ms

  Statistics: 5 sent, 5 received, 0% packet loss

Examine Trace of ping from FD.io VPP to host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The output will demonstrate FD.io VPP's trace of ping for all packets.

.. code-block:: console 

  vpp# show trace
  ------------------- Start of thread 0 vpp_main -------------------
  Packet 1

  00:17:04:099260: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e370 nsec 0x3af2736f vlan 0 vlan_tpid 0
  00:17:04:099269: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:17:04:099285: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099290: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099296: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3f7c
      fragment id 0xe516, flags DONT_FRAGMENT
    ICMP echo_request checksum 0xc043
  00:17:04:099300: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099301: ip4-icmp-echo-request
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f7c
    fragment id 0xe516, flags DONT_FRAGMENT
  ICMP echo_request checksum 0xc043
  00:17:04:099303: ip4-load-balance
  fib 0 dpo-idx 13 flow hash: 0x00000000
  ICMP: 10.10.1.2 -> 10.10.1.1
    tos 0x00, ttl 64, length 84, checksum 0x4437
    fragment id 0xe05b, flags DONT_FRAGMENT
  ICMP echo_reply checksum 0xc843
  00:17:04:099305: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 1 : ipv4 via 10.10.1.1 host-vpp1out: mtu:9000 e20f1e59ecf702fed975d5b40800 flow hash: 0x00000000
  00000000: e20f1e59ecf702fed975d5b4080045000054e05b4000400144370a0a01020a0a
  00000020: 01010000c8437c92000170e3605b000000001c170f00000000001011
  00:17:04:099307: host-vpp1out-output
  host-vpp1out
  IP4: 02:fe:d9:75:d5:b4 -> e2:0f:1e:59:ec:f7
  ICMP: 10.10.1.2 -> 10.10.1.1
    tos 0x00, ttl 64, length 84, checksum 0x4437
    fragment id 0xe05b, flags DONT_FRAGMENT
  ICMP echo_reply checksum 0xc843

  Packet 2

  00:17:09:113964: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 42 snaplen 42 mac 66 net 80
      sec 0x5b60e375 nsec 0x3b3bd57d vlan 0 vlan_tpid 0
  00:17:09:113974: ethernet-input
  ARP: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:17:09:113986: arp-input
  request, type ethernet/IP4, address size 6/4
  e2:0f:1e:59:ec:f7/10.10.1.1 -> 00:00:00:00:00:00/10.10.1.2
  00:17:09:114003: host-vpp1out-output
  host-vpp1out
  ARP: 02:fe:d9:75:d5:b4 -> e2:0f:1e:59:ec:f7
  reply, type ethernet/IP4, address size 6/4
  02:fe:d9:75:d5:b4/10.10.1.2 -> e2:0f:1e:59:ec:f7/10.10.1.1

  Packet 3

  00:18:16:407079: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e3b9 nsec 0x90b7566 vlan 0 vlan_tpid 0
  00:18:16:407085: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:18:16:407090: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3fe8
    fragment id 0x24ab
  ICMP echo_reply checksum 0x37eb
  00:18:16:407094: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3fe8
    fragment id 0x24ab
  ICMP echo_reply checksum 0x37eb
  00:18:16:407097: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3fe8
      fragment id 0x24ab
    ICMP echo_reply checksum 0x37eb
  00:18:16:407101: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3fe8
    fragment id 0x24ab
  ICMP echo_reply checksum 0x37eb
  00:18:16:407104: ip4-icmp-echo-reply
  ICMP echo id 7531 seq 1
  00:18:16:407108: ip4-drop
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3fe8
      fragment id 0x24ab
    ICMP echo_reply checksum 0x37eb
  00:18:16:407111: error-drop
  ip4-icmp-input: unknown type

  Packet 4

  00:18:17:409084: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e3ba nsec 0x90b539f vlan 0 vlan_tpid 0
  00:18:17:409088: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:18:17:409092: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f40
    fragment id 0x2553
  ICMP echo_reply checksum 0xcc6d
  00:18:17:409095: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f40
    fragment id 0x2553
  ICMP echo_reply checksum 0xcc6d
  00:18:17:409097: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3f40
      fragment id 0x2553
    ICMP echo_reply checksum 0xcc6d
  00:18:17:409099: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3f40
    fragment id 0x2553
  ICMP echo_reply checksum 0xcc6d
  00:18:17:409101: ip4-icmp-echo-reply
  ICMP echo id 7531 seq 2
  00:18:17:409104: ip4-drop
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3f40
      fragment id 0x2553
    ICMP echo_reply checksum 0xcc6d
  00:18:17:409104: error-drop
  ip4-icmp-input: unknown type

  Packet 5

  00:18:18:409082: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e3bb nsec 0x8ecad24 vlan 0 vlan_tpid 0
  00:18:18:409087: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:18:18:409091: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e66
    fragment id 0x262d
  ICMP echo_reply checksum 0x8e59
  00:18:18:409093: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e66
    fragment id 0x262d
  ICMP echo_reply checksum 0x8e59
  00:18:18:409096: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3e66
      fragment id 0x262d
    ICMP echo_reply checksum 0x8e59
  00:18:18:409098: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e66
    fragment id 0x262d
  ICMP echo_reply checksum 0x8e59
  00:18:18:409099: ip4-icmp-echo-reply
  ICMP echo id 7531 seq 3
  00:18:18:409102: ip4-drop
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3e66
      fragment id 0x262d
    ICMP echo_reply checksum 0x8e59
  00:18:18:409102: error-drop
  ip4-icmp-input: unknown type

  Packet 6

  00:18:19:414750: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e3bc nsec 0x92450f2 vlan 0 vlan_tpid 0
  00:18:19:414754: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:18:19:414757: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e52
    fragment id 0x2641
  ICMP echo_reply checksum 0x9888
  00:18:19:414760: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e52
    fragment id 0x2641
  ICMP echo_reply checksum 0x9888
  00:18:19:414762: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3e52
      fragment id 0x2641
    ICMP echo_reply checksum 0x9888
  00:18:19:414764: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e52
    fragment id 0x2641
  ICMP echo_reply checksum 0x9888
  00:18:19:414765: ip4-icmp-echo-reply
  ICMP echo id 7531 seq 4
  00:18:19:414768: ip4-drop
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3e52
      fragment id 0x2641
    ICMP echo_reply checksum 0x9888
  00:18:19:414769: error-drop
  ip4-icmp-input: unknown type

  Packet 7

  00:18:20:418038: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 98 snaplen 98 mac 66 net 80
      sec 0x5b60e3bd nsec 0x937bcc2 vlan 0 vlan_tpid 0
  00:18:20:418042: ethernet-input
  IP4: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:18:20:418045: ip4-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e47
    fragment id 0x264c
  ICMP echo_reply checksum 0xc0e8
  00:18:20:418048: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e47
    fragment id 0x264c
  ICMP echo_reply checksum 0xc0e8
  00:18:20:418049: ip4-local
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3e47
      fragment id 0x264c
    ICMP echo_reply checksum 0xc0e8
  00:18:20:418054: ip4-icmp-input
  ICMP: 10.10.1.1 -> 10.10.1.2
    tos 0x00, ttl 64, length 84, checksum 0x3e47
    fragment id 0x264c
  ICMP echo_reply checksum 0xc0e8
  00:18:20:418054: ip4-icmp-echo-reply
  ICMP echo id 7531 seq 5
  00:18:20:418057: ip4-drop
    ICMP: 10.10.1.1 -> 10.10.1.2
      tos 0x00, ttl 64, length 84, checksum 0x3e47
      fragment id 0x264c
    ICMP echo_reply checksum 0xc0e8
  00:18:20:418058: error-drop
  ip4-icmp-input: unknown type

  Packet 8

  00:18:21:419208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 42 snaplen 42 mac 66 net 80
      sec 0x5b60e3be nsec 0x92a9429 vlan 0 vlan_tpid 0
  00:18:21:419876: ethernet-input
  ARP: e2:0f:1e:59:ec:f7 -> 02:fe:d9:75:d5:b4
  00:18:21:419881: arp-input
  request, type ethernet/IP4, address size 6/4
  e2:0f:1e:59:ec:f7/10.10.1.1 -> 00:00:00:00:00:00/10.10.1.2
  00:18:21:419896: host-vpp1out-output
  host-vpp1out
  ARP: 02:fe:d9:75:d5:b4 -> e2:0f:1e:59:ec:f7
  reply, type ethernet/IP4, address size 6/4
  02:fe:d9:75:d5:b4/10.10.1.2 -> e2:0f:1e:59:ec:f7/10.10.1.1

After examining the trace, clear it again using vpp# clear trace.

Examine arp tables
~~~~~~~~~~~~~~~~~~

.. code-block:: console 

  vpp# show ip arp
  Time           IP4       Flags      Ethernet              Interface
  1101.5636    10.10.1.1      D    e2:0f:1e:59:ec:f7 host-vpp1out        

Examine routing tables
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console 

  vpp# show ip fib
    ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] locks:[src:plugin-hi:2, src:adjacency:1, src:default-route:1, ]
  0.0.0.0/0
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:1 buckets:1 uRPF:0 to:[0:0]]
    [0] [@0]: dpo-drop ip4
  0.0.0.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:2 buckets:1 uRPF:1 to:[0:0]]
    [0] [@0]: dpo-drop ip4
  10.10.1.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:10 buckets:1 uRPF:9 to:[0:0]]
    [0] [@0]: dpo-drop ip4
  10.10.1.1/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:13 buckets:1 uRPF:12 to:[5:420] via:[2:168]]
    [0] [@5]: ipv4 via 10.10.1.1 host-vpp1out: mtu:9000 e20f1e59ecf702fed975d5b40800
  10.10.1.0/24
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:9 buckets:1 uRPF:8 to:[0:0]]
    [0] [@4]: ipv4-glean: host-vpp1out: mtu:9000 ffffffffffff02fed975d5b40806
  10.10.1.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:12 buckets:1 uRPF:13 to:[7:588]]
    [0] [@2]: dpo-receive: 10.10.1.2 on host-vpp1out
  10.10.1.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:11 buckets:1 uRPF:11 to:[0:0]]
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

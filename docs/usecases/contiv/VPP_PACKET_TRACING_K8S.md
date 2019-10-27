## How to do VPP Packet Tracing in Kubernetes

This document describes the steps to do *manual* packet tracing (capture) using
VPP in Kubernetes. Contiv/VPP also ships with a simple bash script
[vpptrace.sh](https://github.com/contiv/vpp/blob/master/scripts/vpptrace.sh), 
which allows to *continuously* trace and
*filter* packets incoming through a given set of interface types.
Documentation for vpptrace.sh is available [here](https://github.com/contiv/vpp/blob/master/docs/VPPTRACE.md).


More information about VPP packet tracing is in:

* <https://wiki.fd.io/view/VPP/Command-line_Interface_(CLI)_Guide#packet_tracer>  
* <https://wiki.fd.io/view/VPP/How_To_Use_The_Packet_Generator_and_Packet_Tracer>  
* <https://wiki.fd.io/view/VPP/Tutorial_Routing_and_Switching>  

#### SSH into the Node
Perform the following commands to SSH into the node:

```
cd vpp/vagrant/vagrant-scripts/
vagrant ssh k8s-worker1
```

#### Check the VPP Graph Nodes (Input and Output Queues)

The following content shows what is running on VPP, via the `show run` command

```
vagrant@k8s-worker1:~$ sudo vppctl
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# show run
Time 1026791.9, average vectors/node 1.12, last 128 main loops 0.00 per node 0.00
  vector rates in 1.6459e-4, out 1.5485e-4, drop 1.3635e-5, punt 0.0000e0
             Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call  
GigabitEthernet0/8/0-output      active                 56              69               0          1.34e3            1.23
GigabitEthernet0/8/0-tx          active                 54              67               0          8.09e5            1.24
acl-plugin-fa-cleaner-process  event wait                0               0               1          2.84e4            0.00
admin-up-down-process          event wait                0               0               1          4.59e3            0.00
api-rx-from-ring                any wait                 0               0         3316292          1.24e5            0.00
arp-input                        active                  3               3               0          2.53e5            1.00
bfd-process                    event wait                0               0               1          5.94e3            0.00
cdp-process                     any wait                 0               0          145916          1.36e4            0.00
dhcp-client-process             any wait                 0               0           10268          3.65e4            0.00
dns-resolver-process            any wait                 0               0            1027          5.86e4            0.00
dpdk-input                       polling     8211032318951              93               0         1.48e13            0.00
dpdk-ipsec-process                done                   1               0               0          2.10e5            0.00
dpdk-process                    any wait                 0               0          342233          9.86e6            0.00
error-drop                       active                 12              14               0          6.67e3            1.17
ethernet-input                   active                 60              74               0          5.81e3            1.23
fib-walk                        any wait                 0               0          513322          1.59e4            0.00
flow-report-process             any wait                 0               0               1          1.45e3            0.00
flowprobe-timer-process         any wait                 0               0               1          6.34e3            0.00
ikev2-manager-process           any wait                 0               0         1026484          1.18e4            0.00
interface-output                 active                  2               2               0          3.23e3            1.00
ioam-export-process             any wait                 0               0               1          1.98e3            0.00
ip-route-resolver-process       any wait                 0               0           10268          3.02e4            0.00
ip4-arp                          active                  1               1               0          1.49e4            1.00
ip4-input                        active                223             248               0          3.39e3            1.11
ip4-load-balance                 active                106             132               0          5.34e3            1.25
ip4-local                        active                 86              92               0          2.46e3            1.07
ip4-local-end-of-arc             active                 86              92               0          1.00e3            1.07
ip4-lookup                       active                223             248               0          3.31e3            1.11
ip4-rewrite                      active                190             222               0          1.92e3            1.17
ip4-udp-lookup                   active                 86              92               0          3.76e3            1.07
ip6-drop                         active                  6               7               0          2.29e3            1.17
ip6-icmp-neighbor-discovery-ev  any wait                 0               0         1026484          1.13e4            0.00
ip6-input                        active                  6               7               0          3.33e3            1.17
l2-flood                         active                  2               2               0          4.42e3            1.00
l2-fwd                           active                138             157               0          2.13e3            1.14
l2-input                         active                140             159               0          2.41e3            1.14
l2-learn                         active                 86              92               0          3.64e4            1.07
l2-output                        active                 54              67               0          3.05e3            1.24
l2fib-mac-age-scanner-process  event wait                0               0              85          5.01e4            0.00
lisp-retry-service              any wait                 0               0          513322          1.62e4            0.00
lldp-process                   event wait                0               0               1          5.02e4            0.00
loop0-output                     active                 54              67               0          1.66e3            1.24
loop0-tx                         active                 54               0               0          2.49e3            0.00
memif-process                  event wait                0               0               1          1.70e4            0.00
nat-det-expire-walk               done                   1               0               0          3.79e3            0.00
nat44-classify                   active                171             183               0          2.49e3            1.07
nat44-hairpinning                active                 86              92               0          1.80e3            1.07
nat44-in2out                     active                171             183               0          4.45e3            1.07
nat44-in2out-slowpath            active                171             183               0          3.98e3            1.07
nat44-out2in                     active                 52              65               0          1.28e4            1.25
nat64-expire-walk               any wait                 0               0          102677          5.95e4            0.00
nat64-expire-worker-walk      interrupt wa          102676               0               0          7.39e3            0.00
send-garp-na-process           event wait                0               0               1          1.28e3            0.00
startup-config-process            done                   1               0               1          4.19e3            0.00
tapcli-0-output                  active                  1               1               0          6.97e3            1.00
tapcli-0-tx                      active                  1               1               0          7.32e4            1.00
tapcli-1-output                  active                 57              63               0          1.66e3            1.11
tapcli-1-tx                      active                 57              63               0          1.35e5            1.11
tapcli-2-output                  active                 28              28               0          3.26e3            1.00
tapcli-2-tx                      active                 28              28               0          4.06e5            1.00
tapcli-rx                     interrupt wa              62              76               0          6.58e4            1.23
udp-ping-process                any wait                 0               0               1          1.79e4            0.00
unix-cli-127.0.0.1:43282         active                  2               0             455         1.26e15            0.00
unix-epoll-input                 polling        8010763239               0               0          8.17e2            0.00
vhost-user-process              any wait                 0               0               1          1.96e3            0.00
vhost-user-send-interrupt-proc  any wait                 0               0               1          3.85e3            0.00
vpe-link-state-process         event wait                0               0               8          9.79e4            0.00
vpe-oam-process                 any wait                 0               0          503263          1.21e4            0.00
vxlan-gpe-ioam-export-process   any wait                 0               0               1          2.91e3            0.00
vxlan4-encap                     active                 54              67               0          3.55e3            1.24
vxlan4-input                     active                 86              92               0          3.79e3            1.07
wildcard-ip4-arp-publisher-pro event wait                0               0               1          6.44e3            0.00
```

`tapcli-rx` above is the node-level input queue for incoming packets into all the pods on the node. There is one `tapcli-rx` input queue for every node.

The following are the input and output queues for each pod and the node:

```
tapcli-0-output
tapcli-0-tx
tapcli-1-output
tapcli-1-tx
tapcli-2-output 
tapcli-2-tx
```

Each pod and node has two queues, one for rx (`tapcli-X-output`), and one for tx (`tapcli-X-tx`). The above output is with two `nginx` pods in kubernetes.

#### Clear Existing VPP Packet Trace
Enter the following command:
```
vpp# clear trace             
```

#### How to Turn on VPP Packet Tracing
Enter the following commands:

```
vpp# trace add <input or output queue name> <number of packets to capture>

vpp# trace add dpdk-input 1000

vpp# trace add tapcli-rx 1000
```

#### Send Traffic to the Pods

Open another terminal, SSH into the master node, refer the documentation in `vpp/vagrant/README.md` and send traffic to the two `nginx` pods using `wget`.

```
cd vpp/vagrant/vagrant-scripts/
vagrant ssh k8s-master

vagrant@k8s-master:~$ kubectl get pods -o wide
NAME                   READY     STATUS    RESTARTS   AGE       IP         NODE
nginx-8586cf59-768qw   1/1       Running   0          11d       10.1.2.3   k8s-worker1
nginx-8586cf59-d27h2   1/1       Running   0          11d       10.1.2.2   k8s-worker1

vagrant@k8s-master:~$ wget 10.1.2.2
--2018-02-08 16:46:01--  http://10.1.2.2/
Connecting to 10.1.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 612 [text/html]
Saving to: ‘index.html’
index.html                       100%[=========================================================>]     612  --.-KB/s    in 0.004s  
2018-02-08 16:46:01 (162 KB/s) - ‘index.html’ saved [612/612]

vagrant@k8s-master:~$ wget 10.1.2.3
--2018-02-08 16:46:02--  http://10.1.2.3/
Connecting to 10.1.2.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 612 [text/html]
Saving to: ‘index.html.1’
index.html.1                     100%[=========================================================>]     612  --.-KB/s    in 0.004s  
2018-02-08 16:46:02 (143 KB/s) - ‘index.html.1’ saved [612/612]
```

#### Check the Packets Captured by VPP

Back in the first terminal, check the packets captured by VPP.

```
vpp# show trace
...
...
Packet 33

21:34:51:476110: tapcli-rx
  tapcli-2
21:34:51:476115: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:72:95:66:c7
21:34:51:476117: ip4-input
  TCP: 10.1.2.3 -> 172.30.1.2
    tos 0x00, ttl 64, length 52, checksum 0x6fb4
    fragment id 0x11ec, flags DONT_FRAGMENT
  TCP: 80 -> 58430
    seq. 0x5db741c8 ack 0x709defa7
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 235, checksum 0x55c3
21:34:51:476118: nat44-out2in
  NAT44_OUT2IN: sw_if_index 6, next index 1, session index -1
21:34:51:476120: ip4-lookup
  fib 0 dpo-idx 23 flow hash: 0x00000000
  TCP: 10.1.2.3 -> 172.30.1.2
    tos 0x00, ttl 64, length 52, checksum 0x6fb4
    fragment id 0x11ec, flags DONT_FRAGMENT
  TCP: 80 -> 58430
    seq. 0x5db741c8 ack 0x709defa7
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 235, checksum 0x55c3
21:34:51:476121: ip4-load-balance
  fib 0 dpo-idx 23 flow hash: 0x00000000
  TCP: 10.1.2.3 -> 172.30.1.2
    tos 0x00, ttl 64, length 52, checksum 0x6fb4
    fragment id 0x11ec, flags DONT_FRAGMENT
  TCP: 80 -> 58430
    seq. 0x5db741c8 ack 0x709defa7
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 235, checksum 0x55c3
21:34:51:476122: ip4-rewrite
  tx_sw_if_index 3 dpo-idx 5 : ipv4 via 192.168.30.1 loop0: 1a2b3c4d5e011a2b3c4d5e020800 flow hash: 0x00000000
  00000000: 1a2b3c4d5e011a2b3c4d5e0208004500003411ec40003f0670b40a010203ac1e
  00000020: 01020050e43e5db741c8709defa7801100eb55c300000101080a0f4b
21:34:51:476123: loop0-output
  loop0
  IP4: 1a:2b:3c:4d:5e:02 -> 1a:2b:3c:4d:5e:01
  TCP: 10.1.2.3 -> 172.30.1.2
    tos 0x00, ttl 63, length 52, checksum 0x70b4
    fragment id 0x11ec, flags DONT_FRAGMENT
  TCP: 80 -> 58430
    seq. 0x5db741c8 ack 0x709defa7
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 235, checksum 0x55c3
21:34:51:476124: l2-input
  l2-input: sw_if_index 3 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02
21:34:51:476125: l2-fwd
  l2-fwd:   sw_if_index 3 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 bd_index 1
21:34:51:476125: l2-output
  l2-output: sw_if_index 4 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 data 08 00 45 00 00 34 11 ec 40 00 3f 06
21:34:51:476126: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 10
21:34:51:476126: ip4-load-balance
  fib 4 dpo-idx 22 flow hash: 0x00000103
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 254, length 102, checksum 0x1b33
    fragment id 0x0000
  UDP: 24320 -> 4789
    length 82, checksum 0x0000
21:34:51:476127: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 4 : ipv4 via 192.168.16.1 GigabitEthernet0/8/0: 080027b2610908002733fb6f0800 flow hash: 0x00000103
  00000000: 080027b2610908002733fb6f08004500006600000000fd111c33c0a81002c0a8
  00000020: 10015f0012b5005200000800000000000a001a2b3c4d5e011a2b3c4d
21:34:51:476127: GigabitEthernet0/8/0-output
  GigabitEthernet0/8/0
  IP4: 08:00:27:33:fb:6f -> 08:00:27:b2:61:09
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 102, checksum 0x1c33
    fragment id 0x0000
  UDP: 24320 -> 4789
    length 82, checksum 0x0000
21:34:51:476128: GigabitEthernet0/8/0-tx
  GigabitEthernet0/8/0 tx queue 0
  buffer 0xfa7f: current data -50, length 116, free-list 0, clone-count 0, totlen-nifb 0, trace 0x20
                 l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 255, nb_segs 1, pkt_len 116
    buf_len 2176, data_len 116, ol_flags 0x0, data_off 78, phys_addr 0x569ea040
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:33:fb:6f -> 08:00:27:b2:61:09
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 102, checksum 0x1c33
    fragment id 0x0000
  UDP: 24320 -> 4789
    length 82, checksum 0x0000
```

In the above captured packet, we can see:

* Input queue name `tapcli-rx`
* Pod's IP address `10.1.2.3`
* IP address of the master node `172.30.1.2`, which sent the `wget` traffic to the two pods
* HTTP port `80`, destination port and TCP protocol (`TCP: 80 -> 58430`)
* NAT queue name `nat44-out2in`
* VXLAN VNI ID `VXLAN encap to vxlan_tunnel0 vni 10`
* VXLAN UDP port `4789`
* IP address of `GigabitEthernet0/8/0` interface (`192.168.16.2`)
* Packet on the outgoing queue `GigabitEthernet0/8/0-tx`

#### Find IP Addresses of GigabitEthernet and the Tap Interfaces
Enter the following commands to find the IP addresses and Tap interfaces:

```
vpp# show int address
GigabitEthernet0/8/0 (up):
  L3 192.168.16.2/24
local0 (dn):
loop0 (up):
  L2 bridge bd-id 1 idx 1 shg 0 bvi
  L3 192.168.30.2/24
tapcli-0 (up):
  L3 172.30.2.1/24
tapcli-1 (up):
  L3 10.2.1.2/32
tapcli-2 (up):
  L3 10.2.1.3/32
vxlan_tunnel0 (up):
  L2 bridge bd-id 1 idx 1 shg 0  
```

#### Other Useful VPP CLIs

Enter the following commands to see additional information about VPP:

```
vpp# show int
              Name               Idx       State          Counter          Count     
GigabitEthernet0/8/0              1         up       rx packets                   138
                                                     rx bytes                   18681
                                                     tx packets                   100
                                                     tx bytes                   29658
                                                     drops                          1
                                                     ip4                          137
                                                     tx-error                       2
local0                            0        down      drops                          1
loop0                             3         up       rx packets                   137
                                                     rx bytes                    9853
                                                     tx packets                   200
                                                     tx bytes                   49380
                                                     drops                          1
                                                     ip4                          136
tapcli-0                          2         up       rx packets                     8
                                                     rx bytes                     600
                                                     tx packets                     1
                                                     tx bytes                      42
                                                     drops                          9
                                                     ip6                            7
tapcli-1                          5         up       rx packets                    56
                                                     rx bytes                   13746
                                                     tx packets                    78
                                                     tx bytes                    6733
                                                     drops                          1
                                                     ip4                           56
tapcli-2                          6         up       rx packets                    42
                                                     rx bytes                   10860
                                                     tx packets                    58
                                                     tx bytes                    4996
                                                     drops                          1
                                                     ip4                           42
vxlan_tunnel0                     4         up       rx packets                   137
                                                     rx bytes                   11771
                                                     tx packets                   100
                                                     tx bytes                   28290

vpp# show hardware
              Name                Idx   Link  Hardware
GigabitEthernet0/8/0               1     up   GigabitEthernet0/8/0
  Ethernet address 08:00:27:33:fb:6f
  Intel 82540EM (e1000)
    carrier up full duplex speed 1000 mtu 9216 
    rx queues 1, rx desc 1024, tx queues 1, tx desc 1024
    cpu socket 0

    tx frames ok                                         100
    tx bytes ok                                        29658
    rx frames ok                                         138
    rx bytes ok                                        19233
    extended stats:
      rx good packets                                    138
      tx good packets                                    100
      rx good bytes                                    19233
      tx good bytes                                    29658
local0                             0    down  local0
  local
loop0                              3     up   loop0
  Ethernet address 1a:2b:3c:4d:5e:02
tapcli-0                           2     up   tapcli-0
  Ethernet address 02:fe:95:07:df:9c
tapcli-1                           5     up   tapcli-1
  Ethernet address 02:fe:3f:5f:0f:9a
tapcli-2                           6     up   tapcli-2
  Ethernet address 02:fe:72:95:66:c7
vxlan_tunnel0                      4     up   vxlan_tunnel0
  VXLAN

vpp# show bridge-domain         
  BD-ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
    1       1      1     off        on        on        on        on       off      loop0  

vpp# show bridge-domain 1 detail
  BD-ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
    1       1      1     off        on        on        on        on       off      loop0  

           Interface           If-idx ISN  SHG  BVI  TxFlood        VLAN-Tag-Rewrite       
             loop0               3     3    0    *      *                 none             
         vxlan_tunnel0           4     1    0    -      *                 none             

vpp# show l2fib verbose         
    Mac-Address     BD-Idx If-Idx BSN-ISN Age(min) static filter bvi         Interface-Name        
 1a:2b:3c:4d:5e:02    1      3      0/0      -       *      -     *               loop0            
 1a:2b:3c:4d:5e:01    1      4      1/1      -       -      -     -           vxlan_tunnel0        
L2FIB total/learned entries: 2/1  Last scan time: 0.0000e0sec  Learn limit: 4194304 

vpp# show ip fib
ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] locks:[src:(nil):2, src:adjacency:3, src:default-route:1, ]
0.0.0.0/0
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:1 buckets:1 uRPF:21 to:[0:0]]
    [0] [@5]: ipv4 via 172.30.2.2 tapcli-0: def35b93961902fe9507df9c0800
0.0.0.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:2 buckets:1 uRPF:1 to:[0:0]]
    [0] [@0]: dpo-drop ip4
10.1.1.0/24
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:24 buckets:1 uRPF:29 to:[0:0]]
    [0] [@10]: dpo-load-balance: [proto:ip4 index:23 buckets:1 uRPF:28 to:[0:0] via:[98:23234]]
          [0] [@5]: ipv4 via 192.168.30.1 loop0: 1a2b3c4d5e011a2b3c4d5e020800
10.1.2.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:27 buckets:1 uRPF:12 to:[78:5641]]
    [0] [@5]: ipv4 via 10.1.2.2 tapcli-1: 00000000000202fe3f5f0f9a0800
10.1.2.3/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:29 buckets:1 uRPF:32 to:[58:4184]]
    [0] [@5]: ipv4 via 10.1.2.3 tapcli-2: 00000000000202fe729566c70800
10.2.1.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:26 buckets:1 uRPF:31 to:[0:0]]
    [0] [@2]: dpo-receive: 10.2.1.2 on tapcli-1
10.2.1.3/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:28 buckets:1 uRPF:33 to:[0:0]]
    [0] [@2]: dpo-receive: 10.2.1.3 on tapcli-2
172.30.1.0/24
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:25 buckets:1 uRPF:29 to:[98:23234]]
    [0] [@10]: dpo-load-balance: [proto:ip4 index:23 buckets:1 uRPF:28 to:[0:0] via:[98:23234]]
          [0] [@5]: ipv4 via 192.168.30.1 loop0: 1a2b3c4d5e011a2b3c4d5e020800
172.30.2.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:14 buckets:1 uRPF:15 to:[0:0]]
    [0] [@0]: dpo-drop ip4
172.30.2.0/24
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:13 buckets:1 uRPF:14 to:[0:0]]
    [0] [@4]: ipv4-glean: tapcli-0
172.30.2.1/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:16 buckets:1 uRPF:19 to:[0:0]]
    [0] [@2]: dpo-receive: 172.30.2.1 on tapcli-0
172.30.2.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:17 buckets:1 uRPF:18 to:[0:0]]
    [0] [@5]: ipv4 via 172.30.2.2 tapcli-0: def35b93961902fe9507df9c0800
172.30.2.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:15 buckets:1 uRPF:17 to:[0:0]]
    [0] [@0]: dpo-drop ip4
192.168.16.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:10 buckets:1 uRPF:9 to:[0:0]]
    [0] [@0]: dpo-drop ip4
192.168.16.1/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:22 buckets:1 uRPF:34 to:[0:0] via:[100:28290]]
    [0] [@5]: ipv4 via 192.168.16.1 GigabitEthernet0/8/0: 080027b2610908002733fb6f0800
192.168.16.0/24
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:9 buckets:1 uRPF:30 to:[0:0]]
    [0] [@4]: ipv4-glean: GigabitEthernet0/8/0
192.168.16.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:12 buckets:1 uRPF:13 to:[137:16703]]
    [0] [@2]: dpo-receive: 192.168.16.2 on GigabitEthernet0/8/0
192.168.16.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:11 buckets:1 uRPF:11 to:[0:0]]
    [0] [@0]: dpo-drop ip4
192.168.30.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:19 buckets:1 uRPF:23 to:[0:0]]
    [0] [@0]: dpo-drop ip4
192.168.30.1/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:23 buckets:1 uRPF:28 to:[0:0] via:[98:23234]]
    [0] [@5]: ipv4 via 192.168.30.1 loop0: 1a2b3c4d5e011a2b3c4d5e020800
192.168.30.0/24
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:18 buckets:1 uRPF:22 to:[0:0]]
    [0] [@4]: ipv4-glean: loop0
192.168.30.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:21 buckets:1 uRPF:27 to:[0:0]]
    [0] [@2]: dpo-receive: 192.168.30.2 on loop0
192.168.30.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:20 buckets:1 uRPF:25 to:[0:0]]
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
```

How to connect VPP instances using IKEv2
========================================

This section describes how to initiate IKEv2 session between two VPP instances
using Linux veth interfaces and namespaces.


Create veth interfaces and namespaces and configure it:

```
sudo ip link add ifresp type veth peer name ifinit
sudo ip link set dev ifresp up
sudo ip link set dev ifinit up

sudo ip netns add clientns
sudo ip netns add serverns
sudo ip link add veth_client type veth peer name client
sudo ip link add veth_server type veth peer name server
sudo ip link set dev veth_client up netns clientns
sudo ip link set dev veth_server up netns serverns

sudo ip netns exec clientns \
      bash -c "
              ip link set dev lo up
              ip addr add 192.168.5.2/24 dev veth_client
              ip addr add fec5::2/16 dev veth_client
              ip route add 192.168.3.0/24 via 192.168.5.1
              ip route add fec3::0/16 via fec5::1
      "

sudo ip netns exec serverns \
      bash -c "
              ip link set dev lo up
              ip addr add 192.168.3.2/24 dev veth_server
              ip addr add fec3::2/16 dev veth_server
              ip route add 192.168.5.0/24 via 192.168.3.1
              ip route add fec5::0/16 via fec3::1
      "
```

Run responder VPP:

```
sudo /usr/bin/vpp unix { \
      cli-listen /tmp/vpp_resp.sock \
      gid $(id -g) } \
      api-segment { prefix vpp } \
      plugins { plugin dpdk_plugin.so { disable } }
```

Configure the responder


```
create host-interface name ifresp
set interface ip addr host-ifresp 192.168.10.2/24
set interface state host-ifresp up

create host-interface name server
set interface ip addr host-server 192.168.3.1/24
set interface state host-server up

ikev2 profile add pr1
ikev2 profile set pr1 auth shared-key-mic string Vpp123
ikev2 profile set pr1 id local ipv4 192.168.10.2
ikev2 profile set pr1 id remote ipv4 192.168.10.1

ikev2 profile set pr1 traffic-selector local ip-range 192.168.3.0 - 192.168.3.255 port-range 0 - 65535 protocol 0
ikev2 profile set pr1 traffic-selector remote ip-range 192.168.5.0 - 192.168.5.255 port-range 0 - 65535 protocol 0

create ipip tunnel src 192.168.10.2 dst 192.168.10.1
ikev2 profile set pr1 tunnel ipip0
ip route add 192.168.5.0/24 via 192.168.10.1 ipip0
set interface unnumbered ipip0 use host-ifresp
```

Run initiator VPP:

```
sudo /usr/bin/vpp unix { \
      cli-listen /tmp/vpp_init.sock \
      gid $(id -g) } \
      api-segment { prefix vpp } \
      plugins { plugin dpdk_plugin.so { disable } }
```

Configure initiator:
```
create host-interface name ifinit
set interface ip addr host-ifinit 192.168.10.1/24
set interface state host-ifinit up

create host-interface name client
set interface ip addr host-client 192.168.5.1/24
set interface state host-client up

ikev2 profile add pr1
ikev2 profile set pr1 auth shared-key-mic string Vpp123
ikev2 profile set pr1 id local ipv4 192.168.10.1
ikev2 profile set pr1 id remote ipv4 192.168.10.2

ikev2 profile set pr1 traffic-selector remote ip-range 192.168.3.0 - 192.168.3.255 port-range 0 - 65535 protocol 0
ikev2 profile set pr1 traffic-selector local ip-range 192.168.5.0 - 192.168.5.255 port-range 0 - 65535 protocol 0

ikev2 profile set pr1 responder host-ifinit 192.168.10.2
ikev2 profile set pr1 ike-crypto-alg aes-gcm-16 256 ike-dh modp-2048
ikev2 profile set pr1 esp-crypto-alg aes-gcm-16 256

create ipip tunnel src 192.168.10.1 dst 192.168.10.2
ikev2 profile set pr1 tunnel ipip0
ip route add 192.168.3.0/24 via 192.168.10.2 ipip0
set interface unnumbered ipip0 use host-ifinit
```

Initiate the IKEv2 connection:

```
vpp# ikev2 initiate sa-init pr1
```

Responder's and initiator's private networks are now connected with IPSEC tunnel:

```
$ sudo ip netns exec clientns ping 192.168.3.1
PING 192.168.3.1 (192.168.3.1) 56(84) bytes of data.
64 bytes from 192.168.3.1: icmp_seq=1 ttl=63 time=1.64 ms
64 bytes from 192.168.3.1: icmp_seq=2 ttl=63 time=7.24 ms
```

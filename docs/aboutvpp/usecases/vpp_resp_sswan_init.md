VPP as IKEv2 responder and strongSwan as initiator
==================================================


Prerequisites
-------------

To make the examples easier to configure ``docker`` it is required to pull strongSwan docker image. The networking is done using Linux' veth interfaces and namespaces.

Setup
-----

First a topology:

```
192.168.3.2                      192.168.5.2
     +                           loopback
     |                                 +
+----+----+ 192.168.10.2         +-----+----+
|  VPP    |                      |initiator |
|responder+----------------------+strongSwan|
+---------+                      +----------+
                     192.168.10.1
```

Create veth interfaces and namespaces and configure them:

```
sudo ip link add gw type veth peer name swanif
sudo ip link set dev gw up

sudo ip netns add ns
sudo ip link add veth_priv type veth peer name priv
sudo ip link set dev priv up
sudo ip link set dev veth_priv up netns ns

sudo ip netns exec ns \
  bash -c "
    ip link set dev lo up
    ip addr add 192.168.3.2/24 dev veth_priv
    ip route add 192.168.5.0/24 via 192.168.3.1"
```


Create directory with strongswan configs that will be mounted to the docker container
```
mkdir /tmp/sswan
```

Create the ``ipsec.conf`` file in the ``/tmp/sswan`` directory with following content:
```
config setup
 strictcrlpolicy=no

conn initiator
 mobike=no
 auto=add
 type=tunnel
 keyexchange=ikev2
 ike=aes256gcm16-prfsha256-modp2048!
 esp=aes256gcm16-esn!

 # local:
 leftauth=psk
 leftid=@roadwarrior.vpn.example.com
 leftsubnet=192.168.5.0/24

 # remote: (vpp gateway)
 rightid=@vpp.home
 right=192.168.10.2
 rightauth=psk
 rightsubnet=192.168.3.0/24
```

``/tmp/sswan/ipsec.secrets``
```
: PSK 'Vpp123'
```

``/tmp/sswan/strongswan.conf``
```
charon {
  load_modular = yes
  plugins {
    include strongswan.d/charon/*.conf
  }
  filelog {
    /tmp/charon.log {
      time_format = %b %e %T
      ike_name = yes
      append = no
      default = 2
      flush_line = yes
    }
  }
}
include strongswan.d/*.conf
```

Start docker container with strongSwan:

```
 docker run --name sswan -d --privileged --rm --net=none \
  -v /tmp/sswan:/conf -v /tmp/sswan:/etc/ipsec.d philplckthun/strongswan
```

Finish configuration of initiator's private network:

```
pid=$(docker inspect --format "{{.State.Pid}}" sswan)
sudo ip link set netns $pid dev swanif

sudo nsenter -t $pid -n ip addr add 192.168.10.1/24 dev swanif
sudo nsenter -t $pid -n ip link set dev swanif up

sudo nsenter -t $pid -n ip addr add 192.168.5.2/32 dev lo
sudo nsenter -t $pid -n ip link set dev lo up
```

Start VPP ...

```
sudo /usr/bin/vpp unix { \
      cli-listen /tmp/vpp.sock \
      gid $(id -g) } \
      api-segment { prefix vpp } \
      plugins { plugin dpdk_plugin.so { disable } }
```

... and configure it:

```
create host-interface name gw
set interface ip addr host-gw 192.168.10.2/24
set interface state host-gw up

create host-interface name priv
set interface ip addr host-priv 192.168.3.1/24
set interface state host-priv up

ikev2 profile add pr1
ikev2 profile set pr1 auth shared-key-mic string Vpp123
ikev2 profile set pr1 id local fqdn vpp.home
ikev2 profile set pr1 id remote fqdn roadwarrior.vpn.example.com

ikev2 profile set pr1 traffic-selector local ip-range 192.168.3.0 - 192.168.3.255 port-range 0 - 65535 protocol 0
ikev2 profile set pr1 traffic-selector remote ip-range 192.168.5.0 - 192.168.5.255 port-range 0 - 65535 protocol 0

create ipip tunnel src 192.168.10.2 dst 192.168.10.1
ikev2 profile set pr1 tunnel ipip0
ip route add 192.168.5.0/24 via 192.168.10.1 ipip0
set interface unnumbered ipip0 use host-gw
```

Initiate the IKEv2 connection:

```
$ sudo docker exec sswan ipsec up initiator

...
CHILD_SA initiator{1} established with SPIs c320c95f_i 213932c2_o and TS 192.168.5.0/24 === 192.168.3.0/24
connection 'initiator' established successfully
```

```
vpp# show ikev2 sa details

iip 192.168.10.1 ispi 7849021d9f655f1b rip 192.168.10.2 rspi 5a9ca7469a035205
 encr:aes-gcm-16 prf:hmac-sha2-256  dh-group:modp-2048
 nonce i:692ce8fd8f1c1934f63bfa2b167c4de2cff25640dffe938cdfe01a5d7f6820e6
       r:3ed84a14ea8526063e5aa762312be225d33e866d7152b9ce23e50f0ededca9e3
 SK_d    9a9b896ed6c35c78134fcd6e966c04868b6ecacf6d5088b4b2aee8b05d30fdda
 SK_e  i:00000000: 1b1619788d8c812ca5916c07e635bda860f15293099f3bf43e8d88e52074b006
         00000020: 72c8e3e3
       r:00000000: 89165ceb2cef6a6b3319f437386292d9ef2e96d8bdb21eeb0cb0d3b92733de03
         00000020: bbc29c50
 SK_p  i:fe35fca30985ee75e7c8bc0d7bc04db7a0e1655e997c0f5974c31458826b6fef
       r:0dd318662a96a25fcdf4998d8c6e4180c67c03586cf91dab26ed43aeda250272
 identifier (i) id-type fqdn data roadwarrior.vpn.example.com
 identifier (r) id-type fqdn data vpp.home
   child sa 0:encr:aes-gcm-16  esn:yes
    spi(i) c320c95f spi(r) 213932c2
    SK_e  i:2a6c9eae9dbed202c0ae6ccc001621aba5bb0b01623d4de4d14fd27bd5185435
          r:15e2913d39f809040ca40a02efd27da298b6de05f67bd8f10210da5e6ae606fb
    traffic selectors (i):0 type 7 protocol_id 0 addr 192.168.5.0 - 192.168.5.255 port 0 - 65535
    traffic selectors (r):0 type 7 protocol_id 0 addr 192.168.3.0 - 192.168.3.255 port 0 - 65535

```

Now we can generate some traffic between responder's and initiator's private networks and see it works.

```
$ sudo ip netns exec ns ping 192.168.5.2
PING 192.168.5.2 (192.168.5.2) 56(84) bytes of data.
64 bytes from 192.168.5.2: icmp_seq=1 ttl=63 time=1.02 ms
64 bytes from 192.168.5.2: icmp_seq=2 ttl=63 time=0.599 ms
```

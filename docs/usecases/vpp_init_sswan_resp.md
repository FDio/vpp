VPP as IKEv2 initiator and strongSwan as responder
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
|  VPP    |                      |strongSwan|
|initiator+----------------------+responder |
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
  leftid=@sswan.vpn.example.com
  leftsubnet=192.168.5.0/24

# remote: (gateway)
  rightid=@roadwarrior.vpp
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
ikev2 profile set pr1 id local fqdn roadwarrior.vpp
ikev2 profile set pr1 id remote fqdn sswan.vpn.example.com

ikev2 profile set pr1 traffic-selector local ip-range 192.168.3.0 - 192.168.3.255 port-range 0 - 65535 protocol 0
ikev2 profile set pr1 traffic-selector remote ip-range 192.168.5.0 - 192.168.5.255 port-range 0 - 65535 protocol 0

ikev2 profile set pr1 responder host-gw 192.168.10.1
ikev2 profile set pr1 ike-crypto-alg aes-gcm-16 256 ike-dh modp-2048
ikev2 profile set pr1 esp-crypto-alg aes-gcm-16 256

create ipip tunnel src 192.168.10.2 dst 192.168.10.1
ikev2 profile set pr1 tunnel ipip0
ip route add 192.168.5.0/24 via 192.168.10.1 ipip0
set interface unnumbered ipip0 use host-gw
```

Initiate the IKEv2 connection:

```
vpp# ikev2 initiate sa-init pr1
```

```
vpp# show ikev2 sa details
 iip 192.168.10.2 ispi f717b0cbd17e27c3 rip 192.168.10.1 rspi e9b7af7fc9b13361
 encr:aes-gcm-16 prf:hmac-sha2-256  dh-group:modp-2048
 nonce i:eb0354613b268c6372061bbdaab13deca37c8a625b1f65c073d25df2ecfe672e
       r:70e1248ac09943047064f6a2135fa2a424778ba03038ab9c4c2af8aba179ed84
 SK_d    96bd4feb59be2edf1930a12a3a5d22e30195ee9f56ea203c5fb6cba5dd2bb80f
 SK_e  i:00000000: 5b75b9d808c8467fd00a0923c06efee2a4eb1d033c57532e05f9316ed9c56fe9
         00000020: c4db9114
       r:00000000: 95121b63372d20b83558dc3e209b9affef042816cf071c86a53543677b40c15b
         00000020: f169ab67
 SK_p  i:fb40d1114c347ddc3228ba004d4759d58f9c1ae6f1746833f908d39444ef92b1
       r:aa049828240cb242e1d5aa625cd5914dc8f8e980a74de8e06883623d19384902
 identifier (i) id-type fqdn data roadwarrior.vpp
 identifier (r) id-type fqdn data sswan.vpn.example.com
   child sa 0:encr:aes-gcm-16  esn:yes
    spi(i) 9dffd57a spi(r) c4e0ef53
    SK_e  i:290c681694f130b33d511335dd257e78721635b7e8aa87930dd77bb1d6dd3f42
          r:0a09fa18cf1cf65c6324df02b46dcc998b84e5397cf911b63e0c096053946c2e
    traffic selectors (i):0 type 7 protocol_id 0 addr 192.168.3.0 - 192.168.3.255 port 0 - 65535
    traffic selectors (r):0 type 7 protocol_id 0 addr 192.168.5.0 - 192.168.5.255 port 0 - 65535
```

Now we can generate some traffic between responder's and initiator's private networks and see it works.

```
$ sudo ip netns exec ns ping 192.168.5.2
PING 192.168.5.2 (192.168.5.2) 56(84) bytes of data.
64 bytes from 192.168.5.2: icmp_seq=1 ttl=63 time=0.450 ms
64 bytes from 192.168.5.2: icmp_seq=2 ttl=63 time=0.630 ms
```

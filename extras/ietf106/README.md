# What's `runner.py` doing?

## Common configurations

### VPP1
```
create host-interface name eth1
set int ip addr host-eth1 A1::1/120
set int state host-eth1 up
ip route add ::/0 via host-eth1 A1::2
```


### VPP2

```
create host-interface name eth1
set int ip addr host-eth1 A1::2/120
create host-interface name eth2
set int ip addr host-eth2 A2::1/120
set int state host-eth1 up
set int state host-eth2 up
ip route add ::/0 via host-eth2 A2::2
```


### VPP3

```
create host-interface name eth1
set int ip addr host-eth1 A2::2/120
create host-interface name eth2
set int ip addr host-eth2 A3::1/120
set int state host-eth1 up
set int state host-eth2 up
ip route add ::/0 via host-eth1 A2::1
```

### VPP4

```
create host-interface name eth1
set int ip addr host-eth1 A3::2/120
set int state host-eth1 up
ip route add ::/0 via host-eth1 A3::1
```


## Drop-in for GTP-U over IPv4

What's happened when you run `test tmap`:

    $ ./runner.py test tmap


Setting up a virtual interface of packet generator:

#### VPP1

```
create packet-generator interface pg0
set int mac address pg0 aa:bb:cc:dd:ee:01
set int ip addr pg0 172.16.0.1/30
set ip arp pg0 172.16.0.2/30 aa:bb:cc:dd:ee:02
```

#### VPP4

```
create packet-generator interface pg0
set int mac address pg0 aa:bb:cc:dd:ee:11
set int ip addr pg0 1.0.0.2/30
set ip arp pg0 1.0.0.1 aa:bb:cc:dd:ee:22
```

SRv6 and IP routing settings:

#### VPP1

```
sr policy add bsid D1:: next D2:: next D3:: gtp4_removal sr_prefix D4::/32 v6src_prefix C1::/64
sr steer l3 172.20.0.1/32 via bsid D1::

```

#### VPP2

```
sr localsid address D2:: behavior end
ip route add D3::/128 via host-eth2 A2::2
```

#### VPP3

```
sr localsid address D3:: behavior end
ip route add D4::/32 via host-eth2 A3::2
```

#### VPP4

```
sr localsid prefix D4::/32 behavior end.m.gtp4.e v4src_position 64
ip route add 172.20.0.1/32 via pg0 1.0.0.1
```




## Packet generator and testing

    Example how to build custom SRv6 packet in scapy and ipaddress pkgs

    s = '\x11' * 4 + IPv4Address(u"192.168.192.10").packed + '\x11' * 8
    ip6 = IPv6Address(s)
    IPv6(dst=ip6, src=ip6)


## end.m.gtp4.e

    First set behavior so our localsid node is called with the packet
    matching C1::1 in fib table
    sr localsid address C1::1 behavior end.m.gtp4.ess

    show sr localsids behaviors
    show sr localsid

    We should send a well formated packet to C::1 destination address
    that contains the correct spec as for end.m.gtp4.e with encapsulated
    ipv4 src and dst address and teid with port for the conversion to
    GTPU IPv4 packet


## additional commands

    gdb - breakpoint

    break sr_policy_rewrite.c:1620

    break src/plugins/srv6-end/node.c:84

    TMAP
    Linux:

    ip link add tmp1 type veth peer name tmp2
    ip link set dev tmp1 up
    ip link set dev tmp2 up
    ip addr add 172.20.0.2/24 dev tmp2

    create host-interface name tmp1
    set int mac address host-tmp1 02:fe:98:c6:c8:7b
    set interface ip address host-tmp1 172.20.0.1/24
    set interface state host-tmp1 up

    VPP
    set sr encaps source addr C1::
    sr policy add bsid D1::999:2 next D2:: next D3:: gtp4_removal sr-prefix fc34:5678::/64 local-prefix C1::/64
    sr steer l3 172.21.0.0/24 via bsid d1::999:2

    END
    Linux
    create host-interface name tmp1
    set int mac address host-tmp1 02:fe:98:c6:c8:7b
    set interface ip address host-tmp1 A1::1/64
    set interface state host-tmp1 up

    VPP
    sr localsid address 1111:1111:c0a8:c00a:1122:1111:1111:1111 behavior end.m.gtp4.e

    trace add af-packet-input 10

    sr localsid address C3:: behavior end.m.gtp4.e
    sr localsid address 2001:200:0:1ce1:3000:757f:0:2 behavior end.m.gtp4.e

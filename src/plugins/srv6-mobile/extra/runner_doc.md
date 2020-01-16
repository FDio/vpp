# What's `runner.py` doing? {#srv6_mobile_runner_doc}

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

Drop-in mode is handy to test both GTP-U-to-SRv6 and SRv6-to-GTP-U functions at same time. Let's see what's happened when you run `test gtp4`:

    $ ./runner.py test gtp4


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
sr policy add bsid D4:: next D2:: next D3::
sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4
sr steer l3 172.20.0.1/32 via bsid D5::
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

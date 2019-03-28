# VPP1

## Linux
    sysctl net.ipv6.conf.all.disable_ipv6=0
    ip link add tmp1 type veth peer name tmp2
    ip link set dev tmp1 up
    ip link set dev tmp2 up
    ip -6 addr add a20::2/120 dev tmp2
    ip -6 route del default
    ip -6 route add default dev tmp2 via a20::1

    ping a30::2

## VPP SRv6

    create host-interface name tmp1
    set interface ip address host-tmp1 a20::1/120
    set interface state host-tmp1 up
    set sr encaps source addr C1::
    sr policy add bsid c1::999:1 next c2:: next c3:: next c4::
    sr steer l3 a30::/120 via bsid c1::999:1

# VPP2

## VPP SRv6

    sr localsid address C2:: behavior end

# VPP3

## VPP SRv6

    sr localsid address C3:: behavior end

# VPP4

## Linux
    sysctl net.ipv6.conf.all.disable_ipv6=0
    ip link add tmp1 type veth peer name tmp2
    ip link set dev tmp1 up
    ip link set dev tmp2 up
    ip -6 addr add a30::2/120 dev tmp2
    ip -6 route del default
    ip -6 route add default dev tmp2 via a30::1

## VPP SRv6
    create host-interface name tmp1
    set interface ip address host-tmp1 a30::1/120
    set interface state host-tmp1 up
    sr localsid address C4:: behavior end.dx6 host-tmp1 a30::2

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



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

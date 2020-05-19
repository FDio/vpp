SRv6 Mobile User Plane Plugins {#srv6_mobile_plugin_doc}
========================

# Introduction

This plugin module can provide the stateless mobile user plane protocols translation between GTP-U and SRv6. The plugin also provides FIB table lookup for an IPv4/IPv6 packet encapsulated in GTP-U. These plugin functions take advantage of SRv6 network programmability.

[SRv6 Mobile User Plane](https://tools.ietf.org/html/draft-ietf-dmm-srv6-mobile-uplane) defines the user plane protocol using SRv6
including following stateless translation functions:

- **T.M.GTP4.D:**
   GTP-U over UDP/IPv4 -> SRv6
- **End.M.GTP4.E:**
   SRv6 -> GTP-U over UDP/IPv4
- **End.M.GTP6.D:**
   GTP-U over UDP/IPv6 -> SRv6
- **End.M.GTP6.E:**
   SRv6 -> GTP-U over UDP/IPv6

These functions benefit user plane(overlay) to be able to utilize data plane(underlay) networks properly. And also it benefits data plane to be able to handle user plane in routing paradigm.

In addition to the above functions, the plugin supports following functions:

- **T.M.GTP4.DT{4|6|46}:**
   FIB table lookup for IPv4/IP6 encapsulated in GTP-U over UDP/IPv4
- **End.M.GTP6.DT{4|6|46}:**
   FIB table lookup for IPv4/IP6 encapsulated in GTP-U over UDP/IPv6

Noted that the prefix of function names follow naming convention of SRv6 network programming. "T" means transit function, "End" means end function, "M" means Mobility specific function. The suffix "D" and "E" mean that "decapsulation" and "encapsulation" respectively.


# Implementation

All SRv6 mobile functions are implemented as VPP plugin modules. The plugin modules leverage the sr_policy and sr_localsid mechanisms.

# Configurations

## GTP-U to SRv6

The GTP-U tunnel and flow identifiers of a receiving packet are mapped to a Segment Identifier(SID) of sending SRv6 packets.

### IPv4 infrastructure case

In case that **IPv4** networks are the infrastructure of GTP-U, T.M.GTP4.D function translates the receiving GTP-U packets to SRv6 packets.

A T.M.GTP4.D function is associated with the following mandatory parameters:

- SID: A SRv6 SID to represents the function
- DST-PREFIX: Prefix of remote SRv6 segment. The destination address or last SID of out packets consists of the prefix followed by dst IPv4 address, QFI and TEID of the receiving packets.
- SRC-PREFIX: Prefix for src address of sending packets. The src IPv6 address consists of the prefix followed by the src IPv4 address of the receiving packets.

The following command instantiates a new T.M.GTP4.D function.

```
sr policy add bsid SID behavior t.m.gtp4.d DST-PREFIX v6src_prefix SRC-PREFIX [nhtype {ipv4|ipv6|non-ip}]
```

For example, the below command configures the SID 2001:db8::1 with `t.m.gtp4.d` behavior for translating receiving GTP-U over IPv4 packets to SRv6 packets with next-header type is IPv4.

```
sr policy add bsid 2001:db8::1 behavior t.m.gtp4.d D1::/32 v6src_prefix A1::/64 nhtype ipv4
```

It should be interesting how a SRv6 BSID works to decapsulate the receiving GTP-U packets over IPv4 header. To utilize ```t.m.gtp4.d``` function, you need to configure some SR steering policy like:

```
sr steer l3 172.20.0.1/32 via bsid 2001:db8::1
```

The above steering policy with the BSID of `t.m.gtp4.d` would work properly for the GTP-U packets destined to 172.20.0.1.

If you have a SID(s) list of SR policy which the configured gtp4.d function to be applied, the SR Policy can be configured as following:

```
sr policy add bsid D1:: next A1:: next B1:: next C1::
```

### IPv6 infrastructure case

In case that GTP-U is deployed over **IPv6** infrastructure, you don't need to configure T.M.GTP4.D function and associated SR steering policy.  Instead of that, you just need to configure a localsid of End.M.GTP6.D segment.

An End.M.GTP6.D segment is associated with the following mandatory parameters:

- SID-PREFIX: SRv6 SID prefix to represent the function. In this function, it should be the dst address of receiving GTP-U packets.
- DST-PREFIX: Prefix of remote SRv6 Segment. The destination address or last SID of output packets consists of the prefix followed by QFI and TEID of the receiving packets.

The following command instantiates a new End.M.GTP6.D function.

```
sr localsid prefix SID-PREFIX behavior end.m.gtp6.d DST-PREFIX [nhtype {ipv4|ipv6|non-ip}]
```
For example, the below command configures the SID prefix 2001:db8::/64 with `end.m.gtp6.d` behavior for translating receiving GTP-U over IPv6 packets which have IPv6 destination addresses within 2001:db8::/64 to SRv6 packets. The dst IPv6 address of the outgoing packets consists of D4::/64 followed by QFI and TEID.

```
sr localsid prefix 2001:db8::/64 behavior end.m.gtp6.d D4::/64
```

In another case, the translated packets from GTP-U over IPv6 to SRv6 will be re-translated back to GTP-U, which is so called 'Drop-In' mode.

In Drop-In mode, an additional IPv6 specific end segment is required, named End.M.GTP6.D.Di. It is because that unlike `end.m.gtp6.d`, it needs to preserve original IPv6 dst address as the last SID in the SRH.

Regardless of that difference exists, the required configuration parameters are same as `end.m.gtp6.d`.

The following command instantiates a new End.M.GTP6.D.Di function.

```
sr localsid prefix 2001:db8::/64 behavior end.m.gtp6.d.di D4::/64
```


## SRv6 to GTP-U

The SRv6 Mobile functions on SRv6 to GTP-U direction are End.M.GTP4.E and End.M.GTP6.D.

In this direction with GTP-U over IPv4 infrastructure, an End.M.GTP4.E segment is associated with the following mandatory parameters:

- SID-PREFIX: SRv6 SID prefix to represent the function.
- V4SRC-ADDR-POSITION: Integer number indicates bit position where IPv4 src address embedded.

The following command instantiates a new End.M.GTP4.E function.

```
sr localsid prefix SID-PREFIX behavior end.m.gtp4.e v4src_position V4SRC-ADDR-POSITION
```

For example, the below command configures the SID prefix 2001:db8::/32 with `end.m.gtp4.e` behavior for translating the receiving SRv6 packets to GTP-U packets encapsulated with UDP/IPv4 header. All the GTP-U tunnel and flow identifiers are extracted from the active SID in the receiving packets. The src IPv4 address of sending GTP-U packets is extracted from the configured bit position in the src IPv6 address.

```
sr localsid prefix 2001:db8::/32 behavior end.m.gtp4.e v4src_position 64
```

In IPv6 infrastructure case, an End.M.GTP6.E segment is associated with the following mandatory parameters:

- SID-PREFIX: SRv6 SID prefix to represent the function.

The following command instantiates a new End.M.GTP6.E function.

```
sr localsid prefix SID-PREFIX behavior end.m.gtp6.e
```

For example, the below command configures the SID prefix 2001:db8::/64 with `end.m.gtp6.e` behavior for translating the receiving SRv6 packets to GTP-U packets encapsulated with UDP/IPv6 header. While the last SID indicates GTP-U dst IPv6 address, 32-bits GTP-U TEID and 6-bits QFI are extracted from the active SID in the receiving packets.

```
sr localsid prefix 2001:db8::/64 behavior end.m.gtp6.e
```

## FIB Table Lookup for Inner IPv4/IPv6 packet

SRv6 Mobile functions of `t.m.gtp4.dt*` and `end.m.gtp6.dt*` support decapsulating outer IP/UDP/GTP-U headers and forwarding inner IP packet based on specific fib table.

In case of the both outer and inner IP address families are IPv4, `t.m.gtp4.dt4` function supports GTP-U decapsulation and fib lookup for inner IPv4 with an associated steering policy and the following parameters:

- SID: A SRv6 SID to represents the function
- FIB: fib-table number for inner IPv4 packet lookup and forwarding

The following command instantiates a new T.M.GTP4.DT4 function.

```
sr policy add bsid SID behavior t.m.gtp4.dt4 fib-table FIB
```

For example, the below commands configure D5:: as the SID instantiates `t.m.gtp4.dt4` function. A steering policy for packets destine to 172.20.0.1 binds to the SID.

```
sr steer l3 172.20.0.1/32 via bsid D5::
sr policy add bsid D5:: behavior t.m.gtp4.dt4 fib-table 0
```

In addition, inner IPv6, or mix of IPv4 and IPv6 inner packet cases require the function to be configured with local-fib table.

- LOCAL-FIB: fib-table number for lookup and forward GTP-U packet based on outer IP destination address

This is inner IPv6 case specific. The reason is that GTP-U encapsulates link local IPv6 packet for NDP (Neighber Discovery Protocol). Outer GTP-U header should be kept until the packets reach to the node responsible for NDP handling. It is typically UPF(User Plane Function) node.

The following command instantiates a new T.M.GTP4.DT6 function.

```
sr policy add bsid D5:: behavior t.m.gtp4.dt6 fib-table 0 local-fib-table LOCAL-FIB
```

Following example configures fib 0 for inner packet and fib 1 for outer GTP-U packet forwarding:

```
sr policy add bsid D5:: behavior t.m.gtp4.dt6 fib-table 0 local-fib-table 1
```

If you need to suport both IPv4 and IPv6 inner packet lookup with just one SID, you can configure `t.m.gtp4.dt46` function:

```
sr policy add bsid D5:: behavior t.m.gtp4.dt46 fib-table 0 local-fib-table 1
```

In case of GTP-U over IPv6 case, `end.m.gtp6.dt4`, `end.m.gtp6.dt6` and `end.m.gtp6.dt46` functions support inner IPv4, IPv6 and IPv4/IPv6 lookup and forwarding respectively. Specifiyng fib table for inner IP packet forwarding is required as same as GTP-U over IPv4 case, and local-fib table for inner IPv6 and IPv4/IPv6 cases as well.

```
sr localsid prefix D::/64 behavior end.m.gtp6.dt46 fib-table 0 local-fib-table 0
```

To run some demo setup please refer to: @subpage srv6_mobile_runner_doc


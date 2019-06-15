# MTU Introduction {#mtu_doc}
Maximum Transmission Unit is a term used to describe the maximum sized "thingy" that can be sent out an interface. It can refer to the maximum frame size that a NIC can send. On Ethernet that would include the Ethernet header but typically not the IGF. It can refer to the maximum packet size, that is, on Ethernet an MTU of 1500, would allow an IPv4 packet of 1500 bytes, that would result in an Ethernet frame of 1518 bytes.

# MTU in VPP
VPP allows setting of the physical payload MTU. I.e. not including L2 overhead. Setting the hardware MTU will program the NIC.
This MTU will be inherited by all software interfaces.

VPP also allows setting of the payload MTU for software interfaces. Independently of the MTU set on the hardware. If the software payload MTU is set higher than the capability of the NIC, the packet will be dropped.

In addition VPP supports setting the MTU of individual network layer protocols. IPv4, IPv6 or MPLS. For example an IPv4 MTU of 1500 (includes the IPv4 header) will fit in a hardware payload MTU of 1500.

_Note we might consider changing the hardware payload MTU to hardware MTU_. That is, the MTU includes all L2 framing. Then the payload MTU can be calculated based on the interface's configuration. E.g. 802.1q tags etc.

There are currently no checks or warnings if e.g. the user configures a per-protocol MTU larger than the underlying payload MTU. If that happens packets will be fragmented or dropped.

## Data structures
The hardware payload MTU is stored in the max_packet_bytes variable in the vnet_hw_interface_t structure.

The software MTU (previously max_l3_packet_bytes) is in vnet_sw_interface_t->in mtu[VNET_N_MTU].

# API

## Set physical MTU

This API message is used to set the physical MTU. It is currently limited to Ethernet interfaces. Note, this programs the NIC.

```
autoreply define hw_interface_set_mtu
{
 u32 client_index;
 u32 context;
 u32 sw_if_index;
 u16 mtu;
};
```

## Set the L2 payload MTU (not including the L2 header) and per-protocol MTUs

This API message sets the L3 payload MTU. E.g. on Ethernet it is the maximum size of the Ethernet payload. If a value is left as 0, then the default is picked from VNET_MTU_L3.

```
autoreply define sw_interface_set_mtu
{
 u32 client_index;
 u32 context;
 u32 sw_if_index;
 /* $$$$ Replace with enum */
 u32 mtu[4]; /* 0 - L3, 1 - IP4, 2 - IP6, 3 - MPLS */
};

```

## Get interface MTU

The various MTUs on an interface can be queried with the sw_interface_dump/sw_interface_details calls.

```
define sw_interface_details
{
  /* MTU */
  u16 link_mtu;

  /* Per protocol MTUs */
  u32 mtu[4]; /* 0 - L3, 1 - IP4, 2 - IP6, 3 - MPLS */
};
```

# CLI

```
set interface mtu [packet|ip4|ip6|mpls] <value> <interface>
```

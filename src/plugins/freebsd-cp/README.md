# FreeBSD control plane

The `freebsd_cp` plugin pairs an Ethernet interface owned by VPP with an
existing FreeBSD TAP interface. FreeBSD supplies the control plane and VPP
forwards packets. Host IP addresses, ARP/ND neighbors and gateway routes in
the default FIB are mirrored into VPP from the routing socket. Existing host
state is loaded when the pair is created; IP punts and ARP are sent to the TAP.
Unknown IPv4/IPv6 UDP ports (including IKE when no VPP handler owns them) use
the IP punt redirect. IPsec NAT-T packets punted with the SPI-zero reason use
a pair-aware path to the TAP; punts from unpaired interfaces are dropped.
Disable VPP's `ikev2_plugin.so` when strongSwan should receive IKE on the TAP.

Unlike '`linux_cp` plugin, the `freebsd_cp`plugin does not create TAP device automatically.
The TAP device must be created outisde VPP before starting the pair (for example,
`ifconfig tap0 create`). Next load the plugin, then run:

```text
fcp create <vpp-interface> host-if tap0
show fcp
fcp delete <vpp-interface>
```

Packet tracing uses Linux CP-style interface indices: `fcp-xc: <host> -> <physical>`
for TAP input and `fcp-punt: <physical> -> <host>` for IPsec punts and TAP output.
An IPsec punt without a pair shows host index `4294967295` and is dropped.
ARP traces show `rx-sw-if-index: <index> opcode: <opcode>` in host byte order.
To trace packets received from the TAP:

```text
trace add freebsd-cp-input 10
show trace
```

To trace physical-to-host traffic, enable tracing on the physical interface's
input node. Traced packets retain their traces through `freebsd-cp-arp`,
`freebsd-cp-ipsec-punt`, and the TAP transmit node as applicable.

The TAP must have an MTU small enough to fit in one VPP buffer. The plugin
sets its link address to the VPP physical interface address and enables
promiscuous mode. VPP admin state, L3 MTU, and IPv4/IPv6 address changes are
copied to the TAP; existing VPP addresses are copied when the pair is created.
FreeBSD routing-socket updates still flow in the opposite direction. On pair
deletion, the original TAP link address, flags, and MTU are restored; synced
IP addresses remain on the existing TAP and must be removed separately if no
longer needed. The TAP device itself is not destroyed.

Only untagged Ethernet interfaces in the default network context are
supported. Pairing VPP subinterfaces, sending or receiving tagged frames, and
specifying `netns` are rejected. TUN, MPLS, non-default FIBs, and Linux-style
output feature/adjacency handling are not implemented. A FreeBSD build and
packet-level validation are required before relying on this plugin in
production.

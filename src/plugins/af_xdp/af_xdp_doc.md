# AF_XDP Ethernet driver {#af_xdp_doc}

This driver relies on Linux AF_XDP socket to rx/tx Ethernet packets.

## Maturity level
Under development: it should work, but has not been thoroughly tested.

## Features
 - copy and zero-copy mode

## Missing features
 - API
 - multiqueue
 - custom eBPF XDP programs

## Requirements
The Linux kernel interface must be up before creating the VPP AF_XDP
interface, otherwise Linux will deny creating the AF_XDP socket.
The AF_XDP interface will always claim NIC RX queue #0. It means all packets
destined to NIC RX queue #0 will be received by the AF_XDP interface, and only
them. Depending on your configuration, there will usually be several RX queues
(typically 1 per core) and packets are spread accross queues by RSS. In order
to receive consistent traffic, you **must** program the NIC dispatching
accordingly. The simplest way to get all the packets is to reconfigure the
Linux kernel driver to use only 1 RX queue:
```
~# ethtool -L <iface> combined 1
```
Additionally, the VPP AF_XDP interface will use a MAC address generated at
creation time instead of the Linux kernel interface MAC. As Linux kernel
interface are not in promiscuous mode by default (see below) this will
probably results in a useless configuration where the VPP AF_XDP interface
only receives packets destined to the Linux kernel interface MAC just to drop
them because the destination MAC does not match VPP AF_XDP interface MAC.
If you want to use the Linux interface MAC for the VPP AF_XDP interface, you
can change it afterwards in VPP:
```
~# vppctl set int mac address <iface> <mac>
```
Finally, if you wish to receive all packets and not only the packets destined
to the Linux kernel interface MAC you need to set the Linux kernel interface
in promiscuous mode:
```
~# ip link set dev <iface> promisc on
```

## Security considerations
When creating an AF_XDP interface, it will receive all packets arriving to the
NIC RX queue #0. You need to configure the Linux kernel NIC driver properly to
ensure that only intented packets will arrive in this queue. There is no way
to filter the packets after-the-fact using eg. netfilter or eBPF.

## Quickstart
1. Setup the Linux kernel interface (enp216s0f0 here) to use a single queue:
```
~# ethtool -L enp216s0f0 combined 1
```
2. Put the Linux kernel interface up and in promiscuous mode:
```
~# ip l set dev enp216s0f0 promisc on up
```
3. Create the AF_XDP interface:
```
~# vppctl create int af_xdp host-if enp216s0f0
```
4. Use the interface as usual, eg.:
```
~# vppctl set int ip addr enp216s0f0/0 1.1.1.1/24
~# vppctl set int st enp216s0f0/0 up
~# vppctl ping 1.1.1.100`
```

## Performance consideration
AF_XDP relies on the Linux kernel NIC driver to rx/tx packets. To reach
high-performance (10's MPPS), the Linux kernel NIC driver must support
zero-copy mode and its RX path must run on a dedicated core in the NUMA where
the NIC is physically connected.

# RDMA (ibverb) Ethernet driver

This driver relies on Linux rdma-core (libibverb) userspace poll-mode driver
to rx/tx Ethernet packets. Despite using the RDMA APIs, this is **not** about
RDMA (no Infiniband, no RoCE, no iWARP), just pure traditional Ethernet
packets.

## Maturity level
Under development: it should work, but has not been thoroughly tested.

## Supported Hardware
 - Mellanox ConnectX-4
 - Mellanox ConnectX-5

## Features
 - bifurcation: MAC based flow steering for transparent sharing of a single
physical port between multiple virtual interfaces including Linux netdev
 - multiqueue

## Quickstart
1. Make sure the ib_uverbs module is loaded:
```
~# modprobe ib_uverbs
```
2. In VPP, create a new rdma virtual interface tied to the Linux netdev of the
physical port you want to use (`enp94s0f0` in this example):
```
vpp# create int rdma host-if enp94s0f0 name rdma-0
```
3. Use the interface as usual, eg.:
```
vpp# set int ip addr rdma-0 1.1.1.1/24
vpp# set int st rdma-0 up
vpp# ping 1.1.1.100`
```

AF_XDP device driver
====================

This driver relies on Linux AF_XDP socket to rx/tx Ethernet packets.

Maturity level
--------------

Under development: it should work, but has not been thoroughly tested.

Features
--------

-  copy and zero-copy mode
-  multiqueue
-  API
-  custom eBPF program
-  polling, interrupt and adaptive mode

Known limitations
-----------------

MTU
~~~

Because of AF_XDP restrictions, the MTU is limited to below PAGE_SIZE
(4096-bytes on most systems) minus 256-bytes, and they are additional
limitations depending upon specific Linux device drivers. As a rule of
thumb, a MTU of 3000-bytes or less should be safe.

Number of buffers
~~~~~~~~~~~~~~~~~

Furthermore, upon UMEM creation, the kernel allocates a
physically-contiguous structure, whose size is proportional to the
number of 4KB pages contained in the UMEM. That allocation might fail
when the number of buffers allocated by VPP is too high. That number can
be controlled with the ``buffers { buffers-per-numa }`` configuration
option. Finally, note that because of this limitation, this plugin is
unlikely to be compatible with the use of 1GB hugepages.

Interrupt mode
~~~~~~~~~~~~~~

Interrupt and adaptive mode are supported but is limited by default to
single threaded (no worker) configurations because of a kernel
limitation prior to 5.6. You can bypass the limitation at interface
creation time by adding the ``no-syscall-lock`` parameter, but you must
be sure that your kernel can support it, otherwise you will experience
double-frees. See
https://lore.kernel.org/bpf/BYAPR11MB365382C5DB1E5FCC53242609C1549@BYAPR11MB3653.namprd11.prod.outlook.com/
for more details.

Mellanox
~~~~~~~~

When setting the number of queues on Mellanox NIC with ``ethtool -L``,
you must use twice the amount of configured queues: it looks like the
Linux driver will create separate RX queues and TX queues (but all
queues can be used for both RX and TX, the NIC will just not sent any
packet on “pure” TX queues. Confused? So I am.). For example if you set
``combined 2`` you will effectively have to create 4 rx queues in AF_XDP
if you want to be sure to receive all packets.

Requirements
------------

This drivers supports Linux kernel 5.4 and later. Kernels older than 5.4
are missing unaligned buffers support.

The Linux kernel interface must be up and have enough queues before
creating the VPP AF_XDP interface, otherwise Linux will deny creating
the AF_XDP socket. The AF_XDP interface will claim NIC RX queue starting
from 0, up to the requested number of RX queues (only 1 by default). It
means all packets destined to NIC RX queue ``[0, num_rx_queues[`` will
be received by the AF_XDP interface, and only them. Depending on your
configuration, there will usually be several RX queues (typically 1 per
core) and packets are spread across queues by RSS. In order to receive
consistent traffic, you **must** program the NIC dispatching
accordingly. The simplest way to get all the packets is to specify
``num-rx-queues all`` to grab all available queues or to reconfigure the
Linux kernel driver to use only ``num_rx_queues`` RX queues (i.e. all NIC
queues will be associated with the AF_XDP socket):

::

   ~# ethtool -L <iface> combined <num_rx_queues>

Additionally, the VPP AF_XDP interface will use a MAC address generated
at creation time instead of the Linux kernel interface MAC. As Linux
kernel interface are not in promiscuous mode by default (see below) this
will results in a useless configuration where the VPP AF_XDP interface
only receives packets destined to the Linux kernel interface MAC just to
drop them because the destination MAC does not match VPP AF_XDP
interface MAC. If you want to use the Linux interface MAC for the VPP
AF_XDP interface, you can change it afterwards in VPP:

::

   ~# vppctl set int mac address <iface> <mac>

Finally, if you wish to receive all packets and not only the packets
destined to the Linux kernel interface MAC you need to set the Linux
kernel interface in promiscuous mode:

::

   ~# ip link set dev <iface> promisc on

Security considerations
-----------------------

When creating an AF_XDP interface, it will receive all packets arriving
to the NIC RX queue ``[0, num_rx_queues[``. You need to configure the
Linux kernel NIC driver properly to ensure that only intended packets
will arrive in this queue. There is no way to filter the packets
after-the-fact using e.g. netfilter or eBPF.

Quickstart
----------

1. Put the Linux kernel interface up and in promiscuous mode:

::

   ~# ip l set dev enp216s0f0 promisc on up

2. Create the AF_XDP interface:

::

   ~# vppctl create int af_xdp host-if enp216s0f0 num-rx-queues all

3. Use the interface as usual, e.g.:

::

   ~# vppctl set int ip addr enp216s0f0/0 1.1.1.1/24
   ~# vppctl set int st enp216s0f0/0 up
   ~# vppctl ping 1.1.1.100`

Custom eBPF XDP program
-----------------------

This driver relies on libbpf and as such relies on the ``xsks_map`` eBPF
map. The default behavior is to use the XDP program already attached to
the interface if any, otherwise load the default one. You can request to
load a custom XDP program with the ``prog`` option when creating the
interface in VPP:

::

   ~# vppctl create int af_xdp host-if enp216s0f0 num-rx-queues 4 prog extras/bpf/af_xdp.bpf.o

In that case it will replace any previously attached program. A custom
XDP program example is provided in ``extras/bpf/``.

Performance consideration
-------------------------

AF_XDP relies on the Linux kernel NIC driver to rx/tx packets. To reach
high-performance (10’s MPPS), the Linux kernel NIC driver must support
zero-copy mode and its RX path must run on a dedicated core in the NUMA
where the NIC is physically connected.

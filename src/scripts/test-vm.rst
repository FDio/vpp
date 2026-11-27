.. _test_vm:

Test VM (test-vm)
=================

``src/scripts/test-vm`` builds a small virtio-only guest kernel and an
initramfs and boots them under QEMU/KVM, to run VPP against virtio-net-pci
devices without installing a guest. The guest has the architecture of the host
(x86_64 or aarch64).

The guest mounts the host root filesystem read-only over virtio-9p and the
directory which contains ``vm`` (normally the VPP build directory) read-write
at the same path, so the VPP binaries of the build are used as they are. The
guest has its own ``/tmp``, files there are not visible from the host.

Requirements: KVM (``/dev/kvm``), QEMU (``qemu-system-x86_64`` or
``qemu-system-aarch64``), a static busybox, the kernel build tools and sudo for
QEMU and the tap interfaces.

Building
--------

From the build directory:

.. code-block:: console

   $ <vpp>/src/scripts/test-vm build

This clones the latest stable kernel (``-k <version>`` for another one),
builds it and the initramfs into ``vm`` in the current directory (``-d`` for
another one) and links the ``vm/run`` script.
``test-vm update`` rebuilds only the initramfs and the run link.

Running
-------

``vm/run`` boots the guest. The first virtio-net-pci device is the management
NIC (user mode networking, ssh is forwarded from host port 2222). The data
NICs (``-n``, default 1) are attached to host tap interfaces ``vpp-vm0``,
``vpp-vm1``, ... and bound to vfio-pci in the guest (``-b``). The console
shows their PCI addresses (``init: 0000:00:04.0 -> vfio-pci`` on aarch64).

.. code-block:: console

   $ vm/run                  # shell in the guest
   $ vm/run -r               # bin/vpp -c startup.conf
   $ vm/run -d               # the same under gdb
   $ vm/run -- bin/vpp -c my.conf

The command runs as root in the current directory, which must be below the
directory which contains ``vm``. ``ctrl-a x`` quits QEMU.

Useful options:

* ``-c <n>``, ``-m <size>``: number of guest CPUs and guest memory.
* ``-Q <n>``: queue pairs per data NIC (multiqueue tap, ``mq=on``).
* ``-o <props>``: extra virtio-net-pci properties of the data NICs, e.g.
  ``rss=on`` for RSS or ``packed=on`` for packed rings.
* ``-v``: vhost-net backend, see below.
* ``-i``: emulated IOMMU instead of no-IOMMU vfio.
* ``-q <arg>``: any extra QEMU argument.

``ssh -F vm/ssh/config vm`` logs into the guest as the current user, root
login is not possible. To run ``vppctl`` over ssh, start VPP as the command of
the VM and give the CLI socket the user's group:

.. code-block:: text

   unix { nodaemon cli-listen /run/vpp-cli.sock gid 1000 }

.. code-block:: console

   $ ssh -F vm/ssh/config vm "$PWD/bin/vppctl -s /run/vpp-cli.sock show int"

Data NIC backends
-----------------

The guest always sees a virtio-net-pci device, the backend decides who moves
the packets between the virtqueues in guest memory and the host:

QEMU (default)
   QEMU itself reads and writes the tap interface and copies packets to and
   from the virtqueues. It is the slowest backend, RSS (``-o rss=on``) is
   done in software by QEMU.

vhost-net (``-v``)
   The kernel ``vhost-net`` module moves the packets between the tap interface
   and the virtqueues, QEMU only sets the device up. Faster than QEMU, the
   packets never pass through QEMU. RSS (``-o rss=on``) works as well, QEMU
   steers the packets to the tap queues with an eBPF program.

vhost-user
   A userspace process on the host, e.g. DPDK (``testpmd``) or VPP
   (``create vhost-user``), handles the virtqueues directly over a unix socket
   and guest memory shared with it. The guest memory must be a shared memory
   backend. There is no tap interface, the other process is the peer. The
   backend decides which features the guest is offered: the DPDK vhost library
   offers multiqueue (``MQ``) but no RSS, the queue a packet is received on is
   the queue the backend sends it on.

test-vm has no option for vhost-user, pass the QEMU arguments with ``-q``
(each ``-q`` adds one argument) and ``-n 0`` for no tap NICs. For example with
DPDK ``testpmd`` returning every packet (``macswap``) on two queues:

.. code-block:: console

   $ dpdk-testpmd -l 10-11 --no-huge -m 1024 --no-pci \
       --vdev "net_vhost0,iface=/tmp/vhost0.sock,queues=2" -- \
       -i --rxq=2 --txq=2 --forward-mode=macswap --auto-start
   $ vm/run -n 0 -m 4G \
       -q -object -q memory-backend-memfd,id=mem,size=4G,share=on \
       -q -numa -q node,memdev=mem \
       -q -chardev -q socket,id=vu0,path=/tmp/vhost0.sock \
       -q -netdev -q vhost-user,id=vun0,chardev=vu0,queues=2 \
       -q -device -q virtio-net-pci,netdev=vun0,mac=52:54:00:00:00:01,mq=on,vectors=6

The memory backend size must match ``-m``. The NIC is bound to vfio-pci in the
guest like the tap ones.

Example: RSS of virtio-net-pci
------------------------------

.. code-block:: console

   $ vm/run -Q 4 -o rss=on -- bin/vpp -c vm.conf

with ``num-rx-queues 4`` for the port of the data NIC in ``vm.conf``. Packets
written to ``vpp-vm0`` on the host, e.g. with an ``AF_PACKET`` socket, are
received by the guest, ``trace add <interface>-rx`` shows the receive queue of
each packet. Packets VPP sends out of the data NIC show up on ``vpp-vm0``.

The tap interfaces stay after QEMU exits, remove them with ``sudo ip link del
vpp-vm0``.

.. vhost:

.. toctree::

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .

.. _createvhostuser:

Create Vhost-User
=================

Create a vHost User interface. Once created, a new virtual interface
will exist with the name '*VirtualEthernet0/0/x*', where '*x*' is the
next free index.

There are several parameters associated with a vHost interface:

-  **socket <*socket-filename*>** - Name of the linux socket used by
   hypervisor and VPP to manage the vHost interface. If in '*server*'
   mode, VPP will create the socket if it does not already exist. If in
   '*client*' mode, hypervisor will create the socket if it does not
   already exist. The VPP code is indifferent to the file location.
   However, if SELinux is enabled, then the socket needs to be created
   in '*/var/run/vpp/*'.
-  **server** - Optional flag to indicate that VPP should be the server
   for the linux socket. If not provided, VPP will be the client. In
   '*server*' mode, the VM can be reset without tearing down the vHost
   Interface. In '*client*' mode, VPP can be reset without bringing down
   the VM and tearing down the vHost Interface.
-  **feature-mask <hex>** - Optional virtio/vhost feature set negotiated
   at startup. **This is intended for degugging only.** It is
   recommended that this parameter not be used except by experienced
   users. By default, all supported features will be advertised.
   Otherwise, provide the set of features desired.

   -  0x000008000 (15) - VIRTIO_NET_F_MRG_RXBUF
   -  0x000020000 (17) - VIRTIO_NET_F_CTRL_VQ
   -  0x000200000 (21) - VIRTIO_NET_F_GUEST_ANNOUNCE
   -  0x000400000 (22) - VIRTIO_NET_F_MQ
   -  0x004000000 (26) - VHOST_F_LOG_ALL
   -  0x008000000 (27) - VIRTIO_F_ANY_LAYOUT
   -  0x010000000 (28) - VIRTIO_F_INDIRECT_DESC
   -  0x040000000 (30) - VHOST_USER_F_PROTOCOL_FEATURES
   -  0x100000000 (32) - VIRTIO_F_VERSION_1

-  **hwaddr <mac-addr>** - Optional ethernet address, can be in either
   X:X:X:X:X:X unix or X.X.X cisco format.
-  **renumber <dev_instance>** - Optional parameter which allows the
   instance in the name to be specified. If instance already exists,
   name will be used anyway and multiple instances will have the same
   name. Use with caution.


Summary/Usage
-------------

.. code-block:: shell

    create vhost-user socket <socket-filename> [server] [feature-mask <hex>] [hwaddr <mac-addr>] [renumber <dev_instance>]


Examples
--------

Example of how to create a vhost interface with VPP as the client
and all features enabled:

.. code-block:: console

    vpp# create vhost-user socket /var/run/vpp/vhost1.sock
    VirtualEthernet0/0/0

Example of how to create a vhost interface with VPP as the server
and with just multiple queues enabled:

.. code-block:: console

    vpp# create vhost-user socket /var/run/vpp/vhost2.sock server feature-mask 0x40400000
    VirtualEthernet0/0/1

Once the vHost interface is created, enable the interface using:

.. code-block:: console

    vpp# set interface state VirtualEthernet0/0/0 up

.. _showvhost:

Show Vhost-User
===============

Display the attributes of a single vHost User interface (provide
interface name), multiple vHost User interfaces (provide a list of
interface names seperated by spaces) or all Vhost User interfaces (omit
an interface name to display all vHost interfaces).

Summary/Usage
-------------

.. code-block:: shell

    show vhost-user [<interface> [<interface> [..]]] [descriptors].

Examples
--------
Example of how to display a vhost interface:

.. code-block:: console

    vpp# show vhost-user VirtualEthernet0/0/0
    Virtio vhost-user interfaces
    Global:
      coalesce frames 32 time 1e-3
    Interface: VirtualEthernet0/0/0 (ifindex 1)
    virtio_net_hdr_sz 12
     features mask (0xffffffffffffffff):
     features (0x50408000):
       VIRTIO_NET_F_MRG_RXBUF (15)
       VIRTIO_NET_F_MQ (22)
       VIRTIO_F_INDIRECT_DESC (28)
       VHOST_USER_F_PROTOCOL_FEATURES (30)
      protocol features (0x3)
       VHOST_USER_PROTOCOL_F_MQ (0)
       VHOST_USER_PROTOCOL_F_LOG_SHMFD (1)

     socket filename /var/run/vpp/vhost1.sock type client errno "Success"

    rx placement:
       thread 1 on vring 1
       thread 1 on vring 5
       thread 2 on vring 3
       thread 2 on vring 7
     tx placement: spin-lock
       thread 0 on vring 0
       thread 1 on vring 2
       thread 2 on vring 0

    Memory regions (total 2)
    region fd    guest_phys_addr    memory_size        userspace_addr     mmap_offset        mmap_addr
    ====== ===== ================== ================== ================== ================== ==================
      0     60    0x0000000000000000 0x00000000000a0000 0x00002aaaaac00000 0x0000000000000000 0x00002aab2b400000
      1     61    0x00000000000c0000 0x000000003ff40000 0x00002aaaaacc0000 0x00000000000c0000 0x00002aababcc0000

     Virtqueue 0 (TX)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 128 used.flags 1 used.idx 0
      kickfd 62 callfd 64 errfd -1

     Virtqueue 1 (RX)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
      kickfd 65 callfd 66 errfd -1

     Virtqueue 2 (TX)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 128 used.flags 1 used.idx 0
      kickfd 63 callfd 70 errfd -1

     Virtqueue 3 (RX)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
      kickfd 72 callfd 74 errfd -1

     Virtqueue 4 (TX disabled)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
      kickfd 76 callfd 78 errfd -1

     Virtqueue 5 (RX disabled)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
      kickfd 80 callfd 82 errfd -1

     Virtqueue 6 (TX disabled)
      qsz 256 last_avail_idx 0 last_used_idx 0
     avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
      kickfd 84 callfd 86 errfd -1

     Virtqueue 7 (RX disabled)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
      kickfd 88 callfd 90 errfd -1

The optional '*descriptors*' parameter will display the same output as the
previous example but will include the descriptor table for each queue. The output is truncated below:

.. code-block:: console

    vpp# show vhost-user VirtualEthernet0/0/0 descriptors

    Virtio vhost-user interfaces
    Global:
      coalesce frames 32 time 1e-3
    Interface: VirtualEthernet0/0/0 (ifindex 1)
    virtio_net_hdr_sz 12
     features mask (0xffffffffffffffff):
     features (0x50408000):
       VIRTIO_NET_F_MRG_RXBUF (15)
       VIRTIO_NET_F_MQ (22)
    :
     Virtqueue 0 (TX)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 1 avail.idx 128 used.flags 1 used.idx 0
      kickfd 62 callfd 64 errfd -1

      descriptor table:
       id          addr         len  flags  next      user_addr
      ===== ================== ===== ====== ===== ==================
      0     0x0000000010b6e974 2060  0x0002 1     0x00002aabbc76e974
      1     0x0000000010b6e034 2060  0x0002 2     0x00002aabbc76e034
      2     0x0000000010b6d6f4 2060  0x0002 3     0x00002aabbc76d6f4
      3     0x0000000010b6cdb4 2060  0x0002 4     0x00002aabbc76cdb4
      4     0x0000000010b6c474 2060  0x0002 5     0x00002aabbc76c474
      5     0x0000000010b6bb34 2060  0x0002 6     0x00002aabbc76bb34
      6     0x0000000010b6b1f4 2060  0x0002 7     0x00002aabbc76b1f4
      7     0x0000000010b6a8b4 2060  0x0002 8     0x00002aabbc76a8b4
      8     0x0000000010b69f74 2060  0x0002 9     0x00002aabbc769f74
      9     0x0000000010b69634 2060  0x0002 10    0x00002aabbc769634
      10    0x0000000010b68cf4 2060  0x0002 11    0x00002aabbc768cf4
    :
      249   0x0000000000000000 0     0x0000 250   0x00002aab2b400000
      250   0x0000000000000000 0     0x0000 251   0x00002aab2b400000
      251   0x0000000000000000 0     0x0000 252   0x00002aab2b400000
      252   0x0000000000000000 0     0x0000 253   0x00002aab2b400000
      253   0x0000000000000000 0     0x0000 254   0x00002aab2b400000
      254   0x0000000000000000 0     0x0000 255   0x00002aab2b400000
      255   0x0000000000000000 0     0x0000 32768 0x00002aab2b400000

     Virtqueue 1 (RX)
      qsz 256 last_avail_idx 0 last_used_idx 0


Debug Vhost-User
================
Turn on/off debug for vhost.


Summary/Usage
-------------

.. code-block:: shell

    debug vhost-user <on | off>

Delete Vhost-User
========================
Delete a vHost User interface using the interface name or the software
interface index. Use the '*show interface*' command to determine the
software interface index. On deletion, the linux socket will not be
deleted.

Summary/Usage
-------------

.. code-block:: shell

    delete vhost-user {<interface> | sw_if_index <sw_idx>}

Examples
--------
Example of how to delete a vhost interface by name:

.. code-block:: console

    vpp# delete vhost-user VirtualEthernet0/0/1

Example of how to delete a vhost interface by software interface index:

.. code-block:: console

    vpp# delete vhost-user sw_if_index 1

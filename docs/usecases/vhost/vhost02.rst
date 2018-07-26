.. _vhost02:

Creating the Virtual Machine
----------------------------

We will now create the virtual machine. We use the "virsh create command". For the complete file we
use refer to :ref:`xmlexample`.

It is important to note that in the XML file we specify the socket path that is used to connect to
FD.io VPP.

This is done with a section that looks like this

.. code-block:: console

    <interface type='vhostuser'>
      <mac address='52:54:00:4c:47:f2'/>
      <source type='unix' path='/tmp//vm00.sock' mode='server'/>
      <model type='virtio'/>
      <alias name='net1'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </interface>

Notice the **interface type** and the **path** to the socket.

Now we create the VM. The virsh list command shows the VMs that have been created. We start with no VMs.

.. code-block:: console

    $ virsh list
    Id    Name                           State
    ----------------------------------------------------

Create the VM with the virsh create command specifying our xml file.

.. code-block:: console

    $ virsh create ./iperf3-vm.xml
    Domain iperf-server3 created from ./iperf3-vm.xml

    $ virsh list
    Id    Name                           State
    ----------------------------------------------------
    65    iperf-server3                  running

The VM is now created.

.. note::

    After a VM is created an xml file can created with "virsh dumpxml".

.. code-block:: console

    $ virsh dumpxml iperf-server3
    <domain type='kvm' id='65'>
      <name>iperf-server3</name>
      <uuid>e23d37c1-10c3-4a6e-ae99-f315a4165641</uuid>
      <memory unit='KiB'>262144</memory>
    .....

Once the virtual machine is created notice the socket filename shows **Success** and
there are **Memory Regions**. At this point the VM and FD.io VPP are connected. Also
notice **qsz 256**. This system is running an older version of qemu. A queue size of 256
will affect vhost throughput. The qsz should be 1024. On the web you should be able to
find ways to install a newer version of qemu or change the queue size.

.. code-block:: console

    vpp# show vhost
    Virtio vhost-user interfaces
    Global:
      coalesce frames 32 time 1e-3
      number of rx virtqueues in interrupt mode: 0
    Interface: VirtualEthernet0/0/0 (ifindex 3)
    virtio_net_hdr_sz 12
     features mask (0xffffffffffffffff):
     features (0x58208000):
       VIRTIO_NET_F_MRG_RXBUF (15)
       VIRTIO_NET_F_GUEST_ANNOUNCE (21)
       VIRTIO_F_ANY_LAYOUT (27)
       VIRTIO_F_INDIRECT_DESC (28)
       VHOST_USER_F_PROTOCOL_FEATURES (30)
      protocol features (0x3)
       VHOST_USER_PROTOCOL_F_MQ (0)
       VHOST_USER_PROTOCOL_F_LOG_SHMFD (1)
    
     socket filename /tmp/vm00.sock type client errno "Success"
    
     rx placement:
       thread 1 on vring 1, polling
     tx placement: spin-lock
       thread 0 on vring 0
       thread 1 on vring 0
    
     Memory regions (total 2)
     region fd    guest_phys_addr    memory_size        userspace_addr     mmap_offset        mmap_addr
     ====== ===== ================== ================== ================== ================== ===============    ===
      0     31    0x0000000000000000 0x00000000000a0000 0x00007f1db9c00000 0x0000000000000000 0x00007f7db0400    000
      1     32    0x00000000000c0000 0x000000000ff40000 0x00007f1db9cc0000 0x00000000000c0000 0x00007f7d94ec0    000
    
     Virtqueue 0 (TX)
      qsz 256 last_avail_idx 0 last_used_idx 0
      avail.flags 0 avail.idx 256 used.flags 1 used.idx 0
      kickfd 33 callfd 34 errfd -1
    
     Virtqueue 1 (RX)
      qsz 256 last_avail_idx 8 last_used_idx 8
      avail.flags 0 avail.idx 8 used.flags 1 used.idx 8
      kickfd 29 callfd 35 errfd -1

.. _tap:

Tap, tun and vhost-vdpa interfaces
==================================

The tap plugin creates VPP interfaces backed by virtio rings that VPP shares
with a backend outside of the VPP process. Two backends are supported:

- **vhost-net** (default): the kernel ``vhost-net`` driver moves packets
  between the virtio rings and a Linux tap or tun interface. This is the
  usual way to connect VPP to the host network stack, containers and network
  namespaces.
- **vhost-vdpa**: the virtio rings are handed to a vDPA device, typically a
  NIC virtual function that implements the virtio data path in hardware. The
  kernel is only involved in the setup; packets flow directly between VPP
  memory and the NIC.

Both backends use the same CLI, the same ``show tap`` output and the same
data path nodes.

Maturity level
--------------

- vhost-net backend: production.
- vhost-vdpa backend: experimental, tested with NVIDIA ConnectX vDPA devices
  only (see :ref:`tap_mlx5_vdpa`).

vhost-net backend
-----------------

Requirements
~~~~~~~~~~~~

- ``/dev/net/tun`` and ``/dev/vhost-net`` (``modprobe tun vhost_net``).
- ``CAP_NET_ADMIN`` for creating the host interface, plus ``CAP_SYS_ADMIN``
  when a network namespace is specified.

Creating an interface
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   vpp# create tap id 0 host-if-name vpp0 host-ip4-addr 192.168.10.1/24
   tap0
   vpp# set interface state tap0 up
   vpp# set interface ip address tap0 192.168.10.2/24

This creates the VPP interface ``tap0`` and the Linux interface ``vpp0``
with address ``192.168.10.1/24``. Without ``host-if-name`` the kernel picks
the name (``tap0``, ``tap1``, ...).

A tun interface (layer 3, no Ethernet header) is created by adding ``tun``.
The VPP interface is then called ``tun<id>`` and is not an Ethernet
interface:

.. code-block:: console

   vpp# create tap id 1 tun host-if-name vpptun0 host-ip4-addr 10.10.0.1/24

The same functionality is available through the ``tap_create_v2`` binary API
message, interfaces are listed with ``sw_interface_tap_v2_dump`` and deleted
with ``tap_delete_v2``.

Options
~~~~~~~

==================================== =========================================
Option                               Description
==================================== =========================================
``id <n>``                           Interface instance, used in the VPP
                                     interface name. Allocated automatically
                                     when omitted.
``if-name <name>``                   VPP interface name override.
``hw-addr <mac>``                    MAC address of the VPP interface. Random
                                     when omitted.
``host-if-name <name>``              Name of the Linux interface.
``host-ns <netns>``                  Create the Linux interface in a network
                                     namespace: a name under
                                     ``/var/run/netns``, an absolute path or
                                     ``pid:<pid>``.
``host-mac-addr <mac>``              MAC address of the Linux interface.
``host-bridge <name>``               Attach the Linux interface to an existing
                                     Linux bridge.
``host-ip4-addr <addr/len>``         IPv4 address of the Linux interface.
``host-ip4-gw <addr>``               IPv4 default route in the host (or
                                     namespace) via this gateway.
``host-ip6-addr <addr/len>``         IPv6 address of the Linux interface.
``host-ip6-gw <addr>``               IPv6 default route via this gateway.
``host-mtu-size <n>``                MTU of the Linux interface.
``num-rx-queues <n>``                Number of RX queues (default 1).
``num-tx-queues <n>``                Number of TX queues (default 1, at least
                                     one per VPP thread when more than one
                                     queue is requested).
``rx-ring-size``, ``tx-ring-size``   Ring size, power of 2, up to 32768
                                     (default 256).
``gso``                              Enable checksum offload and TCP
                                     segmentation offload (TSO) towards the
                                     host.
``gro-coalesce``                     With ``gso``: coalesce TCP segments sent
                                     to the host into larger packets.
``csum-offload``                     Enable checksum offload only.
``no-gso``                           Disable offloads (default).
``persist``                          Keep the Linux interface if VPP exits
                                     without deleting it.
``attach``                           Attach to an existing persistent Linux
                                     interface, requires ``host-if-name``.
``tun``                              Create a tun (layer 3) interface.
``consistent-qp``                    Assign TX queue N to VPP thread N+1
                                     (wrapping to the main thread) instead of
                                     thread N.
``packed``, ``in-order``             Accepted for compatibility, no effect.
==================================== =========================================

Multiple queues
~~~~~~~~~~~~~~~

With more than one queue VPP creates a multi-queue Linux tap interface and
opens one ``vhost-net`` instance per queue pair. RX queues are placed on VPP
threads like any other interface (``set interface rx-placement``); TX queues
are spread over threads, so with fewer TX queues than threads some threads
share a queue.

Persistence
~~~~~~~~~~~

``persist`` keeps the Linux interface (and its addresses and routes) when
VPP terminates, for example after a crash. A restarted VPP can reuse it with
``attach host-if-name <name>``. ``delete tap`` always removes the Linux
interface.

Show and delete
~~~~~~~~~~~~~~~

.. code-block:: console

   vpp# show tap
   vpp# show tap tap0 descriptors
   vpp# show tun
   vpp# delete tap tap0

``show tap`` prints backend file descriptors, negotiated virtio features and
the state of every ring, which is useful when packets stop flowing.

vhost-vdpa backend
------------------

A vDPA device exposes a virtio-net data path implemented by hardware. Linux
makes it available to userspace as ``/dev/vhost-vdpa-<n>`` through the
``vhost_vdpa`` module. VPP drives such a device with the same virtio ring
code used for vhost-net, but instead of a Linux tap interface the packets
go directly to and from the device.

Compared to a native NIC driver this gives a vendor neutral data path, and
compared to vhost-net it removes the kernel from the packet path.

Requirements
~~~~~~~~~~~~

- A vDPA device bound to ``vhost_vdpa``, visible as ``/dev/vhost-vdpa-<n>``.
- The device must support ``VIRTIO_F_VERSION_1``,
  ``VIRTIO_F_ACCESS_PLATFORM`` and IOTLB v2 messages.
- VPP buffer memory must be hugepage backed physmem (the default). VPP maps
  all of its physmem into the device at creation time and raises
  ``RLIMIT_MEMLOCK``, because ``vhost_vdpa`` pins mapped memory.

Creating an interface
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   vpp# create tap vdpa /dev/vhost-vdpa-0
   tap0
   vpp# set interface state tap0 up

Unless ``hw-addr`` is given, the interface uses the MAC address configured
on the vDPA device. A different ``hw-addr``, and later changes with
``set interface mac address``, are sent to the device over the control queue
(``VIRTIO_NET_F_CTRL_MAC_ADDR``); creation or the change fails if the device
doesn't support it.

The link state follows the device: VPP reads it at creation and again on
every device configuration change interrupt, and reports the link up only
when the interface is also administratively up.

Supported options are ``id``, ``if-name``, ``hw-addr``, ``num-rx-queues``,
``num-tx-queues``, ``rx-ring-size``, ``tx-ring-size`` (default 256, limited
by the device maximum), ``gso`` and ``csum-offload``. Creation fails if a
requested offload is not offered by the device.

Multiple queues
~~~~~~~~~~~~~~~

A vDPA device has queue pairs: RX and TX queue N always come together. VPP
uses ``max (num-rx-queues, num-tx-queues)`` pairs, up to the number of pairs
the device was created with:

.. code-block:: console

   vpp# create tap vdpa /dev/vhost-vdpa-0 num-rx-queues 4

When the device offers multiqueue (``VIRTIO_NET_F_MQ`` and
``VIRTIO_NET_F_CTRL_VQ``), VPP negotiates it, sets up the requested pairs
plus the control queue, and enables them with a
``VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`` command. The device distributes
received packets over the active RX queues, typically by hashing addresses
and ports. RX queues are placed on VPP threads like on any other interface;
with more threads than TX queues, threads share TX queues.

Limitations
~~~~~~~~~~~

- ``tun`` and the options that configure the Linux side (``host-*``,
  ``persist``, ``attach``) are rejected, there is no Linux interface.
- Available from the CLI only, the binary API does not yet have a vDPA path.
- Physmem growing after the interface is created is not mapped into the
  device.

.. _tap_mlx5_vdpa:

NVIDIA ConnectX (mlx5) vDPA
---------------------------

ConnectX-6 Dx and newer support virtio-net vDPA on SR-IOV virtual functions
through the ``mlx5_vdpa`` kernel driver. Use the upstream kernel driver;
some MLNX_OFED / DOCA-OFED releases ship ``mlx5_vdpa`` as a stub module that
registers no vDPA management devices.

Firmware
~~~~~~~~

SR-IOV must be enabled in the NIC firmware, for example:

.. code-block:: console

   # mlxconfig -d <pci-address> set SRIOV_EN=1 NUM_OF_VFS=4

A firmware reset or reboot is needed after changing it.

Host setup
~~~~~~~~~~

Load the modules and create a virtual function on the physical function:

.. code-block:: console

   # modprobe -a mlx5_vdpa vhost_vdpa
   # echo 1 > /sys/bus/pci/devices/0000:98:00.0/sriov_numvfs
   # vdpa mgmtdev show
   pci/0000:98:00.2:
     supported_classes net
     max_supported_vqs 65
     ...

Then create a vDPA device on the virtual function, with as many queue pairs
as VPP may use (``max_vqp``). It is bound to ``vhost_vdpa`` and shows up as
``/dev/vhost-vdpa-<n>``:

.. code-block:: console

   # vdpa dev add name vdpa0 mgmtdev pci/0000:98:00.2 mac 02:fe:00:00:00:01 max_vqp 4
   # vdpa dev show
   vdpa0: type network mgmtdev pci/0000:98:00.2 vendor_id 5555 max_vqs 9 max_vq_size 256

``mlx5_vdpa`` creates hardware queues for all pairs of the device when it
starts, including pairs VPP doesn't use. VPP gives those an empty ring and
leaves them disabled, so a device with more pairs than requested works, but
each spare pair still costs hardware resources.

Never rebind a vDPA device between ``virtio_vdpa`` and ``vhost_vdpa`` while
it exists; delete it with ``vdpa dev del`` and create it again instead.

Steering traffic to the virtual function
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In legacy SR-IOV mode the embedded switch forwards frames to the virtual
function by destination MAC address. Set the same MAC on the virtual
function from the physical function, on the VF kernel netdev and on the vDPA
device, and keep the VF netdev bound to ``mlx5_core``; without that the
virtual function receives no unicast traffic. For the same reason a MAC
change from VPP is accepted by the device but traffic to the new address is
not delivered in legacy mode:

.. code-block:: console

   # ip link set <pf-netdev> vf 0 mac 02:fe:00:00:00:01
   # ip link set <vf-netdev> address 02:fe:00:00:00:01
   # ip link set <vf-netdev> up

In switchdev mode traffic is steered with representor rules instead, for
example by redirecting everything between the uplink and the VF representor
with hardware-offloaded tc rules:

.. code-block:: console

   # devlink dev eswitch set pci/0000:98:00.0 mode switchdev
   # tc qdisc add dev <uplink> ingress
   # tc qdisc add dev <vf-representor> ingress
   # tc filter add dev <uplink> ingress protocol all flower skip_sw \
       action mirred egress redirect dev <vf-representor>
   # tc filter add dev <vf-representor> ingress protocol all flower skip_sw \
       action mirred egress redirect dev <uplink>

The eswitch mode can only be changed while no virtual functions exist.

VPP
~~~

.. code-block:: console

   vpp# create tap vdpa /dev/vhost-vdpa-0
   vpp# set interface state tap0 up
   vpp# set interface ip address tap0 10.99.0.1/24
   vpp# show tap tap0

Per-queue device counters are available on the host:

.. code-block:: console

   # vdpa dev vstats show vdpa0 qidx 0
   vdpa0: queue_type rx received_desc 2240 completed_desc 2000

``received_desc`` counts descriptors the device has fetched from VPP. If it
stops increasing while ``show tap`` reports a larger ``avail.idx`` the
device is not processing the ring.

Known issues
~~~~~~~~~~~~

- On a ConnectX-7 (firmware 28.50) in an aarch64 system an RX queue of a
  vDPA device can stop after exactly one ring of packets. The device stops
  fetching descriptors (``received_desc`` equals the ring size) and kicks are
  ignored. The same behaviour is seen with DPDK ``net_virtio_user``, so it
  is not specific to VPP. ConnectX-6 Dx (firmware 22.50) on x86_64 is not
  affected.

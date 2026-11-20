.. _dev_framework:

=======================================
Device driver framework (vnet/dev)
=======================================

Overview
========

The ``vnet/dev`` framework is the common infrastructure for VPP native device
drivers. A driver written against it does not talk to ``vnet`` or ``vlib``
directly for device and interface management. It describes the device, its
ports and its queues, and implements a small set of operations. The framework
takes care of everything around them:

* discovering and attaching devices on a bus (PCI, platform),
* creating and tearing down interfaces and queues,
* assigning queues to worker threads and enabling or disabling the RX nodes,
* serializing all control operations of a device in one process node,
* link state, MTU, MAC address, promiscuous mode, RSS, flow and statistics
  plumbing into ``vnet``,
* the ``device`` CLI, the startup configuration and the binary API,
* the crypto engine glue for crypto accelerators.

The framework lives in ``src/vnet/dev``. Drivers live in ``src/drivers`` and are
built as separate shared objects which are loaded at startup from the
``vpp_drivers`` library directory next to the ``vpp`` binary. Which drivers are
built is selected with the ``VPP_DRIVERS`` cmake variable.

The framework covers two device families:

* **Network devices** (:ref:`dev_net`): ports with RX and TX queues which
  become VPP interfaces.
* **Crypto devices** (:ref:`dev_crypto`): queues which are exposed to
  ``vnet_crypto`` as asynchronous crypto engines.

Object model
============

The framework uses the following objects. They form a tree, each object is
allocated by the framework and has driver private data attached to it.

.. code-block:: text

   driver ──┬── bus (pci, platform)
            │
            └── device  (one per attached hardware device, one process node)
                  ├── port 0 ──┬── RX queue 0..n
                  │            ├── TX queue 0..n
                  │            └── interface (primary) + secondary interfaces
                  ├── port 1 ...
                  └── crypto queue 0..n (crypto devices)

driver (``vnet_dev_driver_t``)
   One per ``VNET_DEV_REGISTER_DRIVER``. Holds the driver name, the bus it
   uses, the device match table or probe function, the device operations and
   the driver level and device level arguments. A driver may also hold crypto
   queue groups.

bus (``vnet_dev_bus_t``)
   Abstracts how a device is found and opened (PCI, platform device). It
   provides the device address format, opens and closes the device, maps DMA
   memory and gives access to bus specific data (BARs, interrupts).

device (``vnet_dev_t``)
   One attached hardware device. It owns a process node, DMA allocations, the
   list of ports and the crypto queues. Private data of the driver is reached
   with ``vnet_dev_get_data()``.

port (``vnet_dev_port_t``)
   A network port of a device. A device has one or more ports. Ports have
   attributes (maximum queues, maximum frame size, capabilities, offloads),
   operations (init, start, stop, config change, ...), an RX node and a TX
   node, and private data (``vnet_dev_get_port_data()``).

queue
   RX and TX queues belong to ports (``vnet_dev_rx_queue_t``,
   ``vnet_dev_tx_queue_t``), crypto queues belong to devices
   (``vnet_dev_crypto_queue_t``). Each has private driver data and a counter
   set.

interface
   Every started port has a primary interface which is a normal VPP hardware
   interface. Ports which advertise the ``secondary_interfaces`` capability can
   also have secondary interfaces which share the queues of the port.

Driver registration
===================

A driver registers itself with ``VNET_DEV_REGISTER_DRIVER``:

.. code-block:: c

   VNET_DEV_REGISTER_DRIVER (ice) = {
     .name = "ice",
     .description = "Intel E810, E830 and E835 Ethernet controllers",
     .bus = "pci",
     .device = {
       .data_sz = sizeof (ice_dev_t),
       .ops = {
         .alloc = ice_aq_alloc,
         .init = ice_init,
         .deinit = ice_deinit,
         .free = ice_aq_free,
         .probe = ice_probe,
         .format_info = format_ice_dev_info,
       },
     },
   };

``name``
   The driver name as used on the CLI (``device attach <id> driver <name>``) and
   in the ``driver`` startup configuration.

``bus``
   The bus the driver works on, ``"pci"`` or ``"platform"``.

``probe``
   Called with bus specific device information. If the device is supported the
   function returns a description string (which is used for ``show device``),
   otherwise ``NULL``. PCI drivers typically match on vendor and device id
   (``VNET_DEV_MATCH``), platform drivers on the device tree compatible string.

``priority``
   When no driver is requested explicitly, drivers are probed in priority order
   and the first one which accepts the device wins.

``device.args`` and ``driver.args``
   Arrays of ``clib_arg_t`` describing the device and driver level arguments
   (see :ref:`dev_args`).

``bus_master_enable``
   For PCI drivers, enable DMA for the device when it is opened.

``device.dma_address_space_bits``
   Number of DMA address bits the device can generate, used to refuse
   configurations where the IOMMU or buffer memory would need wider addresses.

The device operations (``vnet_dev_ops_t``) are:

``alloc`` / ``free``
   Optional, allocate and release driver state which must exist before ``init``
   and after ``deinit`` (for example the admin queue of a NIC).

``init`` / ``deinit``
   Bring the device to a usable state, read its capabilities and add the ports
   (``vnet_dev_port_add``) or crypto queues. ``deinit`` undoes it.

``reset``
   Optional, used by ``device reset``.

``config_args``
   Optional, called when the ``driver`` startup configuration is parsed.

``format_info``
   Format function used by ``show device`` for device specific information.

Device lifecycle
================

Attaching a device is done with the ``device attach`` CLI, the ``dev_attach``
API message or a ``dev`` entry in the startup configuration. The framework does
the following:

1. Find the bus from the device id. A device id is the name of the bus, a ``/``
   and the bus specific address, for example ``pci/0000:18:00.0``. Read the bus
   device information.
2. Probe the drivers (the requested one, or all in priority order) until one
   returns a description.
3. Allocate the device, parse the device arguments, create the device process
   node (see :ref:`dev_process`).
4. In the process node: open the device on the bus, check the DMA address
   space, call the driver ``alloc`` and ``init`` operations and initialize
   the crypto queues.

The driver ``init`` operation registers the ports with ``vnet_dev_port_add``. It
passes a ``vnet_dev_port_add_args_t`` describing the port attributes, the port
operations, the RX and TX nodes and the queue limits (see :ref:`dev_net`).

``device detach`` removes all interfaces, stops and tears down the ports and
the device, closes it on the bus and removes the process node. ``device reset``
calls the driver ``reset`` operation.

Port lifecycle
--------------

``device create-interface`` creates the interface of a port. The framework
allocates the queues (the number and size come from the command or the
startup configuration, the limits from the driver), assigns the RX queues to
threads, creates the VPP hardware interface and calls the port ``init``
operation. The interface is administratively down. Setting the interface up
ends in the port ``start`` operation which starts all queues, and setting it
down ends in ``stop``.

.. code-block:: text

   port alloc -> init -> [ start <-> stop ] -> deinit -> free

``start`` may be called many times, ``stop`` must leave the port in a state in
which ``start`` works again. The framework marks the link down once the driver
``stop`` returns, so a driver does not report link down from ``stop`` itself.

.. _dev_process:

The device process node
=======================

Every device has its own process node named ``<device-id>-process``, for
example ``pci/0000:18:00.0-process``. It is the key piece of the architecture:

* **All control operations of a device run in this process.** Attach, init,
  reset, deinit, port start and stop, config changes (MTU, MAC, promiscuous
  mode, RSS, link speed, ...), secondary interface creation and the periodic
  operations of the driver are all executed one after another by the process
  node, so a driver never has to protect its control path against concurrent
  control operations.
* **Operations may block.** A process node may suspend, so a driver operation can
  wait for a command to complete (an admin queue response, a firmware reply)
  with ``vlib_process_suspend`` and does not stall the data path. It runs on the
  main thread, never on a worker.
* **Callers are decoupled.** CLI handlers, API handlers and interface callbacks
  do not call the driver directly. They post an event to the process node
  (``vnet_dev_process_call_op``, ``vnet_dev_process_call_port_op`` and friends)
  and wait for the reply, or use the ``_no_wait`` variants. When the caller is
  the device process node itself the operation is executed inline.
* **Periodic work.** A driver can register functions which the process node runs
  at a fixed interval with ``vnet_dev_poll_dev_add`` and
  ``vnet_dev_poll_port_add``. This is the normal way to poll link state and
  hardware counters. The functions are removed with
  ``vnet_dev_poll_dev_remove`` and ``vnet_dev_poll_port_remove``.

The data path (RX and TX nodes) does not use the process node and never takes a
lock on it. Control operations which must change runtime state of the data
path (enabling an RX node, changing the queue list of a thread) are executed on
the worker threads through the runtime operation mechanism
(``vnet_dev_rt_exec_ops``) at a safe point.

The process node processes events in the order they were sent. Operations
requested from other processes therefore appear atomic from the point of view
of a driver.

Startup configuration
=====================

Devices are normally attached from the ``devices`` section of ``startup.conf``:

.. code-block:: text

   devices {
     dev pci/0000:18:00.0 {
       driver ice
       flags no-stats
       args 'name=value'
       port 0 {
         name eth0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 1024
         tx-queue-size 1024
         rx-queue-assignment queue-per-thread
         flags interrupt-mode
         args 'name=value'
       }
     }
     driver ice {
       args 'name=value'
     }
   }

``dev <device-id> { ... }``
   Attach the device and create its ports. A ``dev <device-id>`` without
   braces just attaches it with defaults.

``driver <name>``
   Select a driver (otherwise the drivers are probed by priority).

``flags no-stats``
   Do not poll the device statistics.

``args '<device-args>'``
   Device level arguments of the driver.

``port <n> { ... }``
   Create the interface of port ``n``. All entries are optional:

   ``name``
      Interface name. The default is ``<driver><device-index>/<port-index>``.

   ``num-rx-queues``, ``num-tx-queues``
      Number of queues. The defaults depend on the port flags and the number
      of worker threads.

   ``rx-queue-size``, ``tx-queue-size``
      Number of descriptors per queue. The value must be within the limits
      advertised by the driver and, for most drivers, a power of two.

   ``rx-queue-assignment``
      ``round-robin`` (default), ``queue-per-thread`` or ``main-thread-only``.
      See :ref:`dev_net`.

   ``flags``
      Port flags, several flags are separated by commas without spaces:
      ``interrupt-mode`` (start the RX queues in interrupt mode),
      ``consistent-qp`` (assign the TX queues to threads in the same order as
      the RX queues, with the main thread last) and ``queue-per-thread`` (one RX
      and one TX queue per thread, including the main thread).

   ``rss-key`` and ``rss-lut``
      RSS hash key and lookup table, see :ref:`dev_net`.

   ``args '<interface-args>'``
      Interface level arguments of the driver.

``driver <name> { args '<driver-args>' }``
   Driver level arguments. They are applied once for all devices of the driver.

Crypto devices additionally accept ``num-crypto-queues``, ``crypto-queue-size``
and ``crypto-queue <i> { size <n> threads <list> }`` in the device section, see
:ref:`dev_crypto`.

.. _dev_args:

Driver arguments
================

Drivers describe their arguments with ``clib_arg_t`` arrays (``CLIB_ARG_BOOL``,
``CLIB_ARG_UINT32``, ``CLIB_ARG_HEX32``, ``CLIB_ARG_STRING`` and
``CLIB_ARG_ENUM``). There are three scopes: **driver** arguments, **device**
arguments (set at attach) and **port** arguments (set at interface creation).
Each argument has a name, a description, a default and optionally a range.

In the configuration an argument string is a whitespace separated list of
``name=value`` pairs, for example::

   args 'rx_cksum_validate=off num_cmd_buffers=64 name=my_name'

Boolean values accept ``true``, ``false``, ``1``, ``0``, ``on``, ``off``, ``yes``
and ``no``. Integers are decimal or, with a ``0x`` prefix, hexadecimal and are
range checked. Strings are single tokens or double quoted. An unknown name or a
bad value fails the attach or the interface creation with ``invalid argument``.
The arguments of each driver are described in its own documentation.

CLI
===

The framework registers the following commands:

``device attach <device-id> [driver <name>] [args <dev-args>] [num-crypto-queues <n>] ...``
   Attach a device.

``device detach <device-id>``
   Detach a device and remove all of its interfaces.

``device reset <device-id>``
   Reset the device (driver ``reset`` operation).

``device create-interface <device-id> [port <port-id>] [name <name>] [num-rx-queues <n>] [num-tx-queues <n>] [rx-queues-size <n>] [tx-queues-size <n>] [flags <flags>] [rx-queue-assignment {round-robin | queue-per-thread | main-thread-only}] [args <iface-args>]``
   Create the primary interface of a port. Without ``name`` the interface is
   named ``<driver><device-index>/<port-index>``.

``device remove-interface [<interface-name> | sw-if-index <n>]``
   Remove an interface.

``device create-secondary-interface`` and ``device remove-secondary-interface``
   Create and remove secondary interfaces of a port.

``device set-rss-config [<intf>] [port <port-id>] [dev <device-id>] [key <rss-key>] [lut <queue-id,...>]``
   Change the RSS key and lookup table at runtime.

``show device [debug] [debug-level <n>] [<device-id> ...]``
   Show devices, ports, queues and their driver specific information.

``show device counters [all] [clear] [<device-id> ...]``
   Show or clear device, port and queue counters. Zero counters are only shown
   with ``all``.

``show device drivers``
   List the loaded drivers with bus, priority, shared object and description.

``show device dma-slabs``
   Show the DMA slab allocator state of the devices.

The same operations are available in the binary API (``dev.api``:
``dev_attach``, ``dev_detach``, ``dev_create_port_if``, ``dev_remove_port_if``).

Buses
=====

A bus registers itself with ``VNET_DEV_REGISTER_BUS`` and provides device
discovery and access:

PCI (``pci``)
   Device ids are ``pci/<address>``, for example ``pci/0000:18:00.0``. The bus
   uses the vfio driver for userspace access. The device must be bound to
   ``vfio-pci`` (and not be in use by a kernel driver) before it is attached. The bus provides
   BAR access (``vnet_dev_pci_map_region``), MSI-X interrupts, DMA memory
   mapping and bus mastering control.

   Enabling the IOMMU (``intel_iommu=on`` or ``amd_iommu=on``) is recommended.
   With an IOMMU the framework sets up virtual address DMA (``va_dma``): drivers
   program the virtual address of a buffer or ring into the device and the
   IOMMU translates it, so no per-buffer physical address lookup is needed. It
   also confines the device to the memory mapped for it. Without an IOMMU
   physical addresses are used.

Platform (``platform``)
   Device ids are of the form ``platform/<name>``. The bus opens memory regions
   described by the device tree through UIO. It is used by SoC drivers.

Both buses record NUMA information and help drivers select the buffer pool and
allocate DMA memory on the right node.

.. _dev_net:

Network devices
===============

This section describes what the framework does for network drivers and what
a driver has to implement.

Port attributes
---------------

The driver passes the attributes in ``vnet_dev_port_add_args_t``:

* ``hw_addr``: default MAC address.
* ``max_rx_queues``, ``max_tx_queues``: queue limits.
* ``max_supported_rx_frame_size``: largest supported frame, **including the 4
  byte FCS**.
* ``caps``: capabilities.

  ``interrupt_mode``
     RX queues can be switched to interrupt mode.
  ``rss``
     RSS configuration is supported.
  ``change_max_rx_frame_size``
     The maximum frame size can be changed at runtime.
  ``mac_filter``
     The hardware filters on the primary MAC and supports additional
     addresses.
  ``secondary_interfaces``
     Secondary interfaces are supported.

* ``rx_offloads`` and ``tx_offloads``: ``ip4_cksum`` and ``l4_cksum`` on RX,
  ``ip4_cksum``, ``tcp_cksum``, ``udp_cksum``, ``tcp_gso`` and ``udp_gso`` on
  TX. A driver must only advertise what it has tested.
* ``speed_caps``: supported link speeds.

Queues
------

The driver supplies the queue limits (``min_size``, ``max_size``,
``default_size`` and whether the size must be a power of two) and the ``alloc``,
``free``, ``start`` and ``stop`` operations for RX and TX queues. Queue
private data is declared with ``data_size`` and reached through
``vnet_dev_get_rx_queue_data()`` and ``vnet_dev_get_tx_queue_data()``.

**RX queue to thread assignment.** Each RX queue is polled by exactly one
thread. ``rx-queue-assignment`` selects how threads are picked:

``round-robin``
   Queues are spread over the worker threads (the main thread is not used when
   workers exist).

``queue-per-thread``
   Queue ``i`` is polled by thread ``i``.

``main-thread-only``
   All queues are polled by the main thread.

**TX queue to thread assignment.** Every thread is assigned a TX queue. If there
are fewer TX queues than threads, queues are shared and a spinlock is taken
in the TX node (``lock_needed``).

**RX node.** One RX node per port is created from the driver node registration.
On each thread the framework keeps a list of the queues of that thread and sets
the node state (polling, interrupt or disabled) accordingly. The node function
iterates the queues with ``foreach_vnet_dev_rx_queue_runtime``, which also applies
pending runtime requests (switching a queue to interrupt mode, changing the next
node or the feature arc, suspending a queue).

**TX node.** One TX node per port. It receives frames from ``vnet`` and enqueues
buffers to the hardware queue of the current thread.

The node functions are registered with ``VNET_DEV_NODE_FN`` so that they are
built for each CPU micro-architecture variant.

Interface creation
------------------

Creating an interface registers a VPP hardware interface, a TX node binding and
a device class. The interface MAC address is the primary MAC of the port. The
frame overhead is the Ethernet header, so the interface MTU is the maximum RX
frame size minus FCS and header. Interface counters are updated in the RX and TX
nodes (for RX ``vnet_dev_increment_interface_counters``).

Link state
----------

The driver reports link changes to the framework with
``vnet_dev_port_state_change`` (link up or down, speed, duplex) from a poll
function, an interrupt or an event. It must report only changes, compared with
``port->link_up`` and ``port->speed``, and speed is 0 while the link is down. The
framework marks the link down when the port is stopped. Because it then holds no
link state, the driver must report the actual link state again after start.

Link monitoring (the poll registration) belongs in the port ``start`` operation
and its removal in ``stop``, so that nothing polls a stopped port.

Configuration changes
---------------------

Changes requested through the interface (promiscuous mode, MAC address, MTU, RSS
key and lookup table, link speed, interrupt mode of a queue, secondary MAC
addresses, flows) are passed to the port ``config_change`` operation as a
request with a type (``VNET_DEV_PORT_CFG_*``). The framework does the generic
checks itself (value ranges, no-change detection, duplicate or missing MAC
addresses, RSS table contents), then calls ``config_change_validate`` and, if it
succeeds, ``config_change``. The framework never stops and restarts a port on
its own: a driver which cannot apply a change while the port is started (for
example a new maximum frame size) refuses it in ``config_change_validate`` and
the user has to set the interface down first.

Statistics and counters
-----------------------

Drivers declare counters with ``vnet_dev_counter_t`` arrays and register them for
a port (``vnet_dev_port_add_counters``), an RX queue or a TX queue. The framework
polls them (``flags no-stats`` disables it), shows them with
``show device counters`` and clears them with ``clear interfaces``. Per-node
error counters are declared in the node registration and are counted with
``vlib_error_count``.

Interrupts and RX interrupt mode
--------------------------------

Ports with the ``interrupt_mode`` capability can run queues in interrupt mode,
where the RX node is not polled but scheduled by an interrupt. The mode is set
with the ``interrupt-mode`` port flag or changed at runtime
(``set interface rx-mode``). The driver switches the hardware queue interrupt
on request and must keep the mode working across stop and start.

RSS
---

Ports with the ``rss`` capability take a hash key and an indirection table.
``rss-key`` and ``rss-lut`` in the configuration and ``device set-rss-config`` at
runtime end in a ``SET_RSS_CONFIG`` configuration change request. The driver can
supply a default key.

Secondary interfaces
--------------------

A port with ``secondary_interfaces`` can host additional interfaces which share
its queues (for example one per virtual function or sub-port). The driver gets
``add_sec_if`` and ``del_sec_if`` operations and a separate argument set
(``sec_if_args``). The RX node receives the secondary interface runtime data and
decides per packet which interface it belongs to.

SFP and QSFP modules
--------------------

A port can implement ``get_module_eeprom`` to expose the module EEPROM
(``show hardware-interfaces <name> eeprom``).

Writing a network driver
------------------------

The usual structure of a driver in ``src/drivers/net/<name>`` is:

* ``<name>.c`` or ``init.c``: registration, probe, device init and deinit, port
  add.
* ``port.c``: port init, start, stop, config change, link handling.
* ``queue.c``: RX and TX queue allocation and start.
* ``rx_node.c`` and ``tx_node.c``: data path.
* ``counters.c``, ``format.c``: counters and format functions.
* ``*_regs.h``, ``*_desc.h``: register and descriptor layouts. Use bitfield
  structures, not raw masks and shifts.

Rules the framework expects from a driver:

* **Link down on stop.** The link must go down when the port is stopped and stay
  down after init until start, so that the link partner sees it. A virtual
  function cannot do this because the physical function owns the link.
* **Report link changes through ``vnet_dev_port_state_change``** only for the
  fields that changed.
* **Frame sizes include the FCS.** Program the hardware with the value as is and
  register the interface with ``.frame_overhead = sizeof (ethernet_header_t)``.
  Frames up to the limit must be delivered and one byte more dropped.
* **Advertise only what is tested.** Every bit in ``rx_offloads`` and
  ``tx_offloads`` needs a test.
* **Free every ring buffer on stop**, reset the ring state so that start works
  repeatedly and re-program anything a reset clears (primary MAC, filters) at
  start.
* **Buffer chains.** Handle chained buffers on RX, cap the number of descriptors
  per packet on TX and drop and count packets over the cap.
* **Counters and tracing.** Register error counters for the node (no free TX
  slots, chain too long, buffer allocation failure, descriptor error) and
  support packet tracing in both nodes.
* Receive multicast, program the primary MAC at start, and when changing
  promiscuous mode do not touch unrelated bits.

.. _dev_crypto:

Crypto devices
==============

Crypto accelerators (for example Intel QuickAssist and the Marvell Octeon
crypto block) use the same device, bus and process node infrastructure, but
instead of ports they expose *crypto queues* which are registered as an
asynchronous crypto *engine* in ``vnet_crypto``.

Concepts
--------

crypto queue (``vnet_dev_crypto_queue_t``)
   A hardware request and response ring pair. Queues of one device with the
   same capabilities and limits belong to a **queue group**.

queue group (``vnet_dev_crypto_queue_group_t``)
   Created by the driver with ``vnet_dev_crypto_queue_group_add`` from the device
   ``init`` operation. A group carries the engine description, the list of
   algorithms (``alg_handlers``: the algorithm and the enqueue nodes for
   encrypt and decrypt), the dequeue node, the key change function, the queue
   size limits and the queue operations. For every group the framework creates
   one crypto engine named ``<driver>-<group>``, and registers or unregisters the
   algorithms with ``vnet_crypto`` as queues start and stop.

queue operations
   ``init``, ``deinit``, ``start``, ``stop`` and ``format_queue_info``.

Queues are added with ``vnet_dev_crypto_queue_add`` (group name, initial private
data, size limits). The framework validates the requested configuration against
the number of worker threads.

Operation
---------

Enqueue and dequeue nodes are normal VPP nodes registered with
``VNET_DEV_NODE_FN``. The framework gives each thread one or more queues
(``multi_queue_per_thread``), assigns queues to threads, and provides helpers for
the node functions:

* ``vnet_dev_crypto_get_thread_queue`` and ``vnet_dev_crypto_get_least_loaded_queue``
  select the queue to use,
* ``vnet_dev_crypto_frame_done`` completes a frame back to ``vnet_crypto``,
* ``vnet_dev_crypto_frame_no_queue`` fails a frame when the thread has no queue,
* ``vnet_dev_crypto_defer_free`` frees session data only after the requests that
  use it have drained.

Queue counters (``enq_req``, ``enq_bytes``, ``enq_full``, ``enq_err``, ``deq_req``,
``deq_err`` and ``deq_auth_fail``) are kept by the framework and shown with
``show device``.

Configuration
-------------

The number and size of crypto queues and their thread binding are set at
attach:

.. code-block:: text

   devices {
     dev pci/0000:6b:00.0 {
       driver qat
       num-crypto-queues 8
       crypto-queue-size 512
       crypto-queue 0 { size 1024 threads 1-2 }
     }
   }

The same options exist on the ``device attach`` CLI. The queue groups of a driver
are listed with ``show device driver <name> groups [debug]``.

Writing a crypto driver
-----------------------

1. In ``init``: map the device, reset it, and describe the algorithms the
   hardware supports.
2. Create the queue group(s) with ``vnet_dev_crypto_queue_group_add`` and add the
   queues with ``vnet_dev_crypto_queue_add``.
3. Implement the queue ``init``, ``start`` and ``stop`` operations (ring setup,
   interrupts).
4. Implement the enqueue node per algorithm and the dequeue node. The dequeue
   node completes frames with ``vnet_dev_crypto_frame_done`` and counts errors.
5. Implement ``key_change`` to translate ``vnet_crypto`` keys into session data.

Memory
======

DMA memory is allocated through the framework so that it is mapped correctly for
the bus and the IOMMU:

* ``vnet_dev_dma_mem_alloc`` and ``vnet_dev_dma_mem_free`` allocate and free
  DMA memory attached to a device, the allocations are listed by ``show
  device debug``.
* ``vnet_dev_dma_slab_alloc`` and friends allocate small DMA objects from a
  slab. ``show device dma-slabs`` shows them.
* ``vnet_dev_get_dma_addr`` returns the DMA address of a pointer.

Packet buffer memory uses the buffer pools of the thread NUMA node. The framework
checks at attach that the DMA address range of the device fits the memory in use.

Debugging
=========

* ``show device`` shows device, port and queue state. With ``debug`` and
  ``debug-level <n>`` it adds driver specific details.
* ``show device counters all`` shows all counters including zero ones.
* ``show hardware-interfaces`` and ``show interface`` show the interface level
  view and ``show errors`` the node error counters of the driver nodes.
* ``trace add <interface-name>-rx 10`` captures packets in the RX node of a port.
  The input node of every interface is named ``<interface-name>-rx``, for example
  ``eth0-rx``.
* Logging: the framework logs through the ``dev`` log class with subclasses
  such as ``config``, ``runtime`` and ``crypto``. Set the level in the startup
  configuration, for example ``logging { class dev/config { level debug } }``
  and read the messages with ``show logging``.
* ``show device drivers`` confirms the driver shared object was loaded. If a
  driver is missing check that it was built (``VPP_DRIVERS``) and that its
  ``.so`` is in the ``vpp_drivers`` directory.
* A common failure is ``device attach`` returning ``already in use`` (the device
  is attached) or ``driver not available`` (no driver matched the device, or the
  device is not bound to ``vfio-pci``).

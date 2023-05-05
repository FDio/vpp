.. _TX_Queue_doc:

Transmit Queues
===============

Overview
________

VPP implements Transmit queues infra to access and manage them. It provides
common registration functions to register or unregister interfaces’ transmit
queues. It also provides functions for queues placement on given thread(s).

The TXQ Infrastructure
_______________________

Infra registers each queue using a unique key which is formed by concatenating
the hardware interface index ``hw_if_index`` and unique queue identifier for
given interface ``queue_id``. As a result of registration of queue, infra
returns back a unique global ``queue_index`` which can be used by driver to
access that queue later.

Interface output node uses pre-computed ``output_node_thread_runtime`` data
which provides essential information related to queue placements on given
thread of given interface. Transmit queue infra implements an algorithm to
pre-compute this information. It also pre-computes scalar arguments of frame
``vnet_hw_if_tx_frame_t``. It also pre-calculates a ``lookup_table`` for
thread if there are multiple transmit queues are placed on that thread.
Interface drivers call ``vnet_hw_if_update_runtime_data()`` to execute that
algorithm after registering the transmit queues to TXQ infra.

The algorithm makes the copy of existing runtime data and iterate through them
for each vpp main and worker thread. In each iteration, algorithm loop through
all the tx queues of given interface to fill the information in the frame data
structure ``vnet_hw_if_tx_frame_t``. Algorithm also updates the information
related to number of transmit queues of given interface on given vpp thread in
data structure ``output_node_thread_runtime``. As a consequence of any update
to the copy, triggers the function to update the actual working copy by taking
the worker barrier and free the old copy of ``output_node_thread_runtime``.

Multi-TXQ infra
^^^^^^^^^^^^^^^

Interface output node uses packet flow hash using hash infra in case of multi-txq
on given thread. Each hardware interface class contains type of the hash required
for interfaces from that hardware interface class i.e. ethernet interface hardware
class contains type ``VNET_HASH_FN_TYPE_ETHERNET``. Though, the hash function
itself is contained by hardware interface data structure of given interface. Default
hashing function is selected upon interface creation based on priority. User can
configure a different hash to an interface for multi-txq use case.

Interface output node uses packet flow hash as an index to the pre-calculated lookup
table to get the queue identifier for given transmit queue. Interface output node
enqueues the packets to respective frame and also copies the ``vnet_hw_if_tx_frame_t``
to frame scalar arguments. Drivers use scalar arguments ``vnet_hw_if_tx_frame_t``
of the given frame to extract the information about the transmit queue to be used to
transmit the packets. Drivers may need to acquire a lock on given queue before
transmitting the packets based on the ``shared_queue`` bit status.

Data structures
^^^^^^^^^^^^^^^

Queue information is stored in data structure ``vnet_hw_if_tx_queue_t``:

.. code:: c

  typedef struct
  {
    /* either this queue is shared among multiple threads */
    u8 shared_queue : 1;
    /* hw interface index */
    u32 hw_if_index;

    /* hardware queue identifier */
    u32 queue_id;

    /* bitmap of threads which use this queue */
    clib_bitmap_t *threads;
  } vnet_hw_if_tx_queue_t;


Frame information is stored in data structure: ``vnet_hw_if_tx_frame_t``:

.. code:: c

  typedef enum
  {
    VNET_HW_IF_TX_FRAME_HINT_NOT_CHAINED = (1 << 0),
    VNET_HW_IF_TX_FRAME_HINT_NO_GSO = (1 << 1),
    VNET_HW_IF_TX_FRAME_HINT_NO_CKSUM_OFFLOAD = (1 << 2),
  } vnet_hw_if_tx_frame_hint_t;

  typedef struct
  {
    u8 shared_queue : 1;
    vnet_hw_if_tx_frame_hint_t hints : 16;
    u32 queue_id;
  } vnet_hw_if_tx_frame_t;

Output node runtime information is stored in data structure: ``output_node_thread_runtime``:

.. code:: c

  typedef struct
  {
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
    vnet_hw_if_tx_frame_t *frame;
    u32 *lookup_table;
    u32 n_queues;
  } vnet_hw_if_output_node_runtime_t;


MultiTXQ API
^^^^^^^^^^^^

This API message is used to place tx queue of an interface to vpp main or worker(s) thread(s).

.. code:: c

  autoendian autoreply define sw_interface_set_tx_placement
  {
      u32 client_index;
      u32 context;
      vl_api_interface_index_t sw_if_index;
      u32 queue_id;
      u32 array_size;
      u32 threads[array_size];
      option vat_help = "<interface | sw_if_index <index>> queue <n> [threads <list> | mask <hex>]";
  };

Multi-TXQ CLI
^^^^^^^^^^^^^

::

  set interface tx-queue                   set interface tx-queue <interface> queue <n> [threads <list>]
  set interface tx-hash                    set interface tx-hash <interface> hash-name <hash-name>

::

  show hardware-interfaces

         Name                Idx   Link  Hardware
  tap0                        1     up   tap0
    Link speed: unknown
    RX Queues:
      queue thread         mode
      0     main (0)       polling
    TX Queues:
      TX Hash: [name: crc32c-5tuple  priority: 50 description: IPv4/IPv6 header and TCP/UDP ports]
      queue shared thread(s)
      0     no     0
    Ethernet address 02:fe:27:69:5a:b5
    VIRTIO interface
       instance 0
         RX QUEUE : Total Packets
                0 : 0
         TX QUEUE : Total Packets
                0 : 0


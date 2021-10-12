.. _libmemif_gettingstarted_doc:

Getting started
===============

For detailed information on api calls and structures please refer to
``libmemif.h``.

Start by creating a memif socket. Memif socket represents UNIX domain
socket and interfaces assigned to use this socket. Memif uses UNIX domain
socket to communicate with other memif drivers.

First fill out the ``memif_socket_args`` struct. The minimum required
configuration is the UNIX socket path. > Use ``@`` or ``\0`` at the
beginning of the path to use abstract socket.

.. code:: c

   memif_socket_args_t sargs;

   strncpy(sargs.path, socket_path, sizeof(sargs.path));

.. code:: c

   memif_socket_handle_t memif_socket;

   memif_create_socket(&memif_socket, &sargs, &private_data);

Once you have created your socket, you can create memif interfaces on
this socket. Fill out the ``memif_conn_args`` struct. Then call
``memif_create()``.

.. code:: c

   memif_conn_args_t cargs;

   /* Assign your socket handle */
   cargs.socket = memif_socket;

.. code:: c

   memif_conn_handle_t conn;

   /* Assign callbacks */
   memif_create (&conn, &cargs, on_connect_cb, on_disconnect_cb, on_interrupt_cb, &private_data);

Now start the polling events using libmemifs builtin polling.

.. code:: c

   do {
       err = memif_poll_event(memif_socket, /* timeout -1 = blocking */ -1);
   } while (err == MEMIF_ERR_SUCCESS);

Polling can be canceled by calling ``memif_cancel_poll_event()``.

.. code:: c

   memif_cancel_poll_event (memif_socket);

On link status change ``on_connect`` and ``on_disconnect`` callbacks are
called respectively. Before you can start transmitting data you, first
need to call ``memif_refill_queue()`` for each RX queue to initialize
this queue.

.. code:: c

   int on_connect (memif_conn_handle_t conn, void *private_ctx)
   {
     my_private_data_t *data = (my_private_data_t *) private_ctx;

     err = memif_refill_queue(conn, 0, -1, 0);
     if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_refill_queue: %s", memif_strerror(err));
       return err;
     }

     /*
      * Do stuff.
      */

     return 0;
   }

Now you are ready to transmit packets. > Example implementation
``examples/common/sender.c`` and ``examples/common/responder.c``

To transmit or receive data you will need to use ``memif_buffer``
struct. The important fields here are ``void *data``, ``uint32_t len``
and ``uint8_t flags``. The ``data`` pointer points directly to the
shared memory packet buffer. This is where you will find/insert your
packets. The ``len`` field is the length of the buffer. If the flag
``MEMIF_BUFFER_FLAG_NEXT`` is present in ``flags`` field, this buffer is
chained so the rest of the data is located in the next buffer, and so
on.

First let’s receive data. To receive data call ``memif_rx_burst()``. The
function will fill out memif buffers passed to it. Then you would
process your data (e.g. copy to your stack). Last you must refill the
queue using ``memif_refill_queue()`` to notify peer that the buffers are
now free and can be overwritten.

.. code:: c

   /* Fill out memif buffers and mark them as received */
   err = memif_rx_burst(conn, qid, buffers, num_buffers, &num_received);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO ("memif_rx_burst: %s", memif_strerror(err));
       return err;
   }
   /*
       Process the buffers.
   */

   /* Refill the queue, so that the peer interface can transmit more packets */
   err = memif_refill_queue(conn, qid, num_received, 0);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_refill_queue: %s", memif_strerror(err));
       goto error;
   }

In order to transmit data you first need to ‘allocate’ memif buffers
using ``memif_buffer_alloc()``. This function similar to
``memif_rx_burst`` will fill out provided memif buffers. You will then
insert your packets directly into the shared memory (don’t forget to
update ``len`` filed if your packet is smaller that buffer length).
Finally call ``memif_tx_burst`` to transmit the buffers.

.. code:: c

   /* Alocate memif buffers */
   err = memif_buffer_alloc(conn, qid, buffers, num_pkts, &num_allocated, packet_size);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_buffer_alloc: %s", memif_strerror(err));
       goto error;
   }

   /*
       Fill out the buffers.

       tx_buffers[i].data field points to the shared memory.
       update tx_buffers[i].len to your packet length, if the packet is smaller.
   */

   /* Transmit the buffers */
   err = memif_tx_burst(conn, qid, buffers, num_allocated, &num_transmitted);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_tx_burst: %s", memif_strerror(err));
       goto error;
   }

Zero-copy Slave
---------------

Interface with slave role is the buffer producer, as such it can use
zero-copy mode.

After receiving buffers, process your packets in place. Then use
``memif_buffer_enq_tx()`` to enqueue rx buffers to tx queue (by swapping
rx buffer with a free tx buffer).

.. code:: c

   /* Fill out memif buffers and mark them as received */
   err = memif_rx_burst(conn, qid, buffers, num_buffers, &num_received);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO ("memif_rx_burst: %s", memif_strerror(err));
       return err;
   }

   /*
       Process the buffers in place.
   */

   /* Enqueue processed buffers to tx queue */
   err = memif_buffer_enq_tx(conn, qid, buffers, num_buffers, &num_enqueued);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_buffer_alloc: %s", memif_strerror(err));
       goto error;
   }

   /* Refill the queue, so that the peer interface can transmit more packets */
   err = memif_refill_queue(conn, qid, num_enqueued, 0);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_refill_queue: %s", memif_strerror(err));
       goto error;
   }

   /* Transmit the buffers. */
   err = memif_tx_burst(conn, qid, buffers, num_enqueued, &num_transmitted);
   if (err != MEMIF_ERR_SUCCESS) {
       INFO("memif_tx_burst: %s", memif_strerror(err));
       goto error;
   }

Custom Event Polling
--------------------

Libmemif can be integrated into your applications fd event polling. You
will need to implement ``memif_control_fd_update_t`` callback and pass
it to ``memif_socket_args.on_control_fd_update``. Now each time any file
descriptor belonging to that socket updates, ``on_control_fd_update``
callback is called. The file descriptor and event type is passed in
``memif_fd_event_t``. It also contains private context that is
associated with this fd. When event is polled on the fd you need to call
``memif_control_fd_handler`` and pass the event type and private context
associated with the fd.

Multi Threading
---------------

Connection establishment
~~~~~~~~~~~~~~~~~~~~~~~~

Memif sockets should not be handled in parallel. Instead each thread
should have it’s own socket. However the UNIX socket can be the same. In
case of non-listener socket, it’s straight forward, just create the
socket using the same path. In case of listener socket, the polling
should be done by single thread. > The socket becomes listener once a
Master interface is assigned to it.

Packet handling
~~~~~~~~~~~~~~~

Single queue must not be handled in parallel. Instead you can assign
queues to threads in such way that each queue is only assigned single
thread.

Shared Memory Layout
--------------------

Please refer to `DPDK MEMIF
documentation <http://doc.dpdk.org/guides/nics/memif.html>`__
``'Shared memory'`` section.

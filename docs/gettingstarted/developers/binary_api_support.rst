.. _binary_api_support:

.. toctree::

Binary API Support
==================

VPP provides a binary API scheme to allow a wide variety of client
codes to program data-plane tables. As of this writing, there are
hundreds of binary APIs.

Messages are defined in \*.api files. Today, there are about 80 api
files, with more arriving as folks add programmable features. The API
file compiler sources reside in src/tools/vppapigen.

From `src/vnet/interface.api
<https://docs.fd.io/vpp/18.11/de/d75/interface_8api.html>`_, here's a
typical request/response message definition:

.. code-block:: console

	autoreply define sw_interface_set_flags
	{
	  u32 client_index;
	  u32 context;
	  u32 sw_if_index;
	  /* 1 = up, 0 = down */
	  u8 admin_up_down;
	};

To a first approximation, the API compiler renders this definition
into
*vpp/build-root/install-vpp_debug-native/vpp/include/vnet/interface.api.h*
as follows:

.. code-block:: C

	/****** Message ID / handler enum ******/

	#ifdef vl_msg_id
	vl_msg_id(VL_API_SW_INTERFACE_SET_FLAGS, vl_api_sw_interface_set_flags_t_handler)
	vl_msg_id(VL_API_SW_INTERFACE_SET_FLAGS_REPLY, vl_api_sw_interface_set_flags_reply_t_handler)
	#endif      
	/****** Message names ******/

	#ifdef vl_msg_name
	vl_msg_name(vl_api_sw_interface_set_flags_t, 1)
	vl_msg_name(vl_api_sw_interface_set_flags_reply_t, 1)
	#endif      
	/****** Message name, crc list ******/

	#ifdef vl_msg_name_crc_list
	#define foreach_vl_msg_name_crc_interface \
	_(VL_API_SW_INTERFACE_SET_FLAGS, sw_interface_set_flags, f890584a) \
	_(VL_API_SW_INTERFACE_SET_FLAGS_REPLY, sw_interface_set_flags_reply, dfbf3afa) \
	#endif      
	/****** Typedefs *****/

	#ifdef vl_typedefs
	#ifndef defined_sw_interface_set_flags
	#define defined_sw_interface_set_flags
	typedef VL_API_PACKED(struct _vl_api_sw_interface_set_flags {
	    u16 _vl_msg_id;
	    u32 client_index;
	    u32 context;
	    u32 sw_if_index;
	    u8 admin_up_down;
	}) vl_api_sw_interface_set_flags_t;
	#endif

	#ifndef defined_sw_interface_set_flags_reply
	#define defined_sw_interface_set_flags_reply
	typedef VL_API_PACKED(struct _vl_api_sw_interface_set_flags_reply {
	    u16 _vl_msg_id;
	    u32 context;
	    i32 retval;
	}) vl_api_sw_interface_set_flags_reply_t;
	#endif
	...
	#endif /* vl_typedefs */

To change the admin state of an interface, a binary api client sends a
`vl_api_sw_interface_set_flags_t
<https://docs.fd.io/vpp/18.11/dc/da3/structvl__api__sw__interface__set__flags__t.html>`_
to VPP, which will respond with a
vl_api_sw_interface_set_flags_reply_t message.

Multiple layers of software, transport types, and shared libraries
implement a variety of features:

* API message allocation, tracing, pretty-printing, and replay.
* Message transport via global shared memory, pairwise/private shared memory, and sockets.
* Barrier synchronization of worker threads across thread-unsafe message handlers.

Correctly-coded message handlers know nothing about the transport used
to deliver messages to/from VPP. It's reasonably straighforward to use
multiple API message transport types simultaneously.

For historical reasons, binary api messages are (putatively) sent in
network byte order. As of this writing, we're seriously considering
whether that choice makes sense.

Message Allocation
__________________

Since binary API messages are always processed in order, we allocate
messages using a ring allocator whenever possible. This scheme is
extremely fast when compared with a traditional memory allocator, and
doesn't cause heap fragmentation. See `src/vlibmemory/memory_shared.c
<https://docs.fd.io/vpp/18.11/dd/d0d/memory__shared_8c.html>`_
`vl_msg_api_alloc_internal()
<https://docs.fd.io/vpp/18.11/dd/d0d/memory__shared_8c.html#ac6b6797850e1a53bc68b206e6b8413fb>`_.

Regardless of transport, binary api messages always follow a `msgbuf_t <https://docs.fd.io/vpp/18.11/d9/d65/structmsgbuf__.html>`_ header:

.. code-block:: C

	/** Message header structure */
	typedef struct msgbuf_
	{
	  svm_queue_t *q; /**< message allocated in this shmem ring  */
	  u32 data_len;                  /**< message length not including header  */
	  u32 gc_mark_timestamp;         /**< message garbage collector mark TS  */
	  u8 data[0];                    /**< actual message begins here  */
	} msgbuf_t;

This structure makes it easy to trace messages without having to
decode them - simply save data_len bytes - and allows
`vl_msg_api_free()
<https://docs.fd.io/vpp/18.11/d6/d1b/api__common_8h.html#aff61e777fe5df789121d8e78134867e6>`_
to rapidly dispose of message buffers:

.. code-block:: C

	void
	vl_msg_api_free (void *a)
	{
	  msgbuf_t *rv;
	  void *oldheap;
	  api_main_t *am = &api_main;

	  rv = (msgbuf_t *) (((u8 *) a) - offsetof (msgbuf_t, data));

	  /*
	   * Here's the beauty of the scheme.  Only one proc/thread has
	   * control of a given message buffer. To free a buffer, we just clear the
	   * queue field, and leave. No locks, no hits, no errors...
	   */
	  if (rv->q)
	    {
	      rv->q = 0;
	      rv->gc_mark_timestamp = 0;
	      <more code...>
	      return;
	    }
	  <more code...>
	}

Message Tracing and Replay
__________________________

It's extremely important that VPP can capture and replay sizeable
binary API traces. System-level issues involving hundreds of thousands
of API transactions can be re-run in a second or less. Partial replay
allows one to binary-search for the point where the wheels fall
off. One can add scaffolding to the data plane, to trigger when
complex conditions obtain.

With binary API trace, print, and replay, system-level bug reports of
the form "after 300,000 API transactions, the VPP data-plane stopped
forwarding traffic, FIX IT!" can be solved offline.

More often than not, one discovers that a control-plane client
misprograms the data plane after a long time or under complex
circumstances. Without direct evidence, "it's a data-plane problem!"

See `src/vlibmemory/memory_vlib::c
<https://docs.fd.io/vpp/18.11/dd/d3e/vpp__get__metrics_8c.html#a7c3855ed3c45b48ff92a7e881bfede73>`_
`vl_msg_api_process_file()
<https://docs.fd.io/vpp/18.11/d0/d5b/vlib__api__cli_8c.html#a60194e3e91c0dc6a75906ea06f4ec113>`_,
and `src/vlibapi/api_shared.c
<https://docs.fd.io/vpp/18.11/d6/dd1/api__shared_8c.html>`_. See also
the debug CLI command "api trace"

Client connection details
_________________________

Establishing a binary API connection to VPP from a C-language client is easy:

.. code-block:: C

	int
	connect_to_vpe (char *client_name, int client_message_queue_length)
	{
	  vat_main_t *vam = &vat_main;
	  api_main_t *am = &api_main;
	  if (vl_client_connect_to_vlib ("/vpe-api", client_name, 
	                                client_message_queue_length) < 0)
	    return -1;
	  /* Memorize vpp's binary API message input queue address */
	  vam->vl_input_queue = am->shmem_hdr->vl_input_queue;
	  /* And our client index */
	  vam->my_client_index = am->my_client_index;
	  return 0;
	}       

32 is a typical value for client_message_queue_length. VPP *cannot*
block when it needs to send an API message to a binary API client. The
VPP-side binary API message handlers are very fast. So, when sending
asynchronous messages, make sure to scrape the binary API rx ring with
some enthusiasm!

**Binary API message RX pthread**

Calling `vl_client_connect_to_vlib
<https://docs.fd.io/vpp/18.11/da/d25/memory__client_8h.html#a6654b42c91be33bfb6a4b4bfd2327920>`_
spins up a binary API message RX pthread:

.. code-block:: C

	static void *
	rx_thread_fn (void *arg)
	{
	  svm_queue_t *q;
	  memory_client_main_t *mm = &memory_client_main;
	  api_main_t *am = &api_main;
	  int i;

	  q = am->vl_input_queue;

	  /* So we can make the rx thread terminate cleanly */
	  if (setjmp (mm->rx_thread_jmpbuf) == 0)
	    {
	      mm->rx_thread_jmpbuf_valid = 1;
	      /*
	       * Find an unused slot in the per-cpu-mheaps array,
	       * and grab it for this thread. We need to be able to
	       * push/pop the thread heap without affecting other thread(s).
	       */
	      if (__os_thread_index == 0)
	        {
	          for (i = 0; i < ARRAY_LEN (clib_per_cpu_mheaps); i++)
	            {
	              if (clib_per_cpu_mheaps[i] == 0)
	                {
	                  /* Copy the main thread mheap pointer */
	                  clib_per_cpu_mheaps[i] = clib_per_cpu_mheaps[0];
	                  __os_thread_index = i;
	                  break;
	                }
	            }
	          ASSERT (__os_thread_index > 0);
	        }
	      while (1)
	        vl_msg_api_queue_handler (q);
	    }
	  pthread_exit (0);
	}

To handle the binary API message queue yourself, use
`vl_client_connect_to_vlib_no_rx_pthread
<https://docs.fd.io/vpp/18.11/da/d25/memory__client_8h.html#a11b9577297106c57c0783b96ab190c36>`_.

**Queue non-empty signalling**

vl_msg_api_queue_handler(...) uses mutex/condvar signalling to wake
up, process VPP -> client traffic, then sleep. VPP supplies a condvar
broadcast when the VPP -> client API message queue transitions from
empty to nonempty.

VPP checks its own binary API input queue at a very high rate. VPP
invokes message handlers in "process" context [aka cooperative
multitasking thread context] at a variable rate, depending on
data-plane packet processing requirements.

Client disconnection details
____________________________

To disconnect from VPP, call `vl_client_disconnect_from_vlib
<https://docs.fd.io/vpp/18.11/da/d25/memory__client_8h.html#a82c9ba6e7ead8362ae2175eefcf2fd12>`_. Please
arrange to call this function if the client application terminates
abnormally. VPP makes every effort to hold a decent funeral for dead
clients, but VPP can't guarantee to free leaked memory in the shared
binary API segment.

Sending binary API messages to VPP
__________________________________

The point of the exercise is to send binary API messages to VPP, and
to receive replies from VPP. Many VPP binary APIs comprise a client
request message, and a simple status reply. For example, to set the
admin status of an interface:

.. code-block:: C

	vl_api_sw_interface_set_flags_t *mp;
	mp = vl_msg_api_alloc (sizeof (*mp));
	memset (mp, 0, sizeof (*mp));
	mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_SW_INTERFACE_SET_FLAGS);
	mp->client_index = api_main.my_client_index;
	mp->sw_if_index = clib_host_to_net_u32 (<interface-sw-if-index>);
	vl_msg_api_send (api_main.shmem_hdr->vl_input_queue, (u8 *)mp);

Key points:

* Use `vl_msg_api_alloc <https://docs.fd.io/vpp/18.11/dc/d5a/memory__shared_8h.html#a109ff1e95ebb2c968d43c100c4a1c55a>`_ to allocate message buffers
* Allocated message buffers are not initialized, and must be presumed to contain trash.
* Don't forget to set the _vl_msg_id field!
* As of this writing, binary API message IDs and data are sent in network byte order
* The client-library global data structure `api_main <https://docs.fd.io/vpp/18.11/d6/dd1/api__shared_8c.html#af58e3e46b569573e9622b826b2f47a22>`_ keeps track of sufficient pointers and handles used to communicate with VPP

Receiving binary API messages from VPP
______________________________________

Unless you've made other arrangements (see
`vl_client_connect_to_vlib_no_rx_pthread
<https://docs.fd.io/vpp/18.11/da/d25/memory__client_8h.html#a11b9577297106c57c0783b96ab190c36>`_),
*messages are received on a separate rx pthread*. Synchronization with
the client application main thread is the responsibility of the
application!

Set up message handlers about as follows:

.. code-block:: C

	#define vl_typedefs         /* define message structures */
	#include <vpp/api/vpe_all_api_h.h>
	#undef vl_typedefs
	/* declare message handlers for each api */
	#define vl_endianfun                /* define message structures */
	#include <vpp/api/vpe_all_api_h.h>
	#undef vl_endianfun
	/* instantiate all the print functions we know about */
	#define vl_print(handle, ...)
	#define vl_printfun
	#include <vpp/api/vpe_all_api_h.h>
	#undef vl_printfun
	/* Define a list of all message that the client handles */
	#define foreach_vpe_api_reply_msg                            \
	   _(SW_INTERFACE_SET_FLAGS_REPLY, sw_interface_set_flags_reply)           
	   static clib_error_t *
	   my_api_hookup (vlib_main_t * vm)
	   {
	     api_main_t *am = &api_main;
	   #define _(N,n)                                                  \
	       vl_msg_api_set_handlers(VL_API_##N, #n,                     \
	                              vl_api_##n##_t_handler,              \
	                              vl_noop_handler,                     \
	                              vl_api_##n##_t_endian,               \
	                              vl_api_##n##_t_print,                \
	                              sizeof(vl_api_##n##_t), 1);
	     foreach_vpe_api_msg;
	   #undef _
	     return 0;
	    }

The key API used to establish message handlers is
`vl_msg_api_set_handlers
<https://docs.fd.io/vpp/18.11/d6/dd1/api__shared_8c.html#aa8a8e1f3876ec1a02f283c1862ecdb7a>`_
, which sets values in multiple parallel vectors in the `api_main_t
<https://docs.fd.io/vpp/18.11/dd/db2/structapi__main__t.html>`_
structure. As of this writing: not all vector element values can be
set through the API. You'll see sporadic API message registrations
followed by minor adjustments of this form:

.. code-block:: C

	/*
	 * Thread-safe API messages
	 */
	am->is_mp_safe[VL_API_IP_ADD_DEL_ROUTE] = 1;
	am->is_mp_safe[VL_API_GET_NODE_GRAPH] = 1;

API message numbering in plugins
--------------------------------

Binary API message numbering in plugins relies on vpp to issue a block 
of message-ID's for the plugin to use:

.. code-block:: C

        static clib_error_t *
        my_init (vlib_main_t * vm)
        {
          my_main_t *mm = &my_main;

          name = format (0, "myplugin_%08x%c", api_version, 0);

          /* Ask for a correctly-sized block of API message decode slots */
          mm->msg_id_base = vl_msg_api_get_msg_ids
            ((char *) name, VL_MSG_FIRST_AVAILABLE);

          }

Control-plane codes use the vl_client_get_first_plugin_msg_id (...) api
to recover the message ID block base:

.. code-block:: C

          /* Ask the vpp engine for the first assigned message-id */
          name = format (0, "myplugin_%08x%c", api_version, 0);
          sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

It's a fairly common error to forget to add msg_id_base when
registering message handlers, or when sending messages. Using macros
from .../src/vlibapi/api_helper_macros.h can automate the process, but
remember to #define REPLY_MSG_ID_BASE before #including the file:

.. code-block:: C

          #define REPLY_MSG_ID_BASE mm->msg_id_base
          #include <vlibapi/api_helper_macros.h>

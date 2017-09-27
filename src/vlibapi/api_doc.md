# Binary API support    {#api_doc}

VPP provides a binary API scheme to allow a wide variety of client codes to
program data-plane tables. As of this writing, there are hundreds of binary
APIs.

Messages are defined in `*.api` files. Today, there are about 50 api files,
with more arriving as folks add programmable features.  The API file compiler
sources reside in @ref src/tools/vppapigen.

From @ref src/vnet/interface.api, here's a typical request/response message
definition:

```{.c}
     autoreply define sw_interface_set_flags
     {
       u32 client_index;
       u32 context;
       u32 sw_if_index;
       /* 1 = up, 0 = down */
       u8 admin_up_down;
     };
```

To a first approximation, the API compiler renders this definition into
`build-root/.../vpp/include/vnet/interface.api.h` as follows:

```{.c}
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
    typedef VL_API_PACKED(struct _vl_api_sw_interface_set_flags {
        u16 _vl_msg_id;
        u32 client_index;
        u32 context;
        u32 sw_if_index;
        u8 admin_up_down;
    }) vl_api_sw_interface_set_flags_t;

    typedef VL_API_PACKED(struct _vl_api_sw_interface_set_flags_reply {
        u16 _vl_msg_id;
        u32 context;
        i32 retval;
    }) vl_api_sw_interface_set_flags_reply_t;

    ...
    #endif /* vl_typedefs */
```

To change the admin state of an interface, a binary api client sends a
@ref vl_api_sw_interface_set_flags_t to VPP, which will respond  with a
@ref vl_api_sw_interface_set_flags_reply_t message.

Multiple layers of software, transport types, and shared libraries
implement a variety of features:

* API message allocation, tracing, pretty-printing, and replay.
* Message transport via global shared memory, pairwise/private shared
  memory, and sockets.
* Barrier synchronization of worker threads across thread-unsafe
  message handlers.
    
Correctly-coded message handlers know nothing about the transport used to
deliver messages to/from VPP. It's reasonably straighforward to use multiple
API message transport types simultaneously.

For historical reasons, binary api messages are (putatively) sent in network
byte order. As of this writing, we're seriously considering whether that
choice makes sense.


## Message Allocation

Since binary API messages are always processed in order, we allocate messages
using a ring allocator whenever possible. This scheme is extremely fast when
compared with a traditional memory allocator, and doesn't cause heap
fragmentation. See
@ref src/vlibmemory/memory_shared.c @ref vl_msg_api_alloc_internal().

Regardless of transport, binary api messages always follow a @ref msgbuf_t
header:

```{.c}
    typedef struct msgbuf_
    {
      unix_shared_memory_queue_t *q;
      u32 data_len;
      u32 gc_mark_timestamp;
      u8 data[0];
    } msgbuf_t;
```

This structure makes it easy to trace messages without having to
decode them - simply save data_len bytes - and allows
@ref vl_msg_api_free() to rapidly dispose of message buffers:

```{.c}
    void
    vl_msg_api_free (void *a)
    {
      msgbuf_t *rv;
      api_main_t *am = &api_main;

      rv = (msgbuf_t *) (((u8 *) a) - offsetof (msgbuf_t, data));

      /*
       * Here's the beauty of the scheme.  Only one proc/thread has
       * control of a given message buffer. To free a buffer, we just 
       * clear the queue field, and leave. No locks, no hits, no errors...
       */
      if (rv->q)
        {
          rv->q = 0;
          rv->gc_mark_timestamp = 0;
          return;
        }
      <snip>
    }
```

## Message Tracing and Replay

It's extremely important that VPP can capture and replay sizeable binary API
traces. System-level issues involving hundreds of thousands of API
transactions can be re-run in a second or less. Partial replay allows one to
binary-search for the point where the wheels fall off. One can add scaffolding
to the data plane, to trigger when complex conditions obtain.

With binary API trace, print, and replay, system-level bug reports of the form
"after 300,000 API transactions, the VPP data-plane stopped forwarding
traffic, FIX IT!" can be solved offline.

More often than not, one discovers that a control-plane client
misprograms the data plane after a long time or under complex
circumstances. Without direct evidence, "it's a data-plane problem!"

See @ref src/vlibmemory/memory_vlib.c @ref vl_msg_api_process_file(),
and @ref src/vlibapi/api_shared.c. See also the debug CLI command "api trace"

## Client connection details

Establishing a binary API connection to VPP from a C-language client
is easy:

```{.c}
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
```

32 is a typical value for client_message_queue_length. VPP cannot
block when it needs to send an API message to a binary API client, and
the VPP-side binary API message handlers are very fast. When sending
asynchronous messages, make sure to scrape the binary API rx ring with
some enthusiasm.

### binary API message RX pthread

Calling @ref vl_client_connect_to_vlib spins up a binary API message RX
pthread:

```{.c}
        static void *
        rx_thread_fn (void *arg)
        {
          unix_shared_memory_queue_t *q;
          memory_client_main_t *mm = &memory_client_main;
          api_main_t *am = &api_main;

          q = am->vl_input_queue;

          /* So we can make the rx thread terminate cleanly */
          if (setjmp (mm->rx_thread_jmpbuf) == 0)
            {
              mm->rx_thread_jmpbuf_valid = 1;
              while (1)
        	{
        	  vl_msg_api_queue_handler (q);
        	}
            }
          pthread_exit (0);
        }       
```

To handle the binary API message queue yourself, use
@ref vl_client_connect_to_vlib_no_rx_pthread.

In turn, vl_msg_api_queue_handler(...) uses mutex/condvar signalling
to wake up, process VPP -> client traffic, then sleep. VPP supplies a
condvar broadcast when the VPP -> client API message queue transitions
from empty to nonempty.

VPP checks its own binary API input queue at a very high rate.  VPP
invokes message handlers in "process" context [aka cooperative
multitasking thread context] at a variable rate, depending on
data-plane packet processing requirements.

## Client disconnection details

To disconnect from VPP, call @ref vl_client_disconnect_from_vlib.
Please arrange to call this function if the client application
terminates abnormally. VPP makes every effort to hold a decent funeral
for dead clients, but VPP can't guarantee to free leaked memory in the
shared binary API segment.

## Sending binary API messages to VPP

The point of the exercise is to send binary API messages to VPP, and
to receive replies from VPP. Many VPP binary APIs comprise a client
request message, and a simple status reply. For example, to
set the admin status of an interface, one codes:

```{.c}
    vl_api_sw_interface_set_flags_t *mp;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_SW_INTERFACE_SET_FLAGS);
    mp->client_index = api_main.my_client_index;
    mp->sw_if_index = clib_host_to_net_u32 (<interface-sw-if-index>);
    vl_msg_api_send (api_main.shmem_hdr->vl_input_queue, (u8 *)mp);
```

Key points:

* Use @ref vl_msg_api_alloc to allocate message buffers

* Allocated message buffers are not initialized, and must be presumed
  to contain trash.

* Don't forget to set the _vl_msg_id field!

* As of this writing, binary API message IDs and data are sent in
  network byte order

* The client-library global data structure @ref api_main keeps track
  of sufficient pointers and handles used to communicate with VPP

## Receiving binary API messages from VPP

Unless you've made other arrangements (see @ref
vl_client_connect_to_vlib_no_rx_pthread), *messages are received on a
separate rx pthread*. Synchronization with the client application main
thread is the responsibility of the application!

Set up message handlers about as follows:

```{.c}
    #define vl_typedefs		/* define message structures */
    #include <vpp/api/vpe_all_api_h.h>
    #undef vl_typedefs

    /* declare message handlers for each api */

    #define vl_endianfun		/* define message structures */
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
```

The key API used to establish message handlers is @ref
vl_msg_api_set_handlers , which sets values in multiple parallel
vectors in the @ref api_main_t structure. As of this writing: not all
vector element values can be set through the API. You'll see sporadic
API message registrations followed by minor adjustments of this form:

```{.c}
    /*
     * Thread-safe API messages
     */
    am->is_mp_safe[VL_API_IP_ADD_DEL_ROUTE] = 1;
    am->is_mp_safe[VL_API_GET_NODE_GRAPH] = 1;
```




              

















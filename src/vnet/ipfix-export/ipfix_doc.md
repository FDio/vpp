# IPFIX support {#ipfix}

VPP includes a high-performance IPFIX record exporter. This note
explains how to use the internal APIs to export IPFIX data, and how to
configure and send the required IPFIX templates.

As you'll see, a bit of typing is required. 

## First: create an ipfix "report"

Include the flow report header file, fill out a @ref
vnet_flow_report_add_del_args_t structure, and call vnet_flow_report_add_del.

```{.c}
   #include <vnet/ipfix-export/flow_report.h>
   /* Defined in flow_report.h, of interest when constructing reports */

   /* ipfix field definitions for a particular report */
   typedef struct
   {
     u32 info_element;
     u32 size;
   } ipfix_report_element_t;

   /* Report add/del argument structure */
   typedef struct
   {
     /* Callback to flush current ipfix packet / frame */
     vnet_flow_data_callback_t *flow_data_callback;

     /* Callback to build the template packet rewrite string */
     vnet_flow_rewrite_callback_t *rewrite_callback;

     /* List of ipfix elements in the report */
     ipfix_report_element_t *report_elements;
     u32 n_report_elements;
     /* Kept in flow report, used e.g. by flow classifier */
     opaque_t opaque;
     /* Add / delete a report */
     int is_add;
     /* Ipfix "domain-ID", see RFC, set as desired */
     u32 domain_id;
     /* ipfix packet source port, often set to UDP_DST_PORT_ipfix */
     u16 src_port;
     /* Set by ipfix infra, needed to send data packets */
     u32 *stream_indexp;
   } vnet_flow_report_add_del_args_t;

   /* Private header file contents */

   /* Report ipfix element definition */
   #define foreach_simple_report_ipfix_element     \
   _(sourceIPv4Address, 4)                         \
   _(destinationIPv4Address, 4)                    \
   _(sourceTransportPort, 2)                       \
   _(destinationTransportPort, 2)                  \
   _(protocolIdentifier, 1)                        \
   _(flowStartMicroseconds, 8)                     \
   _(flowEndMicroseconds, 8)

   static ipfix_report_element_t simple_report_elements[] = {
   #define _(a,b) {a,b},
     foreach_simple_report_ipfix_element
   #undef _
   };

   typedef struct
   {
     /** Buffers and frames, per thread */
     vlib_buffer_t **buffers_by_thread;
     vlib_frame_t **frames_by_thread;
     u32 *next_record_offset_by_thread;

     /** Template ID's */
     u16 *template_ids;

     /** Time reference pair */
     u64 usec_time_0;
     f64 vlib_time_0;

     /** Stream index */
     u32 stream_index;

     /* Convenience */
     flow_report_main_t *flow_report_main;
     vlib_main_t *vlib_main;
     vnet_main_t *vnet_main;
   } my_logging_main_t;
   
   extern my_logging_main_t my_logging_main;

   ...

   /* Recitations */
   flow_report_main_t *frm = &flow_report_main;
   my_logging_main_t *mlm = &my_logging_main;
   vnet_flow_report_add_del_args_t a;
   int rv;
   u16 template_id;

   ... 

   /* Init function: set up time reference pair */
   mlm->vlib_time_0 = vlib_time_now (vm);
   mlm->milisecond_time_0 = unix_time_now_nsec () * 1e-6;

   ...

   /* Create a report */
   memset (&a, 0, sizeof (a));
   a.is_add = 1 /* to enable the report */;
   a.domain_id = 1 /* pick a domain ID */;
   a.src_port = UDP_DST_PORT_ipfix /* src port for reports */;

   /* Use the generic template packet rewrite string generator */
   a.rewrite_callback = vnet_flow_rewrite_generic_callback;

   /* Supply a list of ipfix report elements */
   a.report_elements = simple_report_elements;
   a.n_report_elements = ARRAY_LEN (simple_report_elements);

   /* Pointer to the ipfix stream index, set by the report infra */
   a.stream_indexp = &mlm->stream_index;
   a.flow_data_callback = my_flow_data_callback;

   /* Create the report */
   rv = vnet_flow_report_add_del (frm, &a, &template_id);
   if (rv) 
     oops...

   /* Save the template-ID for later use */
   mlm->template_id = template_id;

```

Several things are worth describing in more detail.

### vnet_flow_rewrite_generic_callback programming

This generic callback helps build ipfix template packets.  When
registering an ipfix report, pass an (array, count)
of ipfix elements as shown above. 

### my_flow_data_callback

The ipfix flow export infrastructure calls this callback to flush the
current ipfix packet; to make sure that ipfix data is not retained for
an unreasonably long period of time.

We typically code it as shown below, to call an application-specific
function with (uninteresting arguments), and "do_flush = 1":


```{.c}

      vlib_frame_t *my_flow_data_callback
                   (flow_report_main_t * frm,
	           flow_report_t * fr,
		   vlib_frame_t * f,
		   u32 * to_next, u32 node_index)
      { 

         my_buffer_flow_record (0, ... , 0, 1 /* do_flush */);
         return f;
      }
```

### my_flow_data_header

This function creates the packet header for an ipfix data packet

```{.c}

   static inline void
   my_flow_report_header (flow_report_main_t * frm,
			  vlib_buffer_t * b0, u32 * offset)
   {
      my_logging_main_t *mlm = &my_logging_main;
      flow_report_stream_t *stream;
      ip4_ipfix_template_packet_t *tp;
      ipfix_message_header_t *h = 0;


      ipfix_set_header_t *s = 0;
      ip4_header_t *ip;
      udp_header_t *udp;

      stream = &frm->streams[mlm->stream_index];

      b0->current_data = 0;
      b0->current_length = sizeof (*ip) + sizeof (*udp) + sizeof (*h) +
        sizeof (*s);
      b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;
      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) & tp->ip4;
      udp = (udp_header_t *) (ip + 1);
      h = (ipfix_message_header_t *) (udp + 1);
      s = (ipfix_set_header_t *) (h + 1);

      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;
      ip->flags_and_fragment_offset = 0;
      ip->src_address.as_u32 = frm->src_address.as_u32;
      ip->dst_address.as_u32 = frm->ipfix_collector.as_u32;
      udp->src_port = clib_host_to_net_u16 (stream->src_port);
      udp->dst_port = clib_host_to_net_u16 (frm->collector_port);
      udp->checksum = 0;

      h->export_time = clib_host_to_net_u32 ((u32)
            				 (((f64) frm->unix_time_0) +
               				  (vlib_time_now (frm->vlib_main) -
               				   frm->vlib_time_0)));
         h->sequence_number = clib_host_to_net_u32 (stream->sequence_number++);
         h->domain_id = clib_host_to_net_u32 (stream->domain_id);

         *offset = (u32) (((u8 *) (s + 1)) - (u8 *) tp);
   }
   ```

   ### fixup and transmit a flow record

   ```{.c}
      
      static inline void
      my_send_ipfix_pkt (flow_report_main_t * frm,
           		 vlib_frame_t * f, vlib_buffer_t * b0, u16 template_id)
      {
        ip4_ipfix_template_packet_t *tp;
        ipfix_message_header_t *h = 0;
        ipfix_set_header_t *s = 0;
        ip4_header_t *ip;
        udp_header_t *udp;
        vlib_main_t *vm = frm->vlib_main;

        tp = vlib_buffer_get_current (b0);
        ip = (ip4_header_t *) & tp->ip4;
        udp = (udp_header_t *) (ip + 1);
        h = (ipfix_message_header_t *) (udp + 1);
        s = (ipfix_set_header_t *) (h + 1);

        s->set_id_length = ipfix_set_id_length (template_id,
      					  b0->current_length -
      					  (sizeof (*ip) + sizeof (*udp) +
      					   sizeof (*h)));
        h->version_length = version_length (b0->current_length -
      				      (sizeof (*ip) + sizeof (*udp)));

        ip->length = clib_host_to_net_u16 (b0->current_length);
        ip->checksum = ip4_header_checksum (ip);
        udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

        if (frm->udp_checksum)
          {
            udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
            if (udp->checksum == 0)
      	udp->checksum = 0xffff;
          }

        ASSERT (ip->checksum == ip4_header_checksum (ip));

        vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
      }  
   ```

   ### my_buffer_flow_record

   This is the key routine which paints individual flow records into
   an ipfix packet under construction. It's pretty straightforward
   (albeit stateful) vpp data-plane code. The code shown below is
   thread-safe by construction.

   ```{.c}
   static inline void
   my_buffer_flow_record_internal (my_flow_record_t * rp, int do_flush,
                                       u32 thread_index)
   {
     vlib_main_t *vm = vlib_mains[thread_index];
     my_logging_main_t *mlm = &jvp_ipfix_main;
     flow_report_main_t *frm = &flow_report_main;
     vlib_frame_t *f;
     vlib_buffer_t *b0 = 0;
     u32 bi0 = ~0;
     u32 offset;

     b0 = mlm->buffers_by_thread[thread_index];

     if (PREDICT_FALSE (b0 == 0))
       {
         if (do_flush)
   	return;

         if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
   	{
   	  clib_warning ("can't allocate ipfix data buffer");
   	  return;
   	}

         b0 = vlib_get_buffer (vm, bi0);
         VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
         offset = 0;
         mlm->buffers_by_thread[thread_index] = b0;
       }
     else
       {
         bi0 = vlib_get_buffer_index (vm, b0);
         offset = mlm->next_record_offset_by_thread[thread_index];
       }

     f = mlm->frames_by_thread[thread_index];
     if (PREDICT_FALSE (f == 0))
       {
         u32 *to_next;
         f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
         mlm->frames_by_thread[thread_index] = f;
         to_next = vlib_frame_vector_args (f);
         to_next[0] = bi0;
         f->n_vectors = 1;
         mlm->frames_by_thread[thread_index] = f;
       }

     if (PREDICT_FALSE (offset == 0))
       my_flow_report_header (frm, b0, &offset);

     if (PREDICT_TRUE (do_flush == 0))
       {
         /* Paint the new ipfix data record into the buffer */
         clib_memcpy (b0->data + offset, rp, sizeof (*rp));
         offset += sizeof (*rp);
         b0->current_length += sizeof (*rp);
       }

     if (PREDICT_FALSE (do_flush || (offset + sizeof (*rp)) > frm->path_mtu))
       {
         /* Nothing to send? */
         if (offset == 0)
   	return;

         send_ipfix_pkt (frm, f, b0, mlm->template_ids[0]);
         mlm->buffers_by_thread[thread_index] = 0;
         mlm->frames_by_thread[thread_index] = 0;
         offset = 0;
       }
     mlm->next_record_offset_by_thread[thread_index] = offset;
   }  

   static void
   my_buffer_flow_record (my_flow_record_t * rp, int do_flush)
   {
     u32 thread_index = vlib_get_thread_index();
     my_buffer_flow_record_internal (rp, do_flush, thread_index);
   }  

```

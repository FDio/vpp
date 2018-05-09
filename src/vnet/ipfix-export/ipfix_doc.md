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

   typedef struct
   {
     vnet_flow_data_callback_t *flow_data_callback;
     vnet_flow_rewrite_callback_t *rewrite_callback;
     opaque_t opaque;
     int is_add;
     u32 domain_id;
     u16 src_port;
   } vnet_flow_report_add_del_args_t;

   ...

   flow_report_main_t *frm = &flow_report_main;
   vnet_flow_report_add_del_args_t a;
   int rv;
   u16 template_id;

   ... 

   /* Set up time reference pair */
   mlm->vlib_time_0 = vlib_time_now (vm);
   mlm->milisecond_time_0 = unix_time_now_nsec () * 1e-6;

   ...

   memset (&a, 0, sizeof (a));
   a.is_add = 1 /* to enable the report */;
   a.domain_id = 1 /* pick a domain ID */;
   a.src_port = UDP_DST_PORT_ipfix /* src port for reports */;
   a.rewrite_callback = my_template_packet_rewrite_callback;
   a.flow_data_callback = my_flow_data_callback;

   /* Create the report */
   rv = vnet_flow_report_add_del (frm, &a, &template_id);
   if (rv) 
     oops...

   /* Save the template-ID for later use */
   mlm->template_id = template_id;

```

Several functions are worth describing in detail.

### template packet rewrite callback function

This callback helps build ipfix template packets when required. We
should reduce the amount of cut-'n-paste coding, since only a fraction
of the code has anything to do with the specific ipfix template we're
trying to build.

```{.c}
   u8 *
   my_template_packet_rewrite_callback (flow_report_main_t * frm,
                                        flow_report_t * fr,
				        ip4_address_t * collector_address,
				        ip4_address_t * src_address,
				        u16 collector_port)
   {
       my_logging_main_t *mlm = &my_logging_main; /* typical */
       ip4_header_t *ip;
       udp_header_t *udp;
       ipfix_message_header_t *h;
       ipfix_set_header_t *s;
       ipfix_template_header_t *t;
       ipfix_field_specifier_t *f;
       ipfix_field_specifier_t *first_field;
       u8 *rewrite = 0;
       ip4_ipfix_template_packet_t *tp;
       u32 field_count = 0;
       flow_report_stream_t *stream;

       stream = &frm->streams[fr->stream_index];

       field_count = number_of_fields_to_export;

       /* allocate rewrite space */
       vec_validate_aligned (rewrite,
  			sizeof (ip4_ipfix_template_packet_t)
			+ field_count * sizeof (ipfix_field_specifier_t) - 1,
			CLIB_CACHE_LINE_BYTES);

       /* create the packet rewrite string */
       tp = (ip4_ipfix_template_packet_t *) rewrite;
       ip = (ip4_header_t *) & tp->ip4;
       udp = (udp_header_t *) (ip + 1);
       h = (ipfix_message_header_t *) (udp + 1);
       s = (ipfix_set_header_t *) (h + 1);
       t = (ipfix_template_header_t *) (s + 1);
       first_field = f = (ipfix_field_specifier_t *) (t + 1);

       ip->ip_version_and_header_length = 0x45;
       ip->ttl = 254;
       ip->protocol = IP_PROTOCOL_UDP;
       ip->src_address.as_u32 = src_address->as_u32;
       ip->dst_address.as_u32 = collector_address->as_u32;
       udp->src_port = clib_host_to_net_u16 (stream->src_port);
       udp->dst_port = clib_host_to_net_u16 (collector_port);
       udp->length = clib_host_to_net_u16 (vec_len (rewrite) - sizeof (*ip));

       /* FIXUP LATER: message header export_time */
       h->domain_id = clib_host_to_net_u32 (stream->domain_id);

       /* 
        * Add your favorite info elements to the template. See
        * .../src/vnet/ipfix-export/ipfix_info_elements.h
        *
        * Highly advisable to make sure field count is correct!
        */

       f->e_id_length = ipfix_e_id_length (0, sourceIPv6Address, 16);
       f++;
       f->e_id_length = ipfix_e_id_length (0, postNATSourceIPv4Address, 4);
       f++;

       /* Back to the template packet... */
       ip = (ip4_header_t *) & tp->ip4;
       udp = (udp_header_t *) (ip + 1);

       ASSERT (f - first_field);
       /* Field count in this template */
       t->id_count = ipfix_id_count (fr->template_id, f - first_field);

       /* set length in octets */
       s->set_id_length =
         ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

       /* message length in octets */
       h->version_length = version_length ((u8 *) f - (u8 *) h);

       ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
       ip->checksum = ip4_header_checksum (ip);

       return rewrite;
   }      
```

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
      snat_ipfix_logging_main_t *mlm = &my_logging_main;
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
(albeit stateful) vpp data-plane code.


```{.c}
   static void
   my_buffer_flow_record (u32 datum0, u32 datum1, ..., int do_flush)
   {
     my_logging_main_t *mlm = &my_logging_main;
     flow_report_main_t *frm = &flow_report_main;
     vlib_frame_t *f;
     vlib_buffer_t *b0 = 0;
     u32 bi0 = ~0;
     u32 offset;
     vlib_main_t *vm = frm->vlib_main;
     u64 now;
     vlib_buffer_free_list_t *fl;
     my_flow_record_t my_flow_record;

     if (!mlm->enabled)
       return;

     now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
     now += mlm->milisecond_time_0;

     /* 
      * (maybe) set up a packed structure from datum0...datumN 
      * Otherwise, paint directly into the buffer below...
      */
     my_flow_record.xxx = datum0;
     my_flow_record.yyy = datum1;


     b0 = mlm->my_data_buffer;

     if (PREDICT_FALSE (b0 == 0))
       {
         if (do_flush)
   	return;

         if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
   	{
   	  clib_warning ("can't allocate ipfix data buffer");
   	  return;
   	}

         b0 = mlm->my_data_buffer = vlib_get_buffer (vm, bi0);
         fl =
   	vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
         vlib_buffer_init_for_free_list (b0, fl);
         VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
         offset = 0;
       }
     else
       {
         bi0 = vlib_get_buffer_index (vm, b0);
         offset = mlm->my_next_record_offset;
       }

     f = mlm->my_ipfix_frame;
     if (PREDICT_FALSE (f == 0))
       {
         u32 *to_next;
         f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
         mlm->my_ipfix_frame = f;
         to_next = vlib_frame_vector_args (f);
         to_next[0] = bi0;
         f->n_vectors = 1;
       }

     if (PREDICT_FALSE (offset == 0))
       my_flow_report_header (frm, b0, &offset);

     if (PREDICT_TRUE (do_flush == 0))
       {
         /* paint time stamp into buffer */
         clib_memcpy (b0->data + offset, &time_stamp, sizeof (time_stamp));
         offset += sizeof (time_stamp);

         /* Paint the new ipfix data record into the buffer */
         clib_memcpy (b0->data + offset, &my_flow_record, 
                     sizeof (my_flow_record));
         offset += sizeof (my_flow_record);
         b0->current_length += sizeof(my_flow_record);
       }

     if (PREDICT_FALSE
         (do_flush || (offset + sizeof (my_flow_record)) > frm->path_mtu))
       {
         my_send_ipfix_pkt (frm, f, b0, mlm->template_id);
         mlm->my_ipfix_frame = 0;
         mlm->my_data_buffer = 0;
         offset = 0;
       }
     mlm->next_record_offset = offset;
   }
```

/*
 * node.c - ipv4 ipfix-per-packet graph node
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <flowperpkt/flowperpkt.h>

/**
 * @file ipv4 flow record generator graph node
 */

typedef struct
{
  /** interface handle */
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u32 src_address;
  u32 dst_address;
  /** ToS bits */
  u8 tos;
  /** packet timestamp */
  u64 timestamp;
  /** size of the buffer */
  u16 buffer_size;
} flowperpkt_ipv4_trace_t;

/* packet trace format function */
static u8 *
format_flowperpkt_ipv4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowperpkt_ipv4_trace_t *t = va_arg (*args, flowperpkt_ipv4_trace_t *);

  s = format (s,
	      "FLOWPERPKT-V4: rx_sw_if_index %d, tx_sw_if_index %d, src %U dst %U tos %0x2, timestamp %lld, size %d",
	      t->rx_sw_if_index, t->tx_sw_if_index,
	      format_ip4_address, &t->src_address,
	      format_ip4_address, &t->dst_address,
	      t->tos, t->timestamp, t->buffer_size);
  return s;
}

vlib_node_registration_t flowperpkt_ipv4_node;

/* No counters at the moment */
#define foreach_flowperpkt_ipv4_error

typedef enum
{
#define _(sym,str) FLOWPERPKT_ERROR_##sym,
  foreach_flowperpkt_ipv4_error
#undef _
    FLOWPERPKT_N_ERROR,
} flowperpkt_ipv4_error_t;

static char *flowperpkt_ipv4_error_strings[] = {
#define _(sym,string) string,
  foreach_flowperpkt_ipv4_error
#undef _
};

typedef enum
{
  FLOWPERPKT_IPV4_NEXT_DROP,
  FLOWPERPKT_IPV4_NEXT_LOOKUP,
  FLOWPERPKT_IPV4_N_NEXT,
} flowperpkt_ipv4_next_t;

/**
 * @brief add an entry to the flow record under construction
 * @param vm vlib_main_t * current worker thread main structure pointer
 * @param fm flowperpkt_main_t * flow-per-packet main structure pointer
 * @param sw_if_index u32 interface handle
 * @param tos u8 ToS bits from the packet
 * @param timestamp u64 timestamp, nanoseconds since 1/1/70
 * @param length u16 ip length of the packet
 * @param do_flush int 1 = flush all cached records, 0 = construct a record
 */

static inline void
add_to_flow_record_ipv4 (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 flowperpkt_main_t * fm,
			 u32 rx_sw_if_index, u32 tx_sw_if_index,
			 u32 src_address, u32 dst_address,
			 u8 tos, u64 timestamp, u16 length, int do_flush)
{
  u32 my_thread_index = vm->thread_index;
  flow_report_main_t *frm = &flow_report_main;
  ip4_header_t *ip;
  udp_header_t *udp;
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  vlib_frame_t *f;
  vlib_buffer_t *b0;
  u16 offset;
  u32 bi0;
  vlib_buffer_free_list_t *fl;

  /* Find or allocate a buffer */
  b0 = fm->ipv4_buffers_per_worker[my_thread_index];

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == 0))
    {
      /* Nothing to flush */
      if (do_flush)
	return;

      /* $$$$ drop counter? */
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	return;

      /* Initialize the buffer */
      b0 = fm->ipv4_buffers_per_worker[my_thread_index] =
	vlib_get_buffer (vm, bi0);
      fl =
	vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (b0, fl);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      /* use the current buffer */
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = fm->ipv4_next_record_offset_per_worker[my_thread_index];
    }

  /* Find or allocate a frame */
  f = fm->ipv4_frames_per_worker[my_thread_index];
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      fm->ipv4_frames_per_worker[my_thread_index] = f;

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  /* Fresh packet, construct header */
  if (PREDICT_FALSE (offset == 0))
    {
      flow_report_stream_t *stream;

      stream = &frm->streams[0];

      b0->current_data = 0;
      b0->current_length = sizeof (*ip) + sizeof (*udp) + sizeof (*h) +
	sizeof (*s);
      b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VLIB_BUFFER_FLOW_REPORT);
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
      udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
      udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
      udp->checksum = 0;

      /* FIXUP: message header export_time */
      h->export_time = (u32)
	(((f64) frm->unix_time_0) +
	 (vlib_time_now (frm->vlib_main) - frm->vlib_time_0));
      h->export_time = clib_host_to_net_u32 (h->export_time);
      h->domain_id = clib_host_to_net_u32 (stream->domain_id);

      /* FIXUP: message header sequence_number */
      h->sequence_number = stream->sequence_number++;
      h->sequence_number = clib_host_to_net_u32 (h->sequence_number);

      offset = (u32) (((u8 *) (s + 1)) - (u8 *) tp);
    }

  /* Add data, unless we're flushing stale data */
  if (PREDICT_TRUE (do_flush == 0))
    {

      /* Add data */
      /* Ingress interface */
      {
	u32 ingress_interface = clib_host_to_net_u32 (rx_sw_if_index);
	clib_memcpy (b0->data + offset, &ingress_interface,
		     sizeof (ingress_interface));
	offset += sizeof (ingress_interface);
      }
      /* Egress interface */
      {
	u32 egress_interface = clib_host_to_net_u32 (tx_sw_if_index);
	clib_memcpy (b0->data + offset, &egress_interface,
		     sizeof (egress_interface));
	offset += sizeof (egress_interface);
      }
      /* ip4 src address */
      {
	clib_memcpy (b0->data + offset, &src_address, sizeof (src_address));
	offset += sizeof (src_address);
      }
      /* ip4 dst address */
      {
	clib_memcpy (b0->data + offset, &dst_address, sizeof (dst_address));
	offset += sizeof (dst_address);
      }

      /* ToS */
      b0->data[offset++] = tos;

      /* Timestamp */
      clib_memcpy (b0->data + offset, &timestamp, sizeof (f64));
      offset += sizeof (f64);

      /* pkt size */
      {
	u16 pkt_size = clib_host_to_net_u16 (length);
	clib_memcpy (b0->data + offset, &pkt_size, sizeof (pkt_size));
	offset += sizeof (pkt_size);
      }

      b0->current_length +=
	/* sw_if_index + tos + timestamp + length = 15 */
	4 * sizeof (u32) + sizeof (u8) + sizeof (f64) + sizeof (u16);

    }
  /* Time to flush the buffer? */
  if (PREDICT_FALSE
      (do_flush || (offset + 4 * sizeof (u32) + sizeof (u8)
		    + sizeof (f64) + sizeof (u16)) > frm->path_mtu))
    {
      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) & tp->ip4;
      udp = (udp_header_t *) (ip + 1);
      h = (ipfix_message_header_t *) (udp + 1);
      s = (ipfix_set_header_t *) (h + 1);

      s->set_id_length = ipfix_set_id_length (fm->ipv4_report_id,
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
	  /* RFC 7011 section 10.3.2. */
	  udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
	  if (udp->checksum == 0)
	    udp->checksum = 0xffff;
	}

      ASSERT (ip->checksum == ip4_header_checksum (ip));

      if (PREDICT_FALSE (vlib_get_trace_count (vm, node) > 0))
	{
	  vlib_trace_buffer (vm, node, FLOWPERPKT_IPV4_NEXT_LOOKUP, b0,
			     0 /* follow chain */ );
	  flowperpkt_ipv4_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t->tx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  t->src_address = 0;
	  t->dst_address = 0;
	  t->tos = 0;
	  t->timestamp = 0;
	  t->buffer_size = b0->current_length;
	}

      vlib_put_frame_to_node (vm, ip4_lookup_node.index,
			      fm->ipv4_frames_per_worker[my_thread_index]);
      fm->ipv4_frames_per_worker[my_thread_index] = 0;
      fm->ipv4_buffers_per_worker[my_thread_index] = 0;
      offset = 0;
    }

  fm->ipv4_next_record_offset_per_worker[my_thread_index] = offset;
}

void
flowperpkt_flush_callback_ipv4 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_ipv4_node.index);

  add_to_flow_record_ipv4 (vm, node, fm, 0 /* rx_sw_if_index */ ,
			   0 /* tx_sw_if_index */ ,
			   0 /* src_address */ ,
			   0 /* dst_address */ ,
			   0 /* ToS */ ,
			   0ULL /* timestamp */ ,
			   0 /* length */ ,
			   1 /* do_flush */ );
}


static uword
flowperpkt_ipv4_node_fn (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  flowperpkt_ipv4_next_t next_index;
  flowperpkt_main_t *fm = &flowperpkt_main;
  u64 now;

  now = (u64) ((vlib_time_now (vm) - fm->vlib_time_0) * 1e9);
  now += fm->nanosecond_time_0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = FLOWPERPKT_IPV4_NEXT_DROP;
	  u32 next1 = FLOWPERPKT_IPV4_NEXT_DROP;
	  ip4_header_t *ip0, *ip1;
	  u16 len0, len1;
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  vnet_feature_next (vnet_buffer (b0)->sw_if_index[VLIB_TX],
			     &next0, b0);
	  vnet_feature_next (vnet_buffer (b1)->sw_if_index[VLIB_TX],
			     &next1, b1);

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  vnet_buffer (b0)->ip.save_rewrite_length);

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record_ipv4 (vm, node, fm,
				     vnet_buffer (b0)->sw_if_index[VLIB_RX],
				     vnet_buffer (b0)->sw_if_index[VLIB_TX],
				     ip0->src_address.as_u32,
				     ip0->dst_address.as_u32,
				     ip0->tos, now, len0, 0 /* flush */ );

	  ip1 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
				  vnet_buffer (b1)->ip.save_rewrite_length);
	  len1 = vlib_buffer_length_in_chain (vm, b1);

	  if (PREDICT_TRUE ((b1->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record_ipv4 (vm, node, fm,
				     vnet_buffer (b1)->sw_if_index[VLIB_RX],
				     vnet_buffer (b1)->sw_if_index[VLIB_TX],
				     ip1->src_address.as_u32,
				     ip1->dst_address.as_u32,
				     ip1->tos, now, len1, 0 /* flush */ );

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  flowperpkt_ipv4_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
		  t->tx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
		  t->src_address = ip0->src_address.as_u32;
		  t->dst_address = ip0->dst_address.as_u32;
		  t->tos = ip0->tos;
		  t->timestamp = now;
		  t->buffer_size = len0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  flowperpkt_ipv4_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->rx_sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
		  t->tx_sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
		  t->src_address = ip1->src_address.as_u32;
		  t->dst_address = ip1->dst_address.as_u32;
		  t->tos = ip1->tos;
		  t->timestamp = now;
		  t->buffer_size = len1;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = FLOWPERPKT_IPV4_NEXT_DROP;
	  ip4_header_t *ip0;
	  u16 len0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_feature_next (vnet_buffer (b0)->sw_if_index[VLIB_TX],
			     &next0, b0);

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  vnet_buffer (b0)->ip.save_rewrite_length);
	  /*
	   * egressInterface, TLV type 14, u32
	   * ipClassOfService, TLV type 5, u8
	   * flowStartNanoseconds, TLV type 156, dateTimeNanoseconds (f64)
	   *   Implementation: f64 nanoseconds since VPP started
	   * dataLinkFrameSize, TLV type 312, u16
	   */
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record_ipv4 (vm, node, fm,
				     vnet_buffer (b0)->sw_if_index[VLIB_RX],
				     vnet_buffer (b0)->sw_if_index[VLIB_TX],
				     ip0->src_address.as_u32,
				     ip0->dst_address.as_u32,
				     ip0->tos, now, len0, 0 /* flush */ );

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      flowperpkt_ipv4_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->tx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->src_address = ip0->src_address.as_u32;
	      t->dst_address = ip0->dst_address.as_u32;
	      t->tos = ip0->tos;
	      t->timestamp = now;
	      t->buffer_size = len0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/**
 * @brief IPFIX ipv4 flow-per-packet graph node
 * @node flowperpkt-ipv4
 *
 * This is the IPFIX flow-record-per-packet node.
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer metadata, next index usage
 *
 * <em>Uses:</em>
 * - <code>vnet_buffer(b)->ip.save_rewrite_length</code>
 *     - tells the node the length of the rewrite which was applied in
 *       ip4/6_rewrite_inline, allows the code to find the IP header without
 *       having to parse L2 headers, or make stupid assumptions about their
 *       length.
 * - <code>vnet_buffer(b)->flags & VLIB_BUFFER_FLOW_REPORT</code>
 *     - Used to suppress flow record generation for flow record packets.
 *
 * <em>Sets:</em>
 * - <code>vnet_buffer(b)->flags & VLIB_BUFFER_FLOW_REPORT</code>
 *     - To suppress flow record generation for flow record packets
 *
 * <em>Next Index:</em>
 * - Next configured output feature on the interface, usually
 *   "interface-output." Generated flow records head for ip4-lookup
 */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowperpkt_ipv4_node) = {
  .function = flowperpkt_ipv4_node_fn,
  .name = "flowperpkt-ipv4",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_ipv4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(flowperpkt_ipv4_error_strings),
  .error_strings = flowperpkt_ipv4_error_strings,

  .n_next_nodes = FLOWPERPKT_IPV4_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [FLOWPERPKT_IPV4_NEXT_DROP] = "error-drop",
    /* Used only to trace ipfix data packets */
    [FLOWPERPKT_IPV4_NEXT_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

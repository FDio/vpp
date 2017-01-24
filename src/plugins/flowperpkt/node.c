/*
 * node.c - ipfix-per-packet graph node
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/ip/ip6_packet.h>

/**
 * @file flow record generator graph node
 */

typedef struct
{
  /** interface handle */
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  /** packet timestamp */
  u64 timestamp;
  /** size of the buffer */
  u16 buffer_size;

  /** L2 information */
  u8 src_mac[6];
  u8 dst_mac[6];
  /** Ethertype */
  u16 ethertype;

  /** L3 information */
  ip46_address_t src_address;
  ip46_address_t dst_address;
  u8 protocol;
  u8 tos;
  bool is_l3_ip6;
  bool is_l3_ip4;

  flowperpkt_variant_t which;
} flowperpkt_trace_t;

static char *flowperpkt_variant_strings[] = {
  [FLOW_VARIANT_IP4] = "IP4",
  [FLOW_VARIANT_IP6] = "IP6",
  [FLOW_VARIANT_L2] = "L2",
  [FLOW_VARIANT_L2_IP4] = "L2-IP4",
  [FLOW_VARIANT_L2_IP6] = "L2-IP6",
};

/* packet trace format function */
static u8 *
format_flowperpkt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowperpkt_trace_t *t = va_arg (*args, flowperpkt_trace_t *);
  uword indent = format_get_indent (s);

  s = format (s,
	      "FLOWPERPKT[%s]: rx_sw_if_index %d, tx_sw_if_index %d, "
	      "timestamp %lld, size %d", flowperpkt_variant_strings[t->which],
	      t->rx_sw_if_index, t->tx_sw_if_index,
	      t->timestamp, t->buffer_size);

  if (t->is_l3_ip6)
    s = format (s, "\n%U%U: %U -> %U", format_white_space, indent,
		format_ip_protocol, t->protocol,
		format_ip46_address, &t->src_address, IP46_TYPE_IP6,
		format_ip46_address, &t->dst_address, IP46_TYPE_IP6);
  else if (t->is_l3_ip4)
    s = format (s, "\n%U%U: %U -> %U", format_white_space, indent,
		format_ip_protocol, t->protocol,
		format_ip46_address, &t->src_address, IP46_TYPE_IP4,
		format_ip46_address, &t->dst_address, IP46_TYPE_IP4);

  return s;
}

vlib_node_registration_t flowperpkt_ip4_node;
vlib_node_registration_t flowperpkt_ip6_node;
vlib_node_registration_t flowperpkt_l2_node;

/* No counters at the moment */
#define foreach_flowperpkt_error		\
  /* Must be first. */				\
 _(NONE, "packet flow collected")		\
 _(L3_NOT_FOUND, "L3 not found")		\
 _(FLUSH_EMPTY, "flush empty")

typedef enum
{
#define _(sym,str) FLOWPERPKT_ERROR_##sym,
  foreach_flowperpkt_error
#undef _
    FLOWPERPKT_N_ERROR,
} flowperpkt_error_t;

static char *flowperpkt_error_strings[] = {
#define _(sym,string) string,
  foreach_flowperpkt_error
#undef _
};

typedef enum
{
  FLOWPERPKT_NEXT_DROP,
  FLOWPERPKT_NEXT_IP4_LOOKUP,
  FLOWPERPKT_N_NEXT,
} flowperpkt_next_t;

#define FLOWPERPKT_NEXT_NODES {					\
    [FLOWPERPKT_NEXT_DROP] = "error-drop",			\
    [FLOWPERPKT_NEXT_IP4_LOOKUP] = "ip4-lookup",		\
}

static inline flowperpkt_variant_t
flowperpkt_get_variant (flowperpkt_variant_t which,
			flowperpkt_record_t flags, u16 ethertype)
{
  if (which == FLOW_VARIANT_L2 && flags & FLOW_RECORD_L3)
    return ethertype == ETHERNET_TYPE_IP6 ?
      FLOW_VARIANT_L2_IP6 : ethertype == ETHERNET_TYPE_IP4 ?
      FLOW_VARIANT_L2_IP4 : FLOW_VARIANT_L2;
  return which;
}

static inline u32
flowperpkt_common_add (vlib_buffer_t * to_b, vlib_buffer_t * from_b,
		       u16 offset, u64 timestamp, u16 length)
{
  u16 start = offset;

  /* Ingress interface */
  u32 rx_if =
    clib_host_to_net_u32 (vnet_buffer (from_b)->sw_if_index[VLIB_RX]);
  clib_memcpy (to_b->data + offset, &rx_if, sizeof (rx_if));
  offset += sizeof (rx_if);

  /* Egress interface */
  u32 tx_if =
    clib_host_to_net_u32 (vnet_buffer (from_b)->sw_if_index[VLIB_TX]);
  clib_memcpy (to_b->data + offset, &tx_if, sizeof (tx_if));
  offset += sizeof (tx_if);

  /* Timestamp */
  clib_memcpy (to_b->data + offset, &timestamp, sizeof (u64));
  offset += sizeof (u64);

  /* pkt size */
  u16 pkt_size = clib_host_to_net_u16 (length);
  clib_memcpy (to_b->data + offset, &pkt_size, sizeof (pkt_size));
  offset += sizeof (pkt_size);

  return offset - start;
}

static inline u32
flowperpkt_l2_add (vlib_buffer_t * to_b, ethernet_header_t * eth, u16 offset)
{
  u16 start = offset;

  /* src mac address */
  clib_memcpy (to_b->data + offset, eth->src_address, 6);
  offset += 6;

  /* dst mac address */
  clib_memcpy (to_b->data + offset, eth->dst_address, 6);
  offset += 6;

  /* ethertype */
  clib_memcpy (to_b->data + offset, &eth->type, 2);
  offset += 2;

  return offset - start;
}

static inline u32
flowperpkt_l3_ip6_add (vlib_buffer_t * to_b, ip6_header_t * ip, u16 offset)
{
  u16 start = offset;

  /* ip6 src address */
  clib_memcpy (to_b->data + offset, &ip->src_address, sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* ip6 dst address */
  clib_memcpy (to_b->data + offset, &ip->dst_address, sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* Protocol */
  to_b->data[offset++] = ip->protocol;

  /* Traffic Class */
  to_b->data[offset++] = ip6_traffic_class (ip);

  return offset - start;
}

static inline u32
flowperpkt_l3_ip4_add (vlib_buffer_t * to_b, ip4_header_t * ip, u16 offset)
{
  u16 start = offset;

  /* ip4 src address */
  clib_memcpy (to_b->data + offset, &ip->src_address, sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* ip4 dst address */
  clib_memcpy (to_b->data + offset, &ip->dst_address, sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* Protocol */
  to_b->data[offset++] = ip->protocol;

  /* ToS */
  to_b->data[offset++] = ip->tos;

  return offset - start;
}

/**
 * @brief add an entry to the flow record under construction
 * @param vm vlib_main_t * current worker thread main structure pointer
 * @param fm flowperpkt_main_t * flow-per-packet main structure pointer
 * @param data_b buffer to write into
 * @param timestamp u64 timestamp, nanoseconds since 1/1/70
 * @param length u16 ip length of the packet
 * @param do_flush int 1 = flush all cached records, 0 = construct a record
 * @param which packet path, L2, IP4 or IP6
 */
static inline void
add_to_flow_record (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    flowperpkt_main_t * fm,
		    vlib_buffer_t * data_b, u64 timestamp, u16 length,
		    int do_flush, flowperpkt_variant_t which)
{
  u32 my_cpu_number = vm->cpu_index;
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
  b0 = fm->context[which].buffers_per_worker[my_cpu_number];

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
      b0 = fm->context[which].buffers_per_worker[my_cpu_number] =
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
      offset =
	fm->context[which].next_record_offset_per_worker[my_cpu_number];
    }

  /* Find or allocate a frame */
  f = fm->context[which].frames_per_worker[my_cpu_number];
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      fm->context[which].frames_per_worker[my_cpu_number] = f;

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

  flowperpkt_record_t flags = fm->context[which].flags;
  bool collect_ip4 = false, collect_ip6 = false;
  ethernet_header_t *eth = data_b ? vlib_buffer_get_current (data_b) : 0;
  u16 ethertype = eth ? clib_net_to_host_u16 (eth->type) : 0;

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  /* Add data, unless we're flushing stale data */
  if (PREDICT_TRUE (do_flush == 0))
    {
      flowperpkt_error_t error = FLOWPERPKT_ERROR_NONE;
      u32 start = offset;
      offset += flowperpkt_common_add (b0, data_b, offset, timestamp, length);

      if (flags & FLOW_RECORD_L2)
	offset += flowperpkt_l2_add (b0, eth, offset);
      if (collect_ip6)
	{
	  /* $$$$ Make ip.save_rewrite_length work for L2 */
	  if (ethertype == ETHERNET_TYPE_IP6)
	    offset += flowperpkt_l3_ip6_add (b0, (ip6_header_t *) (eth + 1),
					     offset);
	  else
	    error = FLOWPERPKT_ERROR_L3_NOT_FOUND;
	}
      if (collect_ip4)
	{
	  if (ethertype == ETHERNET_TYPE_IP4)
	    offset += flowperpkt_l3_ip4_add (b0, (ip4_header_t *) (eth + 1),
					     offset);
	  else
	    error = FLOWPERPKT_ERROR_L3_NOT_FOUND;
	}
      if (flags & FLOW_RECORD_L4)
	/* Not yet implemented */
	;

      if (error == FLOWPERPKT_ERROR_NONE)
	b0->current_length += offset - start;
      else
	{
	  offset = start;
	  vlib_node_increment_counter (vm, node->node_index, error, 1);
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (data_b->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  flowperpkt_trace_t *t =
	    vlib_add_trace (vm, node, data_b, sizeof (*t));
	  t->rx_sw_if_index = vnet_buffer (data_b)->sw_if_index[VLIB_RX];
	  t->tx_sw_if_index = vnet_buffer (data_b)->sw_if_index[VLIB_TX];
	  t->timestamp = timestamp;
	  t->buffer_size = length;
	  t->which = which;

	  /* L2 information */
	  if (flags & FLOW_RECORD_L2)
	    {
	      clib_memcpy (t->src_mac, eth->src_address, 6);
	      clib_memcpy (t->dst_mac, eth->dst_address, 6);
	      t->ethertype = ethertype;
	    }

	  /* L3 information */
	  if (collect_ip4 && ethertype == ETHERNET_TYPE_IP4)
	    {
	      ip4_header_t *ip = (ip4_header_t *) (eth + 1);
	      t->src_address.ip4.as_u32 = ip->src_address.as_u32;
	      t->dst_address.ip4.as_u32 = ip->dst_address.as_u32;
	      t->protocol = ip->protocol;
	      t->tos = ip->tos;
	      t->is_l3_ip4 = true;
	    }
	  else if (collect_ip6 && ethertype == ETHERNET_TYPE_IP6)
	    {
	      ip6_header_t *ip = (ip6_header_t *) (eth + 1);
	      t->src_address.as_u64[0] = ip->src_address.as_u64[0];
	      t->src_address.as_u64[1] = ip->src_address.as_u64[1];
	      t->dst_address.as_u64[0] = ip->dst_address.as_u64[0];
	      t->dst_address.as_u64[1] = ip->dst_address.as_u64[1];
	      t->protocol = ip->protocol;
	      t->tos = ip6_traffic_class (ip);
	      t->is_l3_ip6 = true;
	    }
	}
    }
  /* Time to flush the buffer? */
  if (PREDICT_FALSE (do_flush ||
		     offset + fm->template_size[flags] > frm->path_mtu))
    {
      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) & tp->ip4;
      udp = (udp_header_t *) (ip + 1);
      h = (ipfix_message_header_t *) (udp + 1);
      s = (ipfix_set_header_t *) (h + 1);

      if (offset == (u32) (((u8 *) (s + 1)) - (u8 *) tp))
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       FLOWPERPKT_ERROR_FLUSH_EMPTY, 1);
	  return;
	}

      s->set_id_length = ipfix_set_id_length (fm->template_reports[flags],
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
      vlib_put_frame_to_node
	(vm, ip4_lookup_node.index,
	 fm->context[which].frames_per_worker[my_cpu_number]);
      fm->context[which].frames_per_worker[my_cpu_number] = 0;
      fm->context[which].buffers_per_worker[my_cpu_number] = 0;
      offset = 0;
    }

  fm->context[which].next_record_offset_per_worker[my_cpu_number] = offset;
}

uword
flowperpkt_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame,
		    flowperpkt_variant_t which)
{
  u32 n_left_from, *from, *to_next;
  flowperpkt_next_t next_index;
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
	  u32 next0 = FLOWPERPKT_NEXT_DROP;
	  u32 next1 = FLOWPERPKT_NEXT_DROP;
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

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record (vm, node, fm, b0, now, len0, 0 /* flush */ ,
				flowperpkt_get_variant
				(which, fm->context[which].flags,
				 ethertype0));

	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);

	  if (PREDICT_TRUE ((b1->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record (vm, node, fm, b1, now, len1, 0 /* flush */ ,
				flowperpkt_get_variant
				(which, fm->context[which].flags,
				 ethertype1));

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = FLOWPERPKT_NEXT_DROP;
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

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record (vm, node, fm, b0, now, len0, 0 /* flush */ ,
				flowperpkt_get_variant
				(which, fm->context[which].flags,
				 ethertype0));

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static uword
flowperpkt_ip4_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowperpkt_node_fn (vm, node, frame, FLOW_VARIANT_IP4);
}

static uword
flowperpkt_ip6_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowperpkt_node_fn (vm, node, frame, FLOW_VARIANT_IP6);
}

static uword
flowperpkt_l2_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowperpkt_node_fn (vm, node, frame, FLOW_VARIANT_L2);
}

void
flowperpkt_flush_callback_ip4 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_ip4_node.index);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_IP4);
}

void
flowperpkt_flush_callback_ip6 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_ip6_node.index);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_IP6);
}

void
flowperpkt_flush_callback_l2 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_l2_node.index);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_L2);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_L2_IP4);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_L2_IP6);

}

/**
 * @brief IPFIX ip4 flow-per-packet graph node
 * @node flowperpkt-ip4
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
VLIB_REGISTER_NODE (flowperpkt_ip4_node) = {
  .function = flowperpkt_ip4_node_fn,
  .name = "flowperpkt-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowperpkt_error_strings),
  .error_strings = flowperpkt_error_strings,
  .n_next_nodes = FLOWPERPKT_N_NEXT,
  .next_nodes = FLOWPERPKT_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowperpkt_ip6_node) = {
  .function = flowperpkt_ip6_node_fn,
  .name = "flowperpkt-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowperpkt_error_strings),
  .error_strings = flowperpkt_error_strings,
  .n_next_nodes = FLOWPERPKT_N_NEXT,
  .next_nodes = FLOWPERPKT_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowperpkt_l2_node) = {
  .function = flowperpkt_l2_node_fn,
  .name = "flowperpkt-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowperpkt_error_strings),
  .error_strings = flowperpkt_error_strings,
  .n_next_nodes = FLOWPERPKT_N_NEXT,
  .next_nodes = FLOWPERPKT_NEXT_NODES,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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

  if (t->which == FLOW_VARIANT_L2_IP4 || t->which == FLOW_VARIANT_IP4 ||
      t->which == FLOW_VARIANT_L2_IP6 || t->which == FLOW_VARIANT_IP6)
    s = format (s, "\n%U%U: %U -> %U", format_white_space, indent,
		format_ip_protocol, t->protocol,
		format_ip46_address, &t->src_address, IP46_TYPE_ANY,
		format_ip46_address, &t->dst_address, IP46_TYPE_ANY);
  return s;
}

vlib_node_registration_t flowperpkt_ip4_node;
vlib_node_registration_t flowperpkt_ip6_node;
vlib_node_registration_t flowperpkt_l2_node;

/* No counters at the moment */
#define foreach_flowperpkt_error		\
_(COLLISION, "Hash table collisions")

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
flowperpkt_common_add (vlib_buffer_t * to_b, flowperpkt_entry_t * e,
		       u16 offset)
{
  u16 start = offset;

  /* Ingress interface */
  u32 rx_if = clib_host_to_net_u32 (e->key.rx_sw_if_index);
  clib_memcpy (to_b->data + offset, &rx_if, sizeof (rx_if));
  offset += sizeof (rx_if);

  /* Egress interface */
  u32 tx_if = clib_host_to_net_u32 (e->key.tx_sw_if_index);
  clib_memcpy (to_b->data + offset, &tx_if, sizeof (tx_if));
  offset += sizeof (tx_if);

  /* packet delta count */
  u64 packetdelta = clib_host_to_net_u64 (e->packetcount);
  clib_memcpy (to_b->data + offset, &packetdelta, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
flowperpkt_l2_add (vlib_buffer_t * to_b, flowperpkt_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* src mac address */
  clib_memcpy (to_b->data + offset, &e->key.src_mac, 6);
  offset += 6;

  /* dst mac address */
  clib_memcpy (to_b->data + offset, &e->key.dst_mac, 6);
  offset += 6;

  /* ethertype */
  clib_memcpy (to_b->data + offset, &e->key.ethertype, 2);
  offset += 2;

  return offset - start;
}

static inline u32
flowperpkt_l3_ip6_add (vlib_buffer_t * to_b, flowperpkt_entry_t * e,
		       u16 offset)
{
  u16 start = offset;

  /* ip6 src address */
  clib_memcpy (to_b->data + offset, &e->key.src_address,
	       sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* ip6 dst address */
  clib_memcpy (to_b->data + offset, &e->key.dst_address,
	       sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* Protocol */
  to_b->data[offset++] = e->key.protocol;

  /* octetDeltaCount */
  u64 octetdelta = clib_host_to_net_u64 (e->octetcount);
  clib_memcpy (to_b->data + offset, &octetdelta, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
flowperpkt_l3_ip4_add (vlib_buffer_t * to_b, flowperpkt_entry_t * e,
		       u16 offset)
{
  u16 start = offset;

  /* ip4 src address */
  clib_memcpy (to_b->data + offset, &e->key.src_address.ip4,
	       sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* ip4 dst address */
  clib_memcpy (to_b->data + offset, &e->key.dst_address.ip4,
	       sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* Protocol */
  to_b->data[offset++] = e->key.protocol;

  /* octetDeltaCount */
  u64 octetdelta = clib_host_to_net_u64 (e->octetcount);
  clib_memcpy (to_b->data + offset, &octetdelta, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
flowperpkt_l4_add (vlib_buffer_t * to_b, flowperpkt_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* src port */
  clib_memcpy (to_b->data + offset, &e->key.src_port, 2);
  offset += 2;

  /* dst port */
  clib_memcpy (to_b->data + offset, &e->key.dst_port, 2);
  offset += 2;

  return offset - start;
}

static inline u32
flowperpkt_hash (flowperpkt_key_t * k)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  int i;
  u32 h = 0;
  for (i = 0; i < sizeof (k->as_u32) / sizeof (u32); i++)
    h = crc_u32 (k->as_u32[i], h);
  return h >> (32 - fm->ht_log2len);
}

flowperpkt_entry_t *
flowperpkt_lookup (u32 my_cpu_number, flowperpkt_key_t * k, u32 * poolindex,
		   bool * collision)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  flowperpkt_entry_t *e;
  u32 h;

  h = (fm->active_timer) ? flowperpkt_hash (k) : 0;

  /* Lookup in the flow state pool */
  *poolindex = fm->hash_per_worker[my_cpu_number][h];
  if (*poolindex != ~0)
    {
      e = pool_elt_at_index (fm->pool_per_worker[my_cpu_number], *poolindex);
      if (e)
	{
	  /* Verify key or report collision */
	  if (memcmp (k, &e->key, sizeof (flowperpkt_key_t)))
	    {
	      vlib_main_t *vm = vlib_get_main ();

	      /* Flush data and clean up entry for reuse. Just leave
	         the timers */
	      flowperpkt_export_entry (vm, e);
	      e->key = *k;
	      e->packetcount = 0;
	      e->octetcount = 0;
	      *collision = true;
	    }
	  return e;
	}
    }

  return 0;
}

flowperpkt_entry_t *
flowperpkt_create (u32 my_cpu_number, flowperpkt_key_t * k, u32 * poolindex)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  u32 h;

  flowperpkt_entry_t *e;

  /* Get my index */
  h = (fm->active_timer) ? flowperpkt_hash (k) : 0;

  pool_get (fm->pool_per_worker[my_cpu_number], e);
  *poolindex = e - fm->pool_per_worker[my_cpu_number];
  fm->hash_per_worker[my_cpu_number][h] = *poolindex;

  e->key = *k;
  e->timer_on = false;
  if (fm->passive_timer > 0)
    {
      e->passive_timer_handle = tw_timer_start_2t_1w_2048sl
          (fm->timers_per_worker[my_cpu_number], *poolindex, 1,
           fm->passive_timer);
    }

  return e;
}

static void
flowperpkt_delete (u32 my_cpu_number, flowperpkt_key_t * k, u32 poolindex)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  u32 h;

  /* Get my index */
  h = (fm->active_timer) ? flowperpkt_hash (k) : 0;

  /* Reset hash */
  fm->hash_per_worker[my_cpu_number][h] = ~0;

  pool_put_index (fm->pool_per_worker[my_cpu_number], poolindex);
}

static inline void
add_to_flow_record_state (vlib_main_t * vm, vlib_node_runtime_t * node,
			  flowperpkt_main_t * fm, vlib_buffer_t * b,
			  u64 timestamp, u16 length,
			  flowperpkt_variant_t which)
{
  u32 my_cpu_number = vm->cpu_index;
  u16 octets = 0;

  flowperpkt_record_t flags = fm->context[which].flags;
  bool collect_ip4 = false, collect_ip6 = false;
  ASSERT (b);
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u16 ethertype = clib_net_to_host_u16 (eth->type);
  flowperpkt_key_t k = { 0 };

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  k.rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  k.tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];

  k.which = which;

  if (flags & FLOW_RECORD_L2)
    {
      clib_memcpy (k.src_mac, eth->src_address, 6);
      clib_memcpy (k.dst_mac, eth->dst_address, 6);
      k.ethertype = ethertype;
    }
  if (collect_ip6)
    {
      if (ethertype == ETHERNET_TYPE_IP6)
	{
	  ip6_header_t *ip = (ip6_header_t *) (eth + 1);
	  k.src_address.as_u64[0] = ip->src_address.as_u64[0];
	  k.src_address.as_u64[1] = ip->src_address.as_u64[1];
	  k.dst_address.as_u64[0] = ip->dst_address.as_u64[0];
	  k.dst_address.as_u64[1] = ip->dst_address.as_u64[1];
	  k.protocol = ip->protocol;
	  octets = clib_net_to_host_u16 (ip->payload_length)
	    + sizeof (ip6_header_t);
	  if ((flags & FLOW_RECORD_L4) &&
	      (k.protocol == IP_PROTOCOL_TCP
	       || k.protocol == IP_PROTOCOL_UDP))
	    {
	      udp_header_t *udp = (udp_header_t *) (ip + 1);
	      k.src_port = udp->src_port;
	      k.dst_port = udp->dst_port;
	    }
	}
    }
  if (collect_ip4)
    {
      if (ethertype == ETHERNET_TYPE_IP4)
	{
	  ip4_header_t *ip = (ip4_header_t *) (eth + 1);
	  k.src_address.ip4.as_u32 = ip->src_address.as_u32;
	  k.dst_address.ip4.as_u32 = ip->dst_address.as_u32;
	  k.protocol = ip->protocol;
	  octets = clib_net_to_host_u16 (ip->length);
	  if ((flags & FLOW_RECORD_L4) &&
	      (k.protocol == IP_PROTOCOL_TCP
	       || k.protocol == IP_PROTOCOL_UDP))
	    {
	      udp_header_t *udp = (udp_header_t *) (ip + 1);
	      k.src_port = udp->src_port;
	      k.dst_port = udp->dst_port;
	    }
	}
    }

  u32 poolindex = ~0;
  bool collision = false;
  flowperpkt_entry_t *e = flowperpkt_lookup (my_cpu_number, &k, &poolindex,
					     &collision);
  if (collision)
    vlib_node_increment_counter (vm, node->node_index,
				 FLOWPERPKT_ERROR_COLLISION, 1);
  if (!e)
    {
      /* Create new entry */
      e = flowperpkt_create (my_cpu_number, &k, &poolindex);
    }

  /* Updating existing entry */
  e->packetcount++;
  e->octetcount += octets;
  e->last_updated = vlib_time_now (vm);

  /* Start timer if not already running */
  if (!e->timer_on)
    {
      if (fm->active_timer>0)
        {
          e->active_timer_handle = tw_timer_start_2t_1w_2048sl
              (fm->timers_per_worker[my_cpu_number], poolindex, 0,
               fm->active_timer);
          e->timer_on = true;
        }
      else if (!collision)
        {
          /* Flush data and clean up entry for reuse. */
          vlib_main_t *vm = vlib_get_main ();

          flowperpkt_export_entry (vm, e);
          e->key = (flowperpkt_key_t) { 0 };
          e->packetcount = 0;
          e->octetcount = 0;
          e->timer_on = false;
        }
    }
}

static u16
flowperpkt_get_headersize (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
flowperpkt_export_send (vlib_main_t * vm, vlib_buffer_t * b0,
			flowperpkt_variant_t which)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  ip4_ipfix_template_packet_t *tp;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  flowperpkt_record_t flags = fm->context[which].flags;
  u32 my_cpu_number = vm->cpu_index;

  /* Fill in header */
  flow_report_stream_t *stream;

  /* Nothing to send */
  if (fm->context[which].next_record_offset_per_worker[my_cpu_number] <=
      flowperpkt_get_headersize ())
    return;

  u32 i, index = vec_len(frm->streams);
  for (i = 0; i < vec_len(frm->streams); i++)
    if (!(i < vec_len(frm->streams) && frm->streams[i].domain_id != ~0))
      {
        index = i;
        break;
      }
  vec_validate(frm->streams, index);
  frm->streams[index].domain_id = 1;
  stream = &frm->streams[index];

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

  /* Find or allocate a frame */
  f = fm->context[which].frames_per_worker[my_cpu_number];
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      fm->context[which].frames_per_worker[my_cpu_number] = f;
      u32 bi0 = vlib_get_buffer_index (vm, b0);

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  fm->context[which].frames_per_worker[my_cpu_number] = 0;
  fm->context[which].buffers_per_worker[my_cpu_number] = 0;
  fm->context[which].next_record_offset_per_worker[my_cpu_number] =
    flowperpkt_get_headersize ();;
}

static vlib_buffer_t *
flowperpkt_get_buffer (vlib_main_t * vm, flowperpkt_variant_t which)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_buffer_t *b0;
  u32 bi0;
  vlib_buffer_free_list_t *fl;
  u32 my_cpu_number = vm->cpu_index;

  /* Find or allocate a buffer */
  b0 = fm->context[which].buffers_per_worker[my_cpu_number];

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == 0))
    {
      /* $$$$ drop counter? */
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	return 0;

      /* Initialize the buffer */
      b0 = fm->context[which].buffers_per_worker[my_cpu_number] =
	vlib_get_buffer (vm, bi0);
      fl =
	vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (b0, fl);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

      b0->current_data = 0;
      b0->current_length = flowperpkt_get_headersize ();
      b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VLIB_BUFFER_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;
      fm->context[which].next_record_offset_per_worker[my_cpu_number] =
	b0->current_length;
    }

  return b0;
}

void
flowperpkt_export_entry (vlib_main_t * vm, flowperpkt_entry_t * e)
{
  u32 my_cpu_number = vm->cpu_index;
  flowperpkt_main_t *fm = &flowperpkt_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_buffer_t *b0;
  bool collect_ip4 = false, collect_ip6 = false;
  flowperpkt_variant_t which = e->key.which;
  flowperpkt_record_t flags = fm->context[which].flags;
  u16 offset =
    fm->context[which].next_record_offset_per_worker[my_cpu_number];

  b0 = flowperpkt_get_buffer (vm, which);
  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  offset += flowperpkt_common_add (b0, e, offset);

  if (flags & FLOW_RECORD_L2)
    offset += flowperpkt_l2_add (b0, e, offset);
  if (collect_ip6)
    offset += flowperpkt_l3_ip6_add (b0, e, offset);
  if (collect_ip4)
    offset += flowperpkt_l3_ip4_add (b0, e, offset);
  if (flags & FLOW_RECORD_L4)
    offset += flowperpkt_l4_add (b0, e, offset);

  /* Reset per flow-export counters */
  e->packetcount = 0;
  e->octetcount = 0;

  b0->current_length = offset;

  /* Time to flush the buffer? */
  if (offset + fm->template_size[flags] > frm->path_mtu)
    flowperpkt_export_send (vm, b0, which);
  else
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
	    add_to_flow_record_state (vm, node, fm, b0, now, len0,
				      flowperpkt_get_variant
				      (which, fm->context[which].flags,
				       ethertype0));

	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);

	  if (PREDICT_TRUE ((b1->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record_state (vm, node, fm, b1, now, len1,
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
	    add_to_flow_record_state (vm, node, fm, b0, now, len0,
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

void
flowperpkt_expired_timer_callback (u32 * expired_timers)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  u32 my_cpu_number = os_get_cpu_number ();
  int i;
  u32 poolindex, timer_id;
  flowperpkt_entry_t *e;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      poolindex = expired_timers[i] & 0x7FFFFFFF;
      timer_id = expired_timers[i] >> 31;
      e = pool_elt_at_index (fm->pool_per_worker[my_cpu_number], poolindex);
      if (timer_id == 0)	/* Active timer */
	{
	  e->timer_on = false;
	  /* If anything to report send it to the exporter */
	  if (e->packetcount)
	    flowperpkt_export_entry (vm, e);
	}
      else if (timer_id == 1)	/* Passive timer */
	{
	  /* Check last update timestamp. If it is longer than passive time nuke
	   * entry. Otherwise restart timer with what's left
	   * Premature passive timer by more than 10%
	   */
	  if ((vlib_time_now (vm) - e->last_updated) <
	      (fm->passive_timer * 0.9))
	    {
	      f64 delta = fm->passive_timer -
		(vlib_time_now (vm) - e->last_updated);
	      e->passive_timer_handle = tw_timer_start_2t_1w_2048sl
		(fm->timers_per_worker[my_cpu_number], poolindex, 1, delta);
	    }
	  else			/* Nuke entry */
	    {
	      /* If anything to report send it to the exporter */
	      if (e->packetcount)
	        flowperpkt_export_entry (vm, e);
	      flowperpkt_delete (my_cpu_number, &e->key, poolindex);
	    }
	}
    }
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

static inline void
flush_record (flowperpkt_variant_t which)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *b = flowperpkt_get_buffer (vm, which);
  if (b)
    flowperpkt_export_send (vm, b, which);
}

void
flowperpkt_flush_callback_ip4 (void)
{
  flush_record (FLOW_VARIANT_IP4);
}

void
flowperpkt_flush_callback_ip6 (void)
{
  flush_record (FLOW_VARIANT_IP6);
}

void
flowperpkt_flush_callback_l2 (void)
{
  flush_record (FLOW_VARIANT_L2);
  flush_record (FLOW_VARIANT_L2_IP4);
  flush_record (FLOW_VARIANT_L2_IP6);
}

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

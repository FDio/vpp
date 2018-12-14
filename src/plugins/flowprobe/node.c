/*
 * node.c - ipfix probe graph node
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
#include <vppinfra/crc32.h>
#include <vppinfra/error.h>
#include <flowprobe/flowprobe.h>
#include <vnet/ip/ip6_packet.h>
#include <vlibmemory/api.h>

static void flowprobe_export_entry (vlib_main_t * vm, flowprobe_entry_t * e);

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

  /** L4 information */
  u16 src_port;
  u16 dst_port;

  flowprobe_variant_t which;
} flowprobe_trace_t;

static char *flowprobe_variant_strings[] = {
  [FLOW_VARIANT_IP4] = "IP4",
  [FLOW_VARIANT_IP6] = "IP6",
  [FLOW_VARIANT_L2] = "L2",
  [FLOW_VARIANT_L2_IP4] = "L2-IP4",
  [FLOW_VARIANT_L2_IP6] = "L2-IP6",
};

/* packet trace format function */
static u8 *
format_flowprobe_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowprobe_trace_t *t = va_arg (*args, flowprobe_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s,
	      "FLOWPROBE[%s]: rx_sw_if_index %d, tx_sw_if_index %d, "
	      "timestamp %lld, size %d", flowprobe_variant_strings[t->which],
	      t->rx_sw_if_index, t->tx_sw_if_index,
	      t->timestamp, t->buffer_size);

  if (t->which == FLOW_VARIANT_L2)
    s = format (s, "\n%U -> %U", format_white_space, indent,
		format_ethernet_address, &t->src_mac,
		format_ethernet_address, &t->dst_mac);

  if (t->protocol > 0
      && (t->which == FLOW_VARIANT_L2_IP4 || t->which == FLOW_VARIANT_IP4
	  || t->which == FLOW_VARIANT_L2_IP6 || t->which == FLOW_VARIANT_IP6))
    s =
      format (s, "\n%U%U: %U -> %U", format_white_space, indent,
	      format_ip_protocol, t->protocol, format_ip46_address,
	      &t->src_address, IP46_TYPE_ANY, format_ip46_address,
	      &t->dst_address, IP46_TYPE_ANY);
  return s;
}

vlib_node_registration_t flowprobe_ip4_node;
vlib_node_registration_t flowprobe_ip6_node;
vlib_node_registration_t flowprobe_l2_node;

/* No counters at the moment */
#define foreach_flowprobe_error			\
_(COLLISION, "Hash table collisions")		\
_(BUFFER, "Buffer allocation error")		\
_(EXPORTED_PACKETS, "Exported packets")		\
_(INPATH, "Exported packets in path")

typedef enum
{
#define _(sym,str) FLOWPROBE_ERROR_##sym,
  foreach_flowprobe_error
#undef _
    FLOWPROBE_N_ERROR,
} flowprobe_error_t;

static char *flowprobe_error_strings[] = {
#define _(sym,string) string,
  foreach_flowprobe_error
#undef _
};

typedef enum
{
  FLOWPROBE_NEXT_DROP,
  FLOWPROBE_NEXT_IP4_LOOKUP,
  FLOWPROBE_N_NEXT,
} flowprobe_next_t;

#define FLOWPROBE_NEXT_NODES {					\
    [FLOWPROBE_NEXT_DROP] = "error-drop",			\
    [FLOWPROBE_NEXT_IP4_LOOKUP] = "ip4-lookup",		\
}

static inline flowprobe_variant_t
flowprobe_get_variant (flowprobe_variant_t which,
		       flowprobe_record_t flags, u16 ethertype)
{
  if (which == FLOW_VARIANT_L2
      && (flags & FLOW_RECORD_L3 || flags & FLOW_RECORD_L4))
    return ethertype == ETHERNET_TYPE_IP6 ? FLOW_VARIANT_L2_IP6 : ethertype ==
      ETHERNET_TYPE_IP4 ? FLOW_VARIANT_L2_IP4 : FLOW_VARIANT_L2;
  return which;
}

/*
 * NTP rfc868 : 2 208 988 800 corresponds to 00:00  1 Jan 1970 GMT
 */
#define NTP_TIMESTAMP 2208988800LU

static inline u32
flowprobe_common_add (vlib_buffer_t * to_b, flowprobe_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* Ingress interface */
  u32 rx_if = clib_host_to_net_u32 (e->key.rx_sw_if_index);
  clib_memcpy_fast (to_b->data + offset, &rx_if, sizeof (rx_if));
  offset += sizeof (rx_if);

  /* Egress interface */
  u32 tx_if = clib_host_to_net_u32 (e->key.tx_sw_if_index);
  clib_memcpy_fast (to_b->data + offset, &tx_if, sizeof (tx_if));
  offset += sizeof (tx_if);

  /* packet delta count */
  u64 packetdelta = clib_host_to_net_u64 (e->packetcount);
  clib_memcpy_fast (to_b->data + offset, &packetdelta, sizeof (u64));
  offset += sizeof (u64);

  /* flowStartNanoseconds */
  u32 t = clib_host_to_net_u32 (e->flow_start.sec + NTP_TIMESTAMP);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);
  t = clib_host_to_net_u32 (e->flow_start.nsec);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);

  /* flowEndNanoseconds */
  t = clib_host_to_net_u32 (e->flow_end.sec + NTP_TIMESTAMP);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);
  t = clib_host_to_net_u32 (e->flow_end.nsec);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);

  return offset - start;
}

static inline u32
flowprobe_l2_add (vlib_buffer_t * to_b, flowprobe_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* src mac address */
  clib_memcpy_fast (to_b->data + offset, &e->key.src_mac, 6);
  offset += 6;

  /* dst mac address */
  clib_memcpy_fast (to_b->data + offset, &e->key.dst_mac, 6);
  offset += 6;

  /* ethertype */
  clib_memcpy_fast (to_b->data + offset, &e->key.ethertype, 2);
  offset += 2;

  return offset - start;
}

static inline u32
flowprobe_l3_ip6_add (vlib_buffer_t * to_b, flowprobe_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* ip6 src address */
  clib_memcpy_fast (to_b->data + offset, &e->key.src_address,
		    sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* ip6 dst address */
  clib_memcpy_fast (to_b->data + offset, &e->key.dst_address,
		    sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* Protocol */
  to_b->data[offset++] = e->key.protocol;

  /* octetDeltaCount */
  u64 octetdelta = clib_host_to_net_u64 (e->octetcount);
  clib_memcpy_fast (to_b->data + offset, &octetdelta, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
flowprobe_l3_ip4_add (vlib_buffer_t * to_b, flowprobe_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* ip4 src address */
  clib_memcpy_fast (to_b->data + offset, &e->key.src_address.ip4,
		    sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* ip4 dst address */
  clib_memcpy_fast (to_b->data + offset, &e->key.dst_address.ip4,
		    sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* Protocol */
  to_b->data[offset++] = e->key.protocol;

  /* octetDeltaCount */
  u64 octetdelta = clib_host_to_net_u64 (e->octetcount);
  clib_memcpy_fast (to_b->data + offset, &octetdelta, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
flowprobe_l4_add (vlib_buffer_t * to_b, flowprobe_entry_t * e, u16 offset)
{
  u16 start = offset;

  /* src port */
  clib_memcpy_fast (to_b->data + offset, &e->key.src_port, 2);
  offset += 2;

  /* dst port */
  clib_memcpy_fast (to_b->data + offset, &e->key.dst_port, 2);
  offset += 2;

  /* tcp control bits */
  u16 control_bits = htons (e->prot.tcp.flags);
  clib_memcpy_fast (to_b->data + offset, &control_bits, 2);
  offset += 2;

  return offset - start;
}

static inline u32
flowprobe_hash (flowprobe_key_t * k)
{
  flowprobe_main_t *fm = &flowprobe_main;
  u32 h = 0;

#ifdef clib_crc32c_uses_intrinsics
  h = clib_crc32c ((u8 *) k, sizeof (*k));
#else
  int i;
  u64 tmp = 0;
  for (i = 0; i < sizeof (*k) / 8; i++)
    tmp ^= ((u64 *) k)[i];

  h = clib_xxhash (tmp);
#endif

  return h >> (32 - fm->ht_log2len);
}

flowprobe_entry_t *
flowprobe_lookup (u32 my_cpu_number, flowprobe_key_t * k, u32 * poolindex,
		  bool * collision)
{
  flowprobe_main_t *fm = &flowprobe_main;
  flowprobe_entry_t *e;
  u32 h;

  h = (fm->active_timer) ? flowprobe_hash (k) : 0;

  /* Lookup in the flow state pool */
  *poolindex = fm->hash_per_worker[my_cpu_number][h];
  if (*poolindex != ~0)
    {
      e = pool_elt_at_index (fm->pool_per_worker[my_cpu_number], *poolindex);
      if (e)
	{
	  /* Verify key or report collision */
	  if (memcmp (k, &e->key, sizeof (flowprobe_key_t)))
	    *collision = true;
	  return e;
	}
    }

  return 0;
}

flowprobe_entry_t *
flowprobe_create (u32 my_cpu_number, flowprobe_key_t * k, u32 * poolindex)
{
  flowprobe_main_t *fm = &flowprobe_main;
  u32 h;

  flowprobe_entry_t *e;

  /* Get my index */
  h = (fm->active_timer) ? flowprobe_hash (k) : 0;

  pool_get (fm->pool_per_worker[my_cpu_number], e);
  *poolindex = e - fm->pool_per_worker[my_cpu_number];
  fm->hash_per_worker[my_cpu_number][h] = *poolindex;

  e->key = *k;

  if (fm->passive_timer > 0)
    {
      e->passive_timer_handle = tw_timer_start_2t_1w_2048sl
	(fm->timers_per_worker[my_cpu_number], *poolindex, 0,
	 fm->passive_timer);
    }
  return e;
}

static inline void
add_to_flow_record_state (vlib_main_t * vm, vlib_node_runtime_t * node,
			  flowprobe_main_t * fm, vlib_buffer_t * b,
			  timestamp_nsec_t timestamp, u16 length,
			  flowprobe_variant_t which, flowprobe_trace_t * t)
{
  if (fm->disabled)
    return;

  u32 my_cpu_number = vm->thread_index;
  u16 octets = 0;

  flowprobe_record_t flags = fm->context[which].flags;
  bool collect_ip4 = false, collect_ip6 = false;
  ASSERT (b);
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u16 ethertype = clib_net_to_host_u16 (eth->type);
  /* *INDENT-OFF* */
  flowprobe_key_t k = {};
  /* *INDENT-ON* */
  ip4_header_t *ip4 = 0;
  ip6_header_t *ip6 = 0;
  udp_header_t *udp = 0;
  tcp_header_t *tcp = 0;
  u8 tcp_flags = 0;

  if (flags & FLOW_RECORD_L3 || flags & FLOW_RECORD_L4)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  k.rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  k.tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];

  k.which = which;

  if (flags & FLOW_RECORD_L2)
    {
      clib_memcpy_fast (k.src_mac, eth->src_address, 6);
      clib_memcpy_fast (k.dst_mac, eth->dst_address, 6);
      k.ethertype = ethertype;
    }
  if (collect_ip6 && ethertype == ETHERNET_TYPE_IP6)
    {
      ip6 = (ip6_header_t *) (eth + 1);
      if (flags & FLOW_RECORD_L3)
	{
	  k.src_address.as_u64[0] = ip6->src_address.as_u64[0];
	  k.src_address.as_u64[1] = ip6->src_address.as_u64[1];
	  k.dst_address.as_u64[0] = ip6->dst_address.as_u64[0];
	  k.dst_address.as_u64[1] = ip6->dst_address.as_u64[1];
	}
      k.protocol = ip6->protocol;
      if (k.protocol == IP_PROTOCOL_UDP)
	udp = (udp_header_t *) (ip6 + 1);
      else if (k.protocol == IP_PROTOCOL_TCP)
	tcp = (tcp_header_t *) (ip6 + 1);

      octets = clib_net_to_host_u16 (ip6->payload_length)
	+ sizeof (ip6_header_t);
    }
  if (collect_ip4 && ethertype == ETHERNET_TYPE_IP4)
    {
      ip4 = (ip4_header_t *) (eth + 1);
      if (flags & FLOW_RECORD_L3)
	{
	  k.src_address.ip4.as_u32 = ip4->src_address.as_u32;
	  k.dst_address.ip4.as_u32 = ip4->dst_address.as_u32;
	}
      k.protocol = ip4->protocol;
      if ((flags & FLOW_RECORD_L4) && k.protocol == IP_PROTOCOL_UDP)
	udp = (udp_header_t *) (ip4 + 1);
      else if ((flags & FLOW_RECORD_L4) && k.protocol == IP_PROTOCOL_TCP)
	tcp = (tcp_header_t *) (ip4 + 1);

      octets = clib_net_to_host_u16 (ip4->length);
    }

  if (udp)
    {
      k.src_port = udp->src_port;
      k.dst_port = udp->dst_port;
    }
  else if (tcp)
    {
      k.src_port = tcp->src_port;
      k.dst_port = tcp->dst_port;
      tcp_flags = tcp->flags;
    }

  if (t)
    {
      t->rx_sw_if_index = k.rx_sw_if_index;
      t->tx_sw_if_index = k.tx_sw_if_index;
      clib_memcpy_fast (t->src_mac, k.src_mac, 6);
      clib_memcpy_fast (t->dst_mac, k.dst_mac, 6);
      t->ethertype = k.ethertype;
      t->src_address.ip4.as_u32 = k.src_address.ip4.as_u32;
      t->dst_address.ip4.as_u32 = k.dst_address.ip4.as_u32;
      t->protocol = k.protocol;
      t->src_port = k.src_port;
      t->dst_port = k.dst_port;
      t->which = k.which;
    }

  flowprobe_entry_t *e = 0;
  f64 now = vlib_time_now (vm);
  if (fm->active_timer > 0)
    {
      u32 poolindex = ~0;
      bool collision = false;

      e = flowprobe_lookup (my_cpu_number, &k, &poolindex, &collision);
      if (collision)
	{
	  /* Flush data and clean up entry for reuse. */
	  if (e->packetcount)
	    flowprobe_export_entry (vm, e);
	  e->key = k;
	  e->flow_start = timestamp;
	  vlib_node_increment_counter (vm, node->node_index,
				       FLOWPROBE_ERROR_COLLISION, 1);
	}
      if (!e)			/* Create new entry */
	{
	  e = flowprobe_create (my_cpu_number, &k, &poolindex);
	  e->last_exported = now;
	  e->flow_start = timestamp;
	}
    }
  else
    {
      e = &fm->stateless_entry[my_cpu_number];
      e->key = k;
    }

  if (e)
    {
      /* Updating entry */
      e->packetcount++;
      e->octetcount += octets;
      e->last_updated = now;
      e->flow_end = timestamp;
      e->prot.tcp.flags |= tcp_flags;
      if (fm->active_timer == 0
	  || (now > e->last_exported + fm->active_timer))
	flowprobe_export_entry (vm, e);
    }
}

static u16
flowprobe_get_headersize (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
flowprobe_export_send (vlib_main_t * vm, vlib_buffer_t * b0,
		       flowprobe_variant_t which)
{
  flowprobe_main_t *fm = &flowprobe_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  ip4_ipfix_template_packet_t *tp;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  flowprobe_record_t flags = fm->context[which].flags;
  u32 my_cpu_number = vm->thread_index;

  /* Fill in header */
  flow_report_stream_t *stream;

  /* Nothing to send */
  if (fm->context[which].next_record_offset_per_worker[my_cpu_number] <=
      flowprobe_get_headersize ())
    return;

  u32 i, index = vec_len (frm->streams);
  for (i = 0; i < index; i++)
    if (frm->streams[i].domain_id == 1)
      {
	index = i;
	break;
      }
  if (i == vec_len (frm->streams))
    {
      vec_validate (frm->streams, index);
      frm->streams[index].domain_id = 1;
    }
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
  vlib_node_increment_counter (vm, flowprobe_l2_node.index,
			       FLOWPROBE_ERROR_EXPORTED_PACKETS, 1);

  fm->context[which].frames_per_worker[my_cpu_number] = 0;
  fm->context[which].buffers_per_worker[my_cpu_number] = 0;
  fm->context[which].next_record_offset_per_worker[my_cpu_number] =
    flowprobe_get_headersize ();
}

static vlib_buffer_t *
flowprobe_get_buffer (vlib_main_t * vm, flowprobe_variant_t which)
{
  flowprobe_main_t *fm = &flowprobe_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_buffer_t *b0;
  u32 bi0;
  vlib_buffer_free_list_t *fl;
  u32 my_cpu_number = vm->thread_index;

  /* Find or allocate a buffer */
  b0 = fm->context[which].buffers_per_worker[my_cpu_number];

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == 0))
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  vlib_node_increment_counter (vm, flowprobe_l2_node.index,
				       FLOWPROBE_ERROR_BUFFER, 1);
	  return 0;
	}

      /* Initialize the buffer */
      b0 = fm->context[which].buffers_per_worker[my_cpu_number] =
	vlib_get_buffer (vm, bi0);
      fl =
	vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (b0, fl);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

      b0->current_data = 0;
      b0->current_length = flowprobe_get_headersize ();
      b0->flags |=
	(VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;
      fm->context[which].next_record_offset_per_worker[my_cpu_number] =
	b0->current_length;
    }

  return b0;
}

static void
flowprobe_export_entry (vlib_main_t * vm, flowprobe_entry_t * e)
{
  u32 my_cpu_number = vm->thread_index;
  flowprobe_main_t *fm = &flowprobe_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_buffer_t *b0;
  bool collect_ip4 = false, collect_ip6 = false;
  flowprobe_variant_t which = e->key.which;
  flowprobe_record_t flags = fm->context[which].flags;
  u16 offset =
    fm->context[which].next_record_offset_per_worker[my_cpu_number];

  if (offset < flowprobe_get_headersize ())
    offset = flowprobe_get_headersize ();

  b0 = flowprobe_get_buffer (vm, which);
  /* No available buffer, what to do... */
  if (b0 == 0)
    return;

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  offset += flowprobe_common_add (b0, e, offset);

  if (flags & FLOW_RECORD_L2)
    offset += flowprobe_l2_add (b0, e, offset);
  if (collect_ip6)
    offset += flowprobe_l3_ip6_add (b0, e, offset);
  if (collect_ip4)
    offset += flowprobe_l3_ip4_add (b0, e, offset);
  if (flags & FLOW_RECORD_L4)
    offset += flowprobe_l4_add (b0, e, offset);

  /* Reset per flow-export counters */
  e->packetcount = 0;
  e->octetcount = 0;
  e->last_exported = vlib_time_now (vm);

  b0->current_length = offset;

  fm->context[which].next_record_offset_per_worker[my_cpu_number] = offset;
  /* Time to flush the buffer? */
  if (offset + fm->template_size[flags] > frm->path_mtu)
    flowprobe_export_send (vm, b0, which);
}

uword
flowprobe_node_fn (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame,
		   flowprobe_variant_t which)
{
  u32 n_left_from, *from, *to_next;
  flowprobe_next_t next_index;
  flowprobe_main_t *fm = &flowprobe_main;
  timestamp_nsec_t timestamp;

  unix_time_now_nsec_fraction (&timestamp.sec, &timestamp.nsec);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = FLOWPROBE_NEXT_DROP;
	  u32 next1 = FLOWPROBE_NEXT_DROP;
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

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VNET_BUFFER_F_FLOW_REPORT) == 0))
	    add_to_flow_record_state (vm, node, fm, b0, timestamp, len0,
				      flowprobe_get_variant
				      (which, fm->context[which].flags,
				       ethertype0), 0);

	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);

	  if (PREDICT_TRUE ((b1->flags & VNET_BUFFER_F_FLOW_REPORT) == 0))
	    add_to_flow_record_state (vm, node, fm, b1, timestamp, len1,
				      flowprobe_get_variant
				      (which, fm->context[which].flags,
				       ethertype1), 0);

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = FLOWPROBE_NEXT_DROP;
	  u16 len0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_feature_next (&next0, b0);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VNET_BUFFER_F_FLOW_REPORT) == 0))
	    {
	      flowprobe_trace_t *t = 0;
	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
		t = vlib_add_trace (vm, node, b0, sizeof (*t));

	      add_to_flow_record_state (vm, node, fm, b0, timestamp, len0,
					flowprobe_get_variant
					(which, fm->context[which].flags,
					 ethertype0), t);
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

static uword
flowprobe_ip4_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowprobe_node_fn (vm, node, frame, FLOW_VARIANT_IP4);
}

static uword
flowprobe_ip6_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowprobe_node_fn (vm, node, frame, FLOW_VARIANT_IP6);
}

static uword
flowprobe_l2_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowprobe_node_fn (vm, node, frame, FLOW_VARIANT_L2);
}

static inline void
flush_record (flowprobe_variant_t which)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *b = flowprobe_get_buffer (vm, which);
  if (b)
    flowprobe_export_send (vm, b, which);
}

void
flowprobe_flush_callback_ip4 (void)
{
  flush_record (FLOW_VARIANT_IP4);
}

void
flowprobe_flush_callback_ip6 (void)
{
  flush_record (FLOW_VARIANT_IP6);
}

void
flowprobe_flush_callback_l2 (void)
{
  flush_record (FLOW_VARIANT_L2);
  flush_record (FLOW_VARIANT_L2_IP4);
  flush_record (FLOW_VARIANT_L2_IP6);
}


static void
flowprobe_delete_by_index (u32 my_cpu_number, u32 poolindex)
{
  flowprobe_main_t *fm = &flowprobe_main;
  flowprobe_entry_t *e;
  u32 h;

  e = pool_elt_at_index (fm->pool_per_worker[my_cpu_number], poolindex);

  /* Get my index */
  h = flowprobe_hash (&e->key);

  /* Reset hash */
  fm->hash_per_worker[my_cpu_number][h] = ~0;

  pool_put_index (fm->pool_per_worker[my_cpu_number], poolindex);
}


/* Per worker process processing the active/passive expired entries */
static uword
flowprobe_walker_process (vlib_main_t * vm,
			  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  flowprobe_main_t *fm = &flowprobe_main;
  flow_report_main_t *frm = &flow_report_main;
  flowprobe_entry_t *e;

  /*
   * $$$$ Remove this check from here and track FRM status and disable
   * this process if required.
   */
  if (frm->ipfix_collector.as_u32 == 0 || frm->src_address.as_u32 == 0)
    {
      fm->disabled = true;
      return 0;
    }
  fm->disabled = false;

  u32 cpu_index = os_get_thread_index ();
  u32 *to_be_removed = 0, *i;

  /*
   * Tick the timer when required and process the vector of expired
   * timers
   */
  f64 start_time = vlib_time_now (vm);
  u32 count = 0;

  tw_timer_expire_timers_2t_1w_2048sl (fm->timers_per_worker[cpu_index],
				       start_time);

  vec_foreach (i, fm->expired_passive_per_worker[cpu_index])
  {
    u32 exported = 0;
    f64 now = vlib_time_now (vm);
    if (now > start_time + 100e-6
	|| exported > FLOW_MAXIMUM_EXPORT_ENTRIES - 1)
      break;

    if (pool_is_free_index (fm->pool_per_worker[cpu_index], *i))
      {
	clib_warning ("Element is %d is freed already\n", *i);
	continue;
      }
    else
      e = pool_elt_at_index (fm->pool_per_worker[cpu_index], *i);

    /* Check last update timestamp. If it is longer than passive time nuke
     * entry. Otherwise restart timer with what's left
     * Premature passive timer by more than 10%
     */
    if ((now - e->last_updated) < (u64) (fm->passive_timer * 0.9))
      {
	u64 delta = fm->passive_timer - (now - e->last_updated);
	e->passive_timer_handle = tw_timer_start_2t_1w_2048sl
	  (fm->timers_per_worker[cpu_index], *i, 0, delta);
      }
    else			/* Nuke entry */
      {
	vec_add1 (to_be_removed, *i);
      }
    /* If anything to report send it to the exporter */
    if (e->packetcount && now > e->last_exported + fm->active_timer)
      {
	exported++;
	flowprobe_export_entry (vm, e);
      }
    count++;
  }
  if (count)
    vec_delete (fm->expired_passive_per_worker[cpu_index], count, 0);

  vec_foreach (i, to_be_removed) flowprobe_delete_by_index (cpu_index, *i);
  vec_free (to_be_removed);

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowprobe_ip4_node) = {
  .function = flowprobe_ip4_node_fn,
  .name = "flowprobe-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_flowprobe_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowprobe_error_strings),
  .error_strings = flowprobe_error_strings,
  .n_next_nodes = FLOWPROBE_N_NEXT,
  .next_nodes = FLOWPROBE_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowprobe_ip6_node) = {
  .function = flowprobe_ip6_node_fn,
  .name = "flowprobe-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_flowprobe_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowprobe_error_strings),
  .error_strings = flowprobe_error_strings,
  .n_next_nodes = FLOWPROBE_N_NEXT,
  .next_nodes = FLOWPROBE_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowprobe_l2_node) = {
  .function = flowprobe_l2_node_fn,
  .name = "flowprobe-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_flowprobe_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowprobe_error_strings),
  .error_strings = flowprobe_error_strings,
  .n_next_nodes = FLOWPROBE_N_NEXT,
  .next_nodes = FLOWPROBE_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowprobe_walker_node) = {
  .function = flowprobe_walker_process,
  .name = "flowprobe-walker",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

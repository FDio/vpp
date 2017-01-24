/*
 * flowperpkt.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_flowperpkt_h__
#define __included_flowperpkt_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/flow/flow_report.h>
#include <vnet/flow/flow_report_classify.h>

typedef enum
{
  FLOW_RECORD_L2 = 1 << 0,
  FLOW_RECORD_L3 = 1 << 1,
  FLOW_RECORD_L4 = 1 << 2,
  FLOW_RECORD_L2_IP4 = 1 << 3,
  FLOW_RECORD_L2_IP6 = 1 << 4,
  FLOW_N_RECORDS = 1 << 5,
} flowperpkt_record_t;

typedef enum
{
  FLOW_VARIANT_IP4,
  FLOW_VARIANT_IP6,
  FLOW_VARIANT_L2,
  FLOW_VARIANT_L2_IP4,
  FLOW_VARIANT_L2_IP6,
  FLOW_N_VARIANTS,
} flowperpkt_variant_t;

typedef struct
{
  /* what to collect per variant */
  flowperpkt_record_t flags;
  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **buffers_per_worker;
  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **frames_per_worker;
  /** next record offset, per worker thread */
  u16 *next_record_offset_per_worker;
} flowperpkt_protocol_context;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  flowperpkt_protocol_context context[FLOW_N_VARIANTS];
  u16 template_reports[FLOW_N_RECORDS];
  u16 template_size[FLOW_N_RECORDS];

  /** Time reference pair */
  u64 nanosecond_time_0;
  f64 vlib_time_0;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} flowperpkt_main_t;

extern flowperpkt_main_t flowperpkt_main;

extern vlib_node_registration_t flowperpkt_ipv4_node;

void flowperpkt_flush_callback_ipv4 (void);
void flowperpkt_flush_callback_ipv6 (void);
void flowperpkt_flush_callback_l2 (void);

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
flowperpkt_l2_add (vlib_buffer_t * to_b, vlib_buffer_t * from_b, u16 offset)
{
  u16 start = offset;
  ethernet_header_t *eth = vlib_buffer_get_current (from_b);

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
flowperpkt_l3_ip6_add (vlib_buffer_t * to_b, vlib_buffer_t * from_b,
		       u16 offset)
{
  u16 start = offset;
  ip6_header_t *ip = (ip6_header_t *)
    ((u8 *) vlib_buffer_get_current (from_b) +
     vnet_buffer (from_b)->ip.save_rewrite_length);

  /* ip6 src address */
  clib_memcpy (to_b->data + offset, &ip->src_address, sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* ip6 dst address */
  clib_memcpy (to_b->data + offset, &ip->dst_address, sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* Traffic Class */
  to_b->data[offset++] = ip6_traffic_class (ip);

  return offset - start;
}

static inline u32
flowperpkt_l3_ip4_add (vlib_buffer_t * to_b, vlib_buffer_t * from_b,
		       u16 offset)
{
  u16 start = offset;
  ip4_header_t *ip = (ip4_header_t *)
    ((u8 *) vlib_buffer_get_current (from_b) +
     vnet_buffer (from_b)->ip.save_rewrite_length);

  /* ip4 src address */
  clib_memcpy (to_b->data + offset, &ip->src_address, sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* ip4 dst address */
  clib_memcpy (to_b->data + offset, &ip->dst_address, sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

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
 * @param which protocol L2, IP4 or IP6
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

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  /* Add data, unless we're flushing stale data */
  if (PREDICT_TRUE (do_flush == 0))
    {
      u32 start = offset;
      offset += flowperpkt_common_add (b0, data_b, offset, timestamp, length);
      if (flags & FLOW_RECORD_L2)
	offset += flowperpkt_l2_add (b0, data_b, offset);
      if (collect_ip6)
	offset += flowperpkt_l3_ip6_add (b0, data_b, offset);
      if (collect_ip4)
	offset += flowperpkt_l3_ip4_add (b0, data_b, offset);

      b0->current_length += offset - start;
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

#endif /* __included_flowperpkt_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

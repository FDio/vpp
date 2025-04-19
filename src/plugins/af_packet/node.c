/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
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
 *------------------------------------------------------------------
 */

#include <linux/if_packet.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/packet.h>

#include <af_packet/af_packet.h>
#include <vnet/devices/virtio/virtio_std.h>

#define foreach_af_packet_input_error                                         \
  _ (PARTIAL_PKT, "partial packet")                                           \
  _ (TIMEDOUT_BLK, "timed out block")                                         \
  _ (TOTAL_RECV_BLK, "total received block")
typedef enum
{
#define _(f,s) AF_PACKET_INPUT_ERROR_##f,
  foreach_af_packet_input_error
#undef _
    AF_PACKET_INPUT_N_ERROR,
} af_packet_input_error_t;

static char *af_packet_input_error_strings[] = {
#define _(n,s) s,
  foreach_af_packet_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 queue_id;
  int block;
  u32 pkt_num;
  void *block_start;
  block_desc_t bd;
  union
  {
    tpacket3_hdr_t tph3;
    tpacket2_hdr_t tph2;
  };
  vnet_virtio_net_hdr_t vnet_hdr;
  u8 is_v3;
} af_packet_input_trace_t;

static u8 *
format_af_packet_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  af_packet_input_trace_t *t = va_arg (*args, af_packet_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "af_packet: hw_if_index %d rx-queue %u next-index %d",
	      t->hw_if_index, t->queue_id, t->next_index);

  if (t->is_v3)
    {
      s = format (
	s, "\n%Ublock %u:\n%Uaddress %p version %u seq_num %lu pkt_num %u",
	format_white_space, indent + 2, t->block, format_white_space,
	indent + 4, t->block_start, t->bd.version, t->bd.hdr.bh1.seq_num,
	t->pkt_num);
      s = format (
	s,
	"\n%Utpacket3_hdr:\n%Ustatus 0x%x len %u snaplen %u mac %u net %u"
	"\n%Usec 0x%x nsec 0x%x vlan %U"
#ifdef TP_STATUS_VLAN_TPID_VALID
	" vlan_tpid %u"
#endif
	,
	format_white_space, indent + 2, format_white_space, indent + 4,
	t->tph3.tp_status, t->tph3.tp_len, t->tph3.tp_snaplen, t->tph3.tp_mac,
	t->tph3.tp_net, format_white_space, indent + 4, t->tph3.tp_sec,
	t->tph3.tp_nsec, format_ethernet_vlan_tci, t->tph3.hv1.tp_vlan_tci
#ifdef TP_STATUS_VLAN_TPID_VALID
	,
	t->tph3.hv1.tp_vlan_tpid
#endif
      );
    }
  else
    {
      s = format (
	s,
	"\n%Utpacket2_hdr:\n%Ustatus 0x%x len %u snaplen %u mac %u net %u"
	"\n%Usec 0x%x nsec 0x%x vlan %U"
#ifdef TP_STATUS_VLAN_TPID_VALID
	" vlan_tpid %u"
#endif
	,
	format_white_space, indent + 2, format_white_space, indent + 4,
	t->tph2.tp_status, t->tph2.tp_len, t->tph2.tp_snaplen, t->tph2.tp_mac,
	t->tph2.tp_net, format_white_space, indent + 4, t->tph2.tp_sec,
	t->tph2.tp_nsec, format_ethernet_vlan_tci, t->tph2.tp_vlan_tci
#ifdef TP_STATUS_VLAN_TPID_VALID
	,
	t->tph2.tp_vlan_tpid
#endif
      );
    }

  s = format (s,
	      "\n%Uvnet-hdr:\n%Uflags 0x%02x gso_type 0x%02x hdr_len %u"
	      "\n%Ugso_size %u csum_start %u csum_offset %u",
	      format_white_space, indent + 2, format_white_space, indent + 4,
	      t->vnet_hdr.flags, t->vnet_hdr.gso_type, t->vnet_hdr.hdr_len,
	      format_white_space, indent + 4, t->vnet_hdr.gso_size,
	      t->vnet_hdr.csum_start, t->vnet_hdr.csum_offset);
  return s;
}

always_inline void
buffer_add_to_chain (vlib_buffer_t *b, vlib_buffer_t *first_b,
		     vlib_buffer_t *prev_b, u32 bi)
{
  /* update first buffer */
  first_b->total_length_not_including_first_buffer += b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = ~0;
}

static_always_inline void
fill_gso_offload (vlib_buffer_t *b, u32 gso_size, u8 l4_hdr_sz)
{
  b->flags |= VNET_BUFFER_F_GSO;
  vnet_buffer2 (b)->gso_size = gso_size;
  vnet_buffer2 (b)->gso_l4_hdr_sz = l4_hdr_sz;
}

static_always_inline void
fill_cksum_offload (vlib_buffer_t *b, u8 *l4_hdr_sz, u8 is_ip)
{
  vnet_buffer_oflags_t oflags = 0;
  u16 l2hdr_sz = 0;
  u16 ethertype = 0;
  u8 l4_proto = 0;

  if (is_ip)
    {
      switch (b->data[0] & 0xf0)
	{
	case 0x40:
	  ethertype = ETHERNET_TYPE_IP4;
	  break;
	case 0x60:
	  ethertype = ETHERNET_TYPE_IP6;
	  break;
	}
    }
  else
    {
      ethernet_header_t *eth = (ethernet_header_t *) b->data;
      ethertype = clib_net_to_host_u16 (eth->type);
      l2hdr_sz = sizeof (ethernet_header_t);
      if (ethernet_frame_is_tagged (ethertype))
	{
	  ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eth + 1);

	  ethertype = clib_net_to_host_u16 (vlan->type);
	  l2hdr_sz += sizeof (*vlan);
	  if (ethertype == ETHERNET_TYPE_VLAN)
	    {
	      vlan++;
	      ethertype = clib_net_to_host_u16 (vlan->type);
	      l2hdr_sz += sizeof (*vlan);
	    }
	}
    }

  vnet_buffer (b)->l2_hdr_offset = 0;
  vnet_buffer (b)->l3_hdr_offset = l2hdr_sz;

  if (ethertype == ETHERNET_TYPE_IP4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) (b->data + l2hdr_sz);
      vnet_buffer (b)->l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      b->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L4_HDR_OFFSET_VALID);

      l4_proto = ip4->protocol;
    }
  else if (ethertype == ETHERNET_TYPE_IP6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) (b->data + l2hdr_sz);
      b->flags |= (VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
      u16 ip6_hdr_len = sizeof (ip6_header_t);

      if (ip6_ext_hdr (ip6->protocol))
	{
	  ip6_ext_header_t *p = (void *) (ip6 + 1);
	  ip6_hdr_len += ip6_ext_header_len (p);
	  while (ip6_ext_hdr (p->next_hdr))
	    {
	      ip6_hdr_len += ip6_ext_header_len (p);
	      p = ip6_ext_next_header (p);
	    }
	  l4_proto = p->next_hdr;
	}
      else
	l4_proto = ip6->protocol;
      vnet_buffer (b)->l4_hdr_offset = l2hdr_sz + ip6_hdr_len;
    }

  if (l4_proto == IP_PROTOCOL_TCP)
    {
      oflags |= VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
      tcp_header_t *tcp =
	(tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
      *l4_hdr_sz = tcp_header_bytes (tcp);
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
      *l4_hdr_sz = sizeof (udp_header_t);
    }

  if (oflags)
    vnet_buffer_offload_flags_set (b, oflags);
}

always_inline uword
af_packet_v3_device_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame, af_packet_if_t *apif,
			      u16 queue_id, u8 is_cksum_gso_enabled)
{
  af_packet_main_t *apm = &af_packet_main;
  af_packet_queue_t *rx_queue = vec_elt_at_index (apif->rx_queues, queue_id);
  tpacket3_hdr_t *tph;
  u32 next_index;
  u32 n_free_bufs;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 timedout_blk = 0;
  u32 total = 0;
  u32 *to_next = 0;
  u32 block = rx_queue->next_rx_block;
  u32 block_nr = rx_queue->rx_req->req3.tp_block_nr;
  u8 *block_start = 0;
  uword n_trace = vlib_get_trace_count (vm, node);
  clib_thread_index_t thread_index = vm->thread_index;
  u32 n_buffer_bytes = vlib_buffer_get_default_data_size (vm);
  u32 min_bufs = rx_queue->rx_req->req3.tp_frame_size / n_buffer_bytes;
  u32 num_pkts = 0;
  u32 rx_frame_offset = 0;
  block_desc_t *bd = 0;
  u32 sw_if_index = apif->sw_if_index;
  u8 is_ip = (apif->mode == AF_PACKET_IF_MODE_IP);

  if (is_ip)
    next_index = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
  else
    next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  if ((((block_desc_t *) (block_start = rx_queue->rx_ring[block]))
	 ->hdr.bh1.block_status &
       TP_STATUS_USER) != 0)
    {
      u32 n_required = 0;
      bd = (block_desc_t *) block_start;

      if (PREDICT_FALSE (rx_queue->is_rx_pending))
	{
	  num_pkts = rx_queue->num_rx_pkts;
	  rx_frame_offset = rx_queue->rx_frame_offset;
	  rx_queue->is_rx_pending = 0;
	}
      else
	{
	  num_pkts = bd->hdr.bh1.num_pkts;
	  rx_frame_offset = bd->hdr.bh1.offset_to_first_pkt;
	  total++;

	  if (TP_STATUS_BLK_TMO & bd->hdr.bh1.block_status)
	    timedout_blk++;
	}

      n_required = clib_max (num_pkts, VLIB_FRAME_SIZE);
      n_free_bufs = vec_len (apm->rx_buffers[thread_index]);
      if (PREDICT_FALSE (n_free_bufs < n_required))
	{
	  vec_validate (apm->rx_buffers[thread_index],
			n_required + n_free_bufs - 1);
	  n_free_bufs += vlib_buffer_alloc (
	    vm, &apm->rx_buffers[thread_index][n_free_bufs], n_required);
	  vec_set_len (apm->rx_buffers[thread_index], n_free_bufs);
	}

      while (num_pkts && (n_free_bufs >= min_bufs))
	{
	  u32 next0 = next_index;
	  u32 n_left_to_next;

	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	  while (num_pkts && n_left_to_next && (n_free_bufs >= min_bufs))
	    {
	      tph = (tpacket3_hdr_t *) (block_start + rx_frame_offset);

	      if (num_pkts > 1)
		CLIB_PREFETCH (block_start + rx_frame_offset +
				 tph->tp_next_offset,
			       2 * CLIB_CACHE_LINE_BYTES, LOAD);

	      vlib_buffer_t *b0 = 0, *first_b0 = 0, *prev_b0 = 0;
	      vnet_virtio_net_hdr_t *vnet_hdr = 0;
	      u32 data_len = tph->tp_snaplen;
	      u32 offset = 0;
	      u32 bi0 = ~0, first_bi0 = ~0;
	      u8 l4_hdr_sz = 0;

	      if (is_cksum_gso_enabled)
		vnet_hdr =
		  (vnet_virtio_net_hdr_t *) ((u8 *) tph + tph->tp_mac -
					     sizeof (vnet_virtio_net_hdr_t));

	      // save current state and return
	      if (PREDICT_FALSE (((data_len / n_buffer_bytes) + 1) >
				 vec_len (apm->rx_buffers[thread_index])))
		{
		  rx_queue->rx_frame_offset = rx_frame_offset;
		  rx_queue->num_rx_pkts = num_pkts;
		  rx_queue->is_rx_pending = 1;
		  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		  goto done;
		}

	      while (data_len)
		{
		  /* grab free buffer */
		  u32 last_empty_buffer =
		    vec_len (apm->rx_buffers[thread_index]) - 1;
		  bi0 = apm->rx_buffers[thread_index][last_empty_buffer];
		  vec_set_len (apm->rx_buffers[thread_index],
			       last_empty_buffer);
		  n_free_bufs--;

		  /* copy data */
		  u32 bytes_to_copy =
		    data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
		  u32 vlan_len = 0;
		  u32 bytes_copied = 0;

		  b0 = vlib_get_buffer (vm, bi0);
		  b0->current_data = 0;

		  /* Kernel removes VLAN headers, so reconstruct VLAN */
		  if (PREDICT_FALSE (tph->tp_status & TP_STATUS_VLAN_VALID))
		    {
		      if (PREDICT_TRUE (offset == 0))
			{
			  clib_memcpy_fast (vlib_buffer_get_current (b0),
					    (u8 *) tph + tph->tp_mac,
					    sizeof (ethernet_header_t));
			  ethernet_header_t *eth =
			    vlib_buffer_get_current (b0);
			  ethernet_vlan_header_t *vlan =
			    (ethernet_vlan_header_t *) (eth + 1);
			  vlan->priority_cfi_and_id =
			    clib_host_to_net_u16 (tph->hv1.tp_vlan_tci);
			  vlan->type = eth->type;
			  eth->type =
			    clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
			  vlan_len = sizeof (ethernet_vlan_header_t);
			  bytes_copied = sizeof (ethernet_header_t);
			}
		    }
		  clib_memcpy_fast (((u8 *) vlib_buffer_get_current (b0)) +
				      bytes_copied + vlan_len,
				    (u8 *) tph + tph->tp_mac + offset +
				      bytes_copied,
				    (bytes_to_copy - bytes_copied));

		  /* fill buffer header */
		  b0->current_length = bytes_to_copy + vlan_len;

		  if (offset == 0)
		    {
		      b0->total_length_not_including_first_buffer = 0;
		      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		      vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index;
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;
		      first_b0 = b0;
		      first_bi0 = bi0;
		      if (is_cksum_gso_enabled)
			{
			  if (vnet_hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
			    fill_cksum_offload (first_b0, &l4_hdr_sz, is_ip);
			  if (vnet_hdr->gso_type & (VIRTIO_NET_HDR_GSO_TCPV4 |
						    VIRTIO_NET_HDR_GSO_TCPV6))
			    fill_gso_offload (first_b0, vnet_hdr->gso_size,
					      l4_hdr_sz);
			}
		    }
		  else
		    buffer_add_to_chain (b0, first_b0, prev_b0, bi0);

		  prev_b0 = b0;
		  offset += bytes_to_copy;
		  data_len -= bytes_to_copy;
		}
	      n_rx_packets++;
	      n_rx_bytes += tph->tp_snaplen;
	      to_next[0] = first_bi0;
	      to_next += 1;
	      n_left_to_next--;

	      /* drop partial packets */
	      if (PREDICT_FALSE (tph->tp_len != tph->tp_snaplen))
		{
		  next0 = VNET_DEVICE_INPUT_NEXT_DROP;
		  first_b0->error =
		    node->errors[AF_PACKET_INPUT_ERROR_PARTIAL_PKT];
		}
	      else
		{
		  if (PREDICT_FALSE (apif->mode == AF_PACKET_IF_MODE_IP))
		    {
		      switch (first_b0->data[0] & 0xf0)
			{
			case 0x40:
			  next0 = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
			  break;
			case 0x60:
			  next0 = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
			  break;
			default:
			  next0 = VNET_DEVICE_INPUT_NEXT_DROP;
			  break;
			}
		      if (PREDICT_FALSE (apif->per_interface_next_index != ~0))
			next0 = apif->per_interface_next_index;
		    }
		  else
		    {
		      next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
		      if (PREDICT_FALSE (apif->per_interface_next_index != ~0))
			next0 = apif->per_interface_next_index;
		      /* redirect if feature path enabled */
		      vnet_feature_start_device_input (sw_if_index, &next0,
						       first_b0);
		    }
		}

	      /* trace */
	      if (PREDICT_FALSE (n_trace > 0 &&
				 vlib_trace_buffer (vm, node, next0, first_b0,
						    /* follow_chain */ 0)))
		{
		  af_packet_input_trace_t *tr;
		  vlib_set_trace_count (vm, node, --n_trace);
		  tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
		  tr->is_v3 = 1;
		  tr->next_index = next0;
		  tr->hw_if_index = apif->hw_if_index;
		  tr->queue_id = queue_id;
		  tr->block = block;
		  tr->block_start = bd;
		  tr->pkt_num = bd->hdr.bh1.num_pkts - num_pkts;
		  clib_memcpy_fast (&tr->bd, bd, sizeof (block_desc_t));
		  clib_memcpy_fast (&tr->tph3, tph, sizeof (tpacket3_hdr_t));
		  if (is_cksum_gso_enabled)
		    clib_memcpy_fast (&tr->vnet_hdr, vnet_hdr,
				      sizeof (vnet_virtio_net_hdr_t));
		  else
		    clib_memset_u8 (&tr->vnet_hdr, 0,
				    sizeof (vnet_virtio_net_hdr_t));
		}

	      /* enque and take next packet */
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, first_bi0,
					       next0);

	      /* next packet */
	      num_pkts--;
	      rx_frame_offset += tph->tp_next_offset;
	    }

	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}

      if (PREDICT_TRUE (num_pkts == 0))
	{
	  bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
	  block = (block + 1) % block_nr;
	}
      else
	{
	  rx_queue->rx_frame_offset = rx_frame_offset;
	  rx_queue->num_rx_pkts = num_pkts;
	  rx_queue->is_rx_pending = 1;
	}
    }

  rx_queue->next_rx_block = block;

done:

  if (apm->polling_count == 0)
    {
      if ((((block_desc_t *) (block_start = rx_queue->rx_ring[block]))
	     ->hdr.bh1.block_status &
	   TP_STATUS_USER) != 0)
	vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_POLLING);
      else
	vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_INTERRUPT);
    }

  vlib_error_count (vm, node->node_index, AF_PACKET_INPUT_ERROR_TOTAL_RECV_BLK,
		    total);
  vlib_error_count (vm, node->node_index, AF_PACKET_INPUT_ERROR_TIMEDOUT_BLK,
		    timedout_blk);

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_get_thread_index (), apif->hw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);
  return n_rx_packets;
}

always_inline uword
af_packet_v2_device_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame, af_packet_if_t *apif,
			      u16 queue_id, u8 is_cksum_gso_enabled)
{
  af_packet_main_t *apm = &af_packet_main;
  af_packet_queue_t *rx_queue = vec_elt_at_index (apif->rx_queues, queue_id);
  tpacket2_hdr_t *tph;
  u32 next_index;
  u32 block = 0;
  u32 rx_frame;
  u32 n_free_bufs;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 frame_size = rx_queue->rx_req->req.tp_frame_size;
  u32 frame_num = rx_queue->rx_req->req.tp_frame_nr;
  u8 *block_start = rx_queue->rx_ring[block];
  uword n_trace = vlib_get_trace_count (vm, node);
  clib_thread_index_t thread_index = vm->thread_index;
  u32 n_buffer_bytes = vlib_buffer_get_default_data_size (vm);
  u32 min_bufs = rx_queue->rx_req->req.tp_frame_size / n_buffer_bytes;
  u32 sw_if_index = apif->sw_if_index;
  u8 is_ip = (apif->mode == AF_PACKET_IF_MODE_IP);

  if (is_ip)
    next_index = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
  else
    next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  n_free_bufs = vec_len (apm->rx_buffers[thread_index]);
  if (PREDICT_FALSE (n_free_bufs < VLIB_FRAME_SIZE))
    {
      vec_validate (apm->rx_buffers[thread_index],
		    VLIB_FRAME_SIZE + n_free_bufs - 1);
      n_free_bufs += vlib_buffer_alloc (
	vm, &apm->rx_buffers[thread_index][n_free_bufs], VLIB_FRAME_SIZE);
      vec_set_len (apm->rx_buffers[thread_index], n_free_bufs);
    }

  rx_frame = rx_queue->next_rx_frame;
  tph = (tpacket2_hdr_t *) (block_start + rx_frame * frame_size);
  while ((tph->tp_status & TP_STATUS_USER) && (n_free_bufs > min_bufs))
    {
      vlib_buffer_t *b0 = 0, *first_b0 = 0, *prev_b0 = 0;
      u32 next0 = next_index;

      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while ((tph->tp_status & TP_STATUS_USER) && (n_free_bufs > min_bufs) &&
	     n_left_to_next)
	{
	  vnet_virtio_net_hdr_t *vnet_hdr = 0;
	  u32 data_len = tph->tp_snaplen;
	  u32 offset = 0;
	  u32 bi0 = 0, first_bi0 = 0;
	  u8 l4_hdr_sz = 0;

	  if (is_cksum_gso_enabled)
	    vnet_hdr =
	      (vnet_virtio_net_hdr_t *) ((u8 *) tph + tph->tp_mac -
					 sizeof (vnet_virtio_net_hdr_t));
	  while (data_len)
	    {
	      /* grab free buffer */
	      u32 last_empty_buffer =
		vec_len (apm->rx_buffers[thread_index]) - 1;
	      bi0 = apm->rx_buffers[thread_index][last_empty_buffer];
	      b0 = vlib_get_buffer (vm, bi0);
	      vec_set_len (apm->rx_buffers[thread_index], last_empty_buffer);
	      n_free_bufs--;

	      /* copy data */
	      u32 bytes_to_copy =
		data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
	      u32 vlan_len = 0;
	      u32 bytes_copied = 0;
	      b0->current_data = 0;
	      /* Kernel removes VLAN headers, so reconstruct VLAN */
	      if (PREDICT_FALSE (tph->tp_status & TP_STATUS_VLAN_VALID))
		{
		  if (PREDICT_TRUE (offset == 0))
		    {
		      clib_memcpy_fast (vlib_buffer_get_current (b0),
					(u8 *) tph + tph->tp_mac,
					sizeof (ethernet_header_t));
		      ethernet_header_t *eth = vlib_buffer_get_current (b0);
		      ethernet_vlan_header_t *vlan =
			(ethernet_vlan_header_t *) (eth + 1);
		      vlan->priority_cfi_and_id =
			clib_host_to_net_u16 (tph->tp_vlan_tci);
		      vlan->type = eth->type;
		      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
		      vlan_len = sizeof (ethernet_vlan_header_t);
		      bytes_copied = sizeof (ethernet_header_t);
		    }
		}
	      clib_memcpy_fast (((u8 *) vlib_buffer_get_current (b0)) +
				  bytes_copied + vlan_len,
				(u8 *) tph + tph->tp_mac + offset +
				  bytes_copied,
				(bytes_to_copy - bytes_copied));

	      /* fill buffer header */
	      b0->current_length = bytes_to_copy + vlan_len;

	      if (offset == 0)
		{
		  b0->total_length_not_including_first_buffer = 0;
		  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index;
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;
		  first_bi0 = bi0;
		  first_b0 = vlib_get_buffer (vm, first_bi0);

		  if (is_cksum_gso_enabled)
		    {
		      if (vnet_hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
			fill_cksum_offload (first_b0, &l4_hdr_sz, is_ip);
		      if (vnet_hdr->gso_type & (VIRTIO_NET_HDR_GSO_TCPV4 |
						VIRTIO_NET_HDR_GSO_TCPV6))
			fill_gso_offload (first_b0, vnet_hdr->gso_size,
					  l4_hdr_sz);
		    }
		}
	      else
		buffer_add_to_chain (b0, first_b0, prev_b0, bi0);

	      prev_b0 = b0;
	      offset += bytes_to_copy;
	      data_len -= bytes_to_copy;
	    }
	  n_rx_packets++;
	  n_rx_bytes += tph->tp_snaplen;
	  to_next[0] = first_bi0;
	  to_next += 1;
	  n_left_to_next--;

	  /* drop partial packets */
	  if (PREDICT_FALSE (tph->tp_len != tph->tp_snaplen))
	    {
	      next0 = VNET_DEVICE_INPUT_NEXT_DROP;
	      first_b0->error =
		node->errors[AF_PACKET_INPUT_ERROR_PARTIAL_PKT];
	    }
	  else
	    {
	      if (PREDICT_FALSE (is_ip))
		{
		  switch (first_b0->data[0] & 0xf0)
		    {
		    case 0x40:
		      next0 = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
		      break;
		    case 0x60:
		      next0 = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
		      break;
		    default:
		      next0 = VNET_DEVICE_INPUT_NEXT_DROP;
		      break;
		    }
		  if (PREDICT_FALSE (apif->per_interface_next_index != ~0))
		    next0 = apif->per_interface_next_index;
		}
	      else
		{
		  next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
		  if (PREDICT_FALSE (apif->per_interface_next_index != ~0))
		    next0 = apif->per_interface_next_index;
		  /* redirect if feature path enabled */
		  vnet_feature_start_device_input (sw_if_index, &next0,
						   first_b0);
		}
	    }

	  /* trace */
	  if (PREDICT_FALSE (n_trace > 0 &&
			     vlib_trace_buffer (vm, node, next0, first_b0,
						/* follow_chain */ 0)))
	    {
	      af_packet_input_trace_t *tr;
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
	      tr->is_v3 = 0;
	      tr->next_index = next0;
	      tr->hw_if_index = apif->hw_if_index;
	      tr->queue_id = queue_id;
	      clib_memcpy_fast (&tr->tph2, tph, sizeof (struct tpacket2_hdr));
	      if (is_cksum_gso_enabled)
		clib_memcpy_fast (&tr->vnet_hdr, vnet_hdr,
				  sizeof (vnet_virtio_net_hdr_t));
	      else
		clib_memset_u8 (&tr->vnet_hdr, 0,
				sizeof (vnet_virtio_net_hdr_t));
	    }

	  /* enque and take next packet */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, first_bi0, next0);

	  /* next packet */
	  tph->tp_status = TP_STATUS_KERNEL;
	  rx_frame = (rx_frame + 1) % frame_num;
	  tph = (struct tpacket2_hdr *) (block_start + rx_frame * frame_size);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  rx_queue->next_rx_frame = rx_frame;

  vlib_increment_combined_counter (
    vnet_get_main ()->interface_main.combined_sw_if_counters +
      VNET_INTERFACE_COUNTER_RX,
    vlib_get_thread_index (), apif->hw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);
  return n_rx_packets;
}

always_inline uword
af_packet_device_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame, af_packet_if_t *apif,
			   u16 queue_id, u8 is_cksum_gso_enabled)

{
  if (apif->version == TPACKET_V3)
    return af_packet_v3_device_input_fn (vm, node, frame, apif, queue_id,
					 is_cksum_gso_enabled);
  else
    return af_packet_v2_device_input_fn (vm, node, frame, apif, queue_id,
					 is_cksum_gso_enabled);
}

VLIB_NODE_FN (af_packet_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  u32 n_rx_packets = 0;
  af_packet_main_t *apm = &af_packet_main;
  vnet_hw_if_rxq_poll_vector_t *pv;
  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);
  for (int i = 0; i < vec_len (pv); i++)
    {
      af_packet_if_t *apif;
      apif = vec_elt_at_index (apm->interfaces, pv[i].dev_instance);
      if (apif->is_admin_up)
	{
	  if (apif->is_cksum_gso_enabled)
	    n_rx_packets += af_packet_device_input_fn (vm, node, frame, apif,
						       pv[i].queue_id, 1);
	  else
	    n_rx_packets += af_packet_device_input_fn (vm, node, frame, apif,
						       pv[i].queue_id, 0);
	}
    }
  return n_rx_packets;
}

VLIB_REGISTER_NODE (af_packet_input_node) = {
  .name = "af-packet-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .sibling_of = "device-input",
  .format_trace = format_af_packet_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = AF_PACKET_INPUT_N_ERROR,
  .error_strings = af_packet_input_error_strings,
};


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

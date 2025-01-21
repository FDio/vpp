/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include "af_xdp.h"

#define foreach_af_xdp_input_error                                            \
  _ (SYSCALL_REQUIRED, "syscall required")                                    \
  _ (SYSCALL_FAILURES, "syscall failures")

typedef enum
{
#define _(f,s) AF_XDP_INPUT_ERROR_##f,
  foreach_af_xdp_input_error
#undef _
    AF_XDP_INPUT_N_ERROR,
} af_xdp_input_error_t;

static __clib_unused char *af_xdp_input_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_input_error
#undef _
};

static_always_inline void
af_xdp_device_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			   u32 n_left, const u32 * bi, u32 next_index,
			   u32 hw_if_index)
{
  u32 n_trace = vlib_get_trace_count (vm, node);

  if (PREDICT_TRUE (0 == n_trace))
    return;

  while (n_trace && n_left)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b,
					   /* follow_chain */ 1)))
	{
	  af_xdp_input_trace_t *tr =
	    vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next_index;
	  tr->hw_if_index = hw_if_index;
	  n_trace--;
	}
      n_left--;
      bi++;
    }

  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline void
af_xdp_device_input_refill_db (vlib_main_t * vm,
			       const vlib_node_runtime_t * node,
			       af_xdp_device_t * ad, af_xdp_rxq_t * rxq,
			       const u32 n_alloc)
{
  xsk_ring_prod__submit (&rxq->fq, n_alloc);

  if (AF_XDP_RXQ_MODE_INTERRUPT == rxq->mode ||
      !xsk_ring_prod__needs_wakeup (&rxq->fq))
    return;

  if (node)
    vlib_error_count (vm, node->node_index,
		      AF_XDP_INPUT_ERROR_SYSCALL_REQUIRED, 1);

  if (clib_spinlock_trylock_if_init (&rxq->syscall_lock))
    {
      int ret = recvmsg (rxq->xsk_fd, 0, MSG_DONTWAIT);
      clib_spinlock_unlock_if_init (&rxq->syscall_lock);
      if (PREDICT_FALSE (ret < 0))
	{
	  /* something bad is happening */
	  if (node)
	    vlib_error_count (vm, node->node_index,
			      AF_XDP_INPUT_ERROR_SYSCALL_FAILURES, 1);
	  af_xdp_device_error (ad, "rx poll() failed");
	}
    }
}

static_always_inline void
af_xdp_device_input_refill_inline (vlib_main_t *vm,
				   const vlib_node_runtime_t *node,
				   af_xdp_device_t *ad, af_xdp_rxq_t *rxq)
{
  __u64 *fill;
  const u32 size = rxq->fq.size;
  const u32 mask = size - 1;
  u32 bis[VLIB_FRAME_SIZE], *bi = bis;
  u32 n_alloc, n, n_wrap;
  u32 idx = 0;

  ASSERT (mask == rxq->fq.mask);

  /* do not enqueue more packet than ring space */
  n_alloc = xsk_prod_nb_free (&rxq->fq, 16);
  /* do not bother to allocate if too small */
  if (n_alloc < 16)
    return;

  n_alloc = clib_min (n_alloc, ARRAY_LEN (bis));
  n_alloc = vlib_buffer_alloc_from_pool (vm, bis, n_alloc, ad->pool);
  n = xsk_ring_prod__reserve (&rxq->fq, n_alloc, &idx);
  ASSERT (n == n_alloc);

  fill = xsk_ring_prod__fill_addr (&rxq->fq, idx);
  n = clib_min (n_alloc, size - (idx & mask));
  n_wrap = n_alloc - n;

#define bi2addr(bi) ((bi) << CLIB_LOG2_CACHE_LINE_BYTES)

wrap_around:

  while (n >= 8)
    {
#ifdef CLIB_HAVE_VEC256
      u64x4 b0 = u64x4_from_u32x4 (*(u32x4u *) (bi + 0));
      u64x4 b1 = u64x4_from_u32x4 (*(u32x4u *) (bi + 4));
      *(u64x4u *) (fill + 0) = bi2addr (b0);
      *(u64x4u *) (fill + 4) = bi2addr (b1);
#else
      fill[0] = bi2addr (bi[0]);
      fill[1] = bi2addr (bi[1]);
      fill[2] = bi2addr (bi[2]);
      fill[3] = bi2addr (bi[3]);
      fill[4] = bi2addr (bi[4]);
      fill[5] = bi2addr (bi[5]);
      fill[6] = bi2addr (bi[6]);
      fill[7] = bi2addr (bi[7]);
#endif
      fill += 8;
      bi += 8;
      n -= 8;
    }

  while (n >= 1)
    {
      fill[0] = bi2addr (bi[0]);
      fill += 1;
      bi += 1;
      n -= 1;
    }

  if (n_wrap)
    {
      fill = xsk_ring_prod__fill_addr (&rxq->fq, 0);
      n = n_wrap;
      n_wrap = 0;
      goto wrap_around;
    }

  af_xdp_device_input_refill_db (vm, node, ad, rxq, n_alloc);
}

static_always_inline void
af_xdp_device_input_ethernet (vlib_main_t * vm, vlib_node_runtime_t * node,
			      const u32 next_index, const u32 sw_if_index,
			      const u32 hw_if_index)
{
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  ethernet_input_frame_t *ef;

  if (PREDICT_FALSE (VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT != next_index))
    return;

  nf =
    vlib_node_runtime_get_next_frame (vm, node,
				      VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT);
  f = vlib_get_frame (vm, nf->frame);
  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = sw_if_index;
  ef->hw_if_index = hw_if_index;
  vlib_frame_no_append (f);
}

static_always_inline void
af_xdp_needs_csum (vlib_buffer_t *b0)
{
  u16 ethertype = 0, l2hdr_sz = 0;
  vnet_buffer_oflags_t oflags = 0;
  u8 l4_proto = 0;

  ethernet_header_t *eh = vlib_buffer_get_current (b0);
  ethertype = clib_net_to_host_u16 (eh->type);
  l2hdr_sz = sizeof (*eh);

  if (ethernet_frame_is_tagged (ethertype))
    {
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eh + 1);

      ethertype = clib_net_to_host_u16 (vlan->type);
      l2hdr_sz += sizeof (*vlan);
      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  vlan++;
	  ethertype = clib_net_to_host_u16 (vlan->type);
	  l2hdr_sz += sizeof (*vlan);
	}
    }

  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
  vnet_buffer (b0)->l3_hdr_offset = vnet_buffer (b0)->l2_hdr_offset + l2hdr_sz;

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 = (ip4_header_t *) ((u8 *) eh + l2hdr_sz);
      vnet_buffer (b0)->l4_hdr_offset =
	vnet_buffer (b0)->l3_hdr_offset + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
      b0->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 = (ip6_header_t *) ((u8 *) eh + l2hdr_sz);
      vnet_buffer (b0)->l4_hdr_offset =
	vnet_buffer (b0)->l3_hdr_offset + sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
      b0->flags |= (VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    }

  if (l4_proto == IP_PROTOCOL_TCP)
    oflags |= VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
  else if (l4_proto == IP_PROTOCOL_UDP)
    oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;

  if (oflags)
    vnet_buffer_offload_flags_set (b0, oflags);
}

static_always_inline u32
af_xdp_device_input_bufs (vlib_main_t *vm, const af_xdp_device_t *ad,
			  af_xdp_rxq_t *rxq, u32 *to_next, u32 n_descs,
			  vlib_buffer_t *bt, u32 idx, int csum_enabled,
			  u32 *n_pkts)
{
  u32 options[VLIB_FRAME_SIZE];
  u32 bis[VLIB_FRAME_SIZE];
  u16 lens[VLIB_FRAME_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 offs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 *off = offs;
  u32 *option = options;
  u16 *len = lens;
  const u32 mask = rxq->rx.mask;
  u32 n = n_descs, *bi = bis, bytes = 0, n_rx_packets = 0, last_eop, rollback;

#define addr2bi(addr) ((addr) >> CLIB_LOG2_CACHE_LINE_BYTES)

  for (u32 i = 1; i <= n; i++)
    {
      const struct xdp_desc *desc = xsk_ring_cons__rx_desc (&rxq->rx, idx);
      const u64 addr = desc->addr;
      bi[0] = addr2bi (xsk_umem__extract_addr (addr));
      ASSERT (vlib_buffer_is_known (vm, bi[0]) ==
	      VLIB_BUFFER_KNOWN_ALLOCATED);
      off[0] = xsk_umem__extract_offset (addr) - sizeof (vlib_buffer_t);
      if (desc->options & XDP_PKT_CONTD)
	option[0] = VLIB_BUFFER_NEXT_PRESENT;
      else
	{
	  option[0] = 0;
	  last_eop = i;
	}
      len[0] = desc->len;
      idx = (idx + 1) & mask;
      bi += 1;
      off += 1;
      option += 1;
      len += 1;
    }

  /* Rollback some descriptors if we have a partial packet at the end */
  rollback = n - last_eop;
  n_descs -= rollback;

  vlib_get_buffers (vm, bis, bufs, n_descs);

  n = n_descs;
  off = offs;
  option = options;
  bi = bis;
  len = lens;

  while (n >= 8)
    {
      if ((option[0] & VLIB_BUFFER_NEXT_PRESENT) ||
	  (option[1] & VLIB_BUFFER_NEXT_PRESENT) ||
	  (option[2] & VLIB_BUFFER_NEXT_PRESENT) ||
	  (option[3] & VLIB_BUFFER_NEXT_PRESENT))
	break;

      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_buffer_copy_template (b[0], bt);
      b[0]->current_data = off[0];
      b[0]->flags |= option[0];
      if (csum_enabled)
	af_xdp_needs_csum (b[0]);
      bytes += b[0]->current_length = len[0];

      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_buffer_copy_template (b[1], bt);
      b[1]->current_data = off[1];
      b[1]->flags |= option[1];
      if (csum_enabled)
	af_xdp_needs_csum (b[1]);
      bytes += b[1]->current_length = len[1];

      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_buffer_copy_template (b[2], bt);
      b[2]->current_data = off[2];
      b[2]->flags |= option[2];
      if (csum_enabled)
	af_xdp_needs_csum (b[2]);
      bytes += b[2]->current_length = len[2];

      vlib_prefetch_buffer_header (b[7], LOAD);
      vlib_buffer_copy_template (b[3], bt);
      b[3]->current_data = off[3];
      b[3]->flags |= option[3];
      if (csum_enabled)
	af_xdp_needs_csum (b[3]);
      bytes += b[3]->current_length = len[3];

      to_next[0] = bi[0];
      to_next[1] = bi[1];
      to_next[2] = bi[2];
      to_next[3] = bi[3];

      to_next += 4;
      bi += 4;
      b += 4;
      off += 4;
      option += 4;
      len += 4;
      n -= 4;
      n_rx_packets += 4;
    }

  while (n >= 1)
    {
      vlib_buffer_copy_template (b[0], bt);
      b[0]->current_data = off[0];
      bytes += b[0]->current_length = len[0];

      if (csum_enabled)
	af_xdp_needs_csum (b[0]);

      vlib_buffer_t *b0 = b[0];
      to_next[0] = bi[0];
      to_next += 1;
      while ((option[0] & VLIB_BUFFER_NEXT_PRESENT) && (n >= 1))
	{
	  vlib_buffer_t *pb = b[0];

	  /* advance */
	  b += 1;
	  bi += 1;
	  len += 1;
	  off += 1;
	  option += 1;
	  n -= 1;

	  /* current buffer */
	  vlib_buffer_copy_template (b[0], bt);
	  b[0]->current_data = off[0];
	  bytes += b[0]->current_length = len[0];

	  /* previous buffer */
	  pb->next_buffer = bi[0];
	  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;

	  /* first buffer */
	  b0->total_length_not_including_first_buffer += len[0];
	}

      b += 1;
      off += 1;
      option += 1;
      bi += 1;
      len += 1;
      n -= 1;
      n_rx_packets += 1;
    }

  xsk_ring_cons__cancel (&rxq->rx, rollback);
  xsk_ring_cons__release (&rxq->rx, n_descs);
  ASSERT (n_rx_packets <= n_descs);
  *n_pkts = n_rx_packets;

  return bytes;
}

static_always_inline uword
af_xdp_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			    vlib_frame_t *frame, af_xdp_device_t *ad, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  vlib_buffer_t bt;
  u32 next_index, *to_next, n_left_to_next;
  u32 n_descs, n_rx_bytes, n_pkts = 0;
  u32 idx;
  int csum_enabled = ad->flags & AF_XDP_DEVICE_F_CSUM_ENABLED;

  n_descs = xsk_ring_cons__peek (&rxq->rx, VLIB_FRAME_SIZE, &idx);

  if (PREDICT_FALSE (0 == n_descs))
    goto refill;

  vlib_buffer_copy_template (&bt, ad->buffer_template);
  next_index = ad->per_interface_next_index;
  if (PREDICT_FALSE (vnet_device_input_have_features (ad->sw_if_index)))
    vnet_feature_start_device_input (ad->sw_if_index, &next_index, &bt);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (csum_enabled)
    n_rx_bytes = af_xdp_device_input_bufs (vm, ad, rxq, to_next, n_descs, &bt,
					   idx, 1, &n_pkts);
  else
    n_rx_bytes = af_xdp_device_input_bufs (vm, ad, rxq, to_next, n_descs, &bt,
					   idx, 0, &n_pkts);
  af_xdp_device_input_ethernet (vm, node, next_index, ad->sw_if_index,
				ad->hw_if_index);

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_pkts);

  af_xdp_device_input_trace (vm, node, n_pkts, to_next, next_index,
			     ad->hw_if_index);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, ad->hw_if_index, n_pkts, n_rx_bytes);

refill:
  af_xdp_device_input_refill_inline (vm, node, ad, rxq);

  return n_pkts;
}

VLIB_NODE_FN (af_xdp_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_rx = 0;
  af_xdp_main_t *am = &af_xdp_main;
  vnet_hw_if_rxq_poll_vector_t *p,
    *pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  vec_foreach (p, pv)
    {
      af_xdp_device_t *ad = vec_elt_at_index (am->devices, p->dev_instance);
      if ((ad->flags & AF_XDP_DEVICE_F_ADMIN_UP) == 0)
	continue;
      n_rx += af_xdp_device_input_inline (vm, node, frame, ad, p->queue_id);
    }

  return n_rx;
}

#ifndef CLIB_MARCH_VARIANT
void
af_xdp_device_input_refill (af_xdp_device_t *ad)
{
  vlib_main_t *vm = vlib_get_main ();
  af_xdp_rxq_t *rxq;
  vec_foreach (rxq, ad->rxqs)
    af_xdp_device_input_refill_inline (vm, 0, ad, rxq);
}
#endif /* CLIB_MARCH_VARIANT */

VLIB_REGISTER_NODE (af_xdp_input_node) = {
  .name = "af_xdp-input",
  .sibling_of = "device-input",
  .format_trace = format_af_xdp_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AF_XDP_INPUT_N_ERROR,
  .error_strings = af_xdp_input_error_strings,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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

#include <poll.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/rx_queue_funcs.h>
#include "af_xdp.h"

#define foreach_af_xdp_input_error \
  _(POLL_REQUIRED, "poll required") \
  _(POLL_FAILURES, "poll failures")

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
      if (PREDICT_TRUE
	  (vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0)))
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
  int ret;

  xsk_ring_prod__submit (&rxq->fq, n_alloc);

  if (!xsk_ring_prod__needs_wakeup (&rxq->fq))
    return;

  vlib_error_count (vm, node->node_index, AF_XDP_INPUT_ERROR_POLL_REQUIRED,
		    1);

  struct pollfd fd = {.fd = rxq->xsk_fd,.events = POLLIN };
  ret = poll (&fd, 1, 0);
  if (PREDICT_TRUE (ret >= 0))
    return;

  /* something bad is happening */
  vlib_error_count (vm, node->node_index, AF_XDP_INPUT_ERROR_POLL_FAILURES,
		    1);
  af_xdp_device_error (ad, "poll() failed");
}

static_always_inline void
af_xdp_device_input_refill (vlib_main_t * vm,
			    const vlib_node_runtime_t * node,
			    af_xdp_device_t * ad, af_xdp_rxq_t * rxq,
			    const int copy)
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

  /*
   * Note about headroom: for some reasons, there seem to be a discrepency
   * between 0-copy and copy mode:
   *   - 0-copy: XDP_PACKET_HEADROOM will be added to the user headroom
   *   - copy: nothing is added to the user headroom
   * We privileged 0-copy and set headroom to 0. As XDP_PACKET_HEADROOM ==
   * sizeof(vlib_buffer_t), data will correctly point to vlib_buffer_t->data.
   * In copy mode, we have to add sizeof(vlib_buffer_t) to desc offset during
   * refill.
   */
  STATIC_ASSERT (sizeof (vlib_buffer_t) == XDP_PACKET_HEADROOM, "wrong size");
#define bi2addr(bi) \
  (((bi) << CLIB_LOG2_CACHE_LINE_BYTES) + (copy ? sizeof(vlib_buffer_t) : 0))

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
}

static_always_inline u32
af_xdp_device_input_bufs (vlib_main_t * vm, const af_xdp_device_t * ad,
			  af_xdp_rxq_t * rxq, u32 * bis, const u32 n_rx,
			  vlib_buffer_t * bt, u32 idx, const int copy)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 lens[VLIB_FRAME_SIZE], *len = lens;
  const u32 mask = rxq->rx.mask;
  u32 n = n_rx, *bi = bis, bytes = 0;

#define addr2bi(addr) \
  (((addr) - (copy ? sizeof(vlib_buffer_t) : 0)) >> CLIB_LOG2_CACHE_LINE_BYTES)

  while (n >= 1)
    {
      const struct xdp_desc *desc = xsk_ring_cons__rx_desc (&rxq->rx, idx);
      bi[0] = addr2bi (xsk_umem__extract_addr (desc->addr));
      ASSERT (vlib_buffer_is_known (vm, bi[0]) ==
	      VLIB_BUFFER_KNOWN_ALLOCATED);
      len[0] = desc->len;
      idx = (idx + 1) & mask;
      bi += 1;
      len += 1;
      n -= 1;
    }

  vlib_get_buffers (vm, bis, bufs, n_rx);

  n = n_rx;
  len = lens;

  while (n >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_buffer_copy_template (b[0], bt);
      bytes += b[0]->current_length = len[0];

      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_buffer_copy_template (b[1], bt);
      bytes += b[1]->current_length = len[1];

      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_buffer_copy_template (b[2], bt);
      bytes += b[2]->current_length = len[2];

      vlib_prefetch_buffer_header (b[7], LOAD);
      vlib_buffer_copy_template (b[3], bt);
      bytes += b[3]->current_length = len[3];

      b += 4;
      len += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      vlib_buffer_copy_template (b[0], bt);
      bytes += b[0]->current_length = len[0];
      b += 1;
      len += 1;
      n -= 1;
    }

  xsk_ring_cons__release (&rxq->rx, n_rx);
  return bytes;
}

static_always_inline uword
af_xdp_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, af_xdp_device_t * ad,
			    u16 qid, const int copy)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  vlib_buffer_t bt;
  u32 next_index, *to_next, n_left_to_next;
  u32 n_rx_packets, n_rx_bytes;
  u32 idx;

  n_rx_packets = xsk_ring_cons__peek (&rxq->rx, VLIB_FRAME_SIZE, &idx);

  if (PREDICT_FALSE (0 == n_rx_packets))
    goto refill;

  vlib_buffer_copy_template (&bt, ad->buffer_template);
  next_index = ad->per_interface_next_index;
  if (PREDICT_FALSE (vnet_device_input_have_features (ad->sw_if_index)))
    vnet_feature_start_device_input_x1 (ad->sw_if_index, &next_index, &bt);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  n_rx_bytes =
    af_xdp_device_input_bufs (vm, ad, rxq, to_next, n_rx_packets, &bt, idx,
			      copy);
  af_xdp_device_input_ethernet (vm, node, next_index, ad->sw_if_index,
				ad->hw_if_index);

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  af_xdp_device_input_trace (vm, node, n_rx_packets, to_next, next_index,
			     ad->hw_if_index);

  vlib_increment_combined_counter
    (vnm->interface_main.combined_sw_if_counters +
     VNET_INTERFACE_COUNTER_RX, vm->thread_index,
     ad->hw_if_index, n_rx_packets, n_rx_bytes);

refill:
  af_xdp_device_input_refill (vm, node, ad, rxq, copy);

  return n_rx_packets;
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
      if (PREDICT_TRUE (ad->flags & AF_XDP_DEVICE_F_ZEROCOPY))
	n_rx += af_xdp_device_input_inline (vm, node, frame, ad, p->queue_id,
					    /* copy */ 0);
      else
	n_rx += af_xdp_device_input_inline (vm, node, frame, ad, p->queue_id,
					    /* copy */ 1);
    }

  return n_rx;
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

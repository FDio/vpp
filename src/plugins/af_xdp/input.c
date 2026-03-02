/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/rx_queue_funcs.h>
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
  xsk_ring_prod__submit (&rxq->fq, n_alloc);

  if (AF_XDP_RXQ_MODE_INTERRUPT == rxq->mode ||
      !xsk_ring_prod__needs_wakeup (&rxq->fq))
    return;

  if (node)
    vlib_error_count (vm, node->node_index,
		      AF_XDP_INPUT_ERROR_SYSCALL_REQUIRED, 1);

  if (clib_spinlock_trylock_if_init (&rxq->syscall_lock))
    {
      struct msghdr msg = { 0 };
      struct iovec iov = { 0 };
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;

      int ret = recvmsg (rxq->xsk_fd, &msg, MSG_DONTWAIT);
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

static_always_inline u32
af_xdp_device_input_bufs_mb (vlib_main_t *vm, af_xdp_rxq_t *rxq, u32 *bis, const u32 n_desc,
			     vlib_buffer_t *bt, u32 idx, u32 *n_rx_bytes)
{
  const u32 mask = rxq->rx.mask;
  vlib_buffer_t *head = 0, *tail = 0;
  u32 head_bi = ~0;
  u32 total_len = 0;
  u32 n_pkts = 0;
  u32 bytes = 0;
  u32 n = n_desc;

#define addr2bi(addr) ((addr) >> CLIB_LOG2_CACHE_LINE_BYTES)

  if (rxq->mb_total_len)
    {
      head_bi = rxq->mb_head_bi;
      head = vlib_get_buffer (vm, head_bi);
      tail = vlib_get_buffer (vm, rxq->mb_tail_bi);
      total_len = rxq->mb_total_len;
    }

  while (n--)
    {
      const struct xdp_desc *desc = xsk_ring_cons__rx_desc (&rxq->rx, idx);
      const u64 addr = xsk_umem__extract_addr (desc->addr);
      const u32 bi = addr2bi (addr);
      vlib_buffer_t *b;
      u16 off;

      ASSERT (vlib_buffer_is_known (vm, bi) == VLIB_BUFFER_KNOWN_ALLOCATED);

      b = vlib_get_buffer (vm, bi);
      off = xsk_umem__extract_offset (desc->addr) - sizeof (vlib_buffer_t);

      vlib_buffer_copy_template (b, bt);
      b->current_data = off;
      b->current_length = desc->len;
      b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
      b->next_buffer = 0;

      if (PREDICT_FALSE (head == 0))
	{
	  head = tail = b;
	  head_bi = bi;
	  total_len = b->current_length;
	}
      else
	{
	  tail->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  tail->next_buffer = bi;
	  tail = b;
	  total_len += b->current_length;
	}

      if ((desc->options & XDP_PKT_CONTD) == 0)
	{
	  head->total_length_not_including_first_buffer = total_len - head->current_length;
	  bis[n_pkts++] = head_bi;
	  bytes += total_len;
	  head = tail = 0;
	  head_bi = ~0;
	  total_len = 0;
	}

      idx = (idx + 1) & mask;
    }

  if (PREDICT_FALSE (head != 0))
    {
      rxq->mb_head_bi = head_bi;
      rxq->mb_tail_bi = vlib_get_buffer_index (vm, tail);
      rxq->mb_total_len = total_len;
    }
  else
    {
      rxq->mb_head_bi = ~0;
      rxq->mb_tail_bi = ~0;
      rxq->mb_total_len = 0;
    }

  xsk_ring_cons__release (&rxq->rx, n_desc);
  *n_rx_bytes = bytes;
  return n_pkts;
}

static_always_inline u32
af_xdp_device_input_bufs (vlib_main_t *vm, const af_xdp_device_t *ad,
			  af_xdp_rxq_t *rxq, u32 *bis, const u32 n_rx,
			  vlib_buffer_t *bt, u32 idx)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 offs[VLIB_FRAME_SIZE], *off = offs;
  u16 lens[VLIB_FRAME_SIZE], *len = lens;
  const u32 mask = rxq->rx.mask;
  u32 n = n_rx, *bi = bis, bytes = 0;

  while (n >= 1)
    {
      const struct xdp_desc *desc = xsk_ring_cons__rx_desc (&rxq->rx, idx);
      const u64 addr = desc->addr;
      bi[0] = addr2bi (xsk_umem__extract_addr (addr));
      ASSERT (vlib_buffer_is_known (vm, bi[0]) ==
	      VLIB_BUFFER_KNOWN_ALLOCATED);
      off[0] = xsk_umem__extract_offset (addr) - sizeof (vlib_buffer_t);
      len[0] = desc->len;
      idx = (idx + 1) & mask;
      bi += 1;
      off += 1;
      len += 1;
      n -= 1;
    }

  vlib_get_buffers (vm, bis, bufs, n_rx);

  n = n_rx;
  off = offs;
  len = lens;

  while (n >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_buffer_copy_template (b[0], bt);
      b[0]->current_data = off[0];
      bytes += b[0]->current_length = len[0];

      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_buffer_copy_template (b[1], bt);
      b[1]->current_data = off[1];
      bytes += b[1]->current_length = len[1];

      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_buffer_copy_template (b[2], bt);
      b[2]->current_data = off[2];
      bytes += b[2]->current_length = len[2];

      vlib_prefetch_buffer_header (b[7], LOAD);
      vlib_buffer_copy_template (b[3], bt);
      b[3]->current_data = off[3];
      bytes += b[3]->current_length = len[3];

      b += 4;
      off += 4;
      len += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      vlib_buffer_copy_template (b[0], bt);
      b[0]->current_data = off[0];
      bytes += b[0]->current_length = len[0];
      b += 1;
      off += 1;
      len += 1;
      n -= 1;
    }

  xsk_ring_cons__release (&rxq->rx, n_rx);
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
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u32 n_rx_desc;
  u32 idx;

  n_rx_desc = xsk_ring_cons__peek (&rxq->rx, VLIB_FRAME_SIZE, &idx);

  if (PREDICT_FALSE (0 == n_rx_desc))
    goto refill;

  vlib_buffer_copy_template (&bt, ad->buffer_template);
  next_index = ad->per_interface_next_index;
  if (PREDICT_FALSE (vnet_device_input_have_features (ad->sw_if_index)))
    vnet_feature_start_device_input (ad->sw_if_index, &next_index, &bt);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (ad->flags & AF_XDP_DEVICE_F_MULTI_BUFFER)
    {
      n_rx_packets =
	af_xdp_device_input_bufs_mb (vm, rxq, to_next, n_rx_desc, &bt, idx, &n_rx_bytes);
    }
  else
    {
      n_rx_packets = n_rx_desc;
      n_rx_bytes = af_xdp_device_input_bufs (vm, ad, rxq, to_next, n_rx_packets, &bt, idx);
    }
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
  af_xdp_device_input_refill_inline (vm, node, ad, rxq);

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

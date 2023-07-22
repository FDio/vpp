/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ena/ena.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>

#define ENA_TX_ENQ_BATCH_SZ   64
#define ENA_MAX_LOG2_TXQ_SIZE 11
#define ENA_TX_MAX_TAIL_LEN   5

typedef struct
{
  u32 n_bytes;
  ena_device_t *ed;
  u16 n_desc;
  u32 mask;
  u16 n_packets_left;
  u16 n_free_slots;
  u32 *from;
  u32 *sq_buffer_indices;
  u32 tmp_bi[VLIB_FRAME_SIZE];
  ena_tx_desc_t *sqes;
  u64 *sqe_templates;
  u16 n_dropped_chain_too_long;
  u8 llq;
  void *bd;
} ena_tx_ctx_t;

/* bits inside req_id which represent SQE index */
static const u16 reqid_sqe_idx_mask = (1U << ENA_MAX_LOG2_TXQ_SIZE) - 1;

static_always_inline void
ena_txq_adv_sq_tail (ena_tx_ctx_t *ctx, ena_txq_t *eq)
{
  /* CQEs can arrive out of order, so we cannot blindly advance SQ tail for
   * number of free slots, instead we need to check if slot contains invalid
   * buffer index */

  u32 sq_head = eq->sq_head;
  u32 sq_tail = eq->sq_tail;
  u16 n, offset = sq_tail & ctx->mask;
  u32 *bi = ctx->sq_buffer_indices + offset;
  u16 n_to_check = clib_min (sq_head - sq_tail, ctx->n_desc - offset);

advance_sq_tail:
  n = n_to_check;

#ifdef CLIB_HAVE_VEC256
  for (; n >= 8; n -= 8, bi += 8)
    if (!u32x8_is_all_equal (*(u32x8u *) bi, VLIB_BUFFER_INVALID_INDEX))
      break;
#elif defined(CLIB_HAVE_VEC128)
  for (; n >= 4; n -= 4, bi += 4)
    if (!u32x4_is_all_equal (*(u32x4u *) bi, VLIB_BUFFER_INVALID_INDEX))
      break;
#endif

  for (; n > 0; n -= 1, bi += 1)
    if (bi[0] != VLIB_BUFFER_INVALID_INDEX)
      break;

  sq_tail += n_to_check - n;

  if (n == 0 && sq_tail < sq_head)
    {
      n_to_check = sq_head - sq_tail;
      bi = ctx->sq_buffer_indices;
      goto advance_sq_tail;
    }

  eq->sq_tail = sq_tail;
}

static_always_inline void
ena_txq_deq (vlib_main_t *vm, ena_tx_ctx_t *ctx, ena_txq_t *txq)
{
  /* dequeue CQ, extract SQ slot and number of chained buffers from
   * req_id, move completed buffer indices to temp array */
  const ena_tx_cdesc_t mask_phase = { .phase = 1 };
  ena_tx_cdesc_t *cqes = txq->cqes, *cd, match_phase = {};
  u32 cq_next = txq->cq_next;
  u32 offset, n = 0;
  u32 n_to_check;
  u32 *buffers_to_free = ctx->tmp_bi;
  u32 n_buffers_to_free = 0;

  offset = cq_next & ctx->mask;
  cd = cqes + offset;
  n_to_check = ctx->n_desc - offset;
  match_phase.phase = ~(cq_next & (ctx->n_desc << 1)) != 0;

#ifdef CLIB_HAVE_VEC256
  const u16 reqid_nic1 = 1U << ENA_MAX_LOG2_TXQ_SIZE;
  const ena_tx_cdesc_t mask_reqid = { .req_id = reqid_sqe_idx_mask },
		       match_ph0_nic1 = { .req_id = reqid_nic1, .phase = 0 },
		       match_ph1_nic1 = { .req_id = reqid_nic1, .phase = 1 },
		       mask_ph_nic = { .req_id = ~reqid_sqe_idx_mask,
				       .phase = 1 };
  /* both phase and req_id are in lower 32 bits */
  u32x8 mask_ph_nic_x8 = u32x8_splat (mask_ph_nic.as_u64);
  u32x8 mask_reqid_x8 = u32x8_splat (mask_reqid.as_u64);
  u32x8 match_ph_nic1_x8 = u32x8_splat (
    match_phase.phase ? match_ph1_nic1.as_u64 : match_ph0_nic1.as_u64);
  u32x8 buf_inv_idx_x8 = u32x8_splat (VLIB_BUFFER_INVALID_INDEX);
#endif

more:
  while (n < n_to_check)
    {
      u16 req_id, n_in_chain;

#ifdef CLIB_HAVE_VEC256
      while (n + 7 < n_to_check)
	{
	  u32x8 r, v;

	  /* load lower 32-bits of 8 CQEs in 256-bit register */
	  r = u32x8_shuffle2 (*(u32x8u *) cd, *(u32x8u *) (cd + 4), 0, 2, 4, 6,
			      8, 10, 12, 14);

	  /* check if all 8 CQEs are completed and there is no chained bufs */
	  if (u64x4_is_equal (r & mask_ph_nic_x8, match_ph_nic1_x8) == 0)
	    goto one_by_one;

	  r &= mask_reqid_x8;

	  /* take consumed buffer indices from ring */
	  v = u32x8_gather_u32 (ctx->sq_buffer_indices, r,
				sizeof (ctx->sq_buffer_indices[0]));
	  u32x8_scatter_u32 (ctx->sq_buffer_indices, r, buf_inv_idx_x8,
			     sizeof (ctx->sq_buffer_indices[0]));
	  *(u32x8u *) (buffers_to_free + n_buffers_to_free) = v;
	  n_buffers_to_free += 8;

	  n += 8;
	  cd += 8;
	  continue;
	}
    one_by_one:
#endif

      if ((cd->as_u64 & mask_phase.as_u64) != match_phase.as_u64)
	goto done;

      req_id = cd->req_id;
      n_in_chain = req_id >> ENA_MAX_LOG2_TXQ_SIZE;
      req_id &= reqid_sqe_idx_mask;

      buffers_to_free[n_buffers_to_free++] = ctx->sq_buffer_indices[req_id];
      ctx->sq_buffer_indices[req_id] = VLIB_BUFFER_INVALID_INDEX;

      if (PREDICT_FALSE (n_in_chain > 1))
	while (n_in_chain-- > 1)
	  {
	    req_id = (req_id + 1) & ctx->mask;
	    buffers_to_free[n_buffers_to_free++] =
	      ctx->sq_buffer_indices[req_id];
	    ctx->sq_buffer_indices[req_id] = VLIB_BUFFER_INVALID_INDEX;
	  }

      n++;
      cd++;
    }

  if (PREDICT_FALSE (n == n_to_check))
    {
      cq_next += n;
      n = 0;
      cd = cqes;
      match_phase.phase ^= 1;
#ifdef CLIB_HAVE_VEC256
      match_ph_nic1_x8 ^= u32x8_splat (mask_phase.as_u64);
#endif
      n_to_check = ctx->n_desc;
      goto more;
    }

done:

  if (n_buffers_to_free)
    {
      cq_next += n;

      /* part two - free buffers stored in temporary array */
      vlib_buffer_free_no_next (vm, buffers_to_free, n_buffers_to_free);
      txq->cq_next = cq_next;

      ena_txq_adv_sq_tail (ctx, txq);
    }
}

static_always_inline u16
ena_txq_wr_sqe (vlib_main_t *vm, vlib_buffer_t *b, int use_iova,
		ena_tx_desc_t *dp, u32 n_in_chain, ena_tx_desc_t desc)
{
  uword dma_addr = use_iova ? vlib_buffer_get_current_va (b) :
				    vlib_buffer_get_current_pa (vm, b);
  u16 len = b->current_length;

  desc.req_id_hi = n_in_chain << (ENA_MAX_LOG2_TXQ_SIZE - 10);
  desc.as_u16x8[0] = len;
  ASSERT (dma_addr < 0xffffffffffff); /* > 48bit - should never happen */
  desc.as_u64x2[1] = dma_addr;	      /* this also overwrites header_length */

  /* write descriptor as single 128-bit store */
  dp->as_u64x2 = desc.as_u64x2;
  return len;
}

static_always_inline void
ena_txq_copy_sqes (ena_tx_ctx_t *ctx, u32 off, ena_tx_desc_t *s, u32 n_desc)
{
  const u64 temp_phase_xor = (ena_tx_desc_t){ .phase = 1 }.as_u64x2[0];
  u32 n = 0;

  if (ctx->llq)
    {
      ena_tx_llq_desc128_t *llq_descs = (ena_tx_llq_desc128_t *) ctx->sqes;
      for (; n < n_desc; n += 1, s += 1, off += 1)
	{
	  ena_tx_llq_desc128_t td = {};
	  u64 t = ctx->sqe_templates[off];
	  u64x2 v = { t, 0 };
	  ctx->sqe_templates[off] = t ^ temp_phase_xor;
	  td.desc[0].as_u64x2 = v | s->as_u64x2;
	  td.desc[0].phase = 1;
	  td.desc[0].header_length = 96;
	  td.desc[0].length -= 96;
	  td.desc[0].buff_addr_lo += 96;
	  vlib_buffer_t *b =
	    vlib_get_buffer (vlib_get_main (), ctx->sq_buffer_indices[off]);
	  clib_memcpy_fast (td.data, vlib_buffer_get_current (b), 96);
	  fformat (stderr, "%U\n", format_hexdump_u32, &td, 32);
	  fformat (stderr, "%U\n", format_ena_tx_desc, &td);
	  clib_memcpy_fast (llq_descs + off, &td, 128);
	}
      return;
    }

#ifdef CLIB_HAVE_VEC512
  u64x8 temp_phase_xor_x8 = u64x8_splat (temp_phase_xor);
  for (; n + 7 < n_desc; n += 8, s += 8, off += 8)
    {
      u64x8 t8 = *(u64x8u *) (ctx->sqe_templates + off);
      *(u64x8u *) (ctx->sqe_templates + off) = t8 ^ temp_phase_xor_x8;
      u64x8 r0 = *(u64x8u *) s;
      u64x8 r1 = *(u64x8u *) (s + 4);
      r0 |= u64x8_shuffle2 (t8, (u64x8){}, 0, 9, 1, 11, 2, 13, 3, 15);
      r1 |= u64x8_shuffle2 (t8, (u64x8){}, 4, 9, 5, 11, 6, 13, 7, 15);
      *((u64x8u *) (ctx->sqes + off)) = r0;
      *((u64x8u *) (ctx->sqes + off + 4)) = r1;
    }
#elif defined(CLIB_HAVE_VEC256)
  u64x4 temp_phase_xor_x4 = u64x4_splat (temp_phase_xor);
  for (; n + 3 < n_desc; n += 4, s += 4, off += 4)
    {
      u64x4 t4 = *(u64x4u *) (ctx->sqe_templates + off);
      *(u64x4u *) (ctx->sqe_templates + off) = t4 ^ temp_phase_xor_x4;
      u64x4 r0 = *(u64x4u *) s;
      u64x4 r1 = *(u64x4u *) (s + 2);
      r0 |= u64x4_shuffle2 (t4, (u64x4){}, 0, 5, 1, 7);
      r1 |= u64x4_shuffle2 (t4, (u64x4){}, 2, 5, 3, 7);
      *((u64x4u *) (ctx->sqes + off)) = r0;
      *((u64x4u *) (ctx->sqes + off + 2)) = r1;
    }
#endif

  for (; n < n_desc; n += 1, s += 1, off += 1)
    {
      u64 t = ctx->sqe_templates[off];
      u64x2 v = { t, 0 };
      ctx->sqe_templates[off] = t ^ temp_phase_xor;
      ctx->sqes[off].as_u64x2 = v | s->as_u64x2;
    }
}

static_always_inline u32
ena_txq_enq_one (vlib_main_t *vm, ena_tx_ctx_t *ctx, vlib_buffer_t *b0,
		 ena_tx_desc_t *d, u16 n_free_desc, u32 *f, int use_iova)
{
  const ena_tx_desc_t single = { .first = 1, .last = 1 };
  vlib_buffer_t *b;
  u32 i, n;

  /* non-chained buffer */
  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
    {
      ctx->n_bytes += ena_txq_wr_sqe (vm, b0, use_iova, d, 1, single);
      f[0] = ctx->from[0];
      ctx->from += 1;
      ctx->n_packets_left -= 1;
      return 1;
    }

  /* count number of buffers in chain */
  for (n = 1, b = b0; b->flags & VLIB_BUFFER_NEXT_PRESENT; n++)
    b = vlib_get_buffer (vm, b->next_buffer);

  /* if chain is too long, drop packet */
  if (n > ENA_TX_MAX_TAIL_LEN + 1)
    {
      vlib_buffer_free_one (vm, ctx->from[0]);
      ctx->from += 1;
      ctx->n_packets_left -= 1;
      ctx->n_dropped_chain_too_long++;
      return 0;
    }

  /* no enough descriptors to accomodate? */
  if (n > n_free_desc)
    return 0;

  /* first */
  f++[0] = ctx->from[0];
  ctx->from += 1;
  ctx->n_packets_left -= 1;
  ctx->n_bytes +=
    ena_txq_wr_sqe (vm, b0, use_iova, d++, n, (ena_tx_desc_t){ .first = 1 });

  /* mid */
  for (i = 1, b = b0; i < n - 1; i++)
    {
      f++[0] = b->next_buffer;
      b = vlib_get_buffer (vm, b->next_buffer);
      ctx->n_bytes +=
	ena_txq_wr_sqe (vm, b, use_iova, d++, 0, (ena_tx_desc_t){});
    }

  /* last */
  f[0] = b->next_buffer;
  b = vlib_get_buffer (vm, b->next_buffer);
  ctx->n_bytes +=
    ena_txq_wr_sqe (vm, b, use_iova, d, 0, (ena_tx_desc_t){ .last = 1 });

  return n;
}

static_always_inline uword
ena_txq_enq (vlib_main_t *vm, ena_tx_ctx_t *ctx, ena_txq_t *txq, int use_iova)
{
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 *f = ctx->tmp_bi;
  ena_tx_desc_t desc[ENA_TX_ENQ_BATCH_SZ], *d = desc;
  const ena_tx_desc_t single = { .first = 1, .last = 1 };
  u32 n_desc_left, n;

  if (ctx->n_packets_left == 0)
    return 0;

  if (ctx->n_free_slots == 0)
    return 0;

  n_desc_left = clib_min (ENA_TX_ENQ_BATCH_SZ, ctx->n_free_slots);

  while (n_desc_left >= 4 && ctx->n_packets_left >= 8)
    {
      clib_prefetch_load (vlib_get_buffer (vm, ctx->from[4]));
      b0 = vlib_get_buffer (vm, ctx->from[0]);
      clib_prefetch_load (vlib_get_buffer (vm, ctx->from[5]));
      b1 = vlib_get_buffer (vm, ctx->from[1]);
      clib_prefetch_load (vlib_get_buffer (vm, ctx->from[6]));
      b2 = vlib_get_buffer (vm, ctx->from[2]);
      clib_prefetch_load (vlib_get_buffer (vm, ctx->from[7]));
      b3 = vlib_get_buffer (vm, ctx->from[3]);

      if (PREDICT_FALSE (((b0->flags | b1->flags | b2->flags | b3->flags) &
			  VLIB_BUFFER_NEXT_PRESENT) == 0))
	{
	  ctx->n_bytes += ena_txq_wr_sqe (vm, b0, use_iova, d++, 1, single);
	  ctx->n_bytes += ena_txq_wr_sqe (vm, b1, use_iova, d++, 1, single);
	  ctx->n_bytes += ena_txq_wr_sqe (vm, b2, use_iova, d++, 1, single);
	  ctx->n_bytes += ena_txq_wr_sqe (vm, b3, use_iova, d++, 1, single);
	  vlib_buffer_copy_indices (f, ctx->from, 4);
	  ctx->from += 4;
	  ctx->n_packets_left -= 4;

	  n_desc_left -= 4;
	  f += 4;
	}
      else
	{
	  n = ena_txq_enq_one (vm, ctx, b0, d, n_desc_left, f, use_iova);
	  if (n == 0)
	    break;
	  n_desc_left -= n;
	  f += n;
	  d += n;
	}
    }

  while (n_desc_left > 0 && ctx->n_packets_left > 0)
    {
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, ctx->from[0]);
      n = ena_txq_enq_one (vm, ctx, b0, d, n_desc_left, f, use_iova);
      if (n == 0)
	break;
      n_desc_left -= n;
      f += n;
      d += n;
    }

  n = d - desc;

  if (n)
    {
      u32 head = txq->sq_head;
      u32 offset = head & ctx->mask;
      u32 n_before_wrap = ctx->n_desc - offset;
      u32 n_copy;

      d = desc;
      f = ctx->tmp_bi;

      if (n_before_wrap >= n)
	{
	  n_copy = n;
	  vlib_buffer_copy_indices (ctx->sq_buffer_indices + offset, f,
				    n_copy);
	  ena_txq_copy_sqes (ctx, offset, d, n_copy);
	}
      else
	{
	  n_copy = n_before_wrap;
	  vlib_buffer_copy_indices (ctx->sq_buffer_indices + offset, f,
				    n_copy);
	  ena_txq_copy_sqes (ctx, offset, d, n_copy);

	  n_copy = n - n_before_wrap;
	  vlib_buffer_copy_indices (ctx->sq_buffer_indices, f + n_before_wrap,
				    n_copy);
	  ena_txq_copy_sqes (ctx, 0, d + n_before_wrap, n_copy);
	}

      head += n;
      __atomic_store_n (txq->sq_db, head, __ATOMIC_RELEASE);
      txq->sq_head = head;
      ctx->n_free_slots -= n;

      return n;
    }
  return 0;
}

static_always_inline void
vnet_dev_tx_node_lock_if_shared (vlib_node_runtime_t *node)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  if (rt->lock_required == 0)
    return;
  while (1)
    {
      u8 tmp = 0;

      if (__atomic_compare_exchange_n (&rt->lock, &tmp, 1, 0, __ATOMIC_ACQUIRE,
				       __ATOMIC_RELAXED))
	return;

      while (__atomic_load_n (&rt->lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
    }
}

static_always_inline void
vnet_dev_tx_node_unlock_if_shared (vlib_node_runtime_t *node)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  if (rt->lock_required)
    __atomic_store_n (&rt->lock, 0, __ATOMIC_RELEASE);
}

VNET_DEV_NODE_FN (ena_tx_node_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *tnr = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = tnr->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  ena_device_t *ed = vnet_dev_get_data (dev);
  ena_txq_t *eq = vnet_dev_get_tx_queue_data (txq);
  u32 n_pkts = 0;

  ena_tx_ctx_t ctx = { .mask = txq->size - 1,
		       .n_desc = txq->size,
		       .n_packets_left = frame->n_vectors,
		       .from = vlib_frame_vector_args (frame),
		       .sqe_templates = eq->sqe_templates,
		       .sqes = eq->sqes,
		       .sq_buffer_indices = eq->buffer_indices,
		       .llq = ed->llq };

  vnet_dev_tx_node_lock_if_shared (node);

  /* try 3 times to enquee packets by first freeing consumed from the ring
   * and then trying to enqueue as much as possible */
  for (int i = 0; i < 3; i++)
    {
      /* free buffers consumed by ENA */
      if (eq->sq_head != eq->sq_tail)
	ena_txq_deq (vm, &ctx, eq);

      /* enqueue new buffers, try until last attempt enqueues 0 packets */
      ctx.n_free_slots = ctx.n_desc - (eq->sq_head - eq->sq_tail);

      if (dev->va_dma)
	while (ena_txq_enq (vm, &ctx, eq, /* va */ 1) > 0)
	  ;
      else
	while (ena_txq_enq (vm, &ctx, eq, /* va */ 0) > 0)
	  ;

      if (ctx.n_packets_left == 0)
	break;
    }

  vnet_dev_tx_node_unlock_if_shared (node);

  if (ctx.n_dropped_chain_too_long)
    vlib_error_count (vm, node->node_index, ENA_TX_NODE_ERROR_CHAIN_TOO_LONG,
		      ctx.n_dropped_chain_too_long);

  n_pkts = frame->n_vectors - ctx.n_packets_left;
  vlib_increment_combined_counter (
    vnet_get_main ()->interface_main.combined_sw_if_counters +
      VNET_INTERFACE_COUNTER_TX,
    vm->thread_index, tnr->hw_if_index, n_pkts, ctx.n_bytes);

  if (ctx.n_packets_left)
    {
      vlib_buffer_free (vm, ctx.from, ctx.n_packets_left);
      vlib_error_count (vm, node->node_index, ENA_TX_NODE_ERROR_NO_FREE_SLOTS,
			ctx.n_packets_left);
    }

  return n_pkts;
}

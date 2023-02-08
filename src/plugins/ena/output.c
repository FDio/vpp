/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <ena/ena.h>
#include <ena/ena_inlines.h>

#define ENA_TX_ENQ_BATCH_SZ	 64
#define ENA_TX_DEQ_LOG2_BATCH_SZ 3
#define ENA_TX_MAX_TAIL_LEN	 5

typedef struct
{
  u32 n_bytes;
  ena_device_t *ed;
  u8 log2_n_desc;
  u16 n_desc;
  u32 mask;
  u16 n_packets_left;
  u16 n_free_slots;
  u32 *from;
  u16 n_dropped_chain_too_long;
} ena_txq_enq_ctx;

static_always_inline void
ena_buffer_free_batch (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers)
{
  const u32 batch = 1 << ENA_TX_DEQ_LOG2_BATCH_SZ;
  for (; n_buffers >= batch; n_buffers -= batch, buffer_indices += batch)
    vlib_buffer_free_no_next (vm, buffer_indices, batch);
}

static_always_inline void
ena_device_free_used_buffers (vlib_main_t *vm, vlib_node_runtime_t *node,
			      ena_txq_enq_ctx *ctx, ena_device_t *ed,
			      ena_txq_t *txq)
{
  ena_tx_cdesc_t *cqes = txq->cqes, *cd;
  u32 batch_mask = pow2_mask (ENA_TX_DEQ_LOG2_BATCH_SZ);
  u16 next = txq->cq_next;
  u32 n_free = 0;
  u32 phase;

  if (txq->n_enq == 0)
    return;

  cd = cqes + (next & ctx->mask);
  phase = 1 & ~(next >> ctx->log2_n_desc);

  while (cd->phase == phase)
    {
      n_free += cd->req_id;
      next++;
      cd++;
      if (cd - cqes >= ctx->n_desc)
	{
	  cd = cqes;
	  phase ^= 1;
	}
    }

  if (n_free == 0)
    return;

  txq->cq_next = next;
  n_free += txq->n_free;

  if (n_free > batch_mask)
    {
      u32 n_enq = txq->n_enq;
      u32 start = (txq->sq_next - n_enq) & ctx->mask;

      txq->n_free = n_free & batch_mask;
      n_free &= ~batch_mask;
      txq->n_enq = n_enq - n_free;

      if (PREDICT_FALSE (n_free > ctx->n_desc - start))
	{
	  u32 n = ctx->n_desc - start;
	  ena_buffer_free_batch (vm, txq->buffers + start, n);
	  ena_buffer_free_batch (vm, txq->buffers, n_free - n);
	}
      else
	ena_buffer_free_batch (vm, txq->buffers + start, n_free);
    }
  else
    txq->n_free = n_free;
}

static_always_inline u16
ena_wr_tx_desc (vlib_main_t *vm, vlib_buffer_t *b, int use_iova,
		ena_tx_desc_t *dp, ena_tx_desc_t desc)
{
  uword pa = use_iova ? vlib_buffer_get_current_va (b) :
			      vlib_buffer_get_current_pa (vm, b);
  u16 len = b->current_length;

  desc.length = len;
  desc.buff_addr_lo = pa;
  desc.buf_addr_hi = pa >> 32;
  *dp = desc;
  return len;
}

static_always_inline u32
ena_txq_enq_one (vlib_main_t *vm, ena_txq_enq_ctx *ctx, vlib_buffer_t *b0,
		 ena_tx_desc_t *d, u16 n_free_desc, u32 *f, int use_iova)
{
  const ena_tx_desc_t single = { .first = 1, .last = 1, .req_id_lo = 1 };
  vlib_buffer_t *b;
  u32 i, n;

  /* non-chained buffer */
  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
    {
      ctx->n_bytes += ena_wr_tx_desc (vm, b0, use_iova, d, single);
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
  ctx->n_bytes += ena_wr_tx_desc (
    vm, b0, use_iova, d++, (ena_tx_desc_t){ .first = 1, .req_id_lo = n });

  /* mid */
  for (i = 1, b = b0; i < n - 1; i++)
    {
      f++[0] = b->next_buffer;
      b = vlib_get_buffer (vm, b->next_buffer);
      ctx->n_bytes += ena_wr_tx_desc (vm, b, use_iova, d++, (ena_tx_desc_t){});
    }

  /* last */
  f[0] = b->next_buffer;
  b = vlib_get_buffer (vm, b->next_buffer);
  ctx->n_bytes +=
    ena_wr_tx_desc (vm, b, use_iova, d, (ena_tx_desc_t){ .last = 1 });

  return n;
}

static_always_inline uword
ena_txq_enq (vlib_main_t *vm, ena_txq_enq_ctx *ctx, ena_txq_t *txq,
	     int use_iova)
{
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 flattened[ENA_TX_ENQ_BATCH_SZ], *f = flattened;
  ena_tx_desc_t desc[ENA_TX_ENQ_BATCH_SZ], *d = desc;
  const ena_tx_desc_t single = { .first = 1, .last = 1, .req_id_lo = 1 };
  u32 n_desc_left, n;

  if (ctx->n_packets_left == 0)
    return 0;

  if (ctx->n_free_slots == 0)
    return 0;

  n_desc_left = clib_min (ARRAY_LEN (desc), ctx->n_free_slots);

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
	  ctx->n_bytes += ena_wr_tx_desc (vm, b0, use_iova, d++, single);
	  ctx->n_bytes += ena_wr_tx_desc (vm, b1, use_iova, d++, single);
	  ctx->n_bytes += ena_wr_tx_desc (vm, b2, use_iova, d++, single);
	  ctx->n_bytes += ena_wr_tx_desc (vm, b3, use_iova, d++, single);
	  ctx->from += 4;
	  ctx->n_packets_left -= 4;

	  vlib_buffer_copy_indices (f, ctx->from, 4);
	  n_desc_left -= 4;
	  f += 4;
	}
      else
	{
	  n = ena_txq_enq_one (vm, ctx, b0, d, n_desc_left, f, use_iova);
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
      n_desc_left -= n;
      f += n;
      d += n;
    }

  n = d - desc;

  if (n)
    {
      u32 next = txq->sq_next;
      u32 offset = next & ctx->mask;
      u32 n_before_wrap = ctx->n_desc - offset;
      u32 n_copy;
      ena_tx_desc_t *sqe;

      d = desc;
      f = flattened;

      if (n_before_wrap >= n)
	{
	  n_copy = n;
	  vlib_buffer_copy_indices (txq->buffers + offset, f, n_copy);
	  sqe = txq->sqes + offset;

	  while (n_copy--)
	    sqe++[0] = d++[0];
	}
      else
	{
	  n_copy = n_before_wrap;
	  vlib_buffer_copy_indices (txq->buffers + offset, f, n_copy);
	  sqe = txq->sqes + offset;

	  while (n_copy--)
	    sqe++[0] = d++[0];

	  n_copy = n - n_before_wrap;
	  vlib_buffer_copy_indices (txq->buffers, f + n_before_wrap, n_copy);
	  sqe = txq->sqes;

	  while (n_copy--)
	    sqe++[0] = d++[0];
	}

      next += n;
      txq->sq_next = next;
      txq->n_enq += n;
      ctx->n_free_slots -= n;
      __atomic_store_n (txq->sq_db, next, __ATOMIC_RELEASE);

      return n;
    }
  return 0;
}

VNET_DEVICE_CLASS_TX_FN (ena_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ena_device_t *ed = ena_get_device (rd->dev_instance);
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  u8 qid = tf->queue_id;
  ena_txq_t *txq = pool_elt_at_index (ed->txqs, qid);
  u32 n_pkts = 0;

  ena_txq_enq_ctx ctx = {
    .log2_n_desc = txq->log2_n_desc,
    .mask = pow2_mask (ctx.log2_n_desc),
    .n_desc = 1U << ctx.log2_n_desc,
  };

  ctx.n_packets_left = frame->n_vectors;
  ctx.from = vlib_frame_vector_args (frame);

  if (ena_queue_state_set_in_use (&txq->state) == ENA_QUEUE_STATE_DISABLED)
    goto queue_disabled;

  /* try 3 times to enquee packets by first freeing consumed from the ring
   * and then trying to enqueue as much as possible */
  for (int i = 0; i < 3; i++)
    {
      /* free buffers consumed by ENA */
      ena_device_free_used_buffers (vm, node, &ctx, ed, txq);

      /* enqueue new buffers, try until last attempt enqueues 0 packets */
      ctx.n_free_slots = ctx.n_desc - txq->n_enq;

      if (ed->va_dma)
	while (ena_txq_enq (vm, &ctx, txq, /* va */ 1) > 0)
	  break;
      else
	while (ena_txq_enq (vm, &ctx, txq, /* va */ 0) > 0)
	  break;

      if (ctx.n_packets_left == 0)
	break;
    }

  ena_queue_state_set_ready (&txq->state);

  if (ctx.n_dropped_chain_too_long)
    vlib_error_count (vm, node->node_index, ENA_TX_ERROR_CHAIN_TO_LONG,
		      ctx.n_dropped_chain_too_long);

  n_pkts = frame->n_vectors - ctx.n_packets_left;
  vlib_increment_combined_counter (
    vnet_get_main ()->interface_main.combined_sw_if_counters +
      VNET_INTERFACE_COUNTER_TX,
    vm->thread_index, ed->hw_if_index, n_pkts, ctx.n_bytes);

queue_disabled:
  if (ctx.n_packets_left)
    {
      vlib_buffer_free (vm, ctx.from, ctx.n_packets_left);
      vlib_error_count (vm, node->node_index, ENA_TX_ERROR_NO_FREE_SLOTS,
			ctx.n_packets_left);
    }

  return n_pkts;
}

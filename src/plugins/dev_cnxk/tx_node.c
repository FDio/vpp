/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <dev_cnxk/cnxk.h>
#include <dev_cnxk/common.h>
#include <dev_cnxk/lmt.h>
#include <dev_cnxk/hw_defs.h>

typedef struct
{
  union nix_send_hdr_w0_u hdr_w0_teplate;
  cnxk_lmt_ctx_t lmtctx;
  u32 n_tx_bytes;
  u32 n_drop;
  vlib_buffer_t *drop[VLIB_FRAME_SIZE];
  u32 batch_alloc_not_ready;
  u32 batch_alloc_issue_fail;
} cnxk_tx_ctx_t;

static_always_inline u32
cnxk_batch_free (vlib_main_t *vm, cnxk_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq)
{
  cnxk_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u8 num_cl;
  u64 ah;
  u32 n_freed = 0, n;
  cnxk_npa_batch_alloc_cl128_t *cl;

  num_cl = ctq->ba_num_cl;
  if (num_cl)
    {
      u16 off = ctq->hdr_off;
      u32 *bi = (u32 *) ctq->ba_buffer;

      for (cl = ctq->ba_buffer + ctq->ba_first_cl; num_cl > 0; num_cl--, cl++)
	{
	  u8 count;
	  if (cl->status.ccode == ALLOC_CCODE_INVAL)
	    {
	      ctx->batch_alloc_not_ready++;
	      n_freed = bi - (u32 *) ctq->ba_buffer;
	      if (n_freed > 0)
		{
		  vlib_buffer_free (vm, (u32 *) ctq->ba_buffer, n_freed);
		  ctq->ba_num_cl = num_cl;
		  ctq->ba_first_cl = cl - ctq->ba_buffer;
		  return n_freed;
		}

	      return 0;
	    }

	  count = cl->status.count;

	  if (PREDICT_TRUE (count == 16))
	    {
	      /* optimize for likely case where cacheline is full */
	      vlib_get_buffer_indices_with_offset (vm, (void **) cl, bi, 16,
						   off);
	      bi += 16;
	    }
	  else
	    {
	      vlib_get_buffer_indices_with_offset (vm, (void **) cl, bi, count,
						   off);
	      bi += count;
	    }
	}

      n_freed = bi - (u32 *) ctq->ba_buffer;
      if (n_freed > 0)
	vlib_buffer_free (vm, (u32 *) ctq->ba_buffer, n_freed);

      /* clear status bits in each cacheline */
      n = cl - ctq->ba_buffer;
      for (u32 i = 0; i < n; i++)
	ctq->ba_buffer[i].iova[0] = 0;

      ctq->ba_num_cl = ctq->ba_first_cl = 0;
    }

  ah = ctq->aura_handle;

  if ((n = roc_npa_aura_op_available (ah)) >= 32)
    {
      u64 addr, res;

      n = clib_min (n, ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);

      cnxk_npa_batch_alloc_compare_t cmp = {
	.compare_s = { .aura = roc_npa_aura_handle_to_aura (ah),
		       .stype = ALLOC_STYPE_STF,
		       .count = n }
      };

      addr = roc_npa_aura_handle_to_base (ah) + NPA_LF_AURA_BATCH_ALLOC;
      res = roc_atomic64_casl (cmp.as_u64, (uint64_t) ctq->ba_buffer,
			       (i64 *) addr);
      if (res == ALLOC_RESULT_ACCEPTED || res == ALLOC_RESULT_NOCORE)
	{
	  ctq->ba_num_cl = (n + 15) / 16;
	  ctq->ba_first_cl = 0;
	}
      else
	ctx->batch_alloc_issue_fail++;
    }

  return n_freed;
}

static_always_inline u8
cnxk_tx_enq1 (vlib_main_t *vm, cnxk_tx_ctx_t *ctx, vlib_buffer_t *b,
	      u128 *dword, u32 flags, int maybe_chained)
{
  u8 n_dwords = 2;
  u32 total_len = 0;
  cnxk_tx_desc_t d = {
    .hdr_w0 = ctx->hdr_w0_teplate,
    .sg[0] = {
      .segs = 1,
      .subdc = NIX_SUBDC_SG,
    },
    .sg[4] = {
      .subdc = NIX_SUBDC_SG,
    },
  };

  if (maybe_chained && flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u8 n_tail_segs = 0;
      vlib_buffer_t *tail_segs[5];

      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  b = vlib_get_buffer (vm, b->next_buffer);
	  tail_segs[n_tail_segs++] = b;
	  if (n_tail_segs > 5)
	    {
	      ctx->drop[ctx->n_drop++] = b;
	      return 0;
	    }
	}

      switch (n_tail_segs)
	{
	case 5:
	  d.sg[7].u = (u64) vlib_buffer_get_current (tail_segs[4]);
	  total_len += d.sg[4].seg3_size = tail_segs[4]->current_length;
	  d.sg[4].segs++;
	case 4:
	  d.sg[6].u = (u64) vlib_buffer_get_current (tail_segs[3]);
	  total_len += d.sg[4].seg2_size = tail_segs[3]->current_length;
	  d.sg[4].segs++;
	  n_dwords++;
	case 3:
	  d.sg[5].u = (u64) vlib_buffer_get_current (tail_segs[2]);
	  total_len += d.sg[4].seg1_size = tail_segs[2]->current_length;
	  d.sg[4].segs++;
	  n_dwords++;
	case 2:
	  d.sg[3].u = (u64) vlib_buffer_get_current (tail_segs[1]);
	  total_len += d.sg[0].seg3_size = tail_segs[1]->current_length;
	  d.sg[0].segs++;
	case 1:
	  d.sg[2].u = (u64) vlib_buffer_get_current (tail_segs[0]);
	  total_len += d.sg[0].seg2_size = tail_segs[0]->current_length;
	  d.sg[0].segs++;
	  n_dwords++;
	default:
	  break;
	};
    }

  total_len += d.sg[0].seg1_size = b->current_length;
  d.hdr_w0.total = total_len;
  d.sg[1].u = (u64) vlib_buffer_get_current (b);

  for (u32 i = 0; i < n_dwords; i++)
    dword[i] = d.as_u128[i];

  return n_dwords;
}

static_always_inline u32
cnxk_tx_enq16 (vlib_main_t *vm, cnxk_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
	       vlib_buffer_t **b, u32 n_pkts)
{
  u8 dwords_per_line[16], *dpl = dwords_per_line;
  u128 dwords[16 * 5], *dw = dwords;
  u32 n, n_left;
  const u32 not_simple_flags = VLIB_BUFFER_NEXT_PRESENT;

  for (n_left = n_pkts; n_left >= 4; n_left -= 4, b += 4)
    {
      u32 f0, f1, f2, f3, or_f = 0;
      vlib_prefetch_buffer_header (b[4], LOAD);
      or_f |= f0 = b[0]->flags;
      vlib_prefetch_buffer_header (b[5], LOAD);
      or_f |= f1 = b[1]->flags;
      vlib_prefetch_buffer_header (b[6], LOAD);
      or_f |= f2 = b[2]->flags;
      vlib_prefetch_buffer_header (b[7], LOAD);
      or_f |= f3 = b[3]->flags;

      if ((or_f & not_simple_flags) == 0)
	{
	  cnxk_tx_enq1 (vm, ctx, b[0], dw, f0, /* maybe_chained */ 0);
	  cnxk_tx_enq1 (vm, ctx, b[1], dw + 2, f1, /* maybe_chained */ 0);
	  cnxk_tx_enq1 (vm, ctx, b[2], dw + 4, f2, /* maybe_chained */ 0);
	  cnxk_tx_enq1 (vm, ctx, b[3], dw + 6, f3, /* maybe_chained */ 0);
	  dw += 8;
	  dpl[0] = dpl[1] = dpl[2] = dpl[3] = 2;
	  dpl += 4;
	}
      else
	{
	  n = cnxk_tx_enq1 (vm, ctx, b[0], dw, f0, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	  n = cnxk_tx_enq1 (vm, ctx, b[1], dw, f1, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	  n = cnxk_tx_enq1 (vm, ctx, b[2], dw, f2, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	  n = cnxk_tx_enq1 (vm, ctx, b[3], dw, f3, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	}
    }

  for (; n_left > 0; n_left -= 1, b += 1)
    {
      n = cnxk_tx_enq1 (vm, ctx, b[0], dw, b[0]->flags, /* maybe_chained */ 1);
      dpl++[0] = n;
      dw += n;
    }

  if (dw - dwords == 2 * (dpl - dwords_per_line))
    {
      /* help comiler to optimize by passing constant array for case
       * when all packets are single segment */
      const u8 all2[16] = { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
      cnxk_lmt_store (ctx->lmtctx, dwords, all2, n_pkts);
    }
  else
    cnxk_lmt_store (ctx->lmtctx, dwords, dwords_per_line, n_pkts);

  return n_pkts;
}

VNET_DEV_NODE_FN (cnxk_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  cnxk_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u32 node_index = node->node_index;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n, n_enq, n_left, n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;

  cnxk_tx_ctx_t ctx = {
    .hdr_w0_teplate = {
      .aura = roc_npa_aura_handle_to_aura (ctq->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .lmtctx = cnxk_lmt_ctx (vm->thread_index, ctq->io_addr, ctq->lmt_addr),
  };

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  for (int i = 0; i < 4; i++)
    b[n_pkts + i] = b[n_pkts - 1];

  vnet_dev_tx_queue_lock_if_needed (txq);

  n_enq = ctq->n_enq;
  n_enq -= cnxk_batch_free (vm, &ctx, txq);

  for (n_left = clib_min (n_pkts, txq->size - n_enq), n = 0; n_left >= 16;
       n_left -= 16, b += 16)
    n += cnxk_tx_enq16 (vm, &ctx, txq, b, 16);

  if (n_left)
    n += cnxk_tx_enq16 (vm, &ctx, txq, b, n_left);

  ctq->n_enq = n_enq + n;

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (n < n_pkts)
    {
      n = n_pkts - n;
      vlib_buffer_free (vm, from + n, n);
      vlib_error_count (vm, node->node_index, CNXK_TX_NODE_CTR_NO_FREE_SLOTS,
			n);
      n_pkts -= ctx.n_drop;
    }

  if (ctx.n_drop)
    {
      u32 bi[VLIB_FRAME_SIZE];
      vlib_get_buffer_indices (vm, ctx.drop, bi, ctx.n_drop);
      vlib_buffer_free (vm, bi, ctx.n_drop);
      vlib_error_count (vm, node->node_index, CNXK_TX_NODE_CTR_CHAIN_TOO_LONG,
			ctx.n_drop);
      n_pkts -= ctx.n_drop;
    }

  if (ctx.batch_alloc_not_ready)
    vlib_error_count (vm, node_index,
		      CNXK_TX_NODE_CTR_AURA_BATCH_ALLOC_NOT_READY,
		      ctx.batch_alloc_not_ready);

  if (ctx.batch_alloc_issue_fail)
    vlib_error_count (vm, node_index,
		      CNXK_TX_NODE_CTR_AURA_BATCH_ALLOC_ISSUE_FAIL,
		      ctx.batch_alloc_issue_fail);

  return n_pkts;
}

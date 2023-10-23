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

#define FREE_BATCH_SZ 32

typedef struct
{
  struct nix_send_hdr_s hdr;
  union nix_send_sg_s sg[4];
} cnxk_sq_desc_t;

typedef union
{
  struct
  {
    union nix_send_hdr_w0_u w0;
    union nix_send_hdr_w1_u w1;
  };
  u128 as_u128;
} nix_send_hdr_t;

typedef union
{
  union nix_send_sg_s sg[2];
  u128 as_u128;
} nix_send_sg_pair_t;

typedef struct
{
  nix_send_hdr_t hdr;
  nix_send_sg_pair_t sgpair0;
  cnxk_lmt_ctx_t lmtctx;
  u32 n_tx_bytes;
  u32 n_drop;
  vlib_buffer_t *drop[VLIB_FRAME_SIZE];
} cnxk_tx_ctx_t;

static_always_inline u32
cnxk_batch_free (vlib_main_t *vm, u32 node_index, vnet_dev_tx_queue_t *txq)
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
	      vlib_error_count (vm, node_index,
				CNXK_TX_NODE_CTR_AURA_BATCH_ALLOC_NOT_READY,
				1);
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

  if ((n = roc_npa_aura_op_available (ah)) >= FREE_BATCH_SZ)
    {
      n = clib_min (n, ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);
      if (PREDICT_TRUE (!roc_npa_aura_batch_alloc_issue (
	    ah, (void *) ctq->ba_buffer, n, 0, 0)))
	{
	  ctq->ba_num_cl = (n + 15) / 16;
	  ctq->ba_first_cl = 0;
	}
      else
	vlib_error_count (vm, node_index,
			  CNXK_TX_NODE_CTR_AURA_BATCH_ALLOC_ISSUE_FAIL, 1);
    }

  return n_freed;
}

static_always_inline u8
cnxk_enq1 (vlib_main_t *vm, cnxk_tx_ctx_t *ctx, vlib_buffer_t *b, u128 *dword,
	   u32 flags, int maybe_chained)
{
  nix_send_hdr_t h = ctx->hdr;
  nix_send_sg_pair_t sgpair0 = ctx->sgpair0, sgpair1 = {};
  u16 len = b->current_length, total_len = len;

  if (!maybe_chained && flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      vlib_buffer_t *b2 = vlib_get_buffer (vm, b->next_buffer);
      if (b2->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  vlib_buffer_t *b3 = vlib_get_buffer (vm, b2->next_buffer);
	  if (b3->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      ctx->drop[ctx->n_drop++] = b;
	      return 0;
	    }
	  sgpair1.sg[1].u = (u64) vlib_buffer_get_current (b3);
	  total_len += sgpair0.sg[0].seg3_size = b3->current_length;
	}
      sgpair1.sg[0].u = (u64) vlib_buffer_get_current (b2);
      sgpair0.sg[0].seg2_size = b2->current_length;
      dword[2] = sgpair1.as_u128;
      return 3;
    }

  h.w0.total = total_len;
  sgpair0.sg[0].seg1_size = len;
  sgpair0.sg[1].u = (u64) vlib_buffer_get_current (b);
  dword[0] = h.as_u128;
  dword[1] = sgpair0.as_u128;

  return 2;
}

static_always_inline u32
cnxk_enq16 (vlib_main_t *vm, cnxk_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
	    vlib_buffer_t **b, u32 n_pkts)
{
  u8 dwords_per_line[16], *dpl = dwords_per_line;
  u128 dwords[16 * 3], *dw = dwords;
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
	  cnxk_enq1 (vm, ctx, b[0], dw, f0, /* maybe_chained */ 0);
	  cnxk_enq1 (vm, ctx, b[1], dw + 2, f1, /* maybe_chained */ 0);
	  cnxk_enq1 (vm, ctx, b[2], dw + 4, f2, /* maybe_chained */ 0);
	  cnxk_enq1 (vm, ctx, b[3], dw + 6, f3, /* maybe_chained */ 0);
	  dw += 8;
	  dpl[0] = dpl[1] = dpl[2] = dpl[3] = 2;
	  dpl += 4;
	}
      else
	{
	  n = cnxk_enq1 (vm, ctx, b[0], dw, f0, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	  n = cnxk_enq1 (vm, ctx, b[1], dw, f1, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	  n = cnxk_enq1 (vm, ctx, b[2], dw, f2, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	  n = cnxk_enq1 (vm, ctx, b[3], dw, f3, /* maybe_chained */ 1);
	  dpl++[0] = n;
	  dw += n;
	}
    }

  for (; n_left > 0; n_left -= 1, b += 1)
    {
      n = cnxk_enq1 (vm, ctx, b[0], dw, b[0]->flags, /* maybe_chained */ 1);
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
    .hdr.w0 = {
      .aura = roc_npa_aura_handle_to_aura (ctq->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .sgpair0.sg[0] = {
      .segs = 1,
      .subdc = NIX_SUBDC_SG,
    },
    .lmtctx = cnxk_lmt_ctx (vm->thread_index, ctq->io_addr, ctq->lmt_addr),
  };

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  for (int i = 0; i < 4; i++)
    b[n_pkts + i] = b[n_pkts - 1];

  vnet_dev_tx_queue_lock_if_needed (txq);

  n_enq = ctq->n_enq;
  n_enq -= cnxk_batch_free (vm, node_index, txq);

  for (n_left = clib_min (n_pkts, txq->size - n_enq), n = 0; n_left >= 16;
       n_left -= 16, b += 16)
    n += cnxk_enq16 (vm, &ctx, txq, b, 16);

  if (n_left)
    n += cnxk_enq16 (vm, &ctx, txq, b, n_left);

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

  return n_pkts;
}

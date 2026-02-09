/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
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

#include <octeon.h>

typedef struct
{
  union nix_send_hdr_w0_u hdr_w0_teplate;
  vlib_node_runtime_t *node;
  u32 n_tx_bytes;
  u32 n_drop;
  vlib_buffer_t *drop[VLIB_FRAME_SIZE];
  u32 n_exd_mtu;
  vlib_buffer_t *exd_mtu[VLIB_FRAME_SIZE];
  u32 batch_alloc_not_ready;
  u32 batch_alloc_issue_fail;
  int max_pkt_len;
  u16 lmt_id;
  u64 lmt_ioaddr;
  lmt_line_t *lmt_lines;
} oct_tx_ctx_t;

#ifdef PLATFORM_OCTEON9
static_always_inline u32
oct_batch_free (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u16 off = ctq->hdr_off;
  u64 ah = ctq->aura_handle;
  u32 n_freed = 0, n;

  ah = ctq->aura_handle;

  if ((n = roc_npa_aura_op_available (ah)) >= 32)
    {
      u64 buffers[n];
      u32 bi[n];

      n_freed = roc_npa_aura_op_bulk_alloc (ah, buffers, n, 0, 1);
      vlib_get_buffer_indices_with_offset (vm, (void **) &buffers, bi, n_freed,
					   off);
      vlib_buffer_free_no_next (vm, bi, n_freed);
    }

  return n_freed;
}

static_always_inline void
oct_lmt_copy (void *lmt_addr, u64 io_addr, void *desc, u64 dwords)
{
  u64 lmt_status;

  do
    {
      roc_lmt_mov_seg (lmt_addr, desc, dwords);
      lmt_status = roc_lmt_submit_ldeor (io_addr);
    }
  while (lmt_status == 0);
}
#else
static_always_inline u32
oct_batch_free (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u8 num_cl;
  u64 ah;
  u32 n_freed = 0, n;
  oct_npa_batch_alloc_cl128_t *cl;

  num_cl = ctq->ba_num_cl;
  if (num_cl)
    {
      u16 off = ctq->hdr_off;
      u32 *bi = (u32 *) ctq->ba_buffer;

      for (cl = ctq->ba_buffer + ctq->ba_first_cl; num_cl > 0; num_cl--, cl++)
	{
	  oct_npa_batch_alloc_status_t st;

	  if ((st.as_u64 = __atomic_load_n (cl->iova, __ATOMIC_RELAXED)) ==
	      OCT_BATCH_ALLOC_IOVA0_MASK + ALLOC_CCODE_INVAL)
	    {
	    cl_not_ready:
	      ctx->batch_alloc_not_ready++;
	      n_freed = bi - (u32 *) ctq->ba_buffer;
	      if (n_freed > 0)
		{
		  vlib_buffer_free_no_next (vm, (u32 *) ctq->ba_buffer,
					    n_freed);
		  ctq->ba_num_cl = num_cl;
		  ctq->ba_first_cl = cl - ctq->ba_buffer;
		  return n_freed;
		}

	      return 0;
	    }

	  if (st.status.count > 8 &&
	      __atomic_load_n (cl->iova + 8, __ATOMIC_RELAXED) ==
		OCT_BATCH_ALLOC_IOVA0_MASK)
	    goto cl_not_ready;

#if (CLIB_DEBUG > 0)
	  cl->iova[0] &= OCT_BATCH_ALLOC_IOVA0_MASK;
#endif
	  if (PREDICT_TRUE (st.status.count == 16))
	    {
	      /* optimize for likely case where cacheline is full */
	      vlib_get_buffer_indices_with_offset (vm, (void **) cl, bi, 16,
						   off);
	      bi += 16;
	    }
	  else
	    {
	      vlib_get_buffer_indices_with_offset (vm, (void **) cl, bi,
						   st.status.count, off);
	      bi += st.status.count;
	    }
	}

      n_freed = bi - (u32 *) ctq->ba_buffer;
      if (n_freed > 0)
	vlib_buffer_free_no_next (vm, (u32 *) ctq->ba_buffer, n_freed);

      /* clear status bits in each cacheline */
      n = cl - ctq->ba_buffer;
      for (u32 i = 0; i < n; i++)
	ctq->ba_buffer[i].iova[0] = ctq->ba_buffer[i].iova[8] =
	  OCT_BATCH_ALLOC_IOVA0_MASK;

      ctq->ba_num_cl = ctq->ba_first_cl = 0;
    }

  ah = ctq->aura_handle;

  if ((n = roc_npa_aura_op_available (ah)) >= 32)
    {
      u64 addr, res;

      n = clib_min (n, ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);

      oct_npa_batch_alloc_compare_t cmp = {
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
#endif

static_always_inline u8
oct_tx_enq1 (vlib_main_t *vm, oct_tx_ctx_t *ctx, vlib_buffer_t *b,
	     lmt_line_t *line, u32 flags, int simple, int trace, u32 *n,
	     u8 *dpl)
{
  u8 n_dwords = 2;
  u32 total_len = 0;
  oct_tx_desc_t d = {
    .hdr_w0 = ctx->hdr_w0_teplate,
    .sg[0] = {
      .segs = 1,
      .subdc = NIX_SUBDC_SG,
    },
    .sg[4] = {
      .subdc = NIX_SUBDC_SG,
    },
  };

  if (PREDICT_FALSE (vlib_buffer_length_in_chain (vm, b) > ctx->max_pkt_len))
    {
      ctx->exd_mtu[ctx->n_exd_mtu++] = b;
      return 0;
    }

#ifdef PLATFORM_OCTEON9
  /* Override line for Octeon9 */
  line = ctx->lmt_lines;
#endif

  if (!simple && flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u8 n_tail_segs = 0;
      vlib_buffer_t *tail_segs[5], *t = b;

      while (t->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  t = vlib_get_buffer (vm, t->next_buffer);
	  tail_segs[n_tail_segs++] = t;
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
      d.hdr_w0.sizem1 = n_dwords - 1;
    }

  if (!simple && flags & VNET_BUFFER_F_OFFLOAD)
    {
      vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	{
	  d.hdr_w1.ol3type = NIX_SENDL3TYPE_IP4_CKSUM;
	  d.hdr_w1.ol3ptr = vnet_buffer (b)->l3_hdr_offset - b->current_data;
	  d.hdr_w1.ol4ptr = d.hdr_w1.ol3ptr + sizeof (ip4_header_t);
	}
      if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  d.hdr_w1.ol4type = NIX_SENDL4TYPE_UDP_CKSUM;
	  d.hdr_w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  d.hdr_w1.ol4type = NIX_SENDL4TYPE_TCP_CKSUM;
	  d.hdr_w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
    }

  total_len += d.sg[0].seg1_size = b->current_length;
  d.hdr_w0.total = total_len;
  d.sg[1].u = (u64) vlib_buffer_get_current (b);

  if (trace && flags & VLIB_BUFFER_IS_TRACED)
    {
      oct_tx_trace_t *t = vlib_add_trace (vm, ctx->node, b, sizeof (*t));
      t->desc = d;
      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
    }

#ifdef PLATFORM_OCTEON9
  oct_lmt_copy (line, ctx->lmt_ioaddr, &d, n_dwords);
#else
  for (u32 i = 0; i < n_dwords; i++)
    line->dwords[i] = d.as_u128[i];
#endif

  *dpl = n_dwords;
  *n = *n + 1;

  return n_dwords;
}

static_always_inline u32
oct_tx_enq16 (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
	      vlib_buffer_t **b, u32 n_pkts, int trace)
{
  u8 dwords_per_line[16], *dpl = dwords_per_line;
  u64 __attribute__ ((unused)) lmt_arg, ioaddr, n_lines;
  u32 __attribute__ ((unused)) or_flags_16 = 0;
  u32 n_left, n = 0;
  const u32 not_simple_flags =
    VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD;
  lmt_line_t *l = ctx->lmt_lines;

  /* Data Store Memory Barrier - outer shareable domain */
  asm volatile("dmb oshst" ::: "memory");

  for (n_left = n_pkts; n_left >= 8; n_left -= 8, b += 8)
    {
      u32 f0, f1, f2, f3, f4, f5, f6, f7, or_f = 0;
      vlib_prefetch_buffer_header (b[8], LOAD);
      or_f |= f0 = b[0]->flags;
      or_f |= f1 = b[1]->flags;
      vlib_prefetch_buffer_header (b[9], LOAD);
      or_f |= f2 = b[2]->flags;
      or_f |= f3 = b[3]->flags;
      vlib_prefetch_buffer_header (b[10], LOAD);
      or_f |= f4 = b[4]->flags;
      or_f |= f5 = b[5]->flags;
      vlib_prefetch_buffer_header (b[11], LOAD);
      or_f |= f6 = b[6]->flags;
      or_f |= f7 = b[7]->flags;
      vlib_prefetch_buffer_header (b[12], LOAD);
      or_flags_16 |= or_f;

      if ((or_f & not_simple_flags) == 0)
	{
	  int simple = 1;
	  oct_tx_enq1 (vm, ctx, b[0], l, f0, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[1], l + n, f1, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  oct_tx_enq1 (vm, ctx, b[2], l + n, f2, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[3], l + n, f3, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  oct_tx_enq1 (vm, ctx, b[4], l + n, f4, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[5], l + n, f5, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	  oct_tx_enq1 (vm, ctx, b[6], l + n, f6, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[7], l + n, f7, simple, trace, &n, &dpl[n]);
	}
      else
	{
	  int simple = 0;
	  oct_tx_enq1 (vm, ctx, b[0], l, f0, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[1], l + n, f1, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  oct_tx_enq1 (vm, ctx, b[2], l + n, f2, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[3], l + n, f3, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  oct_tx_enq1 (vm, ctx, b[4], l + n, f4, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[5], l + n, f5, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	  oct_tx_enq1 (vm, ctx, b[6], l + n, f6, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[7], l + n, f7, simple, trace, &n, &dpl[n]);
	}
      dpl += n;
      l += n;
      n = 0;
    }

  for (; n_left > 0; n_left -= 1, b += 1)
    {
      u32 f0 = b[0]->flags;
      oct_tx_enq1 (vm, ctx, b[0], l, f0, 0, trace, &n, &dpl[n]);
      or_flags_16 |= f0;
      dpl += n;
      l += n;
      n = 0;
    }

  lmt_arg = ctx->lmt_id;
  ioaddr = ctx->lmt_ioaddr;
  n_lines = dpl - dwords_per_line;

  if (PREDICT_FALSE (!n_lines))
    return n_pkts;

#ifndef PLATFORM_OCTEON9
  if (PREDICT_FALSE (or_flags_16 & VLIB_BUFFER_NEXT_PRESENT))
    {
      dpl = dwords_per_line;
      ioaddr |= (dpl[0] - 1) << 4;

      if (n_lines > 1)
	{
	  lmt_arg |= (--n_lines) << 12;

	  for (u8 bit_off = 19; n_lines; n_lines--, bit_off += 3, dpl++)
	    lmt_arg |= ((u64) dpl[1] - 1) << bit_off;
	}
    }
  else
    {
      const u64 n_dwords = 2;
      ioaddr |= (n_dwords - 1) << 4;

      if (n_lines > 1)
	{
	  lmt_arg |= (--n_lines) << 12;

	  for (u8 bit_off = 19; n_lines; n_lines--, bit_off += 3)
	    lmt_arg |= (n_dwords - 1) << bit_off;
	}
    }

  roc_lmt_submit_steorl (lmt_arg, ioaddr);
#endif

  return n_pkts;
}

VNET_DEV_NODE_FN (oct_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  u32 node_index = node->node_index;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n, n_enq, n_left, n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 8], **b = buffers;
#ifdef PLATFORM_OCTEON9
  u64 lmt_id = 0;
#else
  u64 lmt_id = vm->thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
#endif

  oct_tx_ctx_t ctx = {
    .node = node,
    .hdr_w0_teplate = {
      .aura = roc_npa_aura_handle_to_aura (ctq->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .max_pkt_len = roc_nix_max_pkt_len (cd->nix),
    .lmt_id = lmt_id,
    .lmt_ioaddr = ctq->io_addr,
    .lmt_lines = ctq->lmt_addr + (lmt_id << ROC_LMT_LINE_SIZE_LOG2),
  };

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  for (int i = 0; i < 8; i++)
    b[n_pkts + i] = b[n_pkts - 1];

  vnet_dev_tx_queue_lock_if_needed (txq);

  n_enq = ctq->n_enq;
  n_enq -= oct_batch_free (vm, &ctx, txq);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (n_left = clib_min (n_pkts, txq->size - n_enq), n = 0; n_left >= 16;
	   n_left -= 16, b += 16)
	n += oct_tx_enq16 (vm, &ctx, txq, b, 16, /* trace */ 1);

      if (n_left)
	n += oct_tx_enq16 (vm, &ctx, txq, b, n_left, /* trace */ 1);
    }
  else
    {
      for (n_left = clib_min (n_pkts, txq->size - n_enq), n = 0; n_left >= 16;
	   n_left -= 16, b += 16)
	n += oct_tx_enq16 (vm, &ctx, txq, b, 16, /* trace */ 0);

      if (n_left)
	n += oct_tx_enq16 (vm, &ctx, txq, b, n_left, /* trace */ 0);
    }

  ctq->n_enq = n_enq + n - ctx.n_drop - ctx.n_exd_mtu;

  if (n < n_pkts)
    {
      u32 n_free = n_pkts - n;
      vlib_buffer_free (vm, from + n, n_free);
      vlib_error_count (vm, node->node_index, OCT_TX_NODE_CTR_NO_FREE_SLOTS,
			n_free);
      n_pkts -= n_free;
    }

  if (ctx.n_drop)
    vlib_error_count (vm, node->node_index, OCT_TX_NODE_CTR_CHAIN_TOO_LONG,
		      ctx.n_drop);

  if (PREDICT_FALSE (ctx.n_exd_mtu))
    vlib_error_count (vm, node->node_index, OCT_TX_NODE_CTR_MTU_EXCEEDED,
		      ctx.n_exd_mtu);

  if (ctx.batch_alloc_not_ready)
    vlib_error_count (vm, node_index,
		      OCT_TX_NODE_CTR_AURA_BATCH_ALLOC_NOT_READY,
		      ctx.batch_alloc_not_ready);

  if (ctx.batch_alloc_issue_fail)
    vlib_error_count (vm, node_index,
		      OCT_TX_NODE_CTR_AURA_BATCH_ALLOC_ISSUE_FAIL,
		      ctx.batch_alloc_issue_fail);

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (ctx.n_drop)
    {
      u32 bi[VLIB_FRAME_SIZE];
      vlib_get_buffer_indices (vm, ctx.drop, bi, ctx.n_drop);
      vlib_buffer_free (vm, bi, ctx.n_drop);
      n_pkts -= ctx.n_drop;
    }

  if (PREDICT_FALSE (ctx.n_exd_mtu))
    {
      u32 bi[VLIB_FRAME_SIZE];
      vlib_get_buffer_indices (vm, ctx.exd_mtu, bi, ctx.n_exd_mtu);
      vlib_buffer_free (vm, bi, ctx.n_exd_mtu);
      n_pkts -= ctx.n_exd_mtu;
    }

  return n_pkts;
}

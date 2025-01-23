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
#include <tm.h>

#define OCT_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                                                   \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))
#define OCT_SEND_HDR_DWORDS 1

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
oct_batch_free (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
		oct_per_thread_data_t *ptd)
{
  u16 off = ptd->hdr_off;
  u64 ah = ptd->aura_handle;
  u32 n_freed = 0, n;

  ah = ptd->aura_handle;

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
oct_batch_free (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
		oct_per_thread_data_t *ptd)
{
  u8 num_cl;
  u64 ah;
  u32 n_freed = 0, n;
  oct_npa_batch_alloc_cl128_t *cl;

  num_cl = ptd->ba_num_cl;
  if (num_cl)
    {
      u16 off = ptd->hdr_off;
      u32 *bi = (u32 *) ptd->ba_buffer;

      for (cl = ptd->ba_buffer + ptd->ba_first_cl; num_cl > 0; num_cl--, cl++)
	{
	  oct_npa_batch_alloc_status_t st;

	  if ((st.as_u64 = __atomic_load_n (cl->iova, __ATOMIC_RELAXED)) ==
	      OCT_BATCH_ALLOC_IOVA0_MASK + ALLOC_CCODE_INVAL)
	    {
	    cl_not_ready:
	      ctx->batch_alloc_not_ready++;
	      n_freed = bi - (u32 *) ptd->ba_buffer;
	      if (n_freed > 0)
		{
		  vlib_buffer_free_no_next (vm, (u32 *) ptd->ba_buffer, n_freed);
		  ptd->ba_num_cl = num_cl;
		  ptd->ba_first_cl = cl - ptd->ba_buffer;
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

      n_freed = bi - (u32 *) ptd->ba_buffer;
      if (n_freed > 0)
	vlib_buffer_free_no_next (vm, (u32 *) ptd->ba_buffer, n_freed);

      /* clear status bits in each cacheline */
      n = cl - ptd->ba_buffer;
      for (u32 i = 0; i < n; i++)
	ptd->ba_buffer[i].iova[0] = ptd->ba_buffer[i].iova[8] = OCT_BATCH_ALLOC_IOVA0_MASK;

      ptd->ba_num_cl = ptd->ba_first_cl = 0;
    }

  ah = ptd->aura_handle;

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
      res = roc_atomic64_casl (cmp.as_u64, (uint64_t) ptd->ba_buffer, (i64 *) addr);
      if (res == ALLOC_RESULT_ACCEPTED || res == ALLOC_RESULT_NOCORE)
	{
	  ptd->ba_num_cl = (n + 15) / 16;
	  ptd->ba_first_cl = 0;
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

static inline u16
oct_check_fc_nix (struct roc_nix_sq *sq, i32 *fc_cache, u16 pkts)
{
  i32 val, new_val, depth;
  u8 retry_count = 32;

  do
    {
      /* Reduce the cached count */
      val = (i32) __atomic_sub_fetch (fc_cache, pkts, __ATOMIC_RELAXED);
      if (val >= 0)
	return pkts;

      depth = sq->nb_sqb_bufs_adj - __atomic_load_n ((u64 *) sq->fc, __ATOMIC_RELAXED);

      if (depth <= 0)
	return 0;

      /* Update cached value (fc_cache) when lower than `pkts` */
      new_val = (depth << sq->sqes_per_sqb_log2) - pkts;
      if (PREDICT_FALSE (new_val < 0))
	return 0;

      /* Update fc_cache if there is no update done by other cores */
      if (__atomic_compare_exchange_n (fc_cache, &val, new_val, false, __ATOMIC_RELAXED,
				       __ATOMIC_RELAXED))
	return pkts;
    }
  while (retry_count--);

  return 0;
}

static_always_inline u64
oct_add_sg_desc (union nix_send_sg_s *sg, int n_segs, vlib_buffer_t *seg1, vlib_buffer_t *seg2,
		 vlib_buffer_t *seg3)
{
  sg[0].u = 0;
  sg[0].segs = n_segs;
  sg[0].subdc = NIX_SUBDC_SG;

  switch (n_segs)
    {
    case 3:
      sg[0].seg3_size = seg3->current_length;
      sg[3].u = (u64) vlib_buffer_get_current (seg3);
      /* Fall through */
    case 2:
      sg[0].seg2_size = seg2->current_length;
      sg[2].u = (u64) vlib_buffer_get_current (seg2);
      /* Fall through */
    case 1:
      sg[0].seg1_size = seg1->current_length;
      sg[1].u = (u64) vlib_buffer_get_current (seg1);
      break;
    default:
      ASSERT (0);
      return 0;
    }

  /* Return number of dwords in sub-descriptor */
  return n_segs == 1 ? 1 : 2;
}

static_always_inline u64
oct_add_sg_list (union nix_send_sg_s *sg, vlib_buffer_t *b, u64 n_segs)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *seg1, *seg2, *seg3;
  u64 n_dwords;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return oct_add_sg_desc (sg, 1, b, NULL, NULL);

  seg1 = b;
  n_dwords = 0;
  while (n_segs > 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      seg3 = vlib_get_buffer (vm, seg2->next_buffer);

      n_dwords += oct_add_sg_desc (sg, 3, seg1, seg2, seg3);

      if (seg3->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  seg1 = vlib_get_buffer (vm, seg3->next_buffer);
	  sg += 4;
	}
      n_segs -= 3;
    }

  if (n_segs == 1)
    n_dwords += oct_add_sg_desc (sg, 1, seg1, NULL, NULL);
  else if (n_segs == 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      n_dwords += oct_add_sg_desc (sg, 2, seg1, seg2, NULL);
    }

  return n_dwords;
}

static_always_inline u64
oct_add_send_hdr (struct nix_send_hdr_s *hdr, vlib_buffer_t *b, u64 aura_handle, u64 sq,
		  u64 n_dwords)
{
  vnet_buffer_oflags_t oflags;

  hdr->w0.u = 0;
  hdr->w1.u = 0;
  hdr->w0.sq = sq;
  hdr->w0.aura = roc_npa_aura_handle_to_aura (aura_handle);
  hdr->w0.total = b->current_length;
  hdr->w0.sizem1 = n_dwords + OCT_SEND_HDR_DWORDS - 1;

  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    hdr->w0.total = vlib_buffer_length_in_chain (vlib_get_main (), b);

  if (!(b->flags & VNET_BUFFER_F_OFFLOAD))
    return OCT_SEND_HDR_DWORDS;

  if (b->flags & VNET_BUFFER_F_OFFLOAD)
    {
      oflags = vnet_buffer (b)->oflags;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	{
	  hdr->w1.ol3type = NIX_SENDL3TYPE_IP4_CKSUM;
	  hdr->w1.ol3ptr = vnet_buffer (b)->l3_hdr_offset - b->current_data;
	  hdr->w1.ol4ptr = hdr->w1.ol3ptr + sizeof (ip4_header_t);
	}
      if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  hdr->w1.ol4type = NIX_SENDL4TYPE_UDP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  hdr->w1.ol4type = NIX_SENDL4TYPE_TCP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
    }

  return OCT_SEND_HDR_DWORDS;
}

static_always_inline u32
oct_get_tx_vlib_buf_segs (vlib_main_t *vm, vlib_buffer_t *b)
{
  /* Each buffer will have at least 1 segment */
  u32 n_segs = 1;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return n_segs;

  do
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      n_segs++;
    }
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT);

  return n_segs;
}

void static_always_inline
oct_pkts_send_x4 (vlib_main_t *vm, struct roc_nix_sq *sq, u64 aura_handle, vlib_buffer_t *b0,
		  vlib_buffer_t *b1, vlib_buffer_t *b2, vlib_buffer_t *b3)
{
  u64 lmt_arg, core_lmt_base_addr, core_lmt_id, sq_handle;
  u32 desc_sz = 10 /* Worst case - Send hdr + Two SG with 3 segs each */;
  u64 desc0[desc_sz], desc1[desc_sz], desc2[desc_sz], desc3[desc_sz];
  void *lmt_line0, *lmt_line1, *lmt_line2, *lmt_line3;
  union nix_send_sg_s *sg0, *sg1, *sg2, *sg3;
  struct nix_send_hdr_s *send_hdr0, *send_hdr1, *send_hdr2, *send_hdr3;
  u64 io_addr, n_dwords[4], n_segs[4];

  io_addr = sq->io_addr;
  sq_handle = sq->qid;

  send_hdr0 = (struct nix_send_hdr_s *) &desc0[0];
  send_hdr1 = (struct nix_send_hdr_s *) &desc1[0];
  send_hdr2 = (struct nix_send_hdr_s *) &desc2[0];
  send_hdr3 = (struct nix_send_hdr_s *) &desc3[0];

  sg0 = (union nix_send_sg_s *) &desc0[2];
  sg1 = (union nix_send_sg_s *) &desc1[2];
  sg2 = (union nix_send_sg_s *) &desc2[2];
  sg3 = (union nix_send_sg_s *) &desc3[2];

  core_lmt_base_addr = (u64) sq->lmt_addr;
  ROC_LMT_BASE_ID_GET (core_lmt_base_addr, core_lmt_id);

  lmt_line0 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 0);
  lmt_line1 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 1);
  lmt_line2 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 2);
  lmt_line3 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 3);

  n_segs[0] = oct_get_tx_vlib_buf_segs (vm, b0);
  n_segs[1] = oct_get_tx_vlib_buf_segs (vm, b1);
  n_segs[2] = oct_get_tx_vlib_buf_segs (vm, b2);
  n_segs[3] = oct_get_tx_vlib_buf_segs (vm, b3);

  n_dwords[0] = oct_add_sg_list (sg0, b0, n_segs[0]);
  n_dwords[1] = oct_add_sg_list (sg1, b1, n_segs[1]);
  n_dwords[2] = oct_add_sg_list (sg2, b2, n_segs[2]);
  n_dwords[3] = oct_add_sg_list (sg3, b3, n_segs[3]);

  n_dwords[0] += oct_add_send_hdr (send_hdr0, b0, aura_handle, sq_handle, n_dwords[0]);
  n_dwords[1] += oct_add_send_hdr (send_hdr1, b1, aura_handle, sq_handle, n_dwords[1]);
  n_dwords[2] += oct_add_send_hdr (send_hdr2, b2, aura_handle, sq_handle, n_dwords[2]);
  n_dwords[3] += oct_add_send_hdr (send_hdr3, b3, aura_handle, sq_handle, n_dwords[3]);

  /*
   * Add a memory barrier so that LMTLINEs from the previous iteration
   * can be reused for a subsequent transfer.
   */
  asm volatile ("dmb oshst" ::: "memory");

  /* Clear io_addr[6:0] bits */
  io_addr &= ~0x7FULL;
  lmt_arg = core_lmt_id;

  /* Set size-1 of first LMTST at io_addr[6:4] */
  io_addr |= (n_dwords[0] - 1) << 4;

  roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
  roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
  roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
  roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);

  /* Set number of LMTSTs, excluding the first */
  lmt_arg |= (4 - 1) << 12;

  /*
   * Set vector of sizes of next 3 LMTSTs.
   * Every 3 bits represent size-1 of one LMTST
   */
  lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
  lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
  lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));

  roc_lmt_submit_steorl (lmt_arg, io_addr);
}

void static_always_inline
oct_pkts_send_x1 (vlib_main_t *vm, struct roc_nix_sq *sq, u64 aura_handle, vlib_buffer_t *b0)
{
  u64 lmt_arg, core_lmt_base_addr, core_lmt_id, sq_handle;
  u32 desc_sz = 10 /* Worst case - Send hdr + Two SG with 3 segs each */;
  u64 desc0[desc_sz];
  void *lmt_line0;
  union nix_send_sg_s *sg0;
  struct nix_send_hdr_s *send_hdr0;
  u64 io_addr, n_dwords[4], n_segs[4];

  io_addr = sq->io_addr;
  sq_handle = sq->qid;

  send_hdr0 = (struct nix_send_hdr_s *) &desc0[0];
  sg0 = (union nix_send_sg_s *) &desc0[2];

  core_lmt_base_addr = (u64) sq->lmt_addr;
  ROC_LMT_BASE_ID_GET (core_lmt_base_addr, core_lmt_id);

  lmt_line0 = (void *) ((u64) core_lmt_base_addr);
  lmt_arg = core_lmt_id;

  n_segs[0] = oct_get_tx_vlib_buf_segs (vm, b0);

  n_dwords[0] = oct_add_sg_list (sg0, b0, n_segs[0]);
  n_dwords[0] += oct_add_send_hdr (send_hdr0, b0, aura_handle, sq_handle, n_dwords[0]);

  /* Clear io_addr[6:0] bits */
  io_addr &= ~0x7FULL;

  /* Set size-1 of first LMTST at io_addr[6:4] */
  io_addr |= (n_dwords[0] - 1) << 4;

  /*
   * Add a memory barrier so that LMTLINEs from the previous iteration
   * can be reused for a subsequent transfer.
   */
  asm volatile ("dmb oshst" ::: "memory");

  roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
  roc_lmt_submit_steorl (lmt_arg, io_addr);
}

/*
 * Sends packets the SQs based on TM queue id encoded in buffer
 * flow_id when VNET_BUFFER_F_TM_QUEUE_VALID is set.
 */
i32 static_always_inline
oct_pkts_send_tm (vlib_main_t *vm, vlib_node_runtime_t *node, oct_per_thread_data_t *ptd,
		  oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq, u16 tx_pkts, vlib_buffer_t **bufs)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  u64 n_packets;
  u64 sq_handle0, sq_handle1, sq_handle2, sq_handle3, sq_handle_xor;
  u16 n_left0 = tx_pkts;
  u32 failed_buff[VLIB_FRAME_SIZE] = { 0 };
  u64 aura_handle;
  u16 n_nix_fc_drop = 0;
  u32 tmq;
  struct roc_nix_sq *sq0, *sq1, *sq2, *sq3;
  oct_txq_t *ctq0, *ctq1, *ctq2, *ctq3;
  vlib_buffer_t **b;

  b = bufs;
  aura_handle = ptd->aura_handle;
  n_packets = tx_pkts;

  while (n_packets > 4)
    {
      if ((b[0])->flags & VNET_BUFFER_F_TM_QUEUE_VALID)
	{
	  tmq = get_tm_node_id_from_flow_id (b[0]->flow_id);
	  ctq0 = cd->ctqs[tmq];
	}
      else
	ctq0 = ctq;
      if ((b[1])->flags & VNET_BUFFER_F_TM_QUEUE_VALID)
	{
	  tmq = get_tm_node_id_from_flow_id (b[1]->flow_id);
	  ctq1 = cd->ctqs[tmq];
	}
      else
	ctq1 = ctq;
      if ((b[2])->flags & VNET_BUFFER_F_TM_QUEUE_VALID)
	{
	  tmq = get_tm_node_id_from_flow_id (b[2]->flow_id);
	  ctq2 = cd->ctqs[tmq];
	}
      else
	ctq2 = ctq;
      if ((b[3])->flags & VNET_BUFFER_F_TM_QUEUE_VALID)
	{
	  tmq = get_tm_node_id_from_flow_id (b[3]->flow_id);
	  ctq3 = cd->ctqs[tmq];
	}
      else
	ctq3 = ctq;

      sq0 = &ctq0->sq;
      sq1 = &ctq1->sq;
      sq2 = &ctq2->sq;
      sq3 = &ctq3->sq;

      sq_handle0 = sq0->qid;
      sq_handle1 = sq1->qid;
      sq_handle2 = sq2->qid;
      sq_handle3 = sq3->qid;

      sq_handle_xor = sq_handle0 ^ sq_handle1;
      sq_handle_xor += sq_handle1 ^ sq_handle2;
      sq_handle_xor += sq_handle2 ^ sq_handle3;

      if (!sq_handle_xor)
	{
	  n_left0 = oct_check_fc_nix (sq0, &ctq0->cached_pkts, 4);

	  if (!n_left0)
	    {
	      failed_buff[n_nix_fc_drop++] = vlib_get_buffer_index (vm, b[0]);
	      failed_buff[n_nix_fc_drop++] = vlib_get_buffer_index (vm, b[1]);
	      failed_buff[n_nix_fc_drop++] = vlib_get_buffer_index (vm, b[2]);
	      failed_buff[n_nix_fc_drop++] = vlib_get_buffer_index (vm, b[3]);
	    }
	  else
	    oct_pkts_send_x4 (vm, sq0, aura_handle, b[0], b[1], b[2], b[3]);
	}
      else
	{
	  n_left0 = oct_check_fc_nix (sq0, &ctq0->cached_pkts, 1);
	  if (!n_left0)
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[0]);
	      n_nix_fc_drop++;
	    }
	  else
	    oct_pkts_send_x1 (vm, sq0, aura_handle, b[0]);

	  n_left0 = oct_check_fc_nix (sq1, &ctq1->cached_pkts, 1);
	  if (!n_left0)
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[1]);
	      n_nix_fc_drop++;
	    }
	  else
	    oct_pkts_send_x1 (vm, sq1, aura_handle, b[1]);

	  n_left0 = oct_check_fc_nix (sq2, &ctq2->cached_pkts, 1);
	  if (!n_left0)
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[2]);
	      n_nix_fc_drop++;
	    }
	  else
	    oct_pkts_send_x1 (vm, sq2, aura_handle, b[2]);

	  n_left0 = oct_check_fc_nix (sq3, &ctq3->cached_pkts, 1);
	  if (!n_left0)
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[3]);
	      n_nix_fc_drop++;
	    }
	  else
	    oct_pkts_send_x1 (vm, sq3, aura_handle, b[3]);
	}
      n_packets -= 4;
      b += 4;
    }

  while (n_packets)
    {
      if (n_packets > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      if ((b[0])->flags & VNET_BUFFER_F_TM_QUEUE_VALID)
	{
	  tmq = get_tm_node_id_from_flow_id (b[0]->flow_id);
	  ctq0 = cd->ctqs[tmq];
	}
      else
	ctq0 = ctq;

      sq0 = &ctq0->sq;
      sq_handle0 = sq0->qid;
      n_left0 = oct_check_fc_nix (sq0, &ctq0->cached_pkts, 1);
      if (!n_left0)
	{
	  failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[0]);
	  n_nix_fc_drop++;
	}
      else
	oct_pkts_send_x1 (vm, sq0, aura_handle, b[0]);

      n_packets -= 1;
      b += 1;
    }

  /*
   * Free packets which failed in nix_fc_check.
   * These packet indices are stored in failed_buff,
   * as they may not be contiguous when received.
   */
  if (PREDICT_FALSE (n_nix_fc_drop))
    vlib_buffer_free (vm, failed_buff, n_nix_fc_drop);

  return tx_pkts - n_nix_fc_drop;
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
  clib_thread_index_t thread_index = vm->thread_index;
#ifdef PLATFORM_OCTEON9
  u64 lmt_id = 0;
#else
  u64 lmt_id = thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
#endif
  oct_per_thread_data_t *ptd = vec_elt_at_index (oct_main.per_thread_data, thread_index);

  oct_tx_ctx_t ctx = {
    .node = node,
    .hdr_w0_teplate = {
      .aura = roc_npa_aura_handle_to_aura (ptd->aura_handle),
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
  n_enq -= oct_batch_free (vm, &ctx, txq, ptd);

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

VNET_DEV_NODE_FN (oct_tx_tm_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  u32 node_index = node->node_index;
  u32 n_left, n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 8], **b = buffers;
  clib_thread_index_t thread_index = vm->thread_index;
#ifdef PLATFORM_OCTEON9
  u64 lmt_id = 0;
#else
  u64 lmt_id = thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
#endif
  oct_per_thread_data_t *ptd = vec_elt_at_index (oct_main.per_thread_data, thread_index);

  oct_tx_ctx_t ctx = {
    .node = node,
    .hdr_w0_teplate = {
      .aura = roc_npa_aura_handle_to_aura (ptd->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .max_pkt_len = roc_nix_max_pkt_len (cd->nix),
    .lmt_id = lmt_id,
    .lmt_ioaddr = ctq->io_addr,
    .lmt_lines = ctq->lmt_addr + (lmt_id << ROC_LMT_LINE_SIZE_LOG2),
  };

  /* Free completed descriptors */
  oct_batch_free (vm, &ctx, txq, ptd);

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  n_left = n_pkts;

  n_pkts = oct_pkts_send_tm (vm, node, ptd, &ctx, txq, n_pkts, b);

  if (PREDICT_FALSE (n_left != n_pkts))
    {
      vlib_error_count (vm, node_index, OCT_TX_NODE_CTR_NO_FREE_SLOTS, (n_left - n_pkts));
    }

  return n_pkts;
}

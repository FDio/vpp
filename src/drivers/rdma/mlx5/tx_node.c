/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mlx5.h>

#define MLX5_TX_PKT_LAYOUT_DROP 0xff
#define MLX5_TX_MAX_SEGS_2WQEBB 6
#define MLX5_TX_MAX_FLAT_DSEGS	(VLIB_FRAME_SIZE + 4 * MLX5_TX_MAX_SEGS_2WQEBB)

static_always_inline mlx5_tx_trace_t *
mlx5_txq_trace_one (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi, u8 n_sge,
		    mlx5_wqe_ctrl_seg_t *ctrl, mlx5_wqe_eth_seg_t *eseg, mlx5_wqe_data_seg_t *dseg)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  mlx5_tx_trace_t *tr;

  if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
    return 0;

  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  tr->qid = txq->queue_id;
  tr->n_sge = n_sge;
  tr->cs_flags = eseg ? eseg->cs_flags : 0;
  tr->dropped = n_sge == 0;
  tr->hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
  tr->buffer_index = bi;
  tr->data_len = b->current_length;
  tr->ctrl = ctrl ? *ctrl : (mlx5_wqe_ctrl_seg_t){};
  tr->eseg = eseg ? *eseg : (mlx5_wqe_eth_seg_t){};
  tr->dseg = dseg ? *dseg : (mlx5_wqe_data_seg_t){};
  return tr;
}

static_always_inline u32
copy_dseg_to_wqe (mlx5_wqe_data_seg_t *dst, mlx5_wqe_data_seg_t *src, u32 n_dsegs, u32 l_key)
{
  u32 bytes = 0;

#ifdef CLIB_HAVE_VEC128
  u32x4 lk4 = u32x4_splat (l_key);
  u32x4 bytes4 = {};
  u8x16 lk = (u8x16) lk4;

#if defined(CLIB_HAVE_VEC512)
  u8x64 lk16 = (u8x64) u32x16_splat (l_key);
  u32x16 bytes16 = {};

  for (; n_dsegs >= 4; n_dsegs -= 4, dst += 4, src += 4)
    {
      u8x64 s = *(u8x64 *) src;

      *(u8x64 *) dst = u8x64_shuffle2 (
	s, lk16, 3, 2, 1, 0, 64, 65, 66, 67, 15, 14, 13, 12, 11, 10, 9, 8, 19, 18, 17, 16, 64, 65,
	66, 67, 31, 30, 29, 28, 27, 26, 25, 24, 35, 34, 33, 32, 64, 65, 66, 67, 47, 46, 45, 44, 43,
	42, 41, 40, 51, 50, 49, 48, 64, 65, 66, 67, 63, 62, 61, 60, 59, 58, 57, 56);
      bytes16 += (u32x16) s;
    }
  bytes += bytes16[0] + bytes16[4] + bytes16[8] + bytes16[12];
#elif defined(CLIB_HAVE_VEC256)
  u8x32 lk8 = (u8x32) u32x8_splat (l_key);
  u32x8 bytes8 = {};

  for (; n_dsegs >= 2; n_dsegs -= 2, dst += 2, src += 2)
    {
      u8x32 s = *(u8x32 *) src;

      *(u8x32 *) dst =
	u8x32_shuffle2 (s, lk8, 3, 2, 1, 0, 32, 33, 34, 35, 15, 14, 13, 12, 11, 10, 9, 8, 19, 18,
			17, 16, 32, 33, 34, 35, 31, 30, 29, 28, 27, 26, 25, 24);
      bytes8 += (u32x8) s;
    }
  bytes += bytes8[0] + bytes8[4];
#endif

  for (; n_dsegs; n_dsegs--, dst++, src++)
    {
      u8x16 s = *(u8x16 *) src;

      *(u8x16 *) dst =
	u8x16_shuffle2 (s, lk, 3, 2, 1, 0, 16, 17, 18, 19, 15, 14, 13, 12, 11, 10, 9, 8);
      bytes4 += (u32x4) s;
    }
  bytes += bytes4[0];
#else
  for (; n_dsegs; n_dsegs--, dst++, src++)
    {
      dst->byte_count = clib_host_to_net_u32 (src->byte_count);
      dst->lkey = l_key;
      dst->addr = clib_host_to_net_u64 (src->addr);
      bytes += src->byte_count;
    }
#endif

  return bytes;
}

static __clib_noinline void
mlx5_txq_trace_empw_one (vlib_main_t *vm, vlib_node_runtime_t *node, u32 *from, u32 n_ds,
			 mlx5_wqe_ctrl_seg_t *ctrl, mlx5_wqe_eth_seg_t *eseg)
{
  u32 j;

  for (j = 0; j < n_ds; j++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[j]);

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	{
	  mlx5_txq_trace_one (vm, node, from[j], 1, ctrl, eseg, 0);
	}
    }
}

static_always_inline void
mlx5_tx_scan_one (vlib_main_t *vm, vlib_buffer_t *b, mlx5_wqe_data_seg_t **dsegs, u8 *layout,
		  u32 *n_drop)
{
  mlx5_wqe_data_seg_t *ds = *dsegs;
  u32 flags = b->flags;
  u32 n_seg = 1;

  ds->byte_count = b->current_length;
  ds->addr = pointer_to_uword (vlib_buffer_get_current (b));
  ds++;

  if (PREDICT_TRUE ((flags & (VNET_BUFFER_F_OFFLOAD | VLIB_BUFFER_NEXT_PRESENT)) == 0))
    {
      *dsegs = ds;
      return;
    }

  if (PREDICT_TRUE ((flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    {
      *dsegs = ds;
      *layout = 1;
      return;
    }

  while (1)
    {
      if (PREDICT_FALSE (n_seg == MLX5_TX_MAX_SEGS_2WQEBB))
	{
	  *n_drop += 1;
	  *layout = MLX5_TX_PKT_LAYOUT_DROP;
	  return;
	}
      b = vlib_get_buffer (vm, b->next_buffer);
      ds->byte_count = b->current_length;
      ds->addr = pointer_to_uword (vlib_buffer_get_current (b));
      ds++;
      n_seg++;
      if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	break;
    }

  *dsegs = ds;
  *layout = n_seg;
}

static_always_inline u32
mlx5_tx_scan_and_flatten (vlib_main_t *vm, u32 *from, u32 n_avail, vlib_buffer_t **b,
			  mlx5_wqe_data_seg_t *dsegs, u8 *pkt_layout, u32 *n_drop)
{
  u8 *pkt_layout0 = pkt_layout;
  mlx5_wqe_data_seg_t *dseg = dsegs;
  mlx5_wqe_data_seg_t *last_dseg = dsegs + MLX5_TX_MAX_FLAT_DSEGS;
  u32 n_left_scan = n_avail;
  vlib_buffer_t **bp;

  *n_drop = 0;

  vlib_get_buffers (vm, from, b, n_avail);
  b[n_avail + 0] = b[n_avail + 1] = b[n_avail + 2] = b[n_avail + 3] = b[n_avail - 1];
  bp = b;

  for (; n_left_scan >= 4 && dseg + 4 * MLX5_TX_MAX_SEGS_2WQEBB < last_dseg;
       n_left_scan -= 4, pkt_layout += 4, bp += 4)
    {
      vlib_prefetch_buffer_header (bp[4], LOAD);
      vlib_prefetch_buffer_header (bp[5], LOAD);
      vlib_prefetch_buffer_header (bp[6], LOAD);
      vlib_prefetch_buffer_header (bp[7], LOAD);

      mlx5_tx_scan_one (vm, bp[0], &dseg, &pkt_layout[0], n_drop);
      mlx5_tx_scan_one (vm, bp[1], &dseg, &pkt_layout[1], n_drop);
      mlx5_tx_scan_one (vm, bp[2], &dseg, &pkt_layout[2], n_drop);
      mlx5_tx_scan_one (vm, bp[3], &dseg, &pkt_layout[3], n_drop);
    }

  for (; n_left_scan && dseg + MLX5_TX_MAX_SEGS_2WQEBB < last_dseg;
       n_left_scan--, pkt_layout++, bp++)
    mlx5_tx_scan_one (vm, bp[0], &dseg, &pkt_layout[0], n_drop);

  return pkt_layout - pkt_layout0;
}

static_always_inline u8
mlx5_tx_wqe_get_csum_flags (vlib_buffer_t *b)
{
  u8 cs_flags = 0;
  vnet_buffer_oflags_t oflags;

  if (PREDICT_TRUE ((b->flags & VNET_BUFFER_F_OFFLOAD) == 0))
    return 0;

  oflags = vnet_buffer (b)->oflags;
  if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
    cs_flags |= MLX5_ETH_WQE_L3_CSUM;
  if (oflags & (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    cs_flags |= MLX5_ETH_WQE_L4_CSUM;
  return cs_flags;
}

static_always_inline u32
mlx5_count_consecutive_zeros_u8 (u8 *p, u32 max)
{
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u64 bmp;

#if defined(CLIB_HAVE_VEC512)
  bmp = u8x64_is_not_equal_mask (*(u8x64u *) p, u8x64_zero ());
#elif defined(CLIB_HAVE_VEC256)
  bmp = u8x32_msb_mask ((*(u8x32u *) p != u8x32_zero ()));
  bmp |= (u64) u8x32_msb_mask ((*(u8x32u *) (p + 32) != u8x32_zero ())) << 32;
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  bmp = u8x16_msb_mask ((*(u8x16u *) p != u8x16_zero ()));
  bmp |= (u64) u8x16_msb_mask (((u8x16u *) p)[1] != u8x16_zero ()) << 16;
  bmp |= (u64) u8x16_msb_mask (((u8x16u *) p)[2] != u8x16_zero ()) << 32;
  bmp |= (u64) u8x16_msb_mask (((u8x16u *) p)[3] != u8x16_zero ()) << 48;
#endif
  return count_trailing_zeros (bmp | (1ULL << max));
#else
  u8 *q = p, *e = p + max;

  while (q + 8 <= e && *(u64u *) q == 0)
    q += 8;
  while (q < e && *q == 0)
    q += 1;
  return q - p;
#endif
}

static_always_inline void
mlx5_txq_doorbell (mlx5_txq_t *tq, mlx5_wqe_t *last, u16 tail)
{
  last->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
  __atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], clib_host_to_net_u32 (tail), __ATOMIC_RELEASE);
  __atomic_store_n (&tq->dv_sq_db[0], *(u64 *) last, __ATOMIC_RELEASE);
}

static_always_inline void
mlx5_txq_deq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 cq_mask = tq->dv_cq_size - 1;
  u32 pkt_mask = txq->size - 1;
  u32 sq_mask = tq->sq_size - 1;
  u32 log2_cq_size = tq->dv_cq_log2;
  u16 sq_head = tq->sq_head;
  u16 idx = tq->dv_cq_idx;
  struct mlx5_cqe64 *cqes = tq->dv_cq_cqes;
  struct mlx5_cqe64 *cur;
  u16 n_sq;
  u16 n_pkts;
  u16 i;
  u16 n0;
  u16 n1;
  u16 head;
  u8 op_own;
  u16 sq_tail;

  for (;;)
    {
      cur = cqes + (idx & cq_mask);
      op_own = __atomic_load_n (&cur->op_own, __ATOMIC_ACQUIRE);
      if (((idx >> log2_cq_size) & MLX5_CQE_OWNER_MASK) != (op_own & MLX5_CQE_OWNER_MASK) ||
	  (op_own >> 4) == MLX5_CQE_INVALID)
	break;
      idx++;
    }

  if (idx == tq->dv_cq_idx)
    return;

  cur = cqes + ((idx - 1) & cq_mask);
  cur->op_own = 0xf0;
  sq_tail = clib_net_to_host_u16 (cur->wqe_counter);
  n_sq = sq_tail - sq_head;
  n_pkts = 0;
  head = sq_head & sq_mask;
  n0 = clib_min (n_sq, tq->sq_size - head);
  n1 = n_sq - n0;
  for (i = 0; i < n0; i++)
    n_pkts += tq->wqebb_n_pkts[head + i];
  for (i = 0; i < n1; i++)
    n_pkts += tq->wqebb_n_pkts[i];
  if (n_pkts)
    {
      vlib_buffer_free_from_ring (vm, tq->buffers, tq->pkt_head & pkt_mask, txq->size, n_pkts);
      tq->pkt_head += n_pkts;
    }
  tq->sq_head = sq_tail;

  tq->dv_cq_idx = idx;
  __atomic_store_n (&tq->dv_cq_dbrec[0], clib_host_to_net_u32 (idx), __ATOMIC_RELEASE);
}

static_always_inline void
mlx5_tx_build_wqe (mlx5_wqe_t *wqe, u8 opcode, u32 n_seg, u16 sq_tail, u32 qpn_ds_base, u8 cs_flags)
{
  wqe->ctrl = (mlx5_wqe_ctrl_seg_t){
    .opcode = opcode,
    .wqe_index_lo = sq_tail,
    .wqe_index_hi = sq_tail >> 8,
    .qpn_ds = clib_host_to_net_u32 (qpn_ds_base | (2 + n_seg)),
  };
  wqe->eseg = (mlx5_wqe_eth_seg_t){ .cs_flags = cs_flags };
}

static_always_inline u32
mlx5_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	      vlib_buffer_t **b, mlx5_wqe_data_seg_t *dsegs, u8 *pkt_layout, u32 n_pkts,
	      u32 *n_bytes_ptr, u32 *n_done_ptr, u8 with_empw, u8 trace)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 sq_size = tq->sq_size;
  u32 pkt_size = txq->size;
  u32 pkt_mask = pkt_size - 1;
  u32 sq_mask = sq_size - 1;
  u32 qpn_ds_base = tq->qpn_ds_base;
  u32 lkey = tq->dseg_lkey;
  u32 *buffers = tq->buffers;
  u8 *wqebb_n_pkts = tq->wqebb_n_pkts;
  mlx5_wqe_t *sq_wqes = tq->dv_sq_wqes;
  u32 n_bytes = *n_bytes_ptr;
  u32 n_done = 0;
  u32 n_drop = 0;
  u32 bi_drop[VLIB_FRAME_SIZE];
  u32 n_node = 0;
  u16 sq_tail = tq->sq_tail;
  u16 pkt_tail = tq->pkt_tail;
  mlx5_wqe_data_seg_t *ds = dsegs;
  mlx5_wqe_t *wqe = 0;

  while (n_node < n_pkts)
    {
      u32 layout = pkt_layout[n_node];
      u32 slot0 = sq_tail & sq_mask;
      wqe = sq_wqes + slot0;

      if (PREDICT_TRUE (layout == 0))
	{

	  if (with_empw)
	    {
	      u32 contig_wqebb = sq_size - slot0;
	      u32 n_ds = clib_min (n_pkts - n_node, 61); /* 63 - ctrl - eseg */
	      u32 n_wqebb;

	      n_ds = mlx5_count_consecutive_zeros_u8 (pkt_layout + n_node, n_ds);
	      mlx5_tx_build_wqe (wqe, MLX5_OPCODE_ENHANCED_MPSW, n_ds, sq_tail, qpn_ds_base, 0);
	      n_wqebb = (2 + n_ds + 3) >> 2;
	      if (PREDICT_TRUE (n_wqebb <= contig_wqebb))
		{
		  n_bytes += copy_dseg_to_wqe (&wqe->dsegs[2], ds, n_ds, lkey);
		  clib_memset_u8 (wqebb_n_pkts + slot0, 0, n_wqebb);
		}
	      else
		{
		  u32 n_ds_contig = 2 + (contig_wqebb - 1) * 4;

		  n_bytes += copy_dseg_to_wqe (&wqe->dsegs[2], ds, n_ds_contig, lkey);
		  n_bytes += copy_dseg_to_wqe (&sq_wqes[0].dsegs[0], ds + n_ds_contig,
					       n_ds - n_ds_contig, lkey);
		  clib_memset_u8 (wqebb_n_pkts + slot0, 0, contig_wqebb);
		  clib_memset_u8 (wqebb_n_pkts, 0, n_wqebb - contig_wqebb);
		}
	      vlib_buffer_copy_indices_to_ring (buffers, from + n_node, pkt_tail, pkt_size, n_ds);
	      if (trace)
		mlx5_txq_trace_empw_one (vm, node, from + n_node, n_ds, &wqe->ctrl, &wqe->eseg);
	      wqebb_n_pkts[(sq_tail + n_wqebb - 1) & sq_mask] = n_ds;
	      sq_tail += n_wqebb;
	      pkt_tail += n_ds;
	      n_node += n_ds;
	      ds += n_ds;
	      n_done += n_ds;
	    }
	  else
	    {
	      u32 n_ds = n_pkts - n_node;

	      n_ds = mlx5_count_consecutive_zeros_u8 (pkt_layout + n_node, n_ds);
	      for (u32 j = 0; j < n_ds; j++)
		{
		  u32 slot = (sq_tail + j) & sq_mask;
		  wqe = sq_wqes + slot;
		  mlx5_wqe_data_seg_t *dseg = &wqe->dsegs[2];
		  mlx5_tx_build_wqe (wqe, MLX5_OPCODE_SEND, 1, sq_tail + j, qpn_ds_base, 0);
		  if (trace)
		    mlx5_txq_trace_one (vm, node, from[n_node + j], 1, &wqe->ctrl, &wqe->eseg,
					dseg);
		  n_bytes += copy_dseg_to_wqe (dseg, ds + j, 1, lkey);
		}
	      vlib_buffer_copy_indices_to_ring (tq->buffers, from + n_node, pkt_tail, pkt_size,
						n_ds);
	      if (n_ds <= sq_size - slot0)
		clib_memset_u8 (wqebb_n_pkts + slot0, 1, n_ds);
	      else
		{
		  u32 n_contig = sq_size - slot0;
		  clib_memset_u8 (wqebb_n_pkts + slot0, 1, n_contig);
		  clib_memset_u8 (wqebb_n_pkts, 1, n_ds - n_contig);
		}
	      sq_tail += n_ds;
	      pkt_tail += n_ds;
	      n_node += n_ds;
	      ds += n_ds;
	      n_done += n_ds;
	    }
	}
      else if (layout == 1)
	{
	  mlx5_wqe_data_seg_t *dseg = &wqe->dsegs[2];
	  u8 cs_flags = mlx5_tx_wqe_get_csum_flags (b[n_node]);

	  mlx5_tx_build_wqe (wqe, MLX5_OPCODE_SEND, 1, sq_tail, qpn_ds_base, cs_flags);
	  n_bytes += copy_dseg_to_wqe (dseg, ds, 1, lkey);
	  buffers[pkt_tail & pkt_mask] = from[n_node];
	  wqebb_n_pkts[slot0] = 1;
	  if (trace)
	    mlx5_txq_trace_one (vm, node, from[n_node], 1, &wqe->ctrl, &wqe->eseg, dseg);
	  sq_tail += 1;
	  pkt_tail += 1;
	  n_node += 1;
	  ds += 1;
	  n_done += 1;
	}
      else if (layout == MLX5_TX_PKT_LAYOUT_DROP)
	{
	  if (trace)
	    mlx5_txq_trace_one (vm, node, from[n_node], 0, 0, 0, 0);
	  bi_drop[n_drop++] = from[n_node];
	  n_node += 1;
	  n_done += 1;
	}
      else
	{
	  u32 n_seg = layout;
	  u8 cs_flags = mlx5_tx_wqe_get_csum_flags (b[n_node]);

	  mlx5_tx_build_wqe (wqe, MLX5_OPCODE_SEND, n_seg, sq_tail, qpn_ds_base, cs_flags);
	  if (n_seg <= 2)
	    {
	      n_bytes += copy_dseg_to_wqe (&wqe->dsegs[2], ds, n_seg, lkey);
	      wqebb_n_pkts[slot0] = 1;
	      if (trace)
		mlx5_txq_trace_one (vm, node, from[n_node], n_seg, &wqe->ctrl, &wqe->eseg,
				    &wqe->dseg);
	      sq_tail += 1;
	    }
	  else
	    {
	      u32 slot1 = (slot0 + 1) & sq_mask;

	      n_bytes += copy_dseg_to_wqe (&wqe->dsegs[2], ds, 2, lkey);
	      n_bytes += copy_dseg_to_wqe (&sq_wqes[slot1].dsegs[0], ds + 2, n_seg - 2, lkey);
	      wqebb_n_pkts[slot0] = 0;
	      wqebb_n_pkts[slot1] = 1;
	      if (trace)
		mlx5_txq_trace_one (vm, node, from[n_node], n_seg, &wqe->ctrl, &wqe->eseg,
				    &wqe->dseg);
	      sq_tail += 2;
	    }
	  buffers[pkt_tail & pkt_mask] = from[n_node];
	  pkt_tail += 1;
	  n_node += 1;
	  ds += n_seg;
	  n_done += 1;
	}
    }

  *n_bytes_ptr = n_bytes;
  *n_done_ptr = n_done;
  if (n_drop)
    {
      vlib_error_count (vm, node->node_index, RDMA_MLX5_TX_NODE_CTR_CHAIN_TOO_LONG, n_drop);
      vlib_buffer_free (vm, bi_drop, n_drop);
    }

  n_done -= n_drop;
  if (n_done == 0)
    return 0;

  mlx5_txq_doorbell (tq, wqe, sq_tail);
  tq->sq_tail = sq_tail;
  tq->pkt_tail = pkt_tail;
  return n_done;
}

static_always_inline uword
mlx5_tx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_empw)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 size = txq->size;
  vlib_buffer_t *b[VLIB_FRAME_SIZE + 4];
  mlx5_wqe_data_seg_t dsegs[MLX5_TX_MAX_FLAT_DSEGS];
  u8 layout[VLIB_FRAME_SIZE];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_tx_pkts = 0;
  u32 n_bytes = 0;
  int n_retries = 3;
  int trace = (node->flags & VLIB_NODE_FLAG_TRACE) != 0;

  vnet_dev_tx_queue_lock_if_needed (txq);

  while (n_retries-- && n_left)
    {
      u32 n, n_done, n_scan_drop = 0;
      u16 n_enq;

      mlx5_txq_deq (vm, txq);
      n_enq = tq->pkt_tail - tq->pkt_head;
      if (n_enq == size)
	break;
      n = clib_min (n_left, size - n_enq);
      clib_memset_u8 (layout, 0, VLIB_FRAME_SIZE);
      n = mlx5_tx_scan_and_flatten (vm, from, n, b, dsegs, layout, &n_scan_drop);

      if (PREDICT_FALSE (trace))
	n = mlx5_txq_enq (vm, node, txq, from, b, dsegs, layout, n, &n_bytes, &n_done, is_empw, 1);
      else if (is_empw)
	n = mlx5_txq_enq (vm, node, txq, from, b, dsegs, layout, n, &n_bytes, &n_done, 1, 0);
      else
	n = mlx5_txq_enq (vm, node, txq, from, b, dsegs, layout, n, &n_bytes, &n_done, 0, 0);
      from += n_done;
      n_left -= n_done;
      n_tx_pkts += n;
      if (n_done == 0)
	break;
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (n_left)
    {
      if (trace)
	for (u32 i = 0; i < n_left; i++)
	  mlx5_txq_trace_one (vm, node, from[i], 0, 0, 0, 0);
      vlib_error_count (vm, node->node_index, RDMA_MLX5_TX_NODE_CTR_NO_TX_SLOT, n_left);
      vlib_buffer_free (vm, from, n_left);
    }

  vlib_increment_combined_counter (vnet_get_main ()->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_TX,
				   vm->thread_index, rt->hw_if_index, n_tx_pkts, n_bytes);

  return n_tx_pkts;
}

VNET_DEV_NODE_FN (mlx5_tx_node_send)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return mlx5_tx_node_inline (vm, node, frame, 0);
}

VNET_DEV_NODE_FN (mlx5_tx_node_empw)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return mlx5_tx_node_inline (vm, node, frame, 1);
}

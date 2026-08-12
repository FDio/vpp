/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vppinfra/ring.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <rdma/rdma.h>

#define RDMA_TX_RETRIES 5

#define RDMA_TXQ_DV_DSEG_SZ(txq) (RDMA_MLX5_WQE_DS * RDMA_TXQ_DV_SQ_SZ (txq))
#define RDMA_TXQ_DV_DSEG2WQE(d)	 (((d) + RDMA_MLX5_WQE_DS - 1) / RDMA_MLX5_WQE_DS)

/* Keep mlx5 SEND WQEs below the hardware WQE size limit. */
#define RDMA_MLX5_WQE_DS_MAX	   60
#define RDMA_MLX5_EMPW_MAX_PACKETS 32

static_always_inline int
rdma_mlx5_packet_too_short (const rdma_device_t *rd, const vlib_buffer_t *b)
{
  u16 min_length = rd->tx_min_inline ? rd->tx_min_inline : 1;

  return b->current_length < min_length;
}

/*
 * MLX5 direct verbs tx/free functions
 */

static_always_inline void
rdma_device_output_free_mlx5 (vlib_main_t *vm, const vlib_node_runtime_t *node, rdma_device_t *rd,
			      rdma_txq_t *txq)
{
  u16 idx = txq->dv_cq_idx;
  u32 cq_mask = pow2_mask (txq->dv_cq_log2sz);
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 mask = pow2_mask (txq->bufs_log2sz);
  u32 buf_sz = RDMA_TXQ_BUF_SZ (txq);
  u32 log2_cq_sz = txq->dv_cq_log2sz;
  struct mlx5_cqe64 *cqes = txq->dv_cq_cqes, *cur = cqes + (idx & cq_mask);
  u16 cqe_wqe_counter, comp_tail, buf_tail;
  u8 op_own, saved, wqe_ds, completion_error = 0;
  const rdma_mlx5_wqe_t *wqe;

  for (;;)
    {
      op_own = *(volatile u8 *) &cur->op_own;
      if (((idx >> log2_cq_sz) & MLX5_CQE_OWNER_MASK) !=
	  (op_own & MLX5_CQE_OWNER_MASK) || (op_own >> 4) == MLX5_CQE_INVALID)
	break;

      /* The device updates the CQE owner after writing the CQE payload.  In
       * particular, wqe_counter must not be consumed before this barrier. */
      CLIB_DMA_RMB ();

      if (PREDICT_FALSE ((op_own >> 4)) != MLX5_CQE_REQ)
	{
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
	  completion_error = 1;
	}
      idx++;
      cur = cqes + (idx & cq_mask);
    }

  if (idx == txq->dv_cq_idx)
    return;			/* nothing to do */

  cur = cqes + ((idx - 1) & cq_mask);
  saved = cur->op_own;
  cqe_wqe_counter = be16toh (cur->wqe_counter);

  /* Do not access the CQE after returning its slot to hardware. */
  (void) saved;
  cur->op_own = 0xf0;
  txq->dv_cq_idx = idx;

  /* retrieve completion target for the WQEBB reported by the CQE */
  wqe = txq->dv_sq_wqes + (cqe_wqe_counter & sq_mask);
  wqe_ds = ((u8 *) &wqe->ctrl.qpn_ds)[3];
  comp_tail = cqe_wqe_counter + RDMA_TXQ_DV_DSEG2WQE (wqe_ds);
  buf_tail = comp_tail;

  if (rd->flags & RDMA_DEVICE_F_EMPW)
    {
      /* A successful CQE must correspond to the signalled WQE.  Error CQEs
       * may identify an earlier unsignalled WQE, for which the map is also
       * populated. */
      if (PREDICT_FALSE (!(wqe->ctrl.fm_ce_se & MLX5_WQE_CTRL_CQ_UPDATE) &&
			 (saved >> 4) == MLX5_CQE_REQ))
	goto done;
      buf_tail = txq->dv_sq_buf_tail[cqe_wqe_counter & sq_mask];
      txq->dv_sq_head = comp_tail;
    }

  if (PREDICT_FALSE (RDMA_TXQ_USED_SZ (txq->head, buf_tail) > buf_sz ||
		     RDMA_TXQ_USED_SZ (buf_tail, txq->tail) >= buf_sz))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      completion_error = 1;
      goto done;
    }

  /* free sent buffers and update txq head */
  vlib_buffer_free_from_ring (vm, txq->bufs, txq->head & mask, buf_sz,
			      RDMA_TXQ_USED_SZ (txq->head, buf_tail));
  txq->head = buf_tail;

done:
  /* ring doorbell */
  CLIB_DMA_WMB ();
  txq->dv_cq_dbrec[0] = htobe32 (idx & 0xffffff);

  /* An SQ error flushes or ignores subsequent WQEs.  Stop publishing new
   * work until the interface is recreated instead of filling a dead SQ. */
  if (PREDICT_FALSE (completion_error))
    clib_atomic_fetch_or (&rd->flags, RDMA_DEVICE_F_ERROR);
}

static_always_inline void
rdma_device_output_tx_mlx5_empw_doorbell (rdma_txq_t *txq, struct mlx5_wqe_ctrl_seg *last,
					  u16 buf_tail, u16 sq_tail)
{
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 last_idx = ((rdma_mlx5_wqe_t *) last - txq->dv_sq_wqes) & sq_mask;

  txq->dv_sq_buf_tail[last_idx] = buf_tail;
  last->fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;

  CLIB_DMA_WMB ();
  txq->dv_sq_dbrec[MLX5_SND_DBR] = htobe32 (sq_tail);
  CLIB_MMIO_WMB ();
  txq->dv_sq_db[0] = *(u64 *) last;
}

static_always_inline void
rdma_device_output_tx_mlx5_doorbell (rdma_txq_t *txq, rdma_mlx5_wqe_t *last, const u16 tail,
				     u32 sq_mask)
{
  last->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE; /* generate a CQE so we can free buffers */

  ASSERT (tail != txq->tail &&
	  RDMA_TXQ_AVAIL_SZ (txq, txq->head, txq->tail) >= RDMA_TXQ_USED_SZ (txq->tail, tail));

  CLIB_DMA_WMB ();
  txq->dv_sq_dbrec[MLX5_SND_DBR] = htobe32 (tail);
  CLIB_MMIO_WMB ();
  txq->dv_sq_db[0] = *(u64 *) last;
}

static_always_inline void
rdma_mlx5_wqe_init (rdma_mlx5_wqe_t * wqe, const void *tmpl,
		    vlib_buffer_t * b, const u16 tail)
{
  u16 sz = b->current_length;
  const void *cur = vlib_buffer_get_current (b);
  uword addr = pointer_to_uword (cur);

  clib_memcpy_fast (wqe, tmpl, RDMA_MLX5_WQE_SZ);
  /* speculatively copy at least MLX5_ETH_L2_INLINE_HEADER_SIZE (18-bytes) */
  STATIC_ASSERT (STRUCT_SIZE_OF (struct mlx5_wqe_eth_seg, inline_hdr_start) +
		 STRUCT_SIZE_OF (struct mlx5_wqe_eth_seg,
				 inline_hdr) >=
		 MLX5_ETH_L2_INLINE_HEADER_SIZE, "wrong size");
  clib_memcpy_fast (wqe->eseg.inline_hdr_start, cur,
		    MLX5_ETH_L2_INLINE_HEADER_SIZE);

  wqe->wqe_index_lo = tail;
  wqe->wqe_index_hi = tail >> 8;
  if (PREDICT_TRUE (sz >= MLX5_ETH_L2_INLINE_HEADER_SIZE))
    {
      /* inline_hdr_sz is set to MLX5_ETH_L2_INLINE_HEADER_SIZE
         in the template */
      wqe->dseg.byte_count = htobe32 (sz - MLX5_ETH_L2_INLINE_HEADER_SIZE);
      wqe->dseg.addr = htobe64 (addr + MLX5_ETH_L2_INLINE_HEADER_SIZE);
    }
  else
    {
      /* dseg.byte_count and desg.addr are set to 0 in the template */
      wqe->eseg.inline_hdr_sz = htobe16 (sz);
    }
}

static_always_inline int
rdma_mlx5_empw_compatible (const vlib_buffer_t *b)
{
  /* The compact Ethernet segment is shared by the complete session.  Keep
   * packets which require their own SEND/TSO Ethernet segment out of it. */
  return b->current_length != 0 &&
	 !(b->flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_GSO | VNET_BUFFER_F_OFFLOAD));
}

typedef enum
{
  RDMA_MLX5_TX_PACKET_CONSUMED,
  RDMA_MLX5_TX_PACKET_NO_SLOTS,
} rdma_mlx5_tx_packet_result_t;

#define RDMA_MLX5_INLINE_DATA (1u << 31)

static_always_inline void
rdma_mlx5_sq_copy (rdma_txq_t *txq, u32 offset, const void *src, u32 len)
{
  u8 *ring = (u8 *) txq->dv_sq_wqes;
  u32 ring_size = RDMA_TXQ_DV_SQ_SZ (txq) * MLX5_SEND_WQE_BB;
  u32 pos = offset & (ring_size - 1);
  u32 first = clib_min (len, ring_size - pos);

  clib_memcpy_fast (ring + pos, src, first);
  if (PREDICT_FALSE (first != len))
    clib_memcpy_fast (ring, (const u8 *) src + first, len - first);
}

static_always_inline u32
rdma_mlx5_empw_inline_packet_ds (u32 len)
{
  return round_pow2 (sizeof (u32) + len, sizeof (struct mlx5_wqe_data_seg)) /
	 sizeof (struct mlx5_wqe_data_seg);
}

static_always_inline rdma_mlx5_tx_packet_result_t
rdma_mlx5_empw_send_one (vlib_main_t *vm, const vlib_node_runtime_t *node, const rdma_device_t *rd,
			 rdma_txq_t *txq, vlib_buffer_t *b, u32 bi, u16 *sq_tail_p, u32 sq_avail,
			 struct mlx5_wqe_ctrl_seg **last_p)
{
  const u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  const u32 dseg_mask = RDMA_TXQ_DV_DSEG_SZ (txq) - 1;
  struct mlx5_wqe_data_seg *dsegs = (void *) txq->dv_sq_wqes;
  vlib_buffer_t *seg = b;
  u32 n_extra = 0;
  u32 ds, n_wqebb;
  u16 sq_tail = *sq_tail_p;
  rdma_mlx5_wqe_t *wqe;

  while (seg->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      if (PREDICT_FALSE (n_extra == RDMA_MLX5_WQE_DS_MAX - RDMA_MLX5_WQE_DS))
	{
	  vlib_buffer_free_one (vm, bi);
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED, 1);
	  return RDMA_MLX5_TX_PACKET_CONSUMED;
	}
      seg = vlib_get_buffer (vm, seg->next_buffer);
      n_extra++;
    }

  ds = RDMA_MLX5_WQE_DS + n_extra;
  n_wqebb = RDMA_TXQ_DV_DSEG2WQE (ds);
  if (PREDICT_FALSE (n_wqebb > sq_avail))
    return RDMA_MLX5_TX_PACKET_NO_SLOTS;

  wqe = txq->dv_sq_wqes + (sq_tail & sq_mask);
  rdma_mlx5_wqe_init (wqe, txq->dv_wqe_tmpl, b, sq_tail);
  ((u8 *) &wqe->ctrl.qpn_ds)[3] = ds;

  seg = b;
  for (u32 i = 0; i < n_extra; i++)
    {
      struct mlx5_wqe_data_seg *dseg;

      seg = vlib_get_buffer (vm, seg->next_buffer);
      dseg = dsegs + (((u32) sq_tail * RDMA_MLX5_WQE_DS + RDMA_MLX5_WQE_DS + i) & dseg_mask);
      dseg->byte_count = htobe32 (seg->current_length);
      dseg->lkey = htobe32 (rd->lkey);
      dseg->addr = htobe64 (vlib_buffer_get_current_va (seg));
    }

  *last_p = &wqe->ctrl;
  *sq_tail_p += n_wqebb;
  return RDMA_MLX5_TX_PACKET_CONSUMED;
}

static_always_inline u32
rdma_device_output_tx_mlx5_empw (vlib_main_t *vm, const vlib_node_runtime_t *node,
				 const rdma_device_t *rd, rdma_txq_t *txq, u32 n_left_from,
				 const u32 *bi, vlib_buffer_t **b, const u8 inline_max)
{
  const rdma_mlx5_wqe_t *tmpl = (void *) txq->dv_wqe_tmpl;
  const u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  const u32 buf_mask = pow2_mask (txq->bufs_log2sz);
  const u32 dseg_mask = RDMA_TXQ_DV_DSEG_SZ (txq) - 1;
  struct mlx5_wqe_data_seg *dsegs = (void *) txq->dv_sq_wqes;
  struct mlx5_wqe_ctrl_seg *last = 0;
  u16 buf_tail = txq->tail;
  u16 sq_tail = txq->dv_sq_tail;
  u32 n = n_left_from;

  while (n)
    {
      u32 sq_avail = RDMA_TXQ_DV_SQ_AVAIL_SZ (txq) - RDMA_TXQ_USED_SZ (txq->dv_sq_tail, sq_tail);
      u32 part = clib_min (n, RDMA_MLX5_EMPW_MAX_PACKETS);

      if (PREDICT_FALSE (sq_avail == 0))
	break;

      for (u32 i = 0; i < part; i++)
	if (PREDICT_FALSE (!rdma_mlx5_empw_compatible (b[i])))
	  {
	    part = i;
	    break;
	  }

      if (inline_max)
	{
	  u32 inline_part = 0;
	  u32 inline_ds = 2;

	  for (u32 i = 0; i < part; i++)
	    {
	      u32 len = b[i]->current_length;
	      u32 packet_ds;

	      if (len > inline_max)
		break;
	      packet_ds = rdma_mlx5_empw_inline_packet_ds (len);
	      if (inline_ds + packet_ds > RDMA_MLX5_WQE_DS_MAX ||
		  RDMA_TXQ_DV_DSEG2WQE (inline_ds + packet_ds) > sq_avail)
		break;
	      inline_ds += packet_ds;
	      inline_part++;
	    }

	  if (inline_part >= 2)
	    {
	      u16 wqe_tail = sq_tail;
	      u32 n_wqebb = RDMA_TXQ_DV_DSEG2WQE (inline_ds);
	      u32 byte_pos =
		(u32) sq_tail * MLX5_SEND_WQE_BB + 2 * sizeof (struct mlx5_wqe_data_seg);
	      rdma_mlx5_empw_wqe_t *wqe = (void *) (txq->dv_sq_wqes + (wqe_tail & sq_mask));

	      wqe->ctrl = tmpl->ctrl;
	      clib_memset (&wqe->eseg, 0, sizeof (wqe->eseg));
	      wqe->opc_mod = 0;
	      wqe->wqe_index_lo = sq_tail;
	      wqe->wqe_index_hi = sq_tail >> 8;
	      wqe->opcode = MLX5_OPCODE_ENHANCED_MPSW;
	      ((u8 *) &wqe->ctrl.qpn_ds)[3] = inline_ds;

	      for (u32 i = 0; i < inline_part; i++)
		{
		  u32 len = b[i]->current_length;
		  u32 descriptor_bytes =
		    rdma_mlx5_empw_inline_packet_ds (len) * sizeof (struct mlx5_wqe_data_seg);
		  u32 bcount = htobe32 (len | RDMA_MLX5_INLINE_DATA);

		  rdma_mlx5_sq_copy (txq, byte_pos, &bcount, sizeof (bcount));
		  rdma_mlx5_sq_copy (txq, byte_pos + sizeof (bcount),
				     vlib_buffer_get_current (b[i]), len);
		  byte_pos += descriptor_bytes;
		}

	      vlib_buffer_free (vm, (u32 *) bi, inline_part);

	      last = &wqe->ctrl;
	      sq_tail += n_wqebb;
	      txq->dv_sq_buf_tail[wqe_tail & sq_mask] = buf_tail;
	      b += inline_part;
	      bi += inline_part;
	      n -= inline_part;
	      continue;
	    }
	}

      if (part < 2)
	{
	  rdma_mlx5_tx_packet_result_t r;
	  vlib_buffer_t *packet = b[0];
	  u32 packet_bi = bi[0];
	  u16 old_sq_tail = sq_tail;

	  if (PREDICT_FALSE (rdma_mlx5_packet_too_short (rd, packet)))
	    {
	      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_PACKET_TOO_SHORT, 1);
	      vlib_buffer_free_one (vm, packet_bi);
	      r = RDMA_MLX5_TX_PACKET_CONSUMED;
	    }
	  else
	    r = rdma_mlx5_empw_send_one (vm, node, rd, txq, packet, packet_bi, &sq_tail, sq_avail,
					 &last);
	  if (r == RDMA_MLX5_TX_PACKET_NO_SLOTS)
	    break;

	  if (sq_tail != old_sq_tail)
	    {
	      txq->bufs[buf_tail++ & buf_mask] = packet_bi;
	      /* Normally only the last WQE requests a completion.  Keep a
	       * mapping for every WQE as error CQEs may refer to an earlier,
	       * unsignalled WQE. */
	      txq->dv_sq_buf_tail[old_sq_tail & sq_mask] = buf_tail;
	    }
	  b++;
	  bi++;
	  n--;
	  continue;
	}

      part = clib_min (part, sq_avail * RDMA_MLX5_WQE_DS - 2);
      if (part < 2)
	break;

      u16 wqe_tail = sq_tail;
      rdma_mlx5_empw_wqe_t *wqe = (void *) (txq->dv_sq_wqes + (wqe_tail & sq_mask));
      u32 ds = 2 + part;
      u32 n_wqebb = RDMA_TXQ_DV_DSEG2WQE (ds);

      wqe->ctrl = tmpl->ctrl;
      clib_memset (&wqe->eseg, 0, sizeof (wqe->eseg));
      wqe->opc_mod = 0;
      wqe->wqe_index_lo = sq_tail;
      wqe->wqe_index_hi = sq_tail >> 8;
      wqe->opcode = MLX5_OPCODE_ENHANCED_MPSW;
      ((u8 *) &wqe->ctrl.qpn_ds)[3] = ds;

      for (u32 i = 0; i < part; i++)
	{
	  struct mlx5_wqe_data_seg *dseg =
	    dsegs + (((u32) sq_tail * RDMA_MLX5_WQE_DS + 2 + i) & dseg_mask);
	  dseg->byte_count = htobe32 (b[i]->current_length);
	  dseg->lkey = htobe32 (rd->lkey);
	  dseg->addr = htobe64 (vlib_buffer_get_current_va (b[i]));
	  txq->bufs[(buf_tail + i) & buf_mask] = bi[i];
	}

      last = &wqe->ctrl;
      sq_tail += n_wqebb;
      buf_tail += part;
      txq->dv_sq_buf_tail[wqe_tail & sq_mask] = buf_tail;
      b += part;
      bi += part;
      n -= part;
    }

  if (last)
    {
      rdma_device_output_tx_mlx5_empw_doorbell (txq, last, buf_tail, sq_tail);
      txq->tail = buf_tail;
      txq->dv_sq_tail = sq_tail;
    }

  return n_left_from - n;
}

/*
 * specific data path for chained buffers, supporting ring wrap-around
 * contrary to the normal path - otherwise we may fail to enqueue chained
 * buffers because we are close to the end of the ring while we still have
 * plenty of descriptors available
 */
static_always_inline u32
rdma_device_output_tx_mlx5_chained (vlib_main_t *vm,
				    const vlib_node_runtime_t *node,
				    const rdma_device_t *rd, rdma_txq_t *txq,
				    const u32 n_left_from, const u32 *bi,
				    vlib_buffer_t **b, u16 tail)
{
  u32 wqe_n = RDMA_TXQ_AVAIL_SZ (txq, txq->head, tail);
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 mask = pow2_mask (txq->bufs_log2sz);
  u32 dseg_mask = RDMA_TXQ_DV_DSEG_SZ (txq) - 1;
  const u32 lkey = clib_host_to_net_u32 (rd->lkey);
  const u32 done = RDMA_TXQ_USED_SZ (txq->tail, tail);
  u32 n = n_left_from - done;
  rdma_mlx5_wqe_t *last = txq->dv_sq_wqes + (tail & sq_mask);

  bi += done;

  while (n >= 1)
    {
      if (PREDICT_FALSE (rdma_mlx5_packet_too_short (rd, b[0])))
	{
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_PACKET_TOO_SHORT, 1);
	  vlib_buffer_free_one (vm, bi[0]);
	  bi += 1;
	  b += 1;
	  n -= 1;
	  continue;
	}

      if (PREDICT_FALSE (wqe_n == 0))
	break;

      u32 *bufs = txq->bufs + (tail & mask);
      rdma_mlx5_wqe_t *wqe = txq->dv_sq_wqes + (tail & sq_mask);

      /* setup the head WQE */
      rdma_mlx5_wqe_init (wqe, txq->dv_wqe_tmpl, b[0], tail);

      bufs[0] = bi[0];

      if (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  /* Additional dseg are bounded by available WQEBBs and by
	   * the mlx5 WQE size limit. */
	  const u32 dseg_hw_max = RDMA_MLX5_WQE_DS_MAX - RDMA_MLX5_WQE_DS;
	  const u32 dseg_slot_max = RDMA_MLX5_WQE_DS * (wqe_n - 1);
	  const u32 dseg_max = clib_min (dseg_hw_max, dseg_slot_max);
	  vlib_buffer_t *chained_b = b[0];
	  u32 chained_n = 0;

	  /* there are exactly 4 dseg per WQEBB and we rely on that */
	  STATIC_ASSERT (RDMA_MLX5_WQE_DS *
			 sizeof (struct mlx5_wqe_data_seg) ==
			 MLX5_SEND_WQE_BB, "wrong size");

	  /*
	   * iterate over fragments, supporting ring wrap-around contrary to
	   * the normal path - otherwise we may fail to enqueue chained
	   * buffers because we are close to the end of the ring while we
	   * still have plenty of descriptors available
	   */
	  while (chained_n < dseg_max
		 && chained_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      struct mlx5_wqe_data_seg *dseg = (void *) txq->dv_sq_wqes;
	      dseg += ((tail + 1) * RDMA_MLX5_WQE_DS + chained_n) & dseg_mask;
	      if (((clib_address_t) dseg & (MLX5_SEND_WQE_BB - 1)) == 0)
		{
		  /*
		   * start of new WQEBB
		   * head/tail are shared between buffers and descriptor
		   * In order to maintain 1:1 correspondance between
		   * buffer index and descriptor index, we build
		   * 4-fragments chains and save the head
		   */
		  chained_b->flags &= ~(VLIB_BUFFER_NEXT_PRESENT |
					VLIB_BUFFER_TOTAL_LENGTH_VALID);
		  u32 idx = tail + 1 + RDMA_TXQ_DV_DSEG2WQE (chained_n);
		  idx &= mask;
		  txq->bufs[idx] = chained_b->next_buffer;
		}

	      chained_b = vlib_get_buffer (vm, chained_b->next_buffer);
	      dseg->byte_count = htobe32 (chained_b->current_length);
	      dseg->lkey = lkey;
	      dseg->addr = htobe64 (vlib_buffer_get_current_va (chained_b));

	      chained_n += 1;
	    }

	  if (chained_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      /*
	       * no descriptors left: drop the chain including 1st WQE
	       * skip the problematic packet and continue
	       */
	      vlib_buffer_free_from_ring (vm, txq->bufs, tail & mask,
					  RDMA_TXQ_BUF_SZ (txq), 1 +
					  RDMA_TXQ_DV_DSEG2WQE (chained_n));
	      vlib_error_count (vm, node->node_index,
				chained_n == dseg_hw_max ? RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED :
							   RDMA_TX_ERROR_NO_FREE_SLOTS,
				1);

	      /* fixup tail to overwrite wqe head with next packet */
	      tail -= 1;
	    }
	  else
	    {
	      /* update WQE descriptor with new dseg number */
	      ((u8 *) & wqe[0].ctrl.qpn_ds)[3] = RDMA_MLX5_WQE_DS + chained_n;

	      tail += RDMA_TXQ_DV_DSEG2WQE (chained_n);
	      wqe_n -= RDMA_TXQ_DV_DSEG2WQE (chained_n);

	      last = wqe;
	    }
	}
      else
	{
	  /* not chained */
	  last = wqe;
	}

      tail += 1;
      bi += 1;
      b += 1;
      wqe_n -= 1;
      n -= 1;
    }

  if (tail != txq->tail)
    rdma_device_output_tx_mlx5_doorbell (txq, last, tail, sq_mask);

  txq->tail = tail;
  return n_left_from - n;
}

static_always_inline u32
rdma_device_output_tx_mlx5 (vlib_main_t *vm, const vlib_node_runtime_t *node,
			    const rdma_device_t *rd, rdma_txq_t *txq,
			    const u32 n_left_from, const u32 *bi,
			    vlib_buffer_t **b)
{

  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 mask = pow2_mask (txq->bufs_log2sz);
  rdma_mlx5_wqe_t *wqe;
  u32 n, n_wrap;
  u16 tail = txq->tail;

  ASSERT (RDMA_TXQ_BUF_SZ (txq) <= RDMA_TXQ_DV_SQ_SZ (txq));

  /* avoid wrap-around logic in core loop */
  n = clib_min (n_left_from, RDMA_TXQ_BUF_SZ (txq) - (tail & mask));
  n_wrap = n_left_from - n;

wrap_around:
  wqe = txq->dv_sq_wqes + (tail & sq_mask);

  while (n >= 8)
    {
      u32 flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;
      if (PREDICT_FALSE (
	    flags & VLIB_BUFFER_NEXT_PRESENT || rdma_mlx5_packet_too_short (rd, b[0]) ||
	    rdma_mlx5_packet_too_short (rd, b[1]) || rdma_mlx5_packet_too_short (rd, b[2]) ||
	    rdma_mlx5_packet_too_short (rd, b[3])))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq, n_left_from, bi, b, tail);

      vlib_prefetch_buffer_header (b[4], LOAD);
      rdma_mlx5_wqe_init (wqe + 0, txq->dv_wqe_tmpl, b[0], tail + 0);

      vlib_prefetch_buffer_header (b[5], LOAD);
      rdma_mlx5_wqe_init (wqe + 1, txq->dv_wqe_tmpl, b[1], tail + 1);

      vlib_prefetch_buffer_header (b[6], LOAD);
      rdma_mlx5_wqe_init (wqe + 2, txq->dv_wqe_tmpl, b[2], tail + 2);

      vlib_prefetch_buffer_header (b[7], LOAD);
      rdma_mlx5_wqe_init (wqe + 3, txq->dv_wqe_tmpl, b[3], tail + 3);

      b += 4;
      tail += 4;
      wqe += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      if (PREDICT_FALSE (rdma_mlx5_packet_too_short (rd, b[0]) ||
			 b[0]->flags & VLIB_BUFFER_NEXT_PRESENT))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq, n_left_from, bi, b, tail);

      rdma_mlx5_wqe_init (wqe, txq->dv_wqe_tmpl, b[0], tail);

      b += 1;
      tail += 1;
      wqe += 1;
      n -= 1;
    }

  if (n_wrap)
    {
      n = n_wrap;
      n_wrap = 0;
      goto wrap_around;
    }

  rdma_device_output_tx_mlx5_doorbell (txq, &wqe[-1], tail, sq_mask);
  txq->tail = tail;
  return n_left_from;
}

/*
 * standard ibverb tx/free functions
 */

static_always_inline void
rdma_device_output_free_ibverb (vlib_main_t * vm,
				const vlib_node_runtime_t * node,
				rdma_txq_t * txq)
{
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 mask = pow2_mask (txq->bufs_log2sz);
  u16 tail;
  int n;

  n = ibv_poll_cq (txq->ibv_cq, VLIB_FRAME_SIZE, wc);
  if (n <= 0)
    {
      if (PREDICT_FALSE (n < 0))
	vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      return;
    }

  while (PREDICT_FALSE (IBV_WC_SUCCESS != wc[n - 1].status))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      n--;
      if (0 == n)
	return;
    }

  tail = wc[n - 1].wr_id;
  vlib_buffer_free_from_ring (vm, txq->bufs, txq->head & mask,
			      RDMA_TXQ_BUF_SZ (txq),
			      RDMA_TXQ_USED_SZ (txq->head, tail));
  txq->head = tail;
}

static_always_inline u32
rdma_device_output_tx_ibverb (vlib_main_t * vm,
			      const vlib_node_runtime_t * node,
			      const rdma_device_t * rd, rdma_txq_t * txq,
			      u32 n_left_from, u32 * bi, vlib_buffer_t ** b)
{
  struct ibv_send_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  u32 n = n_left_from;

  while (n >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      s[0].addr = vlib_buffer_get_current_va (b[0]);
      s[0].length = b[0]->current_length;
      s[0].lkey = rd->lkey;

      vlib_prefetch_buffer_header (b[5], LOAD);
      s[1].addr = vlib_buffer_get_current_va (b[1]);
      s[1].length = b[1]->current_length;
      s[1].lkey = rd->lkey;

      vlib_prefetch_buffer_header (b[6], LOAD);
      s[2].addr = vlib_buffer_get_current_va (b[2]);
      s[2].length = b[2]->current_length;
      s[2].lkey = rd->lkey;

      vlib_prefetch_buffer_header (b[7], LOAD);
      s[3].addr = vlib_buffer_get_current_va (b[3]);
      s[3].length = b[3]->current_length;
      s[3].lkey = rd->lkey;

      clib_memset_u8 (&w[0], 0, sizeof (w[0]));
      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      clib_memset_u8 (&w[1], 0, sizeof (w[1]));
      w[1].next = &w[1] + 1;
      w[1].sg_list = &s[1];
      w[1].num_sge = 1;
      w[1].opcode = IBV_WR_SEND;

      clib_memset_u8 (&w[2], 0, sizeof (w[2]));
      w[2].next = &w[2] + 1;
      w[2].sg_list = &s[2];
      w[2].num_sge = 1;
      w[2].opcode = IBV_WR_SEND;

      clib_memset_u8 (&w[3], 0, sizeof (w[3]));
      w[3].next = &w[3] + 1;
      w[3].sg_list = &s[3];
      w[3].num_sge = 1;
      w[3].opcode = IBV_WR_SEND;

      s += 4;
      w += 4;
      b += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      s[0].addr = vlib_buffer_get_current_va (b[0]);
      s[0].length = b[0]->current_length;
      s[0].lkey = rd->lkey;

      clib_memset_u8 (&w[0], 0, sizeof (w[0]));
      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      s += 1;
      w += 1;
      b += 1;
      n -= 1;
    }

  w[-1].wr_id = txq->tail;	/* register item to free */
  w[-1].next = 0;		/* fix next pointer in WR linked-list */
  w[-1].send_flags = IBV_SEND_SIGNALED;	/* generate a CQE so we can free buffers */

  w = wr;
  if (PREDICT_FALSE (0 != ibv_post_send (txq->ibv_qp, w, &w)))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SUBMISSION,
			n_left_from - (w - wr));
      n_left_from = w - wr;
    }
  txq->tail += n_left_from;
  return n_left_from;
}

/*
 * common tx/free functions
 */

static void
rdma_device_output_free (vlib_main_t *vm, const vlib_node_runtime_t *node, rdma_device_t *rd,
			 rdma_txq_t *txq)
{
  if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_MLX5DV))
    rdma_device_output_free_mlx5 (vm, node, rd, txq);
  else
    rdma_device_output_free_ibverb (vm, node, txq);
}

static u32
rdma_device_output_tx_try (vlib_main_t *vm, const vlib_node_runtime_t *node,
			   const rdma_device_t *rd, rdma_txq_t *txq,
			   u32 n_left_from, u32 *bi)
{
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  const u32 mask = pow2_mask (txq->bufs_log2sz);

  /* do not enqueue more packet than ring space */
  n_left_from = clib_min (n_left_from, RDMA_TXQ_AVAIL_SZ (txq, txq->head,
							  txq->tail));
  /* if ring is full, do nothing */
  if (PREDICT_FALSE (n_left_from == 0))
    return 0;

  /* speculatively copy buffer indices */
  vlib_buffer_copy_indices_to_ring (txq->bufs, bi, txq->tail & mask,
				    RDMA_TXQ_BUF_SZ (txq), n_left_from);

  vlib_get_buffers (vm, bi, b, n_left_from);

  if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_MLX5DV))
    {
      if (rd->flags & RDMA_DEVICE_F_EMPW)
	{
	  if (PREDICT_FALSE (rd->tx_empw_inline_max != 0))
	    n_left_from = rdma_device_output_tx_mlx5_empw (vm, node, rd, txq, n_left_from, bi, b,
							   rd->tx_empw_inline_max);
	  else
	    n_left_from =
	      rdma_device_output_tx_mlx5_empw (vm, node, rd, txq, n_left_from, bi, b, 0);
	}
      else
	n_left_from = rdma_device_output_tx_mlx5 (vm, node, rd, txq, n_left_from, bi, b);
    }
  else
    n_left_from = rdma_device_output_tx_ibverb (vm, node, rd, txq, n_left_from, bi, b);

  return n_left_from;
}

static uword
rdma_device_output_tx (vlib_main_t *vm, vlib_node_runtime_t *node,
		       rdma_device_t *rd, rdma_txq_t *txq, u32 *from,
		       u32 n_left_from)
{
  int i;

  for (i = 0; i < RDMA_TX_RETRIES && n_left_from > 0; i++)
    {
      u32 n_enq;
      rdma_device_output_free (vm, node, rd, txq);
      if (PREDICT_FALSE (rd->flags & RDMA_DEVICE_F_ERROR))
	break;
      n_enq = rdma_device_output_tx_try (vm, node, rd, txq, n_left_from, from);
      n_left_from -= n_enq;
      from += n_enq;
    }

  return n_left_from;
}

VNET_DEVICE_CLASS_TX_FN (rdma_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  rdma_main_t *rm = &rdma_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  rdma_device_t *rd = pool_elt_at_index (rm->devices, ord->dev_instance);
  rdma_txq_t *txq =
    vec_elt_at_index (rd->txqs, vm->thread_index % vec_len (rd->txqs));
  u32 *from, n_buffers, n_left;

  ASSERT (RDMA_TXQ_BUF_SZ (txq) >= VLIB_FRAME_SIZE);

  from = vlib_frame_vector_args (frame);
  n_buffers = frame->n_vectors;

  clib_spinlock_lock_if_init (&txq->lock);

  n_left = rdma_device_output_tx (vm, node, rd, txq, from, n_buffers);

  clib_spinlock_unlock_if_init (&txq->lock);

  if (PREDICT_FALSE (n_left))
    {
      vlib_buffer_free (vm, from + n_buffers - n_left, n_left);
      vlib_error_count (vm, node->node_index,
			rd->flags & RDMA_DEVICE_F_ERROR ? RDMA_TX_ERROR_DEVICE :
							  RDMA_TX_ERROR_NO_FREE_SLOTS,
			n_left);
    }

  return n_buffers - n_left;
}

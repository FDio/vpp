/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vppinfra/ring.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/buffer.h>
#include <rdma/rdma.h>

#define RDMA_TX_RETRIES 5

#define RDMA_TXQ_DV_DSEG_SZ(txq) (RDMA_MLX5_WQE_DS * RDMA_TXQ_DV_SQ_SZ (txq))
#define RDMA_TXQ_DV_DSEG2WQE(d)	 (((d) + RDMA_MLX5_WQE_DS - 1) / RDMA_MLX5_WQE_DS)

/* Keep mlx5 SEND WQEs below the hardware WQE size limit. */
#define RDMA_MLX5_WQE_DS_MAX 60

static_always_inline u32
rdma_mlx5_wqe_chained_dseg_max (u32 n_wqebb, u32 base_ds)
{
  u32 available_ds = RDMA_MLX5_WQE_DS * n_wqebb;

  if (base_ds >= RDMA_MLX5_WQE_DS_MAX || available_ds <= base_ds)
    return 0;

  return clib_min (available_ds - base_ds, RDMA_MLX5_WQE_DS_MAX - base_ds);
}

/* Sentinel used for WQEBB slots that do not own a buffer index. */
#define RDMA_TXQ_INVALID_BUF ((u32) ~0)

typedef enum
{
  RDMA_MLX5_TSO_REGULAR,
  RDMA_MLX5_TSO_DONE,
  RDMA_MLX5_TSO_NO_SLOTS,
} rdma_mlx5_tso_result_t;

/*
 * MLX5 direct verbs tx/free functions
 */

static_always_inline void
rdma_buffer_free_mlx5_span (vlib_main_t *vm, u32 *buffers, u32 n_buffers)
{
  u32 i = 0;

  while (i < n_buffers)
    {
      u32 first;

      while (i < n_buffers && buffers[i] == RDMA_TXQ_INVALID_BUF)
	i++;

      first = i;
      while (i < n_buffers && buffers[i] != RDMA_TXQ_INVALID_BUF)
	i++;

      if (i > first)
	vlib_buffer_free (vm, buffers + first, i - first);
    }
}

static_always_inline void
rdma_buffer_free_from_ring_mlx5 (vlib_main_t *vm, u32 *ring, u32 start, u32 ring_size,
				 u32 n_buffers)
{
  u32 n;

  ASSERT (n_buffers <= ring_size);

  n = clib_min (n_buffers, ring_size - start);
  rdma_buffer_free_mlx5_span (vm, ring + start, n);
  if (PREDICT_FALSE (n != n_buffers))
    rdma_buffer_free_mlx5_span (vm, ring, n_buffers - n);
}

static_always_inline void
rdma_device_output_free_mlx5 (vlib_main_t *vm, const vlib_node_runtime_t *node, rdma_txq_t *txq,
			      const int is_tso)
{
  u16 idx = txq->dv_cq_idx;
  u32 cq_mask = pow2_mask (txq->dv_cq_log2sz);
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 mask = pow2_mask (txq->bufs_log2sz);
  u32 buf_sz = RDMA_TXQ_BUF_SZ (txq);
  u32 log2_cq_sz = txq->dv_cq_log2sz;
  struct mlx5_cqe64 *cqes = txq->dv_cq_cqes, *cur = cqes + (idx & cq_mask);
  u8 op_own, saved;

  for (;;)
    {
      op_own = *(volatile u8 *) &cur->op_own;
      if (((idx >> log2_cq_sz) & MLX5_CQE_OWNER_MASK) !=
	  (op_own & MLX5_CQE_OWNER_MASK) || (op_own >> 4) == MLX5_CQE_INVALID)
	break;
      if (PREDICT_FALSE ((op_own >> 4)) != MLX5_CQE_REQ)
	vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      idx++;
      cur = cqes + (idx & cq_mask);
    }

  if (idx == txq->dv_cq_idx)
    return;			/* nothing to do */

  cur = cqes + ((idx - 1) & cq_mask);
  saved = cur->op_own;
  (void) saved;
  cur->op_own = 0xf0;
  txq->dv_cq_idx = idx;

  /* retrieve completion target for the WQEBB reported by the CQE */
  u16 cqe_wqe_counter = be16toh (cur->wqe_counter);
  rdma_mlx5_wqe_t *wqe = txq->dv_sq_wqes + (cqe_wqe_counter & sq_mask);
  u16 comp_tail = wqe->ctrl.imm;

  if (PREDICT_FALSE (RDMA_TXQ_USED_SZ (txq->head, comp_tail) > buf_sz ||
		     RDMA_TXQ_USED_SZ (comp_tail, txq->tail) >= buf_sz))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      goto done;
    }

  /* free sent buffers and update txq head */
  if (is_tso)
    rdma_buffer_free_from_ring_mlx5 (vm, txq->bufs, txq->head & mask, buf_sz,
				     RDMA_TXQ_USED_SZ (txq->head, comp_tail));
  else
    vlib_buffer_free_from_ring (vm, txq->bufs, txq->head & mask, buf_sz,
				RDMA_TXQ_USED_SZ (txq->head, comp_tail));
  txq->head = comp_tail;

done:
  /* ring doorbell */
  CLIB_MEMORY_STORE_BARRIER ();
  txq->dv_cq_dbrec[0] = htobe32 (idx);
}

static_always_inline void
rdma_device_output_tx_mlx5_doorbell (rdma_txq_t * txq, rdma_mlx5_wqe_t * last,
				     const u16 tail, u32 sq_mask)
{
  last->ctrl.imm = tail;	/* register item to free */
  last->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;	/* generate a CQE so we can free buffers */

  ASSERT (tail != txq->tail &&
	  RDMA_TXQ_AVAIL_SZ (txq, txq->head, txq->tail) >=
	  RDMA_TXQ_USED_SZ (txq->tail, tail));

  CLIB_MEMORY_STORE_BARRIER ();
  txq->dv_sq_dbrec[MLX5_SND_DBR] = htobe32 (tail);
  CLIB_COMPILER_BARRIER ();
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

  /* Hardware checksum offload: VPP sets VNET_BUFFER_F_OFFLOAD when upper
   * layers (e.g. TCP with TSO enabled) request csum offload.  The WQE
   * template has cs_flags=0; set them per-packet when requested. */
  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_OFFLOAD))
    {
      vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
      u8 cs = 0;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	cs |= MLX5_ETH_WQE_L3_CSUM;
      if (oflags & (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
	cs |= MLX5_ETH_WQE_L4_CSUM;
      wqe->eseg.cs_flags = cs;
    }
}

static_always_inline u16
rdma_mlx5_tso_hdr_sz (vlib_buffer_t *b)
{
  return (vnet_buffer (b)->l4_hdr_offset - b->current_data) + vnet_buffer2 (b)->gso_l4_hdr_sz;
}

static_always_inline u8
rdma_mlx5_tso_inline_ds (u16 hdr_sz)
{
  return (hdr_sz > MLX5_ETH_L2_INLINE_HEADER_SIZE) ?
	   ((hdr_sz - MLX5_ETH_L2_INLINE_HEADER_SIZE + 15) / 16) :
	   0;
}

static_always_inline u8
rdma_mlx5_tso_total_ds (u16 hdr_sz)
{
  return 4 + rdma_mlx5_tso_inline_ds (hdr_sz);
}

static_always_inline u8
rdma_mlx5_tso_n_wqebb (u16 hdr_sz)
{
  return RDMA_TXQ_DV_DSEG2WQE (rdma_mlx5_tso_total_ds (hdr_sz));
}

static_always_inline u8
rdma_mlx5_wqe_init_tso (rdma_txq_t *txq, vlib_buffer_t *b, const u16 tail, const u32 sq_mask,
			const u32 lkey)
{
  const u8 *pkt = vlib_buffer_get_current (b);
  u16 hdr_sz = rdma_mlx5_tso_hdr_sz (b);
  u16 mss = vnet_buffer2 (b)->gso_size;

  /* The entire TCP/IP/Ethernet header must fit in the first fragment.
   * If the TCP options overflow into a second buffer, pay_len would underflow
   * and the inline copy would read past the fragment boundary.
   * Return 0 so the caller can fall back to a regular (non-TSO) SEND. */
  if (PREDICT_FALSE (hdr_sz > b->current_length))
    return 0;

  u32 pay_len = b->current_length - hdr_sz;
  u8 total_ds = rdma_mlx5_tso_total_ds (hdr_sz);
  u8 n_wqebb = RDMA_TXQ_DV_DSEG2WQE (total_ds);
  rdma_mlx5_wqe_t *wqe0 = txq->dv_sq_wqes + (tail & sq_mask);
  u32 dseg_mask = RDMA_TXQ_DV_DSEG_SZ (txq) - 1;

  for (u32 i = 0; i < n_wqebb; i++)
    clib_memset_u8 (txq->dv_sq_wqes + ((tail + i) & sq_mask), 0, RDMA_MLX5_WQE_SZ);

  mlx5dv_set_ctrl_seg (&wqe0->ctrl, tail, MLX5_OPCODE_TSO, 0, txq->qp->qp_num, 0, total_ds, 0,
		       RDMA_TXQ_DV_INVALID_ID);

  wqe0->eseg.cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
  wqe0->eseg.mss = htobe16 (mss);
  wqe0->eseg.inline_hdr_sz = htobe16 (hdr_sz);

  clib_memcpy_fast (wqe0->eseg.inline_hdr_start, pkt,
		    clib_min (hdr_sz, MLX5_ETH_L2_INLINE_HEADER_SIZE));

  if (hdr_sz > MLX5_ETH_L2_INLINE_HEADER_SIZE)
    {
      const u8 *cont = pkt + MLX5_ETH_L2_INLINE_HEADER_SIZE;
      u16 rem = hdr_sz - MLX5_ETH_L2_INLINE_HEADER_SIZE;

      struct mlx5_wqe_data_seg *ds = (void *) txq->dv_sq_wqes;

      for (u32 ds_idx = 3; rem > 0; ds_idx++)
	{
	  u16 n = clib_min (rem, sizeof (struct mlx5_wqe_data_seg));
	  clib_memcpy_fast (ds + ((tail * RDMA_MLX5_WQE_DS + ds_idx) & dseg_mask), cont, n);
	  cont += n;
	  rem -= n;
	}
    }

  u32 dseg_idx = tail * RDMA_MLX5_WQE_DS + total_ds - 1;
  struct mlx5_wqe_data_seg *dseg = (void *) txq->dv_sq_wqes;
  dseg += dseg_idx & dseg_mask;
  dseg->byte_count = htobe32 (pay_len);
  dseg->lkey = clib_host_to_net_u32 (lkey);
  dseg->addr = htobe64 (vlib_buffer_get_current_va (b) + hdr_sz);

  return total_ds;
}

static_always_inline void
rdma_mlx5_tso_mark_bufs (rdma_txq_t *txq, u16 tail, u32 mask, u32 total_wqebb, u32 bi)
{
  txq->bufs[tail & mask] = bi;
  for (u32 i = 1; i < total_wqebb; i++)
    txq->bufs[(tail + i) & mask] = RDMA_TXQ_INVALID_BUF;
}

/*
 * Append chained payload fragments to a TSO WQE that was initialised by
 * rdma_mlx5_wqe_init_tso().  Updates *total_wqebb_p, *wqe_n_p, *tail_p and
 * *last_p in-place so the caller can continue its main loop unchanged.
 */
static_always_inline u8
rdma_mlx5_tso_append_chain (vlib_main_t *vm, const vlib_node_runtime_t *node, rdma_txq_t *txq,
			    vlib_buffer_t *b, u16 tail, u32 sq_mask, u32 dseg_mask, u8 base_ds,
			    u32 lkey_be, u32 *total_wqebb_p, u32 *wqe_n_p, u16 *tail_p,
			    rdma_mlx5_wqe_t **last_p)
{
  u32 total_wqebb = *total_wqebb_p;
  vlib_buffer_t *chained_b = b;
  u32 chained_n = 0;
  const u32 dseg_max = rdma_mlx5_wqe_chained_dseg_max (*wqe_n_p, base_ds);

  while (chained_n < dseg_max && chained_b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u32 rel_ds = base_ds + chained_n;
      u32 dseg_idx = tail * RDMA_MLX5_WQE_DS + rel_ds;
      struct mlx5_wqe_data_seg *dseg = (void *) txq->dv_sq_wqes;
      dseg += dseg_idx & dseg_mask;

      /* The TSO builder clears the WQEBBs covered by base_ds. If the
       * chained payload grows the WQE beyond that, clear each new WQEBB
       * before first use so the NIC never sees stale data. */
      if (PREDICT_FALSE ((rel_ds & (RDMA_MLX5_WQE_DS - 1)) == 0))
	{
	  u32 rel_wqebb = rel_ds / RDMA_MLX5_WQE_DS;
	  if (rel_wqebb >= total_wqebb)
	    {
	      rdma_mlx5_wqe_t *extra_wqe = txq->dv_sq_wqes + ((tail + rel_wqebb) & sq_mask);
	      clib_memset_u8 (extra_wqe, 0, RDMA_MLX5_WQE_SZ);
	    }
	}

      chained_b = vlib_get_buffer (vm, chained_b->next_buffer);
      if (PREDICT_FALSE (chained_b->current_length == 0))
	continue;
      dseg->byte_count = htobe32 (chained_b->current_length);
      dseg->lkey = lkey_be;
      dseg->addr = htobe64 (vlib_buffer_get_current_va (chained_b));
      chained_n++;
    }

  if (chained_b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      vlib_error_count (vm, node->node_index,
			dseg_max == chained_n ? RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED :
						RDMA_TX_ERROR_NO_FREE_SLOTS,
			1);
      return 0;
    }
  else
    {
      u32 total_ds = base_ds + chained_n;
      rdma_mlx5_wqe_t *wqe0 = txq->dv_sq_wqes + (tail & sq_mask);
      ((u8 *) &wqe0->ctrl.qpn_ds)[3] = total_ds;
      /* Advance tail by the actual WQEBB count (NIC uses ctrl.ds, not a
       * fixed N_WQEBB constant). */
      total_wqebb = RDMA_TXQ_DV_DSEG2WQE (total_ds);
      *last_p = wqe0;
      *tail_p += total_wqebb;
      *wqe_n_p -= total_wqebb;
      *total_wqebb_p = total_wqebb;
      return 1;
    }
}

static_always_inline rdma_mlx5_tso_result_t
rdma_mlx5_try_tso (vlib_main_t *vm, const vlib_node_runtime_t *node, const rdma_device_t *rd,
		   rdma_txq_t *txq, vlib_buffer_t *b, u32 bi, u16 *tail_p, u32 *wqe_n_p,
		   u32 sq_mask, u32 dseg_mask, u32 mask, u32 lkey_be, rdma_mlx5_wqe_t **last_p)
{
  u16 tail = *tail_p;
  u16 hdr_sz = rdma_mlx5_tso_hdr_sz (b);
  u32 total_wqebb;
  u8 base_ds;

  if (PREDICT_FALSE (*wqe_n_p < rdma_mlx5_tso_n_wqebb (hdr_sz)))
    return RDMA_MLX5_TSO_NO_SLOTS;

  if (PREDICT_FALSE (hdr_sz > RDMA_MLX5_TSO_HDR_MAX))
    {
      /* Header too large for the TSO WQE inline area (e.g. when
       * TCP options are unusually long). Fall back to the regular
       * chained-SEND path so the packet is not dropped. */
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_TSO_HDR_TOO_BIG, 1);
      b->flags &= ~VNET_BUFFER_F_GSO;
      return RDMA_MLX5_TSO_REGULAR;
    }

  base_ds = rdma_mlx5_wqe_init_tso (txq, b, tail, sq_mask, rd->lkey);

  if (PREDICT_FALSE (base_ds == 0))
    {
      /* Header spans multiple buffer fragments. Fall back to a regular SEND
       * to avoid an invalid TSO WQE (pay_len underflow). */
      b->flags &= ~VNET_BUFFER_F_GSO;
      return RDMA_MLX5_TSO_REGULAR;
    }

  total_wqebb = RDMA_TXQ_DV_DSEG2WQE (base_ds);
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      if (PREDICT_FALSE (!rdma_mlx5_tso_append_chain (vm, node, txq, b, tail, sq_mask, dseg_mask,
						      base_ds, lkey_be, &total_wqebb, wqe_n_p,
						      tail_p, last_p)))
	{
	  txq->bufs[tail & mask] = RDMA_TXQ_INVALID_BUF;
	  vlib_buffer_free_one (vm, bi);
	  return RDMA_MLX5_TSO_DONE;
	}
    }
  else
    {
      *last_p = txq->dv_sq_wqes + (tail & sq_mask);
      *tail_p += total_wqebb;
      *wqe_n_p -= total_wqebb;
    }

  rdma_mlx5_tso_mark_bufs (txq, tail, mask, total_wqebb, bi);
  return RDMA_MLX5_TSO_DONE;
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
				    vlib_buffer_t **b, u16 tail, const int is_tso)
{
  u32 wqe_n = RDMA_TXQ_AVAIL_SZ (txq, txq->head, tail);
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 mask = pow2_mask (txq->bufs_log2sz);
  u32 dseg_mask = RDMA_TXQ_DV_DSEG_SZ (txq) - 1;
  /* lkey_be: rd->lkey pre-converted to big-endian for direct WQE dseg writes.
   * Note: rdma_mlx5_wqe_init_tso() receives rd->lkey in host-endian and
   * converts internally via clib_host_to_net_u32() -- these are distinct. */
  const u32 lkey_be = clib_host_to_net_u32 (rd->lkey);
  const u32 done = RDMA_TXQ_USED_SZ (txq->tail, tail);
  u32 n = n_left_from - done;
  rdma_mlx5_wqe_t *last = txq->dv_sq_wqes + (tail & sq_mask);

  bi += done;

  while (n >= 1 && wqe_n >= 1)
    {
      u32 *bufs = txq->bufs + (tail & mask);
      rdma_mlx5_wqe_t *wqe = txq->dv_sq_wqes + (tail & sq_mask);

      if (is_tso && PREDICT_FALSE (b[0]->flags & VNET_BUFFER_F_GSO))
	{
	  rdma_mlx5_tso_result_t r;

	  r = rdma_mlx5_try_tso (vm, node, rd, txq, b[0], bi[0], &tail, &wqe_n, sq_mask, dseg_mask,
				 mask, lkey_be, &last);
	  if (r == RDMA_MLX5_TSO_NO_SLOTS)
	    break;
	  if (r == RDMA_MLX5_TSO_REGULAR)
	    goto send_regular;

	  n--;
	  bi++;
	  b++;
	  continue;
	}

      /* setup the head WQE */
    send_regular:
      rdma_mlx5_wqe_init (wqe, txq->dv_wqe_tmpl, b[0], tail);

      bufs[0] = bi[0];

      if (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  /* Additional dseg are bounded by available WQEBBs and by
	   * the mlx5 WQE size limit. */
	  const u32 dseg_max = rdma_mlx5_wqe_chained_dseg_max (wqe_n, RDMA_MLX5_WQE_DS);
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
		  u32 rel_wqebb = RDMA_TXQ_DV_DSEG2WQE (chained_n);
		  rdma_mlx5_wqe_t *extra_wqe = txq->dv_sq_wqes + ((tail + 1 + rel_wqebb) & sq_mask);
		  clib_memset_u8 (extra_wqe, 0, RDMA_MLX5_WQE_SZ);
		  chained_b->flags &= ~(VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID);
		  u32 idx = tail + 1 + rel_wqebb;
		  idx &= mask;
		  txq->bufs[idx] = chained_b->next_buffer;
		}

	      chained_b = vlib_get_buffer (vm, chained_b->next_buffer);
	      if (PREDICT_FALSE (chained_b->current_length == 0))
		continue;
	      dseg->byte_count = htobe32 (chained_b->current_length);
	      dseg->lkey = lkey_be;
	      dseg->addr = htobe64 (vlib_buffer_get_current_va (chained_b));

	      chained_n += 1;
	    }

	  if (chained_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      /*
	       * no descriptors left: drop the chain including 1st WQE
	       * skip the problematic packet and continue
	       */
	      if (is_tso)
		rdma_buffer_free_from_ring_mlx5 (vm, txq->bufs, tail & mask,
						 RDMA_TXQ_BUF_SZ (txq),
						 1 + RDMA_TXQ_DV_DSEG2WQE (chained_n));
	      else
		vlib_buffer_free_from_ring (vm, txq->bufs, tail & mask, RDMA_TXQ_BUF_SZ (txq),
					    1 + RDMA_TXQ_DV_DSEG2WQE (chained_n));
	      vlib_error_count (vm, node->node_index,
				dseg_max == chained_n ? RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED :
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
			    vlib_buffer_t **b, const int is_tso)
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
      if (PREDICT_FALSE (flags & (VLIB_BUFFER_NEXT_PRESENT | (is_tso ? VNET_BUFFER_F_GSO : 0))))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq, n_left_from, bi, b, tail,
						   is_tso);

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
      if (PREDICT_FALSE (b[0]->flags &
			 (VLIB_BUFFER_NEXT_PRESENT | (is_tso ? VNET_BUFFER_F_GSO : 0))))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq, n_left_from, bi, b, tail,
						   is_tso);

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
rdma_device_output_tx_ibverb_slow (vlib_main_t *vm, const vlib_node_runtime_t *node,
				   const rdma_device_t *rd, rdma_txq_t *txq, u32 n_left_from,
				   const u32 *bi, vlib_buffer_t **b)
{
  u32 n_processed = 0;
  u32 n_posted = 0;

  while (n_processed < n_left_from)
    {
      struct ibv_send_wr wr = {};
      struct ibv_send_wr *bad = 0;
      struct ibv_sge sge[32];
      vlib_buffer_t *seg = b[n_processed];
      u32 n_sge = 0;

      wr.opcode = IBV_WR_SEND;
      sge[n_sge].addr = vlib_buffer_get_current_va (seg);
      sge[n_sge].length = seg->current_length;
      sge[n_sge].lkey = rd->lkey;
      n_sge++;

      while ((seg->flags & VLIB_BUFFER_NEXT_PRESENT) && n_sge < ARRAY_LEN (sge))
	{
	  seg = vlib_get_buffer (vm, seg->next_buffer);
	  sge[n_sge].addr = vlib_buffer_get_current_va (seg);
	  sge[n_sge].length = seg->current_length;
	  sge[n_sge].lkey = rd->lkey;
	  n_sge++;
	}

      if (PREDICT_FALSE (seg->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  /* Chain exceeds the QP SGE limit: drop this packet.
	   * Free the whole chain and count the packet as consumed without
	   * advancing txq->tail because no WR was posted for it. */
	  vlib_buffer_free_one (vm, bi[n_processed]);
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED, 1);
	  n_processed++;
	  break;
	}

      wr.sg_list = sge;
      wr.num_sge = n_sge;
      wr.send_flags = IBV_SEND_SIGNALED;
      wr.wr_id = txq->tail + n_posted + 1;

      if (PREDICT_FALSE (0 != ibv_post_send (txq->ibv_qp, &wr, &bad)))
	{
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SUBMISSION, 1);
	  break;
	}

      n_posted++;
      n_processed++;
    }

  txq->tail += n_posted;
  return n_processed;
}

static_always_inline u32
rdma_device_output_tx_ibverb (vlib_main_t *vm, const vlib_node_runtime_t *node,
			      const rdma_device_t *rd, rdma_txq_t *txq, u32 n_left_from, u32 *bi,
			      vlib_buffer_t **b)
{
  struct ibv_send_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  struct ibv_send_wr *bad = 0;
  u32 n = n_left_from, n_posted = 0;
  vlib_buffer_t **first = b;

  while (n >= 8)
    {
      u32 flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;
      if (PREDICT_FALSE (flags & VLIB_BUFFER_NEXT_PRESENT))
	return rdma_device_output_tx_ibverb_slow (vm, node, rd, txq, n_left_from, bi, first);

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
      n_posted += 4;
    }

  while (n >= 1)
    {
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT))
	return rdma_device_output_tx_ibverb_slow (vm, node, rd, txq, n_left_from, bi, first);

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
      n_posted += 1;
    }

  w[-1].wr_id = txq->tail + n_posted;
  w[-1].next = 0;
  w[-1].send_flags = IBV_SEND_SIGNALED;

  if (PREDICT_FALSE (0 != ibv_post_send (txq->ibv_qp, wr, &bad)))
    {
      u32 n_done = bad ? bad - wr : 0;
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SUBMISSION, n_posted - n_done);
      n_posted = n_done;
    }

  txq->tail += n_posted;
  return n_posted;
}

/*
 * common tx/free functions
 */

static void
rdma_device_output_free (vlib_main_t *vm, const vlib_node_runtime_t *node,
			 const rdma_device_t *rd, rdma_txq_t *txq)
{
  if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_MLX5DV))
    {
      if (rd->flags & RDMA_DEVICE_F_TSO)
	rdma_device_output_free_mlx5 (vm, node, txq, 1);
      else
	rdma_device_output_free_mlx5 (vm, node, txq, 0);
    }
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
      if (rd->flags & RDMA_DEVICE_F_TSO)
	n_left_from =
	  rdma_device_output_tx_mlx5 (vm, node, rd, txq, n_left_from, bi, b, 1);
      else
	n_left_from =
	  rdma_device_output_tx_mlx5 (vm, node, rd, txq, n_left_from, bi, b, 0);
    }
  else
    n_left_from =
      rdma_device_output_tx_ibverb (vm, node, rd, txq, n_left_from, bi, b);

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
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_NO_FREE_SLOTS,
			n_left);
    }

  return n_buffers - n_left;
}

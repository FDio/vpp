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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_psh_cksum.h>
#include <vnet/tcp/tcp_packet.h>
#include <rdma/rdma.h>

#define RDMA_TX_RETRIES 5

#define RDMA_TXQ_DV_DSEG_SZ(txq)        (RDMA_MLX5_WQE_DS * RDMA_TXQ_DV_SQ_SZ(txq))
#define RDMA_TXQ_DV_DSEG2WQE(d)         (((d) + RDMA_MLX5_WQE_DS - 1) / RDMA_MLX5_WQE_DS)

/* DS count lives in the low 8 bits of mlx5 ctrl.qpn_ds. */
#define RDMA_MLX5_WQE_DS_MAX 0xff
/* Sentinel used for WQEBB slots that do not own a buffer index. */
#define RDMA_TXQ_INVALID_BUF ((u32) ~0)

/*
 * MLX5 direct verbs tx/free functions
 */

static_always_inline void
rdma_buffer_free_from_ring (vlib_main_t *vm, u32 *ring, u32 start, u32 ring_size, u32 n_buffers)
{
  u32 i;

  for (i = 0; i < n_buffers; i++)
    {
      u32 idx = (start + i) % ring_size;

      /* TSO WQEs may consume multiple ring slots while only the first one
       * owns the originating buffer index. */
      if (PREDICT_TRUE (ring[idx] != RDMA_TXQ_INVALID_BUF))
	vlib_buffer_free (vm, ring + idx, 1);
    }
}

static_always_inline void
rdma_txq_record_completion_range (rdma_txq_t *txq, u16 start, u16 end)
{
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);

  while (start != end)
    {
      txq->comp_tail[start & sq_mask] = end;
      start++;
    }
}

static_always_inline void
rdma_device_output_free_mlx5 (vlib_main_t * vm,
			      const vlib_node_runtime_t * node,
			      rdma_txq_t * txq)
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
  u16 comp_tail = txq->comp_tail[cqe_wqe_counter & sq_mask];
  if (PREDICT_FALSE (comp_tail == RDMA_TXQ_DV_INVALID_COMP))
    return; /* can happen if CQE reports an untracked intermediate WQEBB */

  ASSERT (RDMA_TXQ_USED_SZ (txq->head, comp_tail) <= buf_sz &&
	  RDMA_TXQ_USED_SZ (comp_tail, txq->tail) < buf_sz);

  /* free sent buffers and update txq head */
  rdma_buffer_free_from_ring (vm, txq->bufs, txq->head & mask, buf_sz,
			      RDMA_TXQ_USED_SZ (txq->head, comp_tail));
  while (txq->head != comp_tail)
    {
      u32 head_idx = txq->head & sq_mask;
      txq->comp_tail[head_idx] = RDMA_TXQ_DV_INVALID_COMP;
      txq->head++;
    }

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

  /* TSO checksum offload expects the TCP checksum field to contain the
   * pseudo-header checksum, not the full checksum of the super-packet. */
  if (b->flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      tcp_header_t *tcp = (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
      ip4->checksum = ip4_header_checksum (ip4);
      tcp->checksum = ip4_pseudo_header_cksum (ip4);
    }
  else if (b->flags & VNET_BUFFER_F_IS_IP6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      tcp_header_t *tcp = (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
      tcp->checksum = ip6_pseudo_header_cksum (ip6);
    }

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

  while (n >= 1 && wqe_n >= 1)
    {
      u16 start_tail = tail;
      u32 *bufs = txq->bufs + (tail & mask);
      rdma_mlx5_wqe_t *wqe = txq->dv_sq_wqes + (tail & sq_mask);

      if (b[0]->flags & VNET_BUFFER_F_GSO)
	{
	  u16 hdr_sz = rdma_mlx5_tso_hdr_sz (b[0]);
	  u32 total_wqebb;
	  u8 base_ds;

	  if (PREDICT_FALSE (wqe_n < rdma_mlx5_tso_n_wqebb (hdr_sz)))
	    break;

	  if (PREDICT_FALSE (hdr_sz > RDMA_MLX5_TSO_HDR_MAX))
	    {
	      /* Header too large for the TSO WQE inline area (e.g. when
	       * TCP options are unusually long).  Fall back to the regular
	       * chained-SEND path so the packet is not dropped. */
	      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_TSO_HDR_TOO_BIG, 1);
	      b[0]->flags &= ~VNET_BUFFER_F_GSO;
	      goto send_regular;
	    }

	  base_ds = rdma_mlx5_wqe_init_tso (txq, b[0], tail, sq_mask, rd->lkey);

	  if (PREDICT_FALSE (base_ds == 0))
	    {
	      /* Header spans multiple buffer fragments — fall back to a regular
	       * SEND to avoid an invalid TSO WQE (pay_len underflow). */
	      b[0]->flags &= ~VNET_BUFFER_F_GSO;
	      goto send_regular;
	    }

	  total_wqebb = RDMA_TXQ_DV_DSEG2WQE (base_ds);
	  txq->bufs[tail & mask] = bi[0];
	  for (u32 i = 1; i < total_wqebb; i++)
	    txq->bufs[(tail + i) & mask] = RDMA_TXQ_INVALID_BUF;

	  if (!(b[0]->flags & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      /* Advance tail by the actual WQEBB count for this WQE.
	       * The ctrl.ds field tells the NIC exactly how many 16-byte DS to
	       * read; the NIC processes ceil(ds/4) WQEBBs and expects the NEXT
	       * WQE at that offset.  If we advance tail by more than ceil(ds/4)
	       * (e.g. always by N_WQEBB=3), the NIC processes the zeroed extra
	       * WQEBB as a separate WQE, sees opcode=0/ds=0, and raises a local
	       * QP operation error (syndrome=0x2).
	       * rdma_mlx5_wqe_init_tso() sets ctrl.ds=base_ds; advance tail
	       * to the WQEBB count implied by that DS count. */
	      rdma_txq_record_completion_range (txq, tail, tail + total_wqebb);
	      last = txq->dv_sq_wqes + (tail & sq_mask);
	      tail += total_wqebb;
	      wqe_n -= total_wqebb;
	    }
	  else
	    {
	      vlib_buffer_t *chained_b = b[0];
	      u32 chained_n = 0;
	      const u32 dseg_max =
		clib_min (RDMA_MLX5_WQE_DS * wqe_n - base_ds, RDMA_MLX5_WQE_DS_MAX - base_ds);

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
			  rdma_mlx5_wqe_t *extra_wqe =
			    txq->dv_sq_wqes + ((tail + rel_wqebb) & sq_mask);
			  clib_memset_u8 (extra_wqe, 0, RDMA_MLX5_WQE_SZ);
			}
		    }

		  chained_b = vlib_get_buffer (vm, chained_b->next_buffer);
		  dseg->byte_count = htobe32 (chained_b->current_length);
		  dseg->lkey = lkey;
		  dseg->addr = htobe64 (vlib_buffer_get_current_va (chained_b));
		  chained_n++;
		}

	      if (chained_b->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  vlib_buffer_free_one (vm, bi[0]);
		  vlib_error_count (vm, node->node_index,
				    dseg_max == chained_n ? RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED :
							    RDMA_TX_ERROR_NO_FREE_SLOTS,
				    1);
		}
	      else
		{
		  u32 total_ds = base_ds + chained_n;
		  rdma_mlx5_wqe_t *wqe0 = txq->dv_sq_wqes + (tail & sq_mask);
		  ((u8 *) &wqe0->ctrl.qpn_ds)[3] = total_ds;
		  /* Advance tail by the actual WQEBB count for this WQE (same
		   * reasoning as the non-chained path: NIC uses ctrl.ds, not a
		   * fixed N_WQEBB constant). */
		  total_wqebb = RDMA_TXQ_DV_DSEG2WQE (total_ds);
		  /* The head buffer owns the full TSO chain; additional WQEBBs
		   * must not free chain fragments a second time. */
		  for (u32 i = 1; i < total_wqebb; i++)
		    txq->bufs[(tail + i) & mask] = RDMA_TXQ_INVALID_BUF;
		  rdma_txq_record_completion_range (txq, tail, tail + total_wqebb);
		  last = wqe0;
		  tail += total_wqebb;
		  wqe_n -= total_wqebb;
		}
	    }

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
	  /*
	   * max number of available dseg:
	   *  - 4 dseg per WQEBB available
	   *  - max 32 dseg per WQE (5-bits length field in WQE ctrl)
	   */
	  const u32 dseg_max =
	    clib_min (RDMA_MLX5_WQE_DS * (wqe_n - 1), RDMA_MLX5_WQE_DS_MAX);
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
		  chained_b->flags &= ~(VLIB_BUFFER_NEXT_PRESENT |
					VLIB_BUFFER_TOTAL_LENGTH_VALID);
		  u32 idx = tail + 1 + rel_wqebb;
		  idx &= mask;
		  txq->bufs[idx] = chained_b->next_buffer;
		}

	      chained_b = vlib_get_buffer (vm, chained_b->next_buffer);
	      if (PREDICT_FALSE (chained_b->current_length == 0))
		continue;
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
	      rdma_buffer_free_from_ring (vm, txq->bufs, tail & mask, RDMA_TXQ_BUF_SZ (txq),
					  1 + RDMA_TXQ_DV_DSEG2WQE (chained_n));
	      vlib_error_count (vm, node->node_index,
				dseg_max == chained_n ?
				RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED :
				RDMA_TX_ERROR_NO_FREE_SLOTS, 1);

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
      rdma_txq_record_completion_range (txq, start_tail, tail);
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
      if (PREDICT_FALSE (flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_GSO)))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq,
						   n_left_from, bi, b, tail);

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
      if (PREDICT_FALSE (b[0]->flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_GSO)))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq,
						   n_left_from, bi, b, tail);

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

  rdma_txq_record_completion_range (txq, txq->tail, tail);
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
rdma_device_output_tx_ibverb (vlib_main_t *vm, const vlib_node_runtime_t *node,
			      const rdma_device_t *rd, rdma_txq_t *txq, u32 n_left_from, u32 *bi,
			      vlib_buffer_t **b)
{
  u32 n_posted = 0;

  while (n_posted < n_left_from)
    {
      struct ibv_send_wr wr = {};
      struct ibv_send_wr *bad = 0;
      struct ibv_sge sge[64];
      vlib_buffer_t *seg = b[n_posted];
      u32 n_sge = 0;
      u8 is_tso = seg->flags & VNET_BUFFER_F_GSO;

      if (PREDICT_FALSE (is_tso))
	{
	  u16 hdr_sz = rdma_mlx5_tso_hdr_sz (seg);
	  u16 mss = vnet_buffer2 (seg)->gso_size;

	  if (PREDICT_FALSE (hdr_sz > seg->current_length))
	    {
	      seg->flags &= ~VNET_BUFFER_F_GSO;
	      is_tso = 0;
	    }
	  else
	    {
	      wr.opcode = IBV_WR_TSO;
	      wr.tso.hdr = vlib_buffer_get_current (seg);
	      wr.tso.hdr_sz = hdr_sz;
	      wr.tso.mss = mss;

	      if (seg->current_length > hdr_sz)
		{
		  sge[n_sge].addr = vlib_buffer_get_current_va (seg) + hdr_sz;
		  sge[n_sge].length = seg->current_length - hdr_sz;
		  sge[n_sge].lkey = rd->lkey;
		  n_sge++;
		}
	    }
	}

      if (!is_tso)
	wr.opcode = IBV_WR_SEND;

      if (!is_tso)
	{
	  sge[n_sge].addr = vlib_buffer_get_current_va (seg);
	  sge[n_sge].length = seg->current_length;
	  sge[n_sge].lkey = rd->lkey;
	  n_sge++;
	}

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
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SEGMENT_SIZE_EXCEEDED, 1);
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
    rdma_device_output_free_mlx5 (vm, node, txq);
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
    n_left_from =
      rdma_device_output_tx_mlx5 (vm, node, rd, txq, n_left_from, bi, b);
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

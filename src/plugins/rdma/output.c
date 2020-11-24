/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vppinfra/ring.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <rdma/rdma.h>

#define RDMA_TX_RETRIES 5

#define RDMA_TXQ_DV_DSEG_SZ(txq)        (RDMA_MLX5_WQE_DS * RDMA_TXQ_DV_SQ_SZ(txq))
#define RDMA_TXQ_DV_DSEG2WQE(d)         (((d) + RDMA_MLX5_WQE_DS - 1) / RDMA_MLX5_WQE_DS)

/*
 * MLX5 direct verbs tx/free functions
 */

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
  const rdma_mlx5_wqe_t *wqe;

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

  /* retrieve original WQE and get new tail counter */
  wqe = txq->dv_sq_wqes + (be16toh (cur->wqe_counter) & sq_mask);
  if (PREDICT_FALSE (wqe->ctrl.imm == RDMA_TXQ_DV_INVALID_ID))
    return;			/* can happen if CQE reports error for an intermediate WQE */

  ASSERT (RDMA_TXQ_USED_SZ (txq->head, wqe->ctrl.imm) <= buf_sz &&
	  RDMA_TXQ_USED_SZ (wqe->ctrl.imm, txq->tail) < buf_sz);

  /* free sent buffers and update txq head */
  vlib_buffer_free_from_ring (vm, txq->bufs, txq->head & mask, buf_sz,
			      RDMA_TXQ_USED_SZ (txq->head, wqe->ctrl.imm));
  txq->head = wqe->ctrl.imm;

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
}

/*
 * specific data path for chained buffers, supporting ring wrap-around
 * contrary to the normal path - otherwise we may fail to enqueue chained
 * buffers because we are close to the end of the ring while we still have
 * plenty of descriptors available
 */
static_always_inline u32
rdma_device_output_tx_mlx5_chained (vlib_main_t * vm,
				    const vlib_node_runtime_t * node,
				    const rdma_device_t * rd,
				    rdma_txq_t * txq, u32 n_left_from, u32 n,
				    u32 * bi, vlib_buffer_t ** b,
				    rdma_mlx5_wqe_t * wqe, u16 tail)
{
  rdma_mlx5_wqe_t *last = wqe;
  u32 wqe_n = RDMA_TXQ_AVAIL_SZ (txq, txq->head, tail);
  u32 sq_mask = pow2_mask (txq->dv_sq_log2sz);
  u32 mask = pow2_mask (txq->bufs_log2sz);
  u32 dseg_mask = RDMA_TXQ_DV_DSEG_SZ (txq) - 1;
  const u32 lkey = clib_host_to_net_u32 (rd->lkey);

  vlib_buffer_copy_indices_to_ring (txq->bufs, bi, txq->tail & mask,
				    RDMA_TXQ_BUF_SZ (txq), n_left_from - n);
  bi += n_left_from - n;

  while (n >= 1 && wqe_n >= 1)
    {
      u32 *bufs = txq->bufs + (tail & mask);
      rdma_mlx5_wqe_t *wqe = txq->dv_sq_wqes + (tail & sq_mask);

      /* setup the head WQE */
      rdma_mlx5_wqe_init (wqe, txq->dv_wqe_tmpl, b[0], tail);

      bufs[0] = bi[0];

      if (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  /*
	   * max number of available dseg:
	   *  - 4 dseg per WQEBB available
	   *  - max 32 dseg per WQE (5-bits length field in WQE ctrl)
	   */
#define RDMA_MLX5_WQE_DS_MAX    (1 << 5)
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
      bi += 1;
      b += 1;
      wqe_n -= 1;
      n -= 1;
    }

  if (n != n_left_from)
    rdma_device_output_tx_mlx5_doorbell (txq, last, tail, sq_mask);

  txq->tail = tail;
  return n_left_from - n;
}

static_always_inline u32
rdma_device_output_tx_mlx5 (vlib_main_t * vm,
			    const vlib_node_runtime_t * node,
			    const rdma_device_t * rd, rdma_txq_t * txq,
			    const u32 n_left_from, u32 * bi,
			    vlib_buffer_t ** b)
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
      if (PREDICT_FALSE (flags & VLIB_BUFFER_NEXT_PRESENT))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq,
						   n_left_from, n, bi, b, wqe,
						   tail);

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
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT))
	return rdma_device_output_tx_mlx5_chained (vm, node, rd, txq,
						   n_left_from, n, bi, b, wqe,
						   tail);

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
  vlib_buffer_copy_indices_to_ring (txq->bufs, bi, txq->tail & mask,
				    RDMA_TXQ_BUF_SZ (txq), n_left_from);
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
  const u32 mask = pow2_mask (txq->bufs_log2sz);
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
  vlib_buffer_copy_indices_to_ring (txq->bufs, bi, txq->tail & mask,
				    RDMA_TXQ_BUF_SZ (txq), n_left_from);
  txq->tail += n_left_from;
  return n_left_from;
}

/*
 * common tx/free functions
 */

static_always_inline void
rdma_device_output_free (vlib_main_t * vm, const vlib_node_runtime_t * node,
			 rdma_txq_t * txq, int is_mlx5dv)
{
  if (is_mlx5dv)
    rdma_device_output_free_mlx5 (vm, node, txq);
  else
    rdma_device_output_free_ibverb (vm, node, txq);
}

static_always_inline u32
rdma_device_output_tx_try (vlib_main_t * vm, const vlib_node_runtime_t * node,
			   const rdma_device_t * rd, rdma_txq_t * txq,
			   u32 n_left_from, u32 * bi, int is_mlx5dv)
{
  vlib_buffer_t *b[VLIB_FRAME_SIZE];

  /* do not enqueue more packet than ring space */
  n_left_from = clib_min (n_left_from, RDMA_TXQ_AVAIL_SZ (txq, txq->head,
							  txq->tail));
  /* if ring is full, do nothing */
  if (PREDICT_FALSE (n_left_from == 0))
    return 0;

  vlib_get_buffers (vm, bi, b, n_left_from);

  n_left_from = is_mlx5dv ?
    rdma_device_output_tx_mlx5 (vm, node, rd, txq, n_left_from, bi,
				b) : rdma_device_output_tx_ibverb (vm, node,
								   rd, txq,
								   n_left_from,
								   bi, b);

  return n_left_from;
}

static_always_inline uword
rdma_device_output_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame, rdma_device_t * rd,
		       int is_mlx5dv)
{
  u32 thread_index = vm->thread_index;
  rdma_txq_t *txq =
    vec_elt_at_index (rd->txqs, thread_index % vec_len (rd->txqs));
  u32 *from;
  u32 n_left_from;
  int i;

  ASSERT (RDMA_TXQ_BUF_SZ (txq) >= VLIB_FRAME_SIZE);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  clib_spinlock_lock_if_init (&txq->lock);

  for (i = 0; i < RDMA_TX_RETRIES && n_left_from > 0; i++)
    {
      u32 n_enq;
      rdma_device_output_free (vm, node, txq, is_mlx5dv);
      n_enq = rdma_device_output_tx_try (vm, node, rd, txq, n_left_from, from,
					 is_mlx5dv);

      n_left_from -= n_enq;
      from += n_enq;
    }

  clib_spinlock_unlock_if_init (&txq->lock);

  if (PREDICT_FALSE (n_left_from))
    {
      vlib_buffer_free (vm, from, n_left_from);
      vlib_error_count (vm, node->node_index,
			RDMA_TX_ERROR_NO_FREE_SLOTS, n_left_from);
    }

  return frame->n_vectors - n_left_from;
}

VNET_DEVICE_CLASS_TX_FN (rdma_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  rdma_main_t *rm = &rdma_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  rdma_device_t *rd = pool_elt_at_index (rm->devices, ord->dev_instance);

  if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_MLX5DV))
    return rdma_device_output_tx (vm, node, frame, rd, 1 /* is_mlx5dv */ );

  return rdma_device_output_tx (vm, node, frame, rd, 0 /* is_mlx5dv */ );
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

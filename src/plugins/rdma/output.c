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

#ifndef MLX5_ETH_L2_INLINE_HEADER_SIZE
#define MLX5_ETH_L2_INLINE_HEADER_SIZE  18
#endif

#define RDMA_TX_RETRIES 5

#define RDMA_TXQ_BUF_MASK(txq)          (RDMA_TXQ_BUF_SZ(txq)-1)
#define RDMA_TXQ_DV_SQ_MASK(txq)        (RDMA_TXQ_DV_SQ_SZ(txq)-1)
#define RDMA_TXQ_DV_CQ_MASK(txq)        (RDMA_TXQ_DV_CQ_SZ(txq)-1)

#define RDMA_TXQ_BUF_IDX(txq, i)        ((i) & RDMA_TXQ_BUF_MASK(txq))
#define RDMA_TXQ_DV_SQ_IDX(txq, i)      ((i) & RDMA_TXQ_DV_SQ_MASK(txq))
#define RDMA_TXQ_DV_CQ_IDX(txq, i)      ((i) & RDMA_TXQ_DV_CQ_MASK(txq))

static_always_inline u32 *
RDMA_TXQ_BUF (rdma_txq_t * txq, const u16 b)
{
  return &txq->bufs[RDMA_TXQ_BUF_IDX (txq, b)];
}

static_always_inline rdma_mlx5_wqe_t *
RDMA_TXQ_DV_WQE (rdma_txq_t * txq, const u16 w)
{
  rdma_mlx5_wqe_t *wqe = txq->dv_sq_wqes;
  return &wqe[RDMA_TXQ_DV_SQ_IDX (txq, w)];
}

static_always_inline struct mlx5_cqe64 *
RDMA_TXQ_DV_CQE (rdma_txq_t * txq, const u16 i)
{
  struct mlx5_cqe64 *cqe = txq->dv_cq_cqes;
  return &cqe[RDMA_TXQ_DV_CQ_IDX (txq, i)];
}

/*
 * MLX5 direct verbs tx/free functions
 */

static_always_inline void
rdma_device_output_free_mlx5 (vlib_main_t * vm,
			      const vlib_node_runtime_t * node,
			      rdma_txq_t * txq)
{
  u16 idx = txq->dv_cq_idx;
  struct mlx5_cqe64 *cur = RDMA_TXQ_DV_CQE (txq, idx);
  u8 op_own, saved;
  const rdma_mlx5_wqe_t *wqe;

  for (;;)
    {
      op_own = *(volatile u8 *) &cur->op_own;
      if (((idx >> txq->dv_cq_log2sz) & MLX5_CQE_OWNER_MASK) != (op_own & MLX5_CQE_OWNER_MASK)
          || (op_own >> 4) == MLX5_CQE_INVALID)
        break;
      if (PREDICT_FALSE ((op_own >> 4)) != MLX5_CQE_REQ)
        vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      idx++;
      cur = RDMA_TXQ_DV_CQE (txq, idx);
    }

  if (idx == txq->dv_cq_idx)
    return; /* nothing to do */

  cur = RDMA_TXQ_DV_CQE (txq, idx - 1);
  saved = cur->op_own; (void)saved;
  cur->op_own = 0xf0;
  txq->dv_cq_idx = idx;

  CLIB_COMPILER_BARRIER ();

  /* retrieve original WQE and get new tail counter */
  wqe = RDMA_TXQ_DV_WQE (txq, be16toh (cur->wqe_counter));
  if (PREDICT_FALSE(RDMA_TXQ_DV_INVALID_ID == wqe->ctrl.imm))
    return;     /* can happen if CQE reports error for an intermediate WQE */

  ASSERT (RDMA_TXQ_USED_SZ (txq->head, wqe->ctrl.imm) <= RDMA_TXQ_BUF_SZ(txq) && RDMA_TXQ_USED_SZ (wqe->ctrl.imm, txq->tail) < RDMA_TXQ_BUF_SZ(txq));

  /* free sent buffers and update txq head */
  vlib_buffer_free_from_ring (vm, txq->bufs,
			      RDMA_TXQ_BUF_IDX (txq, txq->head),
			      RDMA_TXQ_BUF_SZ (txq),
			      RDMA_TXQ_USED_SZ (txq->head, wqe->ctrl.imm));
  txq->head = wqe->ctrl.imm;

  /* ring doorbell */
  CLIB_COMPILER_BARRIER ();
  ((volatile u32 *) txq->dv_cq_dbrec)[0] = htobe32 (idx);
}

static_always_inline void
rdma_device_output_tx_mlx5_doorbell (rdma_txq_t * txq, rdma_mlx5_wqe_t *last, const u16 tail)
{
  last->ctrl.imm = tail;	/* register item to free */
  last->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;	/* generate a CQE so we can free buffers */

  ASSERT(tail != txq->tail
         && RDMA_TXQ_AVAIL_SZ(txq, txq->head, txq->tail) >= RDMA_TXQ_USED_SZ(txq->tail, tail));
  CLIB_MEMORY_STORE_BARRIER ();
  ((volatile u32 *) txq->dv_sq_dbrec)[MLX5_SND_DBR] = htobe32 (tail);
  CLIB_COMPILER_BARRIER ();
  *(volatile u64 *) txq->dv_sq_db = *(u64 *) RDMA_TXQ_DV_WQE (txq, txq->tail);
  txq->tail = tail;
}

static_always_inline void
rdma_mlx5_wqe_init (rdma_mlx5_wqe_t *wqe, const void *tmpl, vlib_buffer_t *b, const u16 tail)
{
  u16 sz = b->current_length;
  u16 inline_sz = clib_min (sz, MLX5_ETH_L2_INLINE_HEADER_SIZE);

  clib_memcpy_fast (wqe, tmpl, RDMA_MLX5_WQE_SZ);

  wqe->ctrl.opmod_idx_opcode |= ((u32) htobe16 (tail)) << 8;
  /* speculatively copy at least MLX5_ETH_L2_INLINE_HEADER_SIZE (18-bytes) */
  const void *cur = vlib_buffer_get_current (b);
  clib_memcpy_fast (wqe->eseg.inline_hdr_start,
                    cur,
                    MLX5_ETH_L2_INLINE_HEADER_SIZE);
  wqe->eseg.inline_hdr_sz = htobe16 (inline_sz);
  wqe->dseg.byte_count = htobe32 (sz - inline_sz);
  wqe->dseg.addr =
    htobe64 (pointer_to_uword(cur) + inline_sz);
}

static_always_inline u32
rdma_device_output_tx_mlx5 (vlib_main_t * vm,
			    const vlib_node_runtime_t * node,
			    const rdma_device_t * rd, rdma_txq_t * txq,
			    const u32 n_left_from, u32 *bi, vlib_buffer_t ** b)
{
  rdma_mlx5_wqe_t *wqe = RDMA_TXQ_DV_WQE (txq, txq->tail);
  u32 n = n_left_from;
  u16 tail = txq->tail;

  ASSERT (RDMA_TXQ_BUF_SZ (txq) <= RDMA_TXQ_DV_SQ_SZ (txq));

  while (n >= 4)
    {
      if (PREDICT_TRUE (n >= 8))
	{
	  vlib_prefetch_buffer_header (b[4 + 0], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 1], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 2], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 3], LOAD);
	  CLIB_PREFETCH (&wqe[4 + 0], 4 * sizeof (wqe[0]), LOAD);
	}

      rdma_mlx5_wqe_init (&wqe[0], txq->dv_wqe_tmpl, b[0], tail + 0);
      rdma_mlx5_wqe_init (&wqe[1], txq->dv_wqe_tmpl, b[1], tail + 1);
      rdma_mlx5_wqe_init (&wqe[2], txq->dv_wqe_tmpl, b[2], tail + 2);
      rdma_mlx5_wqe_init (&wqe[3], txq->dv_wqe_tmpl, b[3], tail + 3);

      b += 4;
      tail += 4;
      wqe += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      rdma_mlx5_wqe_init (&wqe[0], txq->dv_wqe_tmpl, b[0], tail);

      b += 1;
      tail += 1;
      wqe += 1;
      n -= 1;
    }

  vlib_buffer_copy_indices (RDMA_TXQ_BUF(txq, txq->tail), bi, n_left_from);

  rdma_device_output_tx_mlx5_doorbell (txq, &wqe[-1], tail);
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
  vlib_buffer_free_from_ring (vm, txq->bufs,
			      RDMA_TXQ_BUF_IDX (txq, txq->head),
			      RDMA_TXQ_BUF_SZ (txq),
			      RDMA_TXQ_USED_SZ (txq->head, tail));
  txq->head = tail;
}

static_always_inline u32
rdma_device_output_tx_ibverb (vlib_main_t * vm,
			      const vlib_node_runtime_t * node,
			      const rdma_device_t * rd, rdma_txq_t * txq,
			      u32 n_left_from, u32 *bi, vlib_buffer_t ** b)
{
  struct ibv_send_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  u32 n = n_left_from;

  memset (w, 0, n_left_from * sizeof (w[0]));

  while (n >= 4)
    {
      if (PREDICT_TRUE (n >= 8))
	{
	  vlib_prefetch_buffer_header (b[4 + 0], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 1], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 2], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 3], LOAD);

	  CLIB_PREFETCH (&s[4 + 0], 4 * sizeof (s[0]), STORE);

	  CLIB_PREFETCH (&w[4 + 0], CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&w[4 + 1], CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&w[4 + 2], CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&w[4 + 3], CLIB_CACHE_LINE_BYTES, STORE);
	}

      s[0].addr = vlib_buffer_get_current_va (b[0]);
      s[0].length = b[0]->current_length;
      s[0].lkey = rd->lkey;

      s[1].addr = vlib_buffer_get_current_va (b[1]);
      s[1].length = b[1]->current_length;
      s[1].lkey = rd->lkey;

      s[2].addr = vlib_buffer_get_current_va (b[2]);
      s[2].length = b[2]->current_length;
      s[2].lkey = rd->lkey;

      s[3].addr = vlib_buffer_get_current_va (b[3]);
      s[3].length = b[3]->current_length;
      s[3].lkey = rd->lkey;

      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      w[1].next = &w[1] + 1;
      w[1].sg_list = &s[1];
      w[1].num_sge = 1;
      w[1].opcode = IBV_WR_SEND;

      w[2].next = &w[2] + 1;
      w[2].sg_list = &s[2];
      w[2].num_sge = 1;
      w[2].opcode = IBV_WR_SEND;

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

      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      s += 1;
      w += 1;
      b += 1;
      n -= 1;
    }

  w[-1].wr_id = txq->tail;		/* register item to free */
  w[-1].next = 0;		/* fix next pointer in WR linked-list */
  w[-1].send_flags = IBV_SEND_SIGNALED;	/* generate a CQE so we can free buffers */

  w = wr;
  if (PREDICT_FALSE (0 != ibv_post_send (txq->ibv_qp, w, &w)))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_SUBMISSION,
			n_left_from - (w - wr));
      n_left_from = w - wr;
    }

  vlib_buffer_copy_indices (RDMA_TXQ_BUF (txq, txq->tail), bi, n_left_from);
  txq->tail += n_left_from;
  return n_left_from;
}

/*
 * common tx/free functions
 */

static_always_inline void
rdma_device_output_free (vlib_main_t * vm, const vlib_node_runtime_t * node,
			 rdma_txq_t * txq, int is_dv)
{
  if (is_dv)
    rdma_device_output_free_mlx5 (vm, node, txq);
  else
    rdma_device_output_free_ibverb (vm, node, txq);
}

static_always_inline u32
rdma_device_output_tx_try (vlib_main_t * vm, const vlib_node_runtime_t * node,
			   const rdma_device_t * rd, rdma_txq_t * txq,
			   u32 n_left_from, u32 * bi, int is_dv)
{
  vlib_buffer_t *b[VLIB_FRAME_SIZE];

  /* do not enqueue more packet than ring space */
  n_left_from = clib_min (n_left_from, RDMA_TXQ_AVAIL_SZ (txq, txq->head, txq->tail));
  /* avoid wrap-around logic in core loop */
  n_left_from =
    clib_min (n_left_from,
	      RDMA_TXQ_BUF_SZ (txq) - RDMA_TXQ_BUF_IDX (txq, txq->tail));

  /* if ring is full, do nothing */
  if (PREDICT_FALSE (0 == n_left_from))
    return 0;

  vlib_get_buffers (vm, bi, b, n_left_from);

  return is_dv ?
    rdma_device_output_tx_mlx5 (vm, node, rd, txq, n_left_from, bi, b) :
    rdma_device_output_tx_ibverb (vm, node, rd, txq, n_left_from, bi, b);
}

static_always_inline uword
rdma_device_output_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame, rdma_device_t * rd, int is_dv)
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
      rdma_device_output_free (vm, node, txq, is_dv);
      n_enq =
	rdma_device_output_tx_try (vm, node, rd, txq, n_left_from, from,
				   is_dv);
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
    return rdma_device_output_tx (vm, node, frame, rd, 1 /* is_dv */ );

  return rdma_device_output_tx (vm, node, frame, rd, 0 /* is_dv */ );
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

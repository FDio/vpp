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

/*
 * MLX5 direct verbs tx/free functions
 */

static_always_inline void
rdma_device_output_free_mlx5 (vlib_main_t * vm,
			      const vlib_node_runtime_t * node,
			      rdma_txq_t * txq)
{
  u16 idx = txq->dv_cq_idx;
  u16 mask = (1 << txq->dv_cq_log2sz) - 1;
  struct mlx5_cqe64 *cqe = txq->dv_cq_cqes, *cur = &cqe[idx & mask], *last =
    0;
  const u8 exp_own = (idx >> txq->dv_cq_log2sz) & MLX5_CQE_OWNER_MASK;
  u8 op_own;

  while (((op_own =
	   *(volatile u8 *) &cur->op_own) & MLX5_CQE_OWNER_MASK) == exp_own
	 && (op_own >> 4) != MLX5_CQE_INVALID)
    {
      ASSERT (cur < &cqe[1 << txq->dv_cq_log2sz]);
      if (PREDICT_FALSE ((op_own >> 4)) != MLX5_CQE_REQ)
	vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      else
	last = cur;
      idx++;
      cur = &cqe[idx & mask];
    }

  if (idx != txq->dv_cq_idx)
    {
      cqe[txq->dv_cq_idx & mask].op_own = 0xf0;
      txq->dv_cq_idx = idx;
    }

  if (0 == last)
    return;			/* nothing to do */

  CLIB_COMPILER_BARRIER ();

  /* retrieve original WQE and get new tail counter */
  idx = be16toh (last->wqe_counter);
  mask = (1 << txq->dv_sq_log2sz) - 1;
  const rdma_mlx5_wqe_t *wqe =
    &((rdma_mlx5_wqe_t *) txq->dv_sq_wqes)[idx & mask];
  const u16 tail = wqe->ctrl.imm;
  /* free sent buffers and update txq head */
  const u16 size = 1 << txq->bufs_log2sz;
  const u16 slot = txq->head & (size - 1);
  vlib_buffer_free_from_ring (vm, txq->bufs, slot, size,
			      (u16) (tail - txq->head));
  txq->head = tail;

  /* ring doorbell */
  CLIB_COMPILER_BARRIER ();
  ((volatile u32 *) txq->dv_cq_dbrec)[0] = htobe32 (txq->dv_cq_idx);
}

static_always_inline u32
rmda_device_output_tx_mlx5 (vlib_main_t * vm, const rdma_device_t * rd,
			    rdma_txq_t * txq, u32 n_left_from, u32 * bi,
			    vlib_buffer_t ** b, u16 slot)
{
  const u16 mask = (1 << txq->dv_sq_log2sz) - 1;
  u16 idx = txq->tail;
  rdma_mlx5_wqe_t *first =
    &((rdma_mlx5_wqe_t *) txq->dv_sq_wqes)[idx & mask], *wqe = first;
  u32 *tx = &txq->bufs[slot];
  u32 n = n_left_from;

  while (n >= 4)
    {
      if (PREDICT_TRUE (n >= 8))
	{
	  vlib_prefetch_buffer_header (b[4 + 0], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 1], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 2], LOAD);
	  vlib_prefetch_buffer_header (b[4 + 3], LOAD);
	  CLIB_PREFETCH (&wqe[4 + 0], 4 * sizeof (wqe[0]), STORE);
	}

      ASSERT (&wqe[3] <
	      &((rdma_mlx5_wqe_t *)
		txq->dv_sq_wqes)[(1 << txq->dv_sq_log2sz)]);

      u16 sz[4];
      sz[0] = b[0]->current_length;
      sz[1] = b[1]->current_length;
      sz[2] = b[2]->current_length;
      sz[3] = b[3]->current_length;

      u16 inline_sz[4];
      inline_sz[0] = clib_min (sz[0], MLX5_ETH_L2_INLINE_HEADER_SIZE);
      inline_sz[1] = clib_min (sz[1], MLX5_ETH_L2_INLINE_HEADER_SIZE);
      inline_sz[2] = clib_min (sz[2], MLX5_ETH_L2_INLINE_HEADER_SIZE);
      inline_sz[3] = clib_min (sz[3], MLX5_ETH_L2_INLINE_HEADER_SIZE);

      clib_memcpy_fast (&wqe[0], &txq->dv_wqe_tmpl, RDMA_MLX5_WQE_SZ);
      clib_memcpy_fast (&wqe[1], &txq->dv_wqe_tmpl, RDMA_MLX5_WQE_SZ);
      clib_memcpy_fast (&wqe[2], &txq->dv_wqe_tmpl, RDMA_MLX5_WQE_SZ);
      clib_memcpy_fast (&wqe[3], &txq->dv_wqe_tmpl, RDMA_MLX5_WQE_SZ);

      wqe[0].ctrl.opmod_idx_opcode |= ((u32) htobe16 (idx + 0)) << 8;
      wqe[1].ctrl.opmod_idx_opcode |= ((u32) htobe16 (idx + 1)) << 8;
      wqe[2].ctrl.opmod_idx_opcode |= ((u32) htobe16 (idx + 2)) << 8;
      wqe[3].ctrl.opmod_idx_opcode |= ((u32) htobe16 (idx + 3)) << 8;

      /* speculatively copy at least MLX5_ETH_L2_INLINE_HEADER_SIZE (18-bytes) */
      clib_memcpy_fast (wqe[0].eseg.inline_hdr_start,
			vlib_buffer_get_current (b[0]),
			MLX5_ETH_L2_INLINE_HEADER_SIZE);
      clib_memcpy_fast (wqe[1].eseg.inline_hdr_start,
			vlib_buffer_get_current (b[1]),
			MLX5_ETH_L2_INLINE_HEADER_SIZE);
      clib_memcpy_fast (wqe[2].eseg.inline_hdr_start,
			vlib_buffer_get_current (b[2]),
			MLX5_ETH_L2_INLINE_HEADER_SIZE);
      clib_memcpy_fast (wqe[3].eseg.inline_hdr_start,
			vlib_buffer_get_current (b[3]),
			MLX5_ETH_L2_INLINE_HEADER_SIZE);

      wqe[0].eseg.inline_hdr_sz = htobe16 (inline_sz[0]);
      wqe[1].eseg.inline_hdr_sz = htobe16 (inline_sz[1]);
      wqe[2].eseg.inline_hdr_sz = htobe16 (inline_sz[2]);
      wqe[3].eseg.inline_hdr_sz = htobe16 (inline_sz[3]);

      wqe[0].dseg.byte_count = htobe32 (sz[0] - inline_sz[0]);
      wqe[1].dseg.byte_count = htobe32 (sz[1] - inline_sz[1]);
      wqe[2].dseg.byte_count = htobe32 (sz[2] - inline_sz[2]);
      wqe[3].dseg.byte_count = htobe32 (sz[3] - inline_sz[3]);

      wqe[0].dseg.addr =
	htobe64 (vlib_buffer_get_current_va (b[0]) + inline_sz[0]);
      wqe[1].dseg.addr =
	htobe64 (vlib_buffer_get_current_va (b[1]) + inline_sz[1]);
      wqe[2].dseg.addr =
	htobe64 (vlib_buffer_get_current_va (b[2]) + inline_sz[2]);
      wqe[3].dseg.addr =
	htobe64 (vlib_buffer_get_current_va (b[3]) + inline_sz[3]);

      vlib_buffer_copy_indices (tx, bi, 4);

      wqe += 4;
      idx += 4;
      slot += 4;
      b += 4;
      tx += 4;
      bi += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      ASSERT (&wqe[0] <
	      &((rdma_mlx5_wqe_t *)
		txq->dv_sq_wqes)[(1 << txq->dv_sq_log2sz)]);
      u16 sz = b[0]->current_length;
      u16 inline_sz = clib_min (sz, MLX5_ETH_L2_INLINE_HEADER_SIZE);

      clib_memcpy_fast (&wqe[0], &txq->dv_wqe_tmpl, RDMA_MLX5_WQE_SZ);

      wqe[0].ctrl.opmod_idx_opcode |= ((u32) htobe16 (idx)) << 8;
      /* speculatively copy at least MLX5_ETH_L2_INLINE_HEADER_SIZE (18-bytes) */
      clib_memcpy_fast (wqe[0].eseg.inline_hdr_start,
			vlib_buffer_get_current (b[0]),
			MLX5_ETH_L2_INLINE_HEADER_SIZE);
      wqe[0].eseg.inline_hdr_sz = htobe16 (inline_sz);
      wqe[0].dseg.byte_count = htobe32 (sz - inline_sz);
      wqe[0].dseg.addr =
	htobe64 (vlib_buffer_get_current_va (b[0]) + inline_sz);

      vlib_buffer_copy_indices (tx, bi, 1);

      wqe += 1;
      idx += 1;
      slot += 1;
      b += 1;
      tx += 1;
      bi += 1;
      n -= 1;
    }

  txq->tail += n_left_from;

  wqe[-1].ctrl.imm = txq->tail;	/* register item to free */
  wqe[-1].ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;	/* generate a CQE so we can free buffers */

  /* ring doorbell */
  CLIB_COMPILER_BARRIER ();
  ((volatile u32 *) txq->dv_sq_dbrec)[MLX5_SND_DBR] = htobe32 (txq->tail);
  CLIB_MEMORY_STORE_BARRIER ();
  *(volatile u64 *) txq->dv_sq_db = *(u64 *) first;

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
  u16 tail, slot, size;
  int n;

  n = ibv_poll_cq (txq->ibv_cq, VLIB_FRAME_SIZE, wc);
  if (n <= 0)
    {
      if (PREDICT_FALSE (n < 0))
	{
	  vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION,
			    1);
	  abort ();
	}
      return;
    }

  while (PREDICT_FALSE (IBV_WC_SUCCESS != wc[n - 1].status))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_ERROR_COMPLETION, 1);
      abort ();
      n--;
      if (0 == n)
	return;
    }

  tail = wc[n - 1].wr_id;
  size = 1 << txq->bufs_log2sz;
  slot = txq->head & (size - 1);
  vlib_buffer_free_from_ring (vm, txq->bufs, slot, size,
			      (u16) (tail - txq->head));
  txq->head = tail;
}

static_always_inline u32
rmda_device_output_tx_ibverb (vlib_main_t * vm,
			      const vlib_node_runtime_t * node,
			      const rdma_device_t * rd, rdma_txq_t * txq,
			      u32 n_left_from, u32 * bi, vlib_buffer_t ** b,
			      u16 slot)
{
  struct ibv_send_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  u32 *tx = &txq->bufs[slot];
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

      vlib_buffer_copy_indices (tx, bi, 4);

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
      bi += 4;
      tx += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      vlib_buffer_copy_indices (tx, bi, 1);

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
      bi += 1;
      tx += 1;
      n -= 1;
    }

  w[-1].wr_id = (u16) (txq->tail + n_left_from);	/* register item to free */
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
rmda_device_output_tx_try (vlib_main_t * vm, const vlib_node_runtime_t * node,
			   const rdma_device_t * rd, rdma_txq_t * txq,
			   u32 n_left_from, u32 * bi, int is_dv)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 size = 1 << txq->bufs_log2sz, slot = txq->tail & (size - 1);

  /* do not enqueue more packet than ring space */
  n_left_from = clib_min (n_left_from, size - (u16) (txq->tail - txq->head));
  /* avoid wrap-around logic in core loop */
  n_left_from = clib_min (n_left_from, size - slot);

  /* if ring is full, do nothing */
  if (PREDICT_FALSE (0 == n_left_from))
    return 0;

  vlib_get_buffers (vm, bi, bufs, n_left_from);

  return is_dv ?
    rmda_device_output_tx_mlx5 (vm, rd, txq, n_left_from, bi, bufs, slot) :
    rmda_device_output_tx_ibverb (vm, node, rd, txq, n_left_from, bi, bufs,
				  slot);
}

static_always_inline uword
rdma_device_output_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame, int is_dv)
{
  rdma_main_t *rm = &rdma_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  rdma_device_t *rd = pool_elt_at_index (rm->devices, ord->dev_instance);
  u32 thread_index = vm->thread_index;
  rdma_txq_t *txq =
    vec_elt_at_index (rd->txqs, thread_index % vec_len (rd->txqs));
  u32 *from;
  u32 n_left_from;
  int i;

  ASSERT ((1 << txq->bufs_log2sz) >= VLIB_FRAME_SIZE);
  ASSERT ((1 << txq->bufs_log2sz) >= (u16) (txq->tail - txq->head));

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  clib_spinlock_lock_if_init (&txq->lock);

  for (i = 0; i < RDMA_TX_RETRIES && n_left_from > 0; i++)
    {
      u32 n_enq;
      rdma_device_output_free (vm, node, txq, is_dv);
      n_enq =
	rmda_device_output_tx_try (vm, node, rd, txq, n_left_from, from,
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

VNET_DEVICE_CLASS_TX_FN (rdma_mlx5_device_class) (vlib_main_t * vm,
						  vlib_node_runtime_t * node,
						  vlib_frame_t * frame)
{
  return rdma_device_output_tx (vm, node, frame, 1 /* is_dv */ );
}

VNET_DEVICE_CLASS_TX_FN (rdma_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  return rdma_device_output_tx (vm, node, frame, 0 /* is_dv */ );
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

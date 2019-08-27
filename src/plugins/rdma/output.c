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

static_always_inline void
rdma_device_output_free (vlib_main_t * vm, rdma_txq_t * txq)
{
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 tail, slot;
  int n;

  n = ibv_poll_cq (txq->cq, VLIB_FRAME_SIZE, wc);
  if (n <= 0)
    return;

  tail = wc[n - 1].wr_id;
  slot = txq->head & (txq->size - 1);
  vlib_buffer_free_from_ring (vm, txq->bufs, slot, txq->size,
			      tail - txq->head);
  txq->head = tail;
}

static_always_inline u32
rmda_device_output_tx (vlib_main_t * vm, const rdma_device_t * rd,
		       rdma_txq_t * txq, u32 n_left_from, u32 * bi)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  struct ibv_send_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  u32 n, slot = txq->tail & (txq->size - 1);
  u32 *tx = &txq->bufs[slot];

  /* do not enqueue more packet than ring space */
  n_left_from = clib_min (n_left_from, txq->size - (txq->tail - txq->head));
  /* avoid wrap-around logic in core loop */
  n = n_left_from = clib_min (n_left_from, txq->size - slot);

  /* if ring is full, do nothing */
  if (PREDICT_FALSE (0 == n_left_from))
    return 0;

  vlib_get_buffers (vm, bi, bufs, n_left_from);
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

  w[-1].wr_id = txq->tail + n_left_from;	/* register item to free */
  w[-1].next = 0;		/* fix next pointer in WR linked-list */
  w[-1].send_flags = IBV_SEND_SIGNALED;	/* generate a CQE so we can free buffers */

  w = wr;
  if (PREDICT_FALSE (0 != ibv_post_send (txq->qp, w, &w)))
    n_left_from = w - wr;

  txq->tail += n_left_from;
  return n_left_from;
}

VNET_DEVICE_CLASS_TX_FN (rdma_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
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

  ASSERT (txq->size >= VLIB_FRAME_SIZE && is_pow2 (txq->size));
  ASSERT (txq->tail - txq->head <= txq->size);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  clib_spinlock_lock_if_init (&txq->lock);

  for (i = 0; i < 5 && n_left_from > 0; i++)
    {
      u32 n_enq;
      rdma_device_output_free (vm, txq);
      n_enq = rmda_device_output_tx (vm, rd, txq, n_left_from, from);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

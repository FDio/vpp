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
  u32 to_free[VLIB_FRAME_SIZE];
  int n_free;
  int i;

  n_free = ibv_poll_cq (txq->cq, VLIB_FRAME_SIZE, wc);
  if (n_free <= 0)
    return;

  for (i = 0; i < n_free; i++)
    to_free[i] = wc[i].wr_id;

  vlib_buffer_free (vm, to_free, n_free);
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
  u32 *from, *f, n_left_from;
  u32 n_tx_packets, n_tx_failed;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  struct ibv_send_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  int i;

  f = from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  memset (w, 0, n_left_from * sizeof (w[0]));

  while (n_left_from >= 4)
    {
      if (PREDICT_TRUE (n_left_from >= 8))
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
      s[0].lkey = rd->mr->lkey;

      s[1].addr = vlib_buffer_get_current_va (b[1]);
      s[1].length = b[1]->current_length;
      s[1].lkey = rd->mr->lkey;

      s[2].addr = vlib_buffer_get_current_va (b[2]);
      s[2].length = b[2]->current_length;
      s[2].lkey = rd->mr->lkey;

      s[3].addr = vlib_buffer_get_current_va (b[3]);
      s[3].length = b[3]->current_length;
      s[3].lkey = rd->mr->lkey;

      w[0].wr_id = f[0];
      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      w[1].wr_id = f[1];
      w[1].next = &w[1] + 1;
      w[1].sg_list = &s[1];
      w[1].num_sge = 1;
      w[1].opcode = IBV_WR_SEND;

      w[2].wr_id = f[2];
      w[2].next = &w[2] + 1;
      w[2].sg_list = &s[2];
      w[2].num_sge = 1;
      w[2].opcode = IBV_WR_SEND;

      w[3].wr_id = f[3];
      w[3].next = &w[3] + 1;
      w[3].sg_list = &s[3];
      w[3].num_sge = 1;
      w[3].opcode = IBV_WR_SEND;

      s += 4;
      f += 4;
      w += 4;
      b += 4;
      n_left_from -= 4;
    }

  while (n_left_from >= 1)
    {
      s[0].addr = vlib_buffer_get_current_va (b[0]);
      s[0].length = b[0]->current_length;
      s[0].lkey = rd->mr->lkey;

      w[0].wr_id = f[0];
      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      s += 1;
      f += 1;
      w += 1;
      b += 1;
      n_left_from -= 1;
    }

  w[-1].next = 0;		/* fix next pointer in WR linked-list last item */

  w = wr;
  clib_spinlock_lock_if_init (&txq->lock);
  for (i = 0; i < 5; i++)
    {
      rdma_device_output_free (vm, txq);
      if (0 == ibv_post_send (txq->qp, w, &w))
	break;
    }
  clib_spinlock_unlock_if_init (&txq->lock);

  n_tx_packets = w == wr ? frame->n_vectors : w - wr;
  n_tx_failed = frame->n_vectors - n_tx_packets;

  if (PREDICT_FALSE (n_tx_failed))
    {
      vlib_buffer_free (vm, &from[n_tx_packets], n_tx_failed);
      vlib_error_count (vm, node->node_index,
			RDMA_TX_ERROR_NO_FREE_SLOTS, n_tx_failed);
    }

  return n_tx_packets;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

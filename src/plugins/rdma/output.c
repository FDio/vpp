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

static_always_inline u16
rdma_device_output_tx (vlib_main_t * vm, rdma_device_t * rd, rdma_txq_t * txq,
		       u32 * buffers, u16 n_left, u32 * n_tx_packets,
		       u32 * n_tx_bytes)
{
  struct ibv_sge sg_entry;
  struct ibv_send_wr wr, *bad_wr;
  u16 i;

  for (i = 0; i < n_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
      sg_entry.addr = vlib_buffer_get_current_va (b);
      sg_entry.length = b->current_length;
      sg_entry.lkey = rd->mr->lkey;

      memset (&wr, 0, sizeof (wr));
      wr.num_sge = 1;
      wr.sg_list = &sg_entry;
      wr.opcode = IBV_WR_SEND;
      wr.send_flags = IBV_SEND_SIGNALED;
      wr.wr_id = buffers[i];

      if (ibv_post_send (txq->qp, &wr, &bad_wr) != 0)
	break;

      *n_tx_bytes += b->current_length;
    }

  *n_tx_packets += i;
  return i;
}

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
  vnet_main_t *vnm = vnet_get_main ();
  rdma_main_t *rm = &rdma_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  rdma_device_t *rd = pool_elt_at_index (rm->devices, ord->dev_instance);
  u32 thread_index = vm->thread_index;
  u8 qid = thread_index;
  rdma_txq_t *txq = vec_elt_at_index (rd->txqs, qid % vec_len (rd->txqs));
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_left;
  u16 n_retry = 5;
  u32 n_tx_packets = 0, n_tx_bytes = 0;

  clib_spinlock_lock_if_init (&txq->lock);

  n_left = frame->n_vectors;

  while (n_left)
    {
      u16 n;
      rdma_device_output_free (vm, txq);
      n =
	rdma_device_output_tx (vm, rd, txq, buffers, n_left, &n_tx_packets,
			       &n_tx_bytes);
      n_left -= n;
      buffers += n;

      if (n_left && n_retry--)
	{
	  vlib_buffer_free (vm, buffers, n_left);
	  vlib_error_count (vm, node->node_index,
			    RDMA_TX_ERROR_NO_FREE_SLOTS, n_left);
	  break;
	}
    }

  clib_spinlock_unlock_if_init (&txq->lock);

  vlib_increment_combined_counter
    (vnm->interface_main.combined_sw_if_counters +
     VNET_INTERFACE_COUNTER_TX, thread_index,
     rd->hw_if_index, n_tx_packets, n_tx_bytes);

  return frame->n_vectors - n_left;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

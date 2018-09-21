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
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <vmxnet3/vmxnet3.h>

static_always_inline void
vmxnet3_tx_comp_ring_advance_next (vmxnet3_txq_t * txq)
{
  vmxnet3_tx_comp_ring *comp_ring = &txq->tx_comp_ring;

  comp_ring->next++;
  if (PREDICT_FALSE (comp_ring->next == txq->size))
    {
      comp_ring->next = 0;
      comp_ring->gen ^= VMXNET3_TXCF_GEN;
    }
}

static_always_inline void
vmxnet3_tx_ring_advance_produce (vmxnet3_txq_t * txq)
{
  txq->tx_ring.produce++;
  if (PREDICT_FALSE (txq->tx_ring.produce == txq->size))
    {
      txq->tx_ring.produce = 0;
      txq->tx_ring.gen ^= VMXNET3_TXF_GEN;
    }
}

static_always_inline void
vmxnet3_tx_ring_advance_consume (vmxnet3_txq_t * txq)
{
  txq->tx_ring.consume++;
  txq->tx_ring.consume &= txq->size - 1;
}

static_always_inline void
vmxnet3_txq_release (vlib_main_t * vm, vmxnet3_device_t * vd,
		     vmxnet3_txq_t * txq)
{
  vmxnet3_tx_comp *tx_comp;
  u32 bi0;
  vmxnet3_tx_comp_ring *comp_ring;
  u16 eop_idx, desc_idx;

  comp_ring = &txq->tx_comp_ring;
  tx_comp = &txq->tx_comp[comp_ring->next];

  while ((tx_comp->flags & VMXNET3_TXCF_GEN) == comp_ring->gen)
    {
      eop_idx = tx_comp->index & VMXNET3_TXC_INDEX;
      do
	{
	  desc_idx = txq->tx_ring.consume;
	  bi0 = txq->tx_ring.bufs[desc_idx];
	  txq->tx_ring.bufs[desc_idx] = ~0;
	  vlib_buffer_free_no_next (vm, &bi0, 1);
	  vmxnet3_tx_ring_advance_consume (txq);
	}
      while (desc_idx != eop_idx);

      vmxnet3_tx_comp_ring_advance_next (txq);
      tx_comp = &txq->tx_comp[comp_ring->next];
    }
}

static_always_inline u16
vmxnet3_tx_ring_space_left (vmxnet3_txq_t * txq)
{
  u16 count;

  count = (txq->tx_ring.consume - txq->tx_ring.produce - 1);
  /* Wrapped? */
  if (txq->tx_ring.produce >= txq->tx_ring.consume)
    count += txq->size;
  return count;
}

VNET_DEVICE_CLASS_TX_FN (vmxnet3_device_class) (vlib_main_t * vm,
						vlib_node_runtime_t * node,
						vlib_frame_t * frame)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, rd->dev_instance);
  u32 *buffers = vlib_frame_args (frame);
  u32 bi0;
  vlib_buffer_t *b0;
  vmxnet3_tx_desc *txd;
  u32 desc_idx, generation, first_idx;
  u16 space_left;
  u16 n_left = frame->n_vectors;
  vmxnet3_txq_t *txq;
  u32 thread_index = vm->thread_index;
  u16 qid = thread_index;
  u16 n_retry = 5;

  if (PREDICT_FALSE (!(vd->flags & VMXNET3_DEVICE_F_LINK_UP)))
    {
      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index, VMXNET3_TX_ERROR_LINK_DOWN,
			n_left);
      return (0);
    }

  txq = vec_elt_at_index (vd->txqs, qid % vd->num_tx_queues);
  clib_spinlock_lock_if_init (&txq->lock);

retry:
  vmxnet3_txq_release (vm, vd, txq);

  while (n_left)
    {
      bi0 = buffers[0];
      txd = 0;

      /*
       * Toggle the generation bit for SOP fragment to avoid device starts
       * reading incomplete packet
       */
      generation = txq->tx_ring.gen ^ VMXNET3_TXF_GEN;
      first_idx = txq->tx_ring.produce;
      while (1)
	{
	  b0 = vlib_get_buffer (vm, bi0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  space_left = vmxnet3_tx_ring_space_left (txq);
	  if (PREDICT_FALSE (space_left == 0))
	    {
	      break;
	    }

	  desc_idx = txq->tx_ring.produce;

	  vmxnet3_tx_ring_advance_produce (txq);
	  txq->tx_ring.bufs[desc_idx] = bi0;

	  txd = &txq->tx_desc[desc_idx];
	  txd->address =
	    vlib_get_buffer_data_physical_address (vm,
						   bi0) + b0->current_data;

	  txd->flags[0] = generation | b0->current_length;

	  generation = txq->tx_ring.gen;
	  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      txd->flags[1] = 0;
	      bi0 = b0->next_buffer;
	    }
	  else
	    break;
	}

      if (PREDICT_TRUE (txd != 0))
	{
	  txd->flags[1] = VMXNET3_TXF_CQ | VMXNET3_TXF_EOP;
	  asm volatile ("":::"memory");
	  /*
	   * Now toggle back the generation bit for the first segment.
	   * Device can start reading the packet
	   */
	  txq->tx_desc[first_idx].flags[0] ^= VMXNET3_TXF_GEN;
	  vmxnet3_reg_write (vd, 0, VMXNET3_REG_TXPROD, txq->tx_ring.produce);
	}

      if (PREDICT_FALSE (space_left == 0))
	{
	  break;
	}

      buffers++;
      n_left--;
    }

  if (PREDICT_FALSE (n_left))
    {
      if (PREDICT_TRUE (n_retry--))
	goto retry;
      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index, VMXNET3_TX_ERROR_NO_FREE_SLOTS,
			n_left);
    }
  clib_spinlock_unlock_if_init (&txq->lock);

  return (frame->n_vectors - n_left);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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
  vmxnet3_tx_comp_ring *comp_ring;

  comp_ring = &txq->tx_comp_ring;
  tx_comp = &txq->tx_comp[comp_ring->next];

  while ((tx_comp->flags & VMXNET3_TXCF_GEN) == comp_ring->gen)
    {
      u16 eop_idx = tx_comp->index & VMXNET3_TXC_INDEX;
      u32 bi0 = txq->tx_ring.bufs[txq->tx_ring.consume];

      vlib_buffer_free_one (vm, bi0);
      while (txq->tx_ring.consume != eop_idx)
	{
	  vmxnet3_tx_ring_advance_consume (txq);
	}
      vmxnet3_tx_ring_advance_consume (txq);

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
  vmxnet3_tx_desc *txd = 0;
  u32 desc_idx, generation, first_idx;
  u16 space_left;
  u16 n_left = frame->n_vectors;
  vmxnet3_txq_t *txq;
  u32 thread_index = vm->thread_index;
  u16 qid = thread_index;

  if (PREDICT_FALSE (!(vd->flags & VMXNET3_DEVICE_F_LINK_UP)))
    {
      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index, VMXNET3_TX_ERROR_LINK_DOWN,
			n_left);
      return (0);
    }

  txq = vec_elt_at_index (vd->txqs, qid % vd->num_tx_queues);
  clib_spinlock_lock_if_init (&txq->lock);

  vmxnet3_txq_release (vm, vd, txq);

  while (PREDICT_TRUE (n_left))
    {
      u16 space_needed = 1, i;
      vlib_buffer_t *b;

      bi0 = buffers[0];
      b0 = vlib_get_buffer (vm, bi0);
      b = b0;

      space_left = vmxnet3_tx_ring_space_left (txq);
      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  u32 next_buffer = b->next_buffer;

	  b = vlib_get_buffer (vm, next_buffer);
	  space_needed++;
	}
      if (PREDICT_FALSE (space_left < space_needed))
	{
	  vmxnet3_txq_release (vm, vd, txq);
	  space_left = vmxnet3_tx_ring_space_left (txq);

	  if (PREDICT_FALSE (space_left < space_needed))
	    {
	      vlib_buffer_free_one (vm, bi0);
	      vlib_error_count (vm, node->node_index,
				VMXNET3_TX_ERROR_NO_FREE_SLOTS, 1);
	      buffers++;
	      n_left--;
	      /*
	       * Drop this packet. But we may have enough room for the next
	       * packet
	       */
	      continue;
	    }
	}

      /*
       * Toggle the generation bit for SOP fragment to avoid device starts
       * reading incomplete packet
       */
      generation = txq->tx_ring.gen ^ VMXNET3_TXF_GEN;
      first_idx = txq->tx_ring.produce;
      for (i = 0; i < space_needed; i++)
	{
	  b0 = vlib_get_buffer (vm, bi0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  desc_idx = txq->tx_ring.produce;

	  vmxnet3_tx_ring_advance_produce (txq);
	  txq->tx_ring.bufs[desc_idx] = bi0;

	  txd = &txq->tx_desc[desc_idx];
	  txd->address = vlib_buffer_get_current_pa (vm, b0);

	  txd->flags[0] = generation | b0->current_length;

	  generation = txq->tx_ring.gen;

	  txd->flags[1] = 0;
	  bi0 = b0->next_buffer;
	}

      txd->flags[1] = VMXNET3_TXF_CQ | VMXNET3_TXF_EOP;
      asm volatile ("":::"memory");
      /*
       * Now toggle back the generation bit for the first segment.
       * Device can start reading the packet
       */
      txq->tx_desc[first_idx].flags[0] ^= VMXNET3_TXF_GEN;

      buffers++;
      n_left--;
    }

  vmxnet3_reg_write_inline (vd, 0, VMXNET3_REG_TXPROD, txq->tx_ring.produce);

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

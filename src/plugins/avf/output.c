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

#include <avf/avf.h>

static_always_inline u8
avf_tx_desc_get_dtyp (avf_tx_desc_t * d)
{
  return d->qword[1] & 0x0f;
}

static_always_inline u16
avf_tx_enqueue (vlib_main_t * vm, avf_txq_t * txq, u32 * buffers,
		u32 n_packets, int use_va_dma)
{
  u16 next = txq->next;
  u64 bits = (AVF_TXD_CMD_EOP | AVF_TXD_CMD_RS | AVF_TXD_CMD_RSV);
  u16 n_desc = 0;
  u16 n_desc_left, n_packets_left = n_packets;
  u16 mask = txq->size - 1;
  vlib_buffer_t *b[4];
  avf_tx_desc_t *d = txq->descs + next;

  /* avoid ring wrap */
  n_desc_left = txq->size - clib_max (txq->next, txq->n_enqueued + 8);

  while (n_packets_left && n_desc_left)
    {
      u32 or_flags;
      if (n_packets_left < 8 || n_desc_left < 4)
	goto one_by_one;

      vlib_prefetch_buffer_with_index (vm, buffers[4], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[5], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[6], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[7], LOAD);

      b[0] = vlib_get_buffer (vm, buffers[0]);
      b[1] = vlib_get_buffer (vm, buffers[1]);
      b[2] = vlib_get_buffer (vm, buffers[2]);
      b[3] = vlib_get_buffer (vm, buffers[3]);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;

      if (or_flags & VLIB_BUFFER_NEXT_PRESENT)
	goto one_by_one;

      clib_memcpy_fast (txq->bufs + next, buffers, sizeof (u32) * 4);

      if (use_va_dma)
	{
	  d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
	  d[1].qword[0] = vlib_buffer_get_current_va (b[1]);
	  d[2].qword[0] = vlib_buffer_get_current_va (b[2]);
	  d[3].qword[0] = vlib_buffer_get_current_va (b[3]);
	}
      else
	{
	  d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);
	  d[1].qword[0] = vlib_buffer_get_current_pa (vm, b[1]);
	  d[2].qword[0] = vlib_buffer_get_current_pa (vm, b[2]);
	  d[3].qword[0] = vlib_buffer_get_current_pa (vm, b[3]);
	}

      d[0].qword[1] = ((u64) b[0]->current_length) << 34 | bits;
      d[1].qword[1] = ((u64) b[1]->current_length) << 34 | bits;
      d[2].qword[1] = ((u64) b[2]->current_length) << 34 | bits;
      d[3].qword[1] = ((u64) b[3]->current_length) << 34 | bits;

      next += 4;
      n_desc += 4;
      buffers += 4;
      n_packets_left -= 4;
      n_desc_left -= 4;
      d += 4;
      continue;

    one_by_one:
      txq->bufs[next] = buffers[0];
      b[0] = vlib_get_buffer (vm, buffers[0]);

      if (use_va_dma)
	d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
      else
	d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);

      d[0].qword[1] = (((u64) b[0]->current_length) << 34) | bits;

      next += 1;
      n_desc += 1;
      buffers += 1;
      n_packets_left -= 1;
      n_desc_left -= 1;
      d += 1;
    }

  CLIB_MEMORY_BARRIER ();
  *(txq->qtx_tail) = txq->next = next & mask;
  txq->n_enqueued += n_desc;
  return n_packets - n_packets_left;
}

VNET_DEVICE_CLASS_TX_FN (avf_device_class) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  avf_main_t *am = &avf_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  avf_device_t *ad = pool_elt_at_index (am->devices, rd->dev_instance);
  u32 thread_index = vm->thread_index;
  u8 qid = thread_index;
  avf_txq_t *txq = vec_elt_at_index (ad->txqs, qid % ad->num_queue_pairs);
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_enq, n_left;
  u16 n_retry = 5;

  clib_spinlock_lock_if_init (&txq->lock);

  n_left = frame->n_vectors;

retry:
  /* release consumed bufs */
  if (txq->n_enqueued)
    {
      avf_tx_desc_t *d0;
      u16 first, slot, n_free = 0, mask = txq->size - 1;
      first = slot = (txq->next - txq->n_enqueued) & mask;
      d0 = txq->descs + slot;
      while (n_free < txq->n_enqueued && avf_tx_desc_get_dtyp (d0) == 0x0F)
	{
	  n_free++;
	  slot = (slot + 1) & mask;
	  d0 = txq->descs + slot;
	}

      if (n_free)
	{
	  txq->n_enqueued -= n_free;
	  vlib_buffer_free_from_ring (vm, txq->bufs, first, txq->size,
				      n_free);
	}
    }

  if (ad->flags & AVF_DEVICE_F_VA_DMA)
    n_enq = avf_tx_enqueue (vm, txq, buffers, n_left, 1);
  else
    n_enq = avf_tx_enqueue (vm, txq, buffers, n_left, 0);

  n_left -= n_enq;

  if (n_left)
    {
      buffers += n_enq;

      if (n_retry--)
	goto retry;

      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index,
			AVF_TX_ERROR_NO_FREE_SLOTS, n_left);
    }

  clib_spinlock_unlock_if_init (&txq->lock);

  return frame->n_vectors - n_left;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

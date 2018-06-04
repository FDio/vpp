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

#define AVF_TXQ_DESC_CMD(x)             (1 << (x + 4))
#define AVF_TXQ_DESC_CMD_EOP		AVF_TXQ_DESC_CMD(0)
#define AVF_TXQ_DESC_CMD_RS		AVF_TXQ_DESC_CMD(1)
#define AVF_TXQ_DESC_CMD_RSV		AVF_TXQ_DESC_CMD(2)

static_always_inline u8
avf_tx_desc_get_dtyp (avf_tx_desc_t * d)
{
  return d->qword[1] & 0x0f;
}

static_always_inline uword
avf_get_tx_buffer_dma_addr (vlib_main_t * vm, vlib_buffer_t * b, int use_iova)
{
  vlib_buffer_main_t *bm = &buffer_main;
  vlib_buffer_pool_t *pool;
  if (use_iova)
    return pointer_to_uword (vlib_buffer_get_current (b));

  pool = vec_elt_at_index (bm->buffer_pools, b->buffer_pool_index);
  return b->current_data +
    vlib_physmem_virtual_to_physical (vm, pool->physmem_region, b->data);
}

static_always_inline void
avf_enq_tx_buffer (vlib_main_t * vm, avf_tx_desc_t * d, vlib_buffer_t ** b,
		   u16 bits, int num, int use_iova)
{
  if (num == 4)
    {
      u64 addr0 = avf_get_tx_buffer_dma_addr (vm, b[0], use_iova);
      u64 addr1 = avf_get_tx_buffer_dma_addr (vm, b[1], use_iova);
      u64 addr2 = avf_get_tx_buffer_dma_addr (vm, b[2], use_iova);
      u64 addr3 = avf_get_tx_buffer_dma_addr (vm, b[3], use_iova);
      d[0].qword[0] = addr0;
      d[0].qword[1] = ((u64) b[0]->current_length) << 34 | bits;
      d[1].qword[0] = addr1;
      d[1].qword[1] = ((u64) b[1]->current_length) << 34 | bits;
      d[2].qword[0] = addr2;
      d[2].qword[1] = ((u64) b[2]->current_length) << 34 | bits;
      d[3].qword[0] = addr3;
      d[3].qword[1] = ((u64) b[3]->current_length) << 34 | bits;
    }
  else
    {
      d[0].qword[0] = avf_get_tx_buffer_dma_addr (vm, b[0], use_iova);
      d[0].qword[1] = ((u64) b[0]->current_length) << 34 | bits;
    }
}

static_always_inline void
avf_txq_advance (avf_txq_t * txq, u8 n_slots)
{
  int i;
  for (i = 0; i < n_slots; i++)
    txq->n_tail_bufs[(txq->next + i) & txq->mask] = n_slots - 1 - i;
  txq->next = (txq->next + n_slots) & txq->mask;
}

static_always_inline avf_tx_desc_t *
avf_txq_get_desc (avf_txq_t * txq, u16 slot)
{
  return txq->descs + (slot & txq->mask);
}

static_always_inline int
avf_txq_desc_complete (avf_txq_t * txq, u16 slot)
{
  avf_tx_desc_t *d;
  d = avf_txq_get_desc (txq, slot + txq->n_tail_bufs[slot]);
  return avf_tx_desc_get_dtyp (d) == 0x0F;
}

static_always_inline uword
avf_interface_tx_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 avf_device_t * ad, vlib_frame_t * frame,
			 int use_iova)
{
  u8 qid = vm->thread_index;
  avf_txq_t *txq = vec_elt_at_index (ad->txqs, qid % ad->num_queue_pairs);
  avf_tx_desc_t *d;
  u32 *bi, *from = vlib_frame_args (frame);
  u16 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 n_free_desc, mask = txq->size - 1;

  if (0 && ad->dev_instance == 0)
    clib_warning ("n_left %u n_enqueued %u", n_left, txq->n_enqueued);

  vlib_get_buffers (vm, from, bufs, n_left);

  clib_spinlock_lock_if_init (&txq->lock);

  /* release cosumed bufs */
  if (txq->n_enqueued)
    {
      u16 first, slot, n_free = 0;
      first = slot = (txq->next - txq->n_enqueued) & mask;
      while (n_free < txq->n_enqueued && avf_txq_desc_complete (txq, slot))
	{
	  u8 n_tail_bufs = txq->n_tail_bufs[slot];
	  n_free += 1 + n_tail_bufs;
	  slot = (slot + 1 + n_tail_bufs) & mask;
	}

      if (0 && ad->dev_instance == 0)
	clib_warning ("n_left %u", n_free);

      if (n_free)
	{
	  txq->n_enqueued -= n_free;
	  if (0 && ad->dev_instance == 0)
	    for (int x = 0; x < n_free; x++)
	      clib_warning ("free %x (%u)", txq->bufs[(first + x) & mask],
			    (first + x) & mask);
	  vlib_buffer_free_from_ring_no_next (vm, txq->bufs, first, txq->size,
					      n_free);
	}
    }

  n_free_desc = txq->size - txq->n_enqueued - 8;
  b = bufs;
  bi = from;

  while (n_left && n_free_desc)
    {
      u64 bits = AVF_TXQ_DESC_CMD_EOP | AVF_TXQ_DESC_CMD_RS | AVF_TXQ_DESC_CMD_RSV;
      u32 or_flags;

      d = txq->descs + txq->next;

      if (PREDICT_FALSE ((n_left < 4) || (n_free_desc < 4) ||
			 (txq->size - txq->next <= 4)))
	goto one_by_one;

      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;

      if (PREDICT_FALSE (or_flags & VLIB_BUFFER_NEXT_PRESENT))
	goto one_by_one;

      clib_memcpy (txq->bufs + txq->next, bi, 4 * sizeof (u32));

      avf_enq_tx_buffer (vm, d, b, bits, 4, use_iova);

      txq->next += 4;
      bi += 4;
      b += 4;
      n_left -= 4;
      n_free_desc -= 4;
      continue;

    one_by_one:
      txq->bufs[txq->next] = bi[0];
      if (0 && ad->dev_instance == 0)
	clib_warning ("enq head %x (%u)", bi[0], txq->next);

      d[0].qword[0] = avf_get_tx_buffer_dma_addr (vm, b[0], use_iova);
      d[0].qword[1] = ((u64) b[0]->current_length) << 34;
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  /* chained buffers */
	  vlib_buffer_t *nb = b[0];
	  u16 count = 1;
	  u16 index = txq->next;
	  d[0].qword[1] |= AVF_TXQ_DESC_CMD_RS | AVF_TXQ_DESC_CMD_RSV;
	  while (nb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      if (++count > n_free_desc)
		break;
	      index = (index + 1) & mask;
	      txq->bufs[index] = nb->next_buffer;
	      if (0 && ad->dev_instance == 0)
		clib_warning ("enq next %x (%u)", txq->bufs[index], index);
	      nb = vlib_get_buffer (vm, nb->next_buffer);
	      d = txq->descs + index;
	      d[0].qword[0] = avf_get_tx_buffer_dma_addr (vm, nb, use_iova);
	      d[0].qword[1] = ((u64) nb->current_length) << 34;
	      d[0].qword[1] |= AVF_TXQ_DESC_CMD_RS | AVF_TXQ_DESC_CMD_RSV;
	    }

	  /* next */
	  d[0].qword[1] |= AVF_TXQ_DESC_CMD_RS | AVF_TXQ_DESC_CMD_EOP | AVF_TXQ_DESC_CMD_RSV;
	  n_free_desc -= count;
	  avf_txq_advance (txq, count);
	}
      else
	{
	  d[0].qword[1] |= AVF_TXQ_DESC_CMD_RS | AVF_TXQ_DESC_CMD_EOP | AVF_TXQ_DESC_CMD_RSV;
	  n_free_desc -= 1;
	  avf_txq_advance (txq, 1);
	}

      bi += 1;
      b += 1;
      n_left -= 1;
    }

  txq->n_enqueued = txq->size - 8 - n_free_desc;

  CLIB_MEMORY_BARRIER ();
  *(txq->qtx_tail) = txq->next;

  clib_spinlock_unlock_if_init (&txq->lock);

  if (n_left)
    vlib_buffer_free (vm, from + frame->n_vectors - n_left, n_left);

  return frame->n_vectors - n_left;
}

uword
CLIB_MULTIARCH_FN (avf_interface_tx) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  avf_main_t *am = &avf_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  avf_device_t *ad = pool_elt_at_index (am->devices, rd->dev_instance);

  if (ad->flags & AVF_DEVICE_F_IOVA)
    return avf_interface_tx_inline (vm, node, ad, frame, 1);
  else
    return avf_interface_tx_inline (vm, node, ad, frame, 0);
}

#ifndef CLIB_MARCH_VARIANT
#if __x86_64__
vlib_node_function_t __clib_weak avf_interface_tx_avx512;
vlib_node_function_t __clib_weak avf_interface_tx_avx2;
static void __clib_constructor
avf_interface_tx_multiarch_select (void)
{
  if (avf_interface_tx_avx512 && clib_cpu_supports_avx512f ())
    avf_device_class.tx_function = avf_interface_tx_avx512;
  else if (avf_interface_tx_avx2 && clib_cpu_supports_avx2 ())
    avf_device_class.tx_function = avf_interface_tx_avx2;
}
#endif
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

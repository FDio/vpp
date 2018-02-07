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

static_always_inline u8
avf_tx_desc_get_dtyp (avf_tx_desc_t * d)
{
  return d->qword[1] & 0x0f;
}

uword
CLIB_MULTIARCH_FN (avf_interface_tx) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  avf_main_t *am = &avf_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  avf_device_t *ad = pool_elt_at_index (am->devices, rd->dev_instance);
  u32 thread_index = vlib_get_thread_index ();
  u8 qid = thread_index;
  avf_txq_t *txq = vec_elt_at_index (ad->txqs, qid);
  avf_tx_desc_t *d0, *d1, *d2, *d3;
  u32 *buffers = vlib_frame_args (frame);
  u32 bi0, bi1, bi2, bi3;
  u16 n_left = frame->n_vectors;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u16 mask = txq->size - 1;

  /* release cosumed bufs */
  if (txq->n_bufs)
    {
      u16 first, slot, n_free = 0;
      first = slot = (txq->next - txq->n_bufs) & mask;
      d0 = txq->descs + slot;
      while (n_free < txq->n_bufs && avf_tx_desc_get_dtyp (d0) == 0x0F)
	{
	  n_free++;
	  slot = (slot + 1) & mask;
	  d0 = txq->descs + slot;
	}

      if (n_free)
	{
	  txq->n_bufs -= n_free;;
	  vlib_buffer_free_from_ring (vm, txq->bufs, first, txq->size,
				      n_free);
	}
    }

  while (n_left >= 7)
    {
      u16 slot0, slot1, slot2, slot3;

      vlib_prefetch_buffer_with_index (vm, buffers[5], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[6], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[7], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[8], LOAD);

      slot0 = txq->next;
      slot1 = (txq->next + 1) & mask;
      slot2 = (txq->next + 2) & mask;
      slot3 = (txq->next + 3) & mask;

      d0 = txq->descs + slot0;
      d1 = txq->descs + slot1;
      d2 = txq->descs + slot2;
      d3 = txq->descs + slot3;

      bi0 = buffers[0];
      bi1 = buffers[1];
      bi2 = buffers[2];
      bi3 = buffers[3];

      txq->bufs[slot0] = bi0;
      txq->bufs[slot1] = bi1;
      txq->bufs[slot2] = bi2;
      txq->bufs[slot3] = bi3;
      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);
      b2 = vlib_get_buffer (vm, bi2);
      b3 = vlib_get_buffer (vm, bi3);

#if 0
      d->qword[0] = vlib_get_buffer_data_physical_address (vm, bi0) +
	b0->current_data;
#else
      d0->qword[0] = pointer_to_uword (b0->data);
      d1->qword[0] = pointer_to_uword (b1->data);
      d2->qword[0] = pointer_to_uword (b2->data);
      d3->qword[0] = pointer_to_uword (b3->data);

#endif
      u64 bits = AVF_TXQ_DESC_CMD_EOP | AVF_TXQ_DESC_CMD_RS;
      d0->qword[1] = ((u64) b0->current_length) << 34 | bits;
      d1->qword[1] = ((u64) b1->current_length) << 34 | bits;
      d2->qword[1] = ((u64) b2->current_length) << 34 | bits;
      d3->qword[1] = ((u64) b3->current_length) << 34 | bits;

      txq->next = (txq->next + 4) & mask;
      txq->n_bufs += 4;
      buffers += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      d0 = txq->descs + txq->next;
      bi0 = buffers[0];
      txq->bufs[txq->next] = bi0;
      b0 = vlib_get_buffer (vm, bi0);

#if 0
      d->qword[0] = vlib_get_buffer_data_physical_address (vm, bi0) +
	b0->current_data;
#else
      d0->qword[0] = pointer_to_uword (b0->data);

#endif
      d0->qword[1] = ((u64) b0->current_length) << 34;
      d0->qword[1] |= AVF_TXQ_DESC_CMD_EOP | AVF_TXQ_DESC_CMD_RS;

      txq->next = (txq->next + 1) & mask;
      txq->n_bufs++;
      buffers++;
      n_left--;
    }
  CLIB_MEMORY_BARRIER ();
  *(txq->qtx_tail) = txq->next;

  return frame->n_vectors - n_left;
}

#ifndef CLIB_MULTIARCH_VARIANT
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

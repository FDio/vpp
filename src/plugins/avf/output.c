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
avf_tx_desc_get_dtyp (avf_tx_desc_t *d)
{
  return d->qword[1] & 0x0f;
}

uword
avf_interface_tx (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  avf_main_t *am = &avf_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  avf_device_t *ad = pool_elt_at_index (am->devices, rd->dev_instance);
  u32 thread_index = vlib_get_thread_index ();
  u8 qid = thread_index;
  avf_txq_t *txq = vec_elt_at_index (ad->txqs, qid);
  avf_tx_desc_t *d;
  u32 *buffers = vlib_frame_args (frame);
  u32 bi0;
  u16 n_left = frame->n_vectors;
  vlib_buffer_t *b0;
  u16 mask = txq->size - 1;

  /* release cosumed bufs */
  if (txq->n_bufs)
    {
      u16 slot = (txq->next - txq->n_bufs) & mask;
      d = txq->descs + slot;
      while (txq->n_bufs && avf_tx_desc_get_dtyp (d) == 0x0F)
	{
	  vlib_buffer_free (vm, txq->bufs + slot, 1);
	  txq->n_bufs--;
	  slot = (slot + 1) & mask;
          d = txq->descs + slot;
	}
    }

  while (n_left)
    {
      d = txq->descs + txq->next;
      bi0 = buffers[0];
      txq->bufs[txq->next] = bi0;
      b0 = vlib_get_buffer (vm, bi0);

      d->qword[0] = vlib_get_buffer_data_physical_address (vm, bi0) +
	b0->current_data;
      d->qword[1] = ((u64) b0->current_length) << 34;
      d->qword[1] |= AVF_TXQ_DESC_CMD_EOP | AVF_TXQ_DESC_CMD_RS;

      txq->next = (txq->next + 1) & mask;
      txq->n_bufs++;
      buffers++;
      n_left--;
    }
  CLIB_MEMORY_BARRIER ();
  *(txq->qtx_tail) = txq->next;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

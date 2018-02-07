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
  u32 *buffers = vlib_frame_args (frame);
  u32 bi0;
  u16 n_left = frame->n_vectors;
  vlib_buffer_t *b0;
  u16 mask = txq->size - 1;

  while (n_left)
    {
      avf_tx_desc_t *d = ((avf_tx_desc_t *) txq->descs) + txq->next;
      bi0 = buffers[0];
      b0 = vlib_get_buffer (vm, bi0);

      d->qword[0] = vlib_get_buffer_data_physical_address (vm, bi0) +
	b0->current_data;
      d->qword[1] = ((u64) b0->current_length) << 34;
      d->qword[1] |= 1 << 4;	// EOP

      txq->next = (txq->next + 1) & mask;
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

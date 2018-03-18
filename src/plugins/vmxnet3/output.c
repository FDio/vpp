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

uword
vmxnet3_interface_tx (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, rd->dev_instance);
  u32 *buffers = vlib_frame_args (frame);
  u32 bi0;
  vlib_buffer_t *b0;
  vmxnet3_tx_desc *txd;
  u32 fill;
  u32 desc_idx;
  u32 generation;
  u16 n_left = frame->n_vectors;
  vmxnet3_txq_t *txq;
  u16 qid = 0;
  u16 mask;

  txq = vec_elt_at_index (vd->txqs, qid);
  mask = txq->size - 1;
  while (n_left > 0)
    {
      bi0 = buffers[0];
      b0 = vlib_get_buffer (vm, bi0);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

      fill = vd->count.tx_prod - vd->count.tx_cons;
      if (fill >= VMXNET3_TX_FILL)
	break;

      desc_idx = vd->count.tx_prod & mask;
      if (vd->count.tx_prod & txq->size)
	generation = 0;
      else
	generation = VMXNET3_TXF_GEN;

      vd->count.tx_prod++;

      txq->bufs[txq->next] = bi0;

      txd = &vd->dma->tx_desc[desc_idx];
      txd->address =
	vlib_get_buffer_data_physical_address (vm, bi0) + b0->current_data;
      txd->flags[0] = generation | b0->current_length;
      txd->flags[1] =  VMXNET3_TXF_CQ | VMXNET3_TXF_EOP;

      vmxnet3_reg_write (vd, 0, VMXNET3_REG_TXPROD, vd->count.tx_prod & mask);
      buffers++;
      n_left--;
    }

  return (frame->n_vectors - n_left);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

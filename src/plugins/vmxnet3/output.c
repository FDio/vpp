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
vmxnet3_txq_release (vlib_main_t * vm, vmxnet3_device_t *vd, vmxnet3_txq_t *txq)
{
  vmxnet3_tx_comp *tx_comp;
  u32 comp_idx, desc_idx, generation;
  u16 mask = txq->size - 1;
  u32 bi0;

  while (1)
    {
      comp_idx = txq->consume & mask;
      if (txq->consume & txq->size)
	generation = 0;
      else
	generation = VMXNET3_TXCF_GEN;
      tx_comp = &txq->tx_comp[comp_idx];
      if (generation != (tx_comp->flags & VMXNET3_TXCF_GEN))
	break;

      txq->consume++;

      desc_idx = tx_comp->index & mask;

      bi0 = txq->bufs[desc_idx];
      vlib_buffer_free_one (vm, bi0);
    }
}

uword
CLIB_MULTIARCH_FN (vmxnet3_interface_tx) (vlib_main_t * vm,
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
  u32 desc_idx, generation;
  u64 fill;
  u16 n_left = frame->n_vectors;
  vmxnet3_txq_t *txq;
  u16 mask, qid = 0;

  txq = vec_elt_at_index (vd->txqs, qid);

  vmxnet3_txq_release (vm, vd, txq);

  mask = txq->size - 1;
  while (n_left > 0)
    {
      bi0 = buffers[0];
      b0 = vlib_get_buffer (vm, bi0);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

      fill = txq->produce - txq->consume;
      if (fill >= txq->size - 1)
	break;

      desc_idx = txq->produce & mask;
      if (txq->produce & txq->size)
	generation = 0;
      else
	generation = VMXNET3_TXF_GEN;

      txq->produce++;

      txq->bufs[desc_idx] = bi0;

      txd = &txq->tx_desc[desc_idx];
      txd->address =
	vlib_get_buffer_data_physical_address (vm, bi0) + b0->current_data;
      txd->flags[0] = generation | b0->current_length;
      txd->flags[1] =  VMXNET3_TXF_CQ | VMXNET3_TXF_EOP;

      vmxnet3_reg_write (vd, 0, VMXNET3_REG_TXPROD, txq->produce & mask);
      buffers++;
      n_left--;
    }

  return (frame->n_vectors - n_left);
}

#ifndef CLIB_MARCH_VARIANT
#if __x86_64__
vlib_node_function_t __clib_weak vmxnet3_interface_tx_avx512;
vlib_node_function_t __clib_weak vmxnet3_interface_tx_avx2;
static void __clib_constructor
vmxnet3_interface_tx_multiarch_select (void)
{
  if (vmxnet3_interface_tx_avx512 && clib_cpu_supports_avx512f ())
    vmxnet3_device_class.tx_function = vmxnet3_interface_tx_avx512;
  else if (vmxnet3_interface_tx_avx2 && clib_cpu_supports_avx2 ())
    vmxnet3_device_class.tx_function = vmxnet3_interface_tx_avx2;
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

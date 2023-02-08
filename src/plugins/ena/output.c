/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <ena/ena.h>
#include <ena/ena_inlines.h>

VNET_DEVICE_CLASS_TX_FN (ena_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ena_device_t *ad = ena_get_device (rd->dev_instance);
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  u8 qid = tf->queue_id;
  ena_txq_t *txq = vec_elt_at_index (ad->txqs, qid);
  u16 n_left;

  if (tf->shared_queue)
    clib_spinlock_lock (&txq->lock);

  n_left = frame->n_vectors;

  if (tf->shared_queue)
    clib_spinlock_unlock (&txq->lock);

  return frame->n_vectors - n_left;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <dev_ige/ige.h>

VNET_DEV_NODE_FN (ige_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *buffers = vlib_frame_vector_args (frame);
  ige_txq_t *itq = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1;
  u16 n_enq = 0, n_left;
  u16 tail = itq->tail;
  u16 slot = tail & mask;

  n_left = frame->n_vectors;

  vnet_dev_tx_queue_lock_if_needed (txq);

  ige_tx_desc_t *d = itq->descs + slot;
  vlib_buffer_t *b = vlib_get_buffer (vm, buffers[0]);

  d->eop = 1;
  d->ifcs = 1;
  d->rs = 1;
  d->dd = 1;
  d->dtyp = 0b0011;
  d->addr = vlib_buffer_get_current_va (b);
  d->dtalen = d->paylen = b->current_length;
  tail++;
  n_enq++;
  n_left--;

  fformat (stderr, "slot %u %U\n", slot, format_ige_tx_desc, d);

  if (itq->tail != tail)
    {
      __atomic_store_n (itq->reg_tdt, tail, __ATOMIC_RELEASE);
      itq->tail = tail;
    }

  if (n_left)
    {
      buffers += n_enq;

      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index, IGE_TX_NODE_CTR_NO_FREE_SLOTS,
			n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}

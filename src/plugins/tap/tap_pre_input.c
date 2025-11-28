/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/gso/gro_func.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <tap/internal.h>

static_always_inline u8
tap_txq_is_scheduled (tap_txq_t *txq)
{
  if (txq)
    return (txq->tx_is_scheduled);
  return 1;
}

static_always_inline void
tap_txq_set_scheduled (tap_txq_t *txq)
{
  if (txq)
    txq->tx_is_scheduled = 1;
}

static_always_inline uword
tap_pre_input_inline (vlib_main_t *vm, tap_txq_t *txq_vring,
		      vnet_hw_if_tx_queue_t *txq)
{
  if (!txq->shared_queue)
    {
      vnet_gro_flow_table_schedule_node_on_dispatcher (vm, txq,
						       txq_vring->flow_table);
      return 0;
    }

  if (CLIB_SPINLOCK_TRYLOCK (txq_vring->lock))
    {
      if (tap_txq_is_scheduled (txq_vring))
	goto unlock;
      vnet_gro_flow_table_schedule_node_on_dispatcher (vm, txq,
						       txq_vring->flow_table);
      tap_txq_set_scheduled (txq_vring);
    unlock:
      CLIB_SPINLOCK_UNLOCK (txq_vring->lock);
    }

  return 0;
}

static uword
tap_pre_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  tap_main_t *tm = &tap_main;
  vnet_main_t *vnm = vnet_get_main ();
  tap_if_t *tif;

  pool_foreach (tif, tm->interfaces)
    {
      if (tif->packet_coalesce)
	{
	  tap_txq_t *txq_vring;
	  vec_foreach (txq_vring, tif->tx_queues)
	    {
	      vnet_hw_if_tx_queue_t *txq =
		vnet_hw_if_get_tx_queue (vnm, txq_vring->queue_index);
	      if (clib_bitmap_get (txq->threads, vm->thread_index) == 1)
		tap_pre_input_inline (vm, txq_vring, txq);
	    }
	}
    }

  return 0;
}

/**
 * virtio interfaces support packet coalescing and buffering which
 * depends on timer expiry to flush the stored packets periodically.
 * Previously, virtio input node checked timer expiry and scheduled
 * tx queue accordingly.
 *
 * In poll mode, timer expiry was handled naturally, as input node
 * runs periodically. In interrupt mode, virtio input node was dependent
 * on the interrupts send from backend. Stored packets could starve,
 * if there would not be interrupts to input node.
 *
 * This problem had been solved through a dedicated process node which
 * periodically sends interrupt to virtio input node given coalescing
 * or buffering feature were enabled on an interface.
 *
 * But that approach worked with following limitations:
 * 1) Each VPP thread should have (atleast) 1 rx queue of an interface
 * (with buffering enabled). And rxqs and txqs should be placed on the
 * same thread.
 *
 * New design provides solution to above problem(s) without any limitation
 * through (dedicated) pre-input node running on each VPP thread when
 * atleast 1 virtio interface is enabled with coalescing or buffering.
 */
VLIB_REGISTER_NODE (tap_pre_input_node) = {
  .function = tap_pre_input,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "tap-pre-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

void
tap_pre_input_node_enable (vlib_main_t *vm, tap_if_t *tif)
{
  tap_main_t *tm = &tap_main;
  if (tif->packet_coalesce)
    {
      tm->gro_if_count++;
      if (tm->gro_if_count == 1)
	foreach_vlib_main ()
	  vlib_node_set_state (this_vlib_main, tap_pre_input_node.index,
			       VLIB_NODE_STATE_POLLING);
    }
}

void
tap_pre_input_node_disable (vlib_main_t *vm, tap_if_t *tif)
{
  tap_main_t *tm = &tap_main;
  if (tif->packet_coalesce)
    {
      if (tm->gro_if_count > 0)
	tm->gro_if_count--;
      if (tm->gro_if_count == 0)
	foreach_vlib_main ()
	  vlib_node_set_state (this_vlib_main, tap_pre_input_node.index,
			       VLIB_NODE_STATE_DISABLED);
    }
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/gso/gro_func.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <tap/internal.h>
#include <tap/inline.h>

static_always_inline uword
tap_pre_input_inline (vlib_main_t *vm, vnet_virtio_vring_t *txq_vring,
		      vnet_hw_if_tx_queue_t *txq, u8 packet_coalesce,
		      u8 packet_buffering)
{
  if (txq->shared_queue)
    {
      if (clib_spinlock_trylock (&txq_vring->lockp))
	{
	  if (tap_txq_is_scheduled (txq_vring))
	    goto unlock;
	  if (packet_coalesce)
	    vnet_gro_flow_table_schedule_node_on_dispatcher (
	      vm, txq, txq_vring->flow_table);
	  else if (packet_buffering)
	    tap_vring_buffering_schedule_node_on_dispatcher (
	      vm, txq, txq_vring->buffering);
	  tap_txq_set_scheduled (txq_vring);
	unlock:
	  clib_spinlock_unlock (&txq_vring->lockp);
	}
    }
  else
    {
      if (packet_coalesce)
	vnet_gro_flow_table_schedule_node_on_dispatcher (
	  vm, txq, txq_vring->flow_table);
      else if (packet_buffering)
	tap_vring_buffering_schedule_node_on_dispatcher (vm, txq,
							 txq_vring->buffering);
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
      if (tif->packet_coalesce || tif->packet_buffering)
	{
	  vnet_virtio_vring_t *txq_vring;
	  vec_foreach (txq_vring, tif->txq_vrings)
	    {
	      vnet_hw_if_tx_queue_t *txq =
		vnet_hw_if_get_tx_queue (vnm, txq_vring->queue_index);
	      if (clib_bitmap_get (txq->threads, vm->thread_index) == 1)
		tap_pre_input_inline (vm, txq_vring, txq, tif->packet_coalesce,
				      tif->packet_buffering);
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
VLIB_REGISTER_NODE (tap_virtio_pre_input_node) = {
  .function = tap_pre_input,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "tap-virtio-pre-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

void
tap_pre_input_node_enable (vlib_main_t *vm, tap_if_t *tif)
{
  tap_main_t *tm = &tap_main;
  if (tif->packet_coalesce || tif->packet_buffering)
    {
      tm->gro_or_buffering_if_count++;
      if (tm->gro_or_buffering_if_count == 1)
	{
	  foreach_vlib_main ()
	    {
	      vlib_node_set_state (this_vlib_main,
				   tap_virtio_pre_input_node.index,
				   VLIB_NODE_STATE_POLLING);
	    }
	}
    }
}

void
tap_pre_input_node_disable (vlib_main_t *vm, tap_if_t *tif)
{
  tap_main_t *tm = &tap_main;
  if (tif->packet_coalesce || tif->packet_buffering)
    {
      if (tm->gro_or_buffering_if_count > 0)
	tm->gro_or_buffering_if_count--;
      if (tm->gro_or_buffering_if_count == 0)
	{
	  foreach_vlib_main ()
	    {
	      vlib_node_set_state (this_vlib_main,
				   tap_virtio_pre_input_node.index,
				   VLIB_NODE_STATE_DISABLED);
	    }
	}
    }
}

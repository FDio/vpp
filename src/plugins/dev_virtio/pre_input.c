/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <dev_virtio/virtio.h>
#include <dev_virtio/inline.h>

static_always_inline uword
virtio_pre_input_inline (vlib_main_t *vm, vnet_virtio_vring_t *txq_vring,
			 vnet_dev_tx_queue_t *txq)
{
  if (txq->lock_needed && txq_vring->lockp)
    {
      if (clib_spinlock_trylock (&txq_vring->lockp))
	{
	  if (virtio_txq_is_scheduled (txq_vring))
	    goto unlock;
	  virtio_vring_buffering_schedule_node_on_dispatcher (
	    vm, txq, txq_vring->buffering);
	  virtio_txq_set_scheduled (txq_vring);
	unlock:
	  clib_spinlock_unlock (&txq_vring->lockp);
	}
    }
  else
    {
      virtio_vring_buffering_schedule_node_on_dispatcher (
	vm, txq, txq_vring->buffering);
    }
  return 0;
}

static uword
virtio_pre_input (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame)
{
  virtio_main_t *vim = &virtio_main;
  virtio_if_t *vif;

  pool_foreach (vif, vim->interfaces)
    {
      if (vif->packet_buffering)
	{
	  vnet_dev_t *dev = vnet_dev_get_by_index (vif->dev_index);
	  foreach_vnet_dev_port (port, dev)
	    {
	      foreach_vnet_dev_port_tx_queue (txq, port)
		{
		  virtio_txq_t *vtq = vnet_dev_get_tx_queue_data (txq);
		  vnet_virtio_vring_t *txq_vring = &vtq->vring;
		  if (clib_bitmap_get (txq->assigned_threads,
				       vm->thread_index) == 1)
		    virtio_pre_input_inline (vm, txq_vring, txq);
		}
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
VLIB_REGISTER_NODE (virtio_pre_tx_node) = {
  .function = virtio_pre_input,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "virtio-pre-rx",
  .state = VLIB_NODE_STATE_DISABLED,
};

void
virtio_pre_input_node_enable (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_main_t *vim = &virtio_main;

  if (vif->packet_buffering)
    {
      vim->buffering_if_count++;
      if (vim->buffering_if_count == 1)
	{
	  vlib_worker_thread_barrier_sync (vlib_get_main ());
	  foreach_vlib_main ()
	    {
	      vlib_node_set_state (this_vlib_main, virtio_pre_tx_node.index,
				   VLIB_NODE_STATE_POLLING);
	    }
	  vlib_worker_thread_barrier_release (vlib_get_main ());
	}
    }
}

void
virtio_pre_input_node_disable (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_main_t *vim = &virtio_main;

  if (vif->packet_buffering)
    {
      if (vim->buffering_if_count > 0)
	vim->buffering_if_count--;
      if (vim->buffering_if_count == 0)
	{
	  vlib_worker_thread_barrier_sync (vlib_get_main ());
	  foreach_vlib_main ()
	    {
	      vlib_node_set_state (this_vlib_main, virtio_pre_tx_node.index,
				   VLIB_NODE_STATE_DISABLED);
	    }
	  vlib_worker_thread_barrier_release (vlib_get_main ());
	}
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

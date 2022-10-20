/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vnet/gso/gro_func.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/virtio_inline.h>

static_always_inline uword
virtio_pre_input_inline (vlib_main_t *vm, vnet_virtio_vring_t *txq_vring,
			 vnet_hw_if_tx_queue_t *txq, u8 packet_coalesce,
			 u8 packet_buffering)
{
  if (txq->shared_queue)
    {
      if (clib_spinlock_trylock (&txq_vring->lockp))
	{
	  if (virtio_txq_is_scheduled (txq_vring))
	    goto unlock;
	  if (packet_coalesce)
	    vnet_gro_flow_table_schedule_node_on_dispatcher (
	      vm, txq, txq_vring->flow_table);
	  else if (packet_buffering)
	    virtio_vring_buffering_schedule_node_on_dispatcher (
	      vm, txq, txq_vring->buffering);
	  virtio_txq_set_scheduled (txq_vring);
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
  vnet_main_t *vnm = vnet_get_main ();
  virtio_if_t *vif;

  pool_foreach (vif, vim->interfaces)
    {
      if (vif->packet_coalesce || vif->packet_buffering)
	{
	  vnet_virtio_vring_t *txq_vring;
	  vec_foreach (txq_vring, vif->txq_vrings)
	    {
	      vnet_hw_if_tx_queue_t *txq =
		vnet_hw_if_get_tx_queue (vnm, txq_vring->queue_index);
	      if (clib_bitmap_get (txq->threads, vm->thread_index) == 1)
		virtio_pre_input_inline (vm, txq_vring, txq,
					 vif->packet_coalesce,
					 vif->packet_buffering);
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
VLIB_REGISTER_NODE (virtio_pre_input_node) = {
  .function = virtio_pre_input,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "virtio-pre-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

void
virtio_pre_input_node_enable (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_main_t *vim = &virtio_main;
  if (vif->packet_coalesce || vif->packet_buffering)
    {
      vim->gro_or_buffering_if_count++;
      if (vim->gro_or_buffering_if_count == 1)
	{
	  foreach_vlib_main ()
	    {
	      vlib_node_set_state (this_vlib_main, virtio_pre_input_node.index,
				   VLIB_NODE_STATE_POLLING);
	    }
	}
    }
}

void
virtio_pre_input_node_disable (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_main_t *vim = &virtio_main;
  if (vif->packet_coalesce || vif->packet_buffering)
    {
      if (vim->gro_or_buffering_if_count > 0)
	vim->gro_or_buffering_if_count--;
      if (vim->gro_or_buffering_if_count == 0)
	{
	  foreach_vlib_main ()
	    {
	      vlib_node_set_state (this_vlib_main, virtio_pre_input_node.index,
				   VLIB_NODE_STATE_DISABLED);
	    }
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

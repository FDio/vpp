/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

vnet_device_main_t vnet_device_main;

static vnet_interface_tx_queue_runtime_t tx_queue_runtime_template = {
  .configured_queue = VNET_HW_INVALID_QUEUE
};


static uword
device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (device_input_node) = {
  .function = device_input_fn,
  .name = "device-input",
  .runtime_data_bytes = sizeof (vnet_hw_interface_rx_runtime_t),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_next_nodes = VNET_DEVICE_INPUT_N_NEXT_NODES,
  .next_nodes = VNET_DEVICE_INPUT_NEXT_NODES,
};

/* Table defines how much we need to advance current data pointer
   in the buffer if we shortcut to l3 nodes */

const u32 __attribute__((aligned (CLIB_CACHE_LINE_BYTES)))
device_input_next_node_advance[((VNET_DEVICE_INPUT_N_NEXT_NODES /
				CLIB_CACHE_LINE_BYTES) +1) * CLIB_CACHE_LINE_BYTES] =
{
      [VNET_DEVICE_INPUT_NEXT_IP4_INPUT] = sizeof (ethernet_header_t),
      [VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT] = sizeof (ethernet_header_t),
      [VNET_DEVICE_INPUT_NEXT_IP6_INPUT] = sizeof (ethernet_header_t),
      [VNET_DEVICE_INPUT_NEXT_MPLS_INPUT] = sizeof (ethernet_header_t),
};

VNET_FEATURE_ARC_INIT (device_input, static) =
{
  .arc_name  = "device-input",
  .start_nodes = VNET_FEATURES ("device-input"),
  .arc_index_ptr = &feature_main.device_input_feature_arc_index,
};

VNET_FEATURE_INIT (l2_patch, static) = {
  .arc_name = "device-input",
  .node_name = "l2-patch",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (worker_handoff, static) = {
  .arc_name = "device-input",
  .node_name = "worker-handoff",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (span_input, static) = {
  .arc_name = "device-input",
  .node_name = "span-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (p2p_ethernet_node, static) = {
  .arc_name = "device-input",
  .node_name = "p2p-ethernet-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (ethernet_input, static) = {
  .arc_name = "device-input",
  .node_name = "ethernet-input",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

vnet_hw_interface_rx_queue_t *
vnet_hw_interface_get_or_create_rx_queue (vnet_hw_interface_t * hw,
					  u16 queue_id, u8 create)
{
  vnet_hw_interface_rx_queue_t r;
  if (vec_len (hw->rx_queues) > queue_id)
    return &hw->rx_queues[queue_id];

  if (!create)
    return NULL;

  r.rx_mode = VNET_HW_INTERFACE_RX_MODE_DISABLED;
  r.thread_index = ~0;
  r.rss_slot = 0;
  r.current_rx_queue_runtime = NULL;
  vec_validate_init_empty (hw->rx_queues, queue_id, r);
  return &hw->rx_queues[queue_id];
}

/*
 * Recomputes a thread and rx node state
 */
static void
vnet_hw_interface_update_node_state (vlib_main_t * vm,
				     vnet_hw_interface_t * hw,
				     vnet_hw_interface_rx_runtime_t * rt)
{
  vlib_node_state_t new_mode = VLIB_NODE_STATE_DISABLED;
  if (rt->queue_mode_counters[VNET_HW_INTERFACE_RX_MODE_INTERRUPT])
    new_mode = VLIB_NODE_STATE_INTERRUPT;

  if (rt->queue_mode_counters[VNET_HW_INTERFACE_RX_MODE_POLLING])
    new_mode = VLIB_NODE_STATE_POLLING;

  if (rt->enabled_node_state == new_mode)
    return;

  rt->enabled_node_state = new_mode;
  vlib_node_set_state (vm, hw->input_node_index, rt->enabled_node_state);
}

/*
 * Low level function removing a given queue from the thread that is currently
 * assigned to it.
 */
static void
vnet_hw_interface_rx_unschedule (vnet_main_t * vnm,
				 vnet_hw_interface_t * hw,
				 vnet_hw_interface_rx_queue_t * rxq)
{
  DBG_VNET ("rx remove queue %d from %U ",
	    vnet_hw_interface_rx_queue_id (hw, rxq),
	    format_vnet_hw_interface_name, vnm, hw);

  if (rxq == NULL || rxq->current_rx_queue_runtime == NULL)
    {
      DBG_VNET ("queue doesn't exist for now");
      return;
    }

  vlib_main_t *vm = vlib_mains[rxq->thread_index];
  vnet_hw_interface_rx_runtime_t *rt =
    vlib_node_get_runtime_data (vm, hw->input_node_index);
  vnet_hw_interface_rx_queue_runtime_t *q = rxq->current_rx_queue_runtime;

  vec_del1 (rt->queues_per_rss[rxq->rss_slot],
	    q - rt->queues_per_rss[rxq->rss_slot]);
  rxq->current_rx_queue_runtime = NULL;

  /* Update back pointers */
  vec_foreach (q, rt->queues_per_rss[rxq->rss_slot])
  {
    vnet_hw_interface_t *hw2 = vnet_get_hw_interface (vnm, q->hw_if_index);
    hw2->rx_queues[q->queue_id].current_rx_queue_runtime = q;
  }

  /* Update thread state */
  rt->queue_mode_counters[rxq->rx_mode]--;
  vnet_hw_interface_update_node_state (vm, hw, rt);

  return;
}

/*
 * Low level function assigning a queue to a given thread and rss slot.
 * If thread_index is set to ~0, the previously configured thread and rss slot,
 * if any, is used.
 */
static void
vnet_hw_interface_rx_schedule (vnet_main_t * vnm,
			       vnet_hw_interface_t * hw,
			       vnet_hw_interface_rx_queue_t * rxq)
{
  vnet_device_main_t *vdm = &vnet_device_main;

  DBG_VNET ("rx set queue %d from %U",
	    vnet_hw_interface_rx_queue_id (hw, rxq),
	    format_vnet_hw_interface_name, vnm, hw);

  if (rxq->thread_index == ~0)
    {
      /* Assign default thread */
      rxq->thread_index = vdm->next_worker_thread_index++;
      rxq->rss_slot = 0;
      if (vdm->next_worker_thread_index > vdm->last_worker_thread_index)
	vdm->next_worker_thread_index = vdm->first_worker_thread_index;
    }

  DBG_VNET ("rx set queue %d from %U on thread %d and rss %d",
	    vnet_hw_interface_rx_queue_id (hw, rxq),
	    format_vnet_hw_interface_name, vnm, hw,
	    rxq->thread_index, rxq->rss_slot);

  vlib_main_t *vm = vlib_mains[rxq->thread_index];
  vnet_hw_interface_rx_runtime_t *rt =
    vlib_node_get_runtime_data (vm, hw->input_node_index);
  vnet_hw_interface_rx_queue_runtime_t *qp, q = {
    .dev_instance = hw->dev_instance,
    .hw_if_index = hw->hw_if_index,
    .interrupt_pending = 1,
    .queue_id = vnet_hw_interface_rx_queue_id (hw, rxq),
    .mode = rxq->rx_mode,
  };

  DBG_VNET ("rx add queue rt=%p rss_slot=%d array=%p", rt, rxq->rss_slot,
	    rt->queues_per_rss[rxq->rss_slot]);
  vec_add1 (rt->queues_per_rss[rxq->rss_slot], q);
  /* Update back pointers (all since there might have been a resize) */
  vec_foreach (qp, rt->queues_per_rss[rxq->rss_slot])
  {
    vnet_hw_interface_t *hw2 = vnet_get_hw_interface (vnm, qp->hw_if_index);
    hw2->rx_queues[qp->queue_id].current_rx_queue_runtime = qp;
  }

  /* Update node state */
  rt->queue_mode_counters[rxq->rx_mode]++;	/* Count interface modes */
  vnet_hw_interface_update_node_state (vm, hw, rt);
}


int
vnet_hw_interface_set_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				 u16 queue_id, u32 thread_index, u16 rss_slot)
{
  vlib_main_t *vm0 = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_hw_interface_rx_queue_t *rxq =
    vnet_hw_interface_get_or_create_rx_queue (hw, queue_id, 1);

  DBG_VNET ("rx set rx thread for queue %d from %U on thread %d with rss %d",
	    queue_id, format_vnet_hw_interface_name, vnm, hw,
	    thread_index, rss_slot);

  if (!vnet_thread_is_valid (vdm, thread_index))
    return VNET_API_ERROR_INVALID_THREAD_INDEX;

  vnet_hw_interface_rx_runtime_t *rt =
    vlib_node_get_runtime_data (vlib_mains[thread_index],
				hw->input_node_index);

  if (rss_slot > rt->rss_mask)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  /* Nothing to do */
  if (rxq->thread_index == thread_index && rxq->rss_slot == rss_slot)
    return 0;

  if (rxq->current_rx_queue_runtime != NULL)
    {
      vlib_worker_thread_barrier_sync (vm0);
      vnet_hw_interface_rx_unschedule (vnm, hw, rxq);
      rxq->rss_slot = rss_slot;
      rxq->thread_index = thread_index;
      vnet_hw_interface_rx_schedule (vnm, hw, rxq);
      vlib_worker_thread_barrier_release (vm0);
    }
  else
    {
      rxq->rss_slot = rss_slot;
      rxq->thread_index = thread_index;
    }

  return 0;
}

int
vnet_hw_interface_get_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				 u16 queue_id,
				 u32 * thread_index, u16 * rss_slot)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_rx_queue_t *rxq =
    vnet_hw_interface_get_or_create_rx_queue (hw, queue_id, 0);

  if (rxq == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (thread_index != NULL)
    *thread_index = rxq->thread_index;
  if (rss_slot != NULL)
    *rss_slot = rxq->rss_slot;
  return 0;
}

int
vnet_hw_interface_enable_rx_queue (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id, u8 disable)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_rx_queue_t *rxq;
  rxq = vnet_hw_interface_get_or_create_rx_queue (hw, queue_id, !disable);

  if (!rxq || (!disable && (rxq->current_rx_queue_runtime != NULL)) ||
      (disable && (rxq->current_rx_queue_runtime == NULL)))
    return 0;			/* Nothing to do */

  DBG_VNET ("rx %s queue %d from %U", disable ? "disable" : "enable",
	    queue_id, format_vnet_hw_interface_name, vnm, hw);

  /* The very first time the queue is enabled, and if no mode has been
   * assigned yet, we need to use default. */
  if (rxq->rx_mode == VNET_HW_INTERFACE_RX_MODE_DISABLED)
    {
      vnet_device_class_t *dev_class =
	vnet_get_device_class (vnm, hw->dev_class_index);
      clib_error_t *err;

      if (dev_class->rx_mode_change_function)
	if ((err =
	     dev_class->rx_mode_change_function (vnm, hw_if_index, queue_id,
						 hw->default_rx_mode)) !=
	    NULL)
	  return err->code == 0 ? VNET_API_ERROR_UNSPECIFIED : err->code;

      rxq->rx_mode = hw->default_rx_mode;
    }

  vlib_worker_thread_barrier_sync (vm);
  if (rxq->current_rx_queue_runtime)
    vnet_hw_interface_rx_unschedule (vnm, hw, rxq);
  else
    vnet_hw_interface_rx_schedule (vnm, hw, rxq);
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

int
vnet_hw_interface_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			       u16 queue_id, vnet_hw_interface_rx_mode mode)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_rx_queue_t *rxq;
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hw->dev_class_index);
  clib_error_t *err;

  /* Used to set the default and all existing queues mode */
  if (queue_id == VNET_HW_INVALID_QUEUE)
    {
      hw->default_rx_mode = mode;
      vnet_hw_interface_rx_queue_t *q;
      vec_foreach (q, hw->rx_queues)
      {
	if (q->rx_mode == VNET_HW_INTERFACE_RX_MODE_DISABLED)
	  continue;

	int rv = vnet_hw_interface_set_rx_mode (vnm, hw_if_index,
						vnet_hw_interface_rx_queue_id
						(hw, q), mode);
	if (rv)
	  return rv;
      }
      return 0;
    }

  if (mode == VNET_HW_INTERFACE_RX_MODE_DEFAULT)
    mode = hw->default_rx_mode;

  if (mode >= VNET_HW_INTERFACE_RX_N_API_MODES)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  if (mode != VNET_HW_INTERFACE_RX_MODE_POLLING &&
      (hw->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE) == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  rxq = vnet_hw_interface_get_or_create_rx_queue (hw, queue_id, 1);
  if (rxq->rx_mode == mode)
    return 0;

  DBG_VNET ("set rx mode for interface %U queue %d to %U",
	    format_vnet_hw_interface_name, vnm, hw, queue_id,
	    format_vnet_hw_interface_rx_mode, mode);

  if (rxq->current_rx_queue_runtime)
    {
      /* The queue is used by the driver, so we notify the change */
      if (dev_class->rx_mode_change_function)
	if ((err =
	     dev_class->rx_mode_change_function (vnm, hw_if_index, queue_id,
						 mode)) != NULL)
	  return err->code == 0 ? VNET_API_ERROR_UNSPECIFIED : err->code;

      /* Change runtime */
      vlib_worker_thread_barrier_sync (vm);
      vnet_hw_interface_rx_unschedule (vnm, hw, rxq);
      rxq->rx_mode = mode;
      vnet_hw_interface_rx_schedule (vnm, hw, rxq);
      vlib_worker_thread_barrier_release (vm);
    }
  else
    rxq->rx_mode = mode;

  return 0;
}

int
vnet_hw_interface_get_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			       u16 queue_id, vnet_hw_interface_rx_mode * mode)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_rx_queue_t *rxq =
    vnet_hw_interface_get_or_create_rx_queue (hw, queue_id, 0);

  if (!rxq)
    {
      *mode = VNET_HW_INTERFACE_RX_MODE_DISABLED;
      return 0;
    }
  *mode = rxq->rx_mode;
  return 0;
}

int
vnet_hw_interface_set_rx_queue_rss_mask (vnet_main_t * vnm, u32 hw_if_index,
					 u32 thread_index, u16 rss_mask)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  if (!vnet_thread_is_valid (vdm, thread_index))
    return VNET_API_ERROR_INVALID_THREAD_INDEX;

  if (rss_mask & (rss_mask + 1))	/* Must be a power of 2 minus 1 */
    return VNET_API_ERROR_INVALID_ARGUMENT;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vlib_main_t *vm = vlib_mains[thread_index];
  vlib_main_t *vm0 = vlib_get_main ();
  vnet_hw_interface_rx_runtime_t *rt =
    vlib_node_get_runtime_data (vm, hw->input_node_index);


  vlib_worker_thread_barrier_sync (vm0);
  if (rss_mask < rt->rss_mask)
    {
      /* Reschedule queues with too high rss slots */
      vnet_hw_interface_rx_queue_t *rxq;
      vec_foreach (rxq, hw->rx_queues)
      {
	if (rxq->rss_slot > rss_mask && rxq->current_rx_queue_runtime != NULL
	    && rxq->thread_index == thread_index)
	  {
	    vnet_hw_interface_set_rx_thread (vnm, hw_if_index,
					     rxq - hw->rx_queues,
					     rxq->thread_index,
					     rxq->rss_slot & rss_mask);
	  }
      }
      /* Reduce the vector size */
      _vec_len (rt->queues_per_rss) = rss_mask + 1;
    }
  else
    {
      vec_validate (rt->queues_per_rss, rss_mask);
    }

  /* Now everything should be fine */
  rt->rss_mask = rss_mask;

  vlib_worker_thread_barrier_release (vm0);
  return 0;
}

static u16
vnet_hw_interface_get_tx_queue_index (vnet_hw_interface_t * hw, u32 queue_id)
{
  vnet_hw_interface_tx_queue_t *q;
  vec_foreach (q, hw->tx_queues)
  {
    if (q->queue_id == queue_id)
      return q - hw->tx_queues;
  }
  return VNET_HW_INVALID_QUEUE;
}

int
vnet_hw_interface_update_tx_queues (vnet_main_t * vnm,
				    vnet_hw_interface_t * hw)
{
  u32 thread_index = 0;
  u16 tx_queue_index = 0;
  vnet_hw_interface_tx_queue_t *tx_queue;
  vnet_interface_tx_queue_runtime_t *queue;
  vlib_thread_main_t *vdm = vlib_get_thread_main ();

  DBG_VNET ("Updating TX queues for interface %U",
	    format_vnet_hw_interface_name, vnm, hw);

  /* Let's first reset thread counting for all tx queue. */
  vec_foreach (tx_queue, hw->tx_queues)
  {
    tx_queue->thread_index = 0;
  }

  u8 second_pass = 0;

  do
    {
      for (thread_index = 0; thread_index < vdm->n_vlib_mains; thread_index++)
	{
	  vlib_main_t *vm = vlib_mains[thread_index];
	  vnet_interface_tx_runtime_t *rt =
	    vlib_node_get_runtime_data (vm, hw->tx_node_index);

	  /* Make sure there is enough space for all rss */
	  vec_validate_init_empty (rt->tx_queue_per_rss, rt->rss_mask,
				   tx_queue_runtime_template);

	  vec_foreach (queue, rt->tx_queue_per_rss)
	  {
	    vnet_interface_tx_queue_runtime_t *q2;

	    /* Already configured during first pass */
	    if (second_pass && queue->tx_queue_index != VNET_HW_INVALID_QUEUE)
	      continue;

	    /* Init queue to unknown */
	    queue->tx_queue_index = VNET_HW_INVALID_QUEUE;
	    queue->queue_id = VNET_HW_INVALID_QUEUE;

	    if (queue - rt->tx_queue_per_rss > rt->rss_mask)
	      continue;

	    /* Try to use configured queues during first pass */
	    if (queue->configured_queue != VNET_HW_INVALID_QUEUE &&
		!second_pass)
	      queue->tx_queue_index =
		vnet_hw_interface_get_tx_queue_index (hw,
						      queue->configured_queue);

	    /* If we still didn't find and this is first pass, we'll be back
	     * later. */
	    if (queue->tx_queue_index == VNET_HW_INVALID_QUEUE &&
		!second_pass)
	      continue;

	    /* Prefer one which was already selected for this thread and is
	     * not shared */
	    if (queue->tx_queue_index == VNET_HW_INVALID_QUEUE)
	      {
		vec_foreach (q2, rt->tx_queue_per_rss)
		{
		  if (q2->tx_queue_index != VNET_HW_INVALID_QUEUE &&
		      hw->tx_queues[q2->tx_queue_index].thread_index ==
		      thread_index + 1)
		    {
		      queue->tx_queue_index = q2->tx_queue_index;
		      break;
		    }
		}
	      }

	    /* If we failed, select a tx queue which is not used for now. */
	    if (queue->tx_queue_index == VNET_HW_INVALID_QUEUE)
	      {
		vec_foreach (tx_queue, hw->tx_queues)
		{
		  if (tx_queue->thread_index == 0)
		    {
		      queue->tx_queue_index = tx_queue - hw->tx_queues;
		      break;
		    }
		}
	      }

	    /* If no tx queue is available, just iterate */
	    if (queue->tx_queue_index == VNET_HW_INVALID_QUEUE &&
		vec_len (hw->tx_queues))
	      {
		queue->tx_queue_index = tx_queue_index;
		tx_queue_index++;
		if (tx_queue_index == vec_len (hw->tx_queues))
		  tx_queue_index = 0;
	      }

	    /* If we found a queue, just count. */
	    if (queue->tx_queue_index != VNET_HW_INVALID_QUEUE)
	      {
		queue->queue_id =
		  hw->tx_queues[queue->tx_queue_index].queue_id;

		/* Count whether this thread is the first thread to use the
		 * queue, or the second. */
		if (hw->tx_queues[queue->tx_queue_index].thread_index == 0 ||
		    hw->tx_queues[queue->tx_queue_index].thread_index ==
		    (thread_index + 1))
		  hw->tx_queues[queue->tx_queue_index].thread_index =
		    thread_index + 1;
		else
		  hw->tx_queues[queue->tx_queue_index].thread_index = ~0;
	      }
	  }
	}
    }
  while (!(second_pass++));

  /* Second round to setup the locks */
  for (thread_index = 0;
       thread_index < vlib_get_thread_main ()->n_vlib_mains; thread_index++)
    {
      vlib_main_t *vm = vlib_mains[thread_index];
      vnet_interface_tx_runtime_t *rt =
	vlib_node_get_runtime_data (vm, hw->tx_node_index);
      vec_foreach (queue, rt->tx_queue_per_rss)
      {
	queue->use_lock = 0;
	if (queue->tx_queue_index != VNET_HW_INVALID_QUEUE &&
	    hw->tx_queues[queue->tx_queue_index].thread_index == ~0)
	  {
	    queue->use_lock = 1;
	  }
      }
    }

  return 0;
}

int
vnet_hw_interface_enable_tx_queue (vnet_main_t * vnm,
				   u32 hw_if_index, u16 queue_id, u8 disable)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_tx_queue_t *queue;
  vec_foreach (queue, hw->tx_queues)
  {
    if (queue->queue_id == queue_id)
      {
	if (!disable)		/* Queue is already enabled */
	  return 0;

	DBG_VNET ("disable tx queue %d from %U", queue_id,
		  format_vnet_hw_interface_name, vnm, hw);

	vec_del1 (hw->tx_queues, queue - hw->tx_queues);
	goto done;
      }
  }
  if (disable)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  DBG_VNET ("enable tx queue %d from %U", queue_id,
	    format_vnet_hw_interface_name, vnm, hw);

  vnet_hw_interface_tx_queue_t q = {
    .queue_id = queue_id,
    .thread_index = ~0,
  };
  vec_add1 (hw->tx_queues, q);
done:
  vlib_worker_thread_barrier_sync (vm);
  vnet_hw_interface_update_tx_queues (vnm, hw);
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

int
vnet_hw_interface_set_tx_rss_mask (vnet_main_t * vnm, u32 hw_if_index,
				   u32 thread_index, u16 rss_mask)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vlib_main_t *vm = vlib_mains[thread_index];
  vlib_main_t *vm0 = vlib_get_main ();
  vnet_interface_tx_runtime_t *rt =
    vlib_node_get_runtime_data (vm, hw->tx_node_index);

  DBG_VNET ("Set TX rss for iface %U and thread %d to %d",
	    format_vnet_hw_interface_name, vnm, hw, thread_index,
	    rss_mask + 1);
  DBG_VNET ("  rt=%p rt->tx_queue_per_rss=%p", rt, rt->tx_queue_per_rss);

  if ((rss_mask + 1) & rss_mask)
    return VNET_API_ERROR_INVALID_VALUE;

  /* From that point, we are modifying the node runtime */
  vlib_worker_thread_barrier_sync (vm0);
  rt->rss_mask = rss_mask;
  vec_validate_init_empty (rt->tx_queue_per_rss, rss_mask,
			   tx_queue_runtime_template);
  vnet_hw_interface_update_tx_queues (vnm, hw);
  vlib_worker_thread_barrier_release (vm0);
  return 0;
}

int
vnet_hw_interface_set_tx_thread (vnet_main_t * vnm, u32 hw_if_index,
				 u32 thread_index, u16 rss_slot, u16 queue_id)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vlib_main_t *vm = vlib_mains[thread_index];
  vlib_main_t *vm0 = vlib_get_main ();
  vnet_interface_tx_runtime_t *rt =
    vlib_node_get_runtime_data (vm, hw->tx_node_index);
  DBG_VNET ("Set TX queue for thread %d and rss-slot %d on queue %d",
	    thread_index, rss_slot, queue_id);
  DBG_VNET ("rt=%p rt->tx_queue_per_rss=%p", rt, rt->tx_queue_per_rss);

  if (vec_len (rt->tx_queue_per_rss) > rss_slot &&
      (rt->tx_queue_per_rss[rss_slot].configured_queue == queue_id))
    return 0;

  vlib_worker_thread_barrier_sync (vm0);
  vec_validate_init_empty (rt->tx_queue_per_rss, rss_slot,
			   tx_queue_runtime_template);
  rt->tx_queue_per_rss[rss_slot].configured_queue = queue_id;
  vnet_hw_interface_update_tx_queues (vnm, hw);
  vlib_worker_thread_barrier_release (vm0);
  return 0;
}

static clib_error_t *
vnet_device_init (vlib_main_t * vm)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  uword *p;

  vec_validate_aligned (vdm->workers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;
  if (tr && tr->count > 0)
    {
      vdm->first_worker_thread_index = tr->first_index;
      vdm->next_worker_thread_index = tr->first_index;
      vdm->last_worker_thread_index = tr->first_index + tr->count - 1;
    }
  return 0;
}

VLIB_INIT_FUNCTION (vnet_device_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

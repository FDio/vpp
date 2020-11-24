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
  .runtime_data_bytes = sizeof (vnet_device_input_runtime_t),
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

const u32 __attribute__((aligned (CLIB_CACHE_LINE_BYTES)))
device_input_next_node_flags[((VNET_DEVICE_INPUT_N_NEXT_NODES /
				CLIB_CACHE_LINE_BYTES) +1) * CLIB_CACHE_LINE_BYTES] =
{
      [VNET_DEVICE_INPUT_NEXT_IP4_INPUT] = VNET_BUFFER_F_L3_HDR_OFFSET_VALID,
      [VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT] = VNET_BUFFER_F_L3_HDR_OFFSET_VALID,
      [VNET_DEVICE_INPUT_NEXT_IP6_INPUT] = VNET_BUFFER_F_L3_HDR_OFFSET_VALID,
      [VNET_DEVICE_INPUT_NEXT_MPLS_INPUT] = VNET_BUFFER_F_L3_HDR_OFFSET_VALID,
};

VNET_FEATURE_ARC_INIT (device_input, static) =
{
  .arc_name  = "device-input",
  .start_nodes = VNET_FEATURES ("device-input"),
  .last_in_arc = "ethernet-input",
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

static int
vnet_device_queue_sort (void *a1, void *a2)
{
  vnet_device_and_queue_t *dq1 = a1;
  vnet_device_and_queue_t *dq2 = a2;

  if (dq1->dev_instance > dq2->dev_instance)
    return 1;
  else if (dq1->dev_instance < dq2->dev_instance)
    return -1;
  else if (dq1->queue_id > dq2->queue_id)
    return 1;
  else if (dq1->queue_id < dq2->queue_id)
    return -1;
  else
    return 0;
}

static void
vnet_device_queue_update (vnet_main_t * vnm, vnet_device_input_runtime_t * rt)
{
  vnet_device_and_queue_t *dq;
  vnet_hw_interface_t *hw;

  vec_sort_with_function (rt->devices_and_queues, vnet_device_queue_sort);

  vec_foreach (dq, rt->devices_and_queues)
  {
    hw = vnet_get_hw_interface (vnm, dq->hw_if_index);
    vec_validate (hw->dq_runtime_index_by_queue, dq->queue_id);
    hw->dq_runtime_index_by_queue[dq->queue_id] = dq - rt->devices_and_queues;
  }
}

void
vnet_hw_interface_assign_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				    u16 queue_id, uword thread_index)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  vlib_main_t *vm, *vm0;
  vnet_device_input_runtime_t *rt;
  vnet_device_and_queue_t *dq;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);

  ASSERT (hw->input_node_index > 0);

  if (vdm->first_worker_thread_index == 0)
    thread_index = 0;

  if (thread_index != 0 &&
      (thread_index < vdm->first_worker_thread_index ||
       thread_index > vdm->last_worker_thread_index))
    {
      thread_index = vdm->next_worker_thread_index++;
      if (vdm->next_worker_thread_index > vdm->last_worker_thread_index)
	vdm->next_worker_thread_index = vdm->first_worker_thread_index;
    }

  vm = vlib_mains[thread_index];
  vm0 = vlib_get_main ();

  vlib_worker_thread_barrier_sync (vm0);

  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);

  vec_add2 (rt->devices_and_queues, dq, 1);
  dq->hw_if_index = hw_if_index;
  dq->dev_instance = hw->dev_instance;
  dq->queue_id = queue_id;
  dq->mode = VNET_HW_IF_RX_MODE_POLLING;
  rt->enabled_node_state = VLIB_NODE_STATE_POLLING;

  vnet_device_queue_update (vnm, rt);
  vec_validate (hw->input_node_thread_index_by_queue, queue_id);
  vec_validate (hw->rx_mode_by_queue, queue_id);
  hw->input_node_thread_index_by_queue[queue_id] = thread_index;
  hw->rx_mode_by_queue[queue_id] = VNET_HW_IF_RX_MODE_POLLING;

  vlib_worker_thread_barrier_release (vm0);

  vlib_node_set_state (vm, hw->input_node_index, rt->enabled_node_state);
}

int
vnet_hw_interface_unassign_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				      u16 queue_id)
{
  vlib_main_t *vm, *vm0;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_input_runtime_t *rt;
  vnet_device_and_queue_t *dq;
  uword old_thread_index;
  vnet_hw_if_rx_mode mode;

  if (hw->input_node_thread_index_by_queue == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  if (vec_len (hw->input_node_thread_index_by_queue) < queue_id + 1)
    return VNET_API_ERROR_INVALID_INTERFACE;

  old_thread_index = hw->input_node_thread_index_by_queue[queue_id];

  vm = vlib_mains[old_thread_index];

  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);

  vec_foreach (dq, rt->devices_and_queues)
    if (dq->hw_if_index == hw_if_index && dq->queue_id == queue_id)
    {
      mode = dq->mode;
      goto delete;
    }

  return VNET_API_ERROR_INVALID_INTERFACE;

delete:

  vm0 = vlib_get_main ();
  vlib_worker_thread_barrier_sync (vm0);
  vec_del1 (rt->devices_and_queues, dq - rt->devices_and_queues);
  vnet_device_queue_update (vnm, rt);
  hw->rx_mode_by_queue[queue_id] = VNET_HW_IF_RX_MODE_UNKNOWN;
  vlib_worker_thread_barrier_release (vm0);

  if (vec_len (rt->devices_and_queues) == 0)
    vlib_node_set_state (vm, hw->input_node_index, VLIB_NODE_STATE_DISABLED);
  else if (mode == VNET_HW_IF_RX_MODE_POLLING)
    {
      /*
       * if the deleted interface is polling, we may need to set the node state
       * to interrupt if there is no more polling interface for this device's
       * corresponding thread. This is because mixed interfaces
       * (polling and interrupt), assigned to the same thread, set the
       * thread to polling prior to the deletion.
       */
      vec_foreach (dq, rt->devices_and_queues)
      {
	if (dq->mode == VNET_HW_IF_RX_MODE_POLLING)
	  return 0;
      }
      rt->enabled_node_state = VLIB_NODE_STATE_INTERRUPT;
      vlib_node_set_state (vm, hw->input_node_index, rt->enabled_node_state);
    }

  return 0;
}


int
vnet_hw_interface_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			       u16 queue_id, vnet_hw_if_rx_mode mode)
{
  vlib_main_t *vm;
  uword thread_index;
  vnet_device_and_queue_t *dq;
  vlib_node_state_t enabled_node_state;
  ASSERT (mode < VNET_HW_IF_NUM_RX_MODES);
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_input_runtime_t *rt;
  int is_polling = 0;

  if (mode == VNET_HW_IF_RX_MODE_DEFAULT)
    mode = hw->default_rx_mode;

  if (hw->input_node_thread_index_by_queue == 0 || hw->rx_mode_by_queue == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  if (hw->rx_mode_by_queue[queue_id] == mode)
    return 0;

  if (mode != VNET_HW_IF_RX_MODE_POLLING &&
      (hw->caps & VNET_HW_INTERFACE_CAP_SUPPORTS_INT_MODE) == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  if ((vec_len (hw->input_node_thread_index_by_queue) < queue_id + 1) ||
      (vec_len (hw->rx_mode_by_queue) < queue_id + 1))
    return VNET_API_ERROR_INVALID_QUEUE;

  hw->rx_mode_by_queue[queue_id] = mode;
  thread_index = hw->input_node_thread_index_by_queue[queue_id];
  vm = vlib_mains[thread_index];

  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);

  vec_foreach (dq, rt->devices_and_queues)
  {
    if (dq->hw_if_index == hw_if_index && dq->queue_id == queue_id)
      dq->mode = mode;
    if (dq->mode == VNET_HW_IF_RX_MODE_POLLING)
      is_polling = 1;
  }

  if (is_polling)
    enabled_node_state = VLIB_NODE_STATE_POLLING;
  else
    enabled_node_state = VLIB_NODE_STATE_INTERRUPT;

  if (rt->enabled_node_state != enabled_node_state)
    {
      rt->enabled_node_state = enabled_node_state;
      if (vlib_node_get_state (vm, hw->input_node_index) !=
	  VLIB_NODE_STATE_DISABLED)
	vlib_node_set_state (vm, hw->input_node_index, enabled_node_state);
    }

  return 0;
}

int
vnet_hw_interface_get_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			       u16 queue_id, vnet_hw_if_rx_mode * mode)
{
  vlib_main_t *vm;
  uword thread_index;
  vnet_device_and_queue_t *dq;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_input_runtime_t *rt;

  if (hw->input_node_thread_index_by_queue == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  if ((vec_len (hw->input_node_thread_index_by_queue) < queue_id + 1) ||
      (vec_len (hw->rx_mode_by_queue) < queue_id + 1))
    return VNET_API_ERROR_INVALID_QUEUE;

  thread_index = hw->input_node_thread_index_by_queue[queue_id];
  vm = vlib_mains[thread_index];

  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);

  vec_foreach (dq, rt->devices_and_queues)
    if (dq->hw_if_index == hw_if_index && dq->queue_id == queue_id)
    {
      *mode = dq->mode;
      return 0;
    }

  return VNET_API_ERROR_INVALID_INTERFACE;
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

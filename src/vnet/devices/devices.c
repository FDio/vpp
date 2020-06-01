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
#include <vlib/unix/unix.h>

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

static u32
next_thread_index (vnet_main_t * vnm, u32 thread_index)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  if (vdm->first_worker_thread_index == 0)
    return 0;

  if (thread_index != 0 &&
      (thread_index < vdm->first_worker_thread_index ||
       thread_index > vdm->last_worker_thread_index))
    {
      thread_index = vdm->next_worker_thread_index++;
      if (vdm->next_worker_thread_index > vdm->last_worker_thread_index)
	vdm->next_worker_thread_index = vdm->first_worker_thread_index;
    }

  return thread_index;
}

static int
device_queue_sort (void *a1, void *a2)
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
update_device_and_queue_runtime_data (vnet_main_t * vnm, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  vnet_hw_if_rx_queue_t *rxq;
  vnet_device_and_queue_t **list = 0, *dq;
  vnet_device_input_runtime_t *rt;

  vec_validate (list, vec_len (vlib_mains) - 1);

  /* *INDENT-OFF* */
  pool_foreach (rxq, im->hw_if_rx_queues, ({
    hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
    if (hi->input_node_index == node_index)
      {
        vnet_hw_interface_t *hw;
	vec_add2 (list[rxq->thread_index], dq, 1);
	hw = vnet_get_hw_interface (vnm, rxq->hw_if_index);
	dq->hw_if_index = rxq->hw_if_index;
	dq->dev_instance = hw->dev_instance;
	dq->queue_id = rxq->queue_id;
	dq->mode = rxq->mode;
      }
  }));
  /* *INDENT-ON* */

  for (int i = 0; i < vec_len (list); i++)
    if (list[i])
      vec_sort_with_function (list[i], device_queue_sort);


  vlib_worker_thread_barrier_sync (vm);

  /* *INDENT-OFF* */
  foreach_vlib_main(({
    rt = vlib_node_get_runtime_data (this_vlib_main, node_index);
    vec_free (rt->devices_and_queues);
    rt->devices_and_queues = list[this_vlib_main->thread_index];
    rt->enabled_node_state = VLIB_NODE_STATE_POLLING;
  }));
  /* *INDENT-ON* */

  vlib_worker_thread_barrier_release (vm);

  vec_free (list);
}

void
vnet_hw_if_update_runtime_data (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  update_device_and_queue_runtime_data (vnm, hw->input_node_index);
}

u32
vnet_hw_if_register_rx_queue (vnet_main_t * vnm, u32 hw_if_index,
			      u32 queue_id, u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_if_rx_queue_t *rxq;
  uword *p = hash_get (hw->rx_queue_index_by_rx_queue_id, queue_id);
  u32 queue_index;

  if (p)
    clib_panic ("Trying to register already registered queue id (%u) in the "
		"interface %v\n", queue_id, hw->name);

  thread_index = next_thread_index (vnm, thread_index);

  pool_get_zero (im->hw_if_rx_queues, rxq);
  queue_index = rxq - im->hw_if_rx_queues;
  vec_add1 (hw->rx_queue_indices, queue_index);
  hash_set (hw->rx_queue_index_by_rx_queue_id, queue_id, queue_index);
  rxq->hw_if_index = hw_if_index;
  rxq->queue_id = queue_id;
  rxq->thread_index = thread_index;
  rxq->mode = VNET_HW_IF_RX_MODE_POLLING;
  update_device_and_queue_runtime_data (vnm, hw->input_node_index);
  return queue_index;
}


void
vnet_hw_if_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			vnet_hw_if_rx_mode mode)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq;
  int update_needed = 0;

  ASSERT (vec_len (hw->rx_queue_indices) > 0);

  hw->default_rx_mode = mode;

  for (int i = 0; i < vec_len (hw->rx_queue_indices); i++)
    {
      rxq = pool_elt_at_index (im->hw_if_rx_queues, hw->rx_queue_indices[i]);
      if (rxq->mode != mode)
	{
	  rxq->mode = mode;
	  update_needed = 1;
	}
    }

  if (update_needed)
    vnet_hw_if_update_runtime_data (vnm, hw_if_index);
}

int
vnet_hw_interface_get_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			       u16 queue_id, vnet_hw_if_rx_mode * mode)
{
  vnet_hw_if_rx_queue_t *rxq;

  rxq = vnet_hw_interface_get_rx_queue (vnm, hw_if_index, queue_id);

  if (rxq == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  mode[0] = rxq->mode;
  return 0;
}

u32
vnet_hw_if_get_rx_queue_index_by_queue_id (vnet_main_t * vnm, u32 hw_if_index,
					   u32 queue_id)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  uword *p = hash_get (hw->rx_queue_index_by_rx_queue_id, queue_id);
  return p ? p[0] : ~0;
}

u32
vnet_hw_if_get_rx_queue_numa_node (vnet_main_t * vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq = pool_elt_at_index (im->hw_if_rx_queues,
						  queue_index);
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, rxq->hw_if_index);
  return hw->numa_node;
}

u32
vnet_hw_if_get_rx_queue_thread_index (vnet_main_t * vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq = pool_elt_at_index (im->hw_if_rx_queues,
						  queue_index);
  return rxq->thread_index;
}

void
vnet_hw_if_set_rx_queue_file_index (vnet_main_t * vnm, u32 queue_index,
				    u32 file_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq = pool_elt_at_index (im->hw_if_rx_queues,
						  queue_index);

  rxq->file_index = file_index;
  clib_file_set_polling_thread (&file_main, file_index, rxq->thread_index);
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

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
vnet_device_input_assign_thread (vnet_main_t * vnm, u32 hw_if_index,
				 u16 queue_id, uword thread_index)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  vlib_main_t *vm;
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
  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);

  vec_add2 (rt->devices_and_queues, dq, 1);
  dq->hw_if_index = hw_if_index;
  dq->dev_instance = hw->dev_instance;
  dq->queue_id = queue_id;

  vnet_device_queue_update (vnm, rt);
  vec_validate (hw->input_node_thread_index_by_queue, queue_id);
  hw->input_node_thread_index_by_queue[queue_id] = thread_index;
  vlib_node_set_state (vm, hw->input_node_index, rt->enabled_node_state);
}

int
vnet_device_input_unassign_thread (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id, uword thread_index)
{
  vlib_main_t *vm;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_input_runtime_t *rt;
  vnet_device_and_queue_t *dq;
  uword old_thread_index;

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
      vec_del1 (rt->devices_and_queues, dq - rt->devices_and_queues);
      goto deleted;
    }

  return VNET_API_ERROR_INVALID_INTERFACE;

deleted:

  vnet_device_queue_update (vnm, rt);

  if (vec_len (rt->devices_and_queues) == 0)
    vlib_node_set_state (vm, hw->input_node_index, VLIB_NODE_STATE_DISABLED);

  return 0;
}


int
vnet_device_input_set_mode (vnet_main_t * vnm, u32 hw_if_index, u16 queue_id,
			    vnet_device_input_mode_t mode)
{
  vlib_main_t *vm;
  uword thread_index;
  vnet_device_and_queue_t *dq;
  vlib_node_state_t enabled_node_state;
  ASSERT (mode < VNET_DEVICE_INPUT_N_MODES);
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_input_runtime_t *rt;
  int is_polling = 0;

  if (hw->input_node_thread_index_by_queue == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  thread_index = hw->input_node_thread_index_by_queue[queue_id];
  vm = vlib_mains[thread_index];

  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);

  vec_foreach (dq, rt->devices_and_queues)
  {
    if (dq->hw_if_index == hw_if_index && dq->queue_id == queue_id)
      dq->mode = mode;
    if (dq->mode == VNET_DEVICE_INPUT_MODE_POLLING)
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
vnet_device_input_get_mode (vnet_main_t * vnm, u32 hw_if_index, u16 queue_id,
			    vnet_device_input_mode_t * mode)
{
  vlib_main_t *vm;
  uword thread_index;
  vnet_device_and_queue_t *dq;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_input_runtime_t *rt;

  if (hw->input_node_thread_index_by_queue == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

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
show_device_placement_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  u8 *s = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_device_input_runtime_t *rt;
  vnet_device_and_queue_t *dq;
  vlib_node_t *pn = vlib_get_node_by_name (vm, (u8 *) "device-input");
  uword si;
  int index = 0;

  /* *INDENT-OFF* */
  foreach_vlib_main (({
    clib_bitmap_foreach (si, pn->sibling_bitmap,
      ({
        rt = vlib_node_get_runtime_data (this_vlib_main, si);

        if (vec_len (rt->devices_and_queues))
          s = format (s, "  node %U:\n", format_vlib_node_name, vm, si);

        vec_foreach (dq, rt->devices_and_queues)
	  {
	    s = format (s, "    %U queue %u (%s)\n",
			format_vnet_sw_if_index_name, vnm, dq->hw_if_index,
			dq->queue_id,
			dq->mode == VNET_DEVICE_INPUT_MODE_POLLING ?
			"polling" : "interrupt");
	  }
      }));
    if (vec_len (s) > 0)
      {
        vlib_cli_output(vm, "Thread %u (%v):\n%v", index,
			vlib_worker_threads[index].name, s);
        vec_reset_length (s);
      }
    index++;
  }));
  /* *INDENT-ON* */

  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_delete_command, static) = {
  .path = "show interface placement",
  .short_help = "show interface placement",
  .function = show_device_placement_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_device_placement (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_device_input_mode_t mode;
  u32 hw_if_index = (u32) ~ 0;
  u32 queue_id = (u32) 0;
  u32 thread_index = (u32) ~ 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (line_input, "queue %d", &queue_id))
	;
      else if (unformat (line_input, "main", &thread_index))
	thread_index = 0;
      else if (unformat (line_input, "worker %d", &thread_index))
	thread_index += vdm->first_worker_thread_index;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  if (thread_index > vdm->last_worker_thread_index)
    return clib_error_return (0,
			      "please specify valid worker thread or main");

  rv = vnet_device_input_get_mode (vnm, hw_if_index, queue_id, &mode);

  if (rv)
    return clib_error_return (0, "not found");

  rv = vnet_device_input_unassign_thread (vnm, hw_if_index, queue_id,
					  thread_index);

  if (rv)
    return clib_error_return (0, "not found");

  vnet_device_input_assign_thread (vnm, hw_if_index, queue_id, thread_index);
  vnet_device_input_set_mode (vnm, hw_if_index, queue_id, mode);

  return 0;
}

/*?
 * This command is used to assign a given interface, and optionally a
 * given queue, to a different thread. If the '<em>queue</em>' is not provided,
 * it defaults to 0.
 *
 * @cliexpar
 * Example of how to display the interface placement:
 * @cliexstart{show interface placement}
 * Thread 1 (vpp_wk_0):
 *   GigabitEthernet0/8/0 queue 0
 *   GigabitEthernet0/9/0 queue 0
 * Thread 2 (vpp_wk_1):
 *   GigabitEthernet0/8/0 queue 1
 *   GigabitEthernet0/9/0 queue 1
 * @cliexend
 * Example of how to assign a interface and queue to a thread:
 * @cliexcmd{set interface placement GigabitEthernet0/8/0 queue 1 thread 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_placement,static) = {
    .path = "set interface placement",
    .short_help = "set interface placement <interface> [queue <n>] [thread <n> | main]",
    .function = set_device_placement,
};
/* *INDENT-ON* */

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

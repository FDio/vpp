/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

static clib_error_t *
test_interface_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_hw_interface_flags_t flags;
  vnet_main_t *vnm;
  u32 sw_if_index;

  flags = VNET_HW_INTERFACE_FLAG_NONE;
  sw_if_index = ~0;
  vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "up"))
	flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
      else if (unformat (input, "down"))
	;
      else
	break;
    }

  if (~0 != sw_if_index)
    {
      vnet_sw_interface_t *sw;

      sw = vnet_get_sw_interface (vnm, sw_if_index);

      vnet_hw_interface_set_flags (vnm, sw->hw_if_index, flags);
    }
  else
    {
      return clib_error_return (0, "unknown interface `%U'",
				format_unformat_error, input);
    }

  return (NULL);
}

VLIB_CLI_COMMAND (test_interface_command, static) = {
  .path = "test interface link-state",
  .short_help = "test interface link-state <interface> [up] [down]",
  .function = test_interface_command_fn,
};

static clib_error_t *
test_interface_node_recycle_check (vlib_main_t *vm, vnet_hw_interface_t *hw, u32 *n_threads)
{
  vnet_interface_output_runtime_t *rt;
  vlib_node_runtime_t *nrt;
  u32 nodes[2] = { hw->output_node_index, hw->tx_node_index };

  foreach_vlib_main ()
    {
      for (int i = 0; i < 2; i++)
	{
	  if (nodes[i] >= vec_len (this_vlib_main->node_main.nodes))
	    return clib_error_return (0, "thread %u: no node %u", this_vlib_main->thread_index,
				      nodes[i]);
	  nrt = vlib_node_get_runtime (this_vlib_main, nodes[i]);
	  rt = (vnet_interface_output_runtime_t *) nrt->runtime_data;
	  if (rt->hw_if_index != hw->hw_if_index || rt->sw_if_index != hw->sw_if_index ||
	      rt->dev_instance != hw->dev_instance || (i == 0 && rt->is_deleted) ||
	      nrt->function != vlib_node_get_runtime (vm, nodes[i])->function)
	    return clib_error_return (0, "thread %u: node %u runtime mismatch",
				      this_vlib_main->thread_index, nodes[i]);
	}
      *n_threads += 1;
    }
  return 0;
}

/* The barrier is held for the command, so workers get the nodes registered
 * here only when it is released. Delete and recycle them before that, then
 * release the barrier and check the worker runtimes. */
static clib_error_t *
test_interface_node_recycle_command_fn (vlib_main_t *vm, unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, hw_if_index, output_node_index, instance, n_threads = 0;
  vnet_hw_interface_t *hw;
  clib_error_t *error;
  u8 mac[6] = {};

  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "test needs at least one worker");

  if (vnet_create_loopback_interface (&sw_if_index, mac, 0, 0))
    return clib_error_return (0, "loopback create failed");
  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  output_node_index = hw->output_node_index;

  /* Interface indices are reused, so recreate with another instance to tell
   * the new runtime data from the old. The first free one is not this one */
  instance = clib_bitmap_first_clear (ethernet_main.bm_loopback_instances);

  foreach_vlib_main ()
    if (this_vlib_main != vm && output_node_index < vec_len (this_vlib_main->node_main.nodes))
      {
	vnet_delete_loopback_interface (sw_if_index);
	return clib_error_return (0, "nodes already on workers, old loopback recycled?");
      }

  if (vnet_delete_loopback_interface (sw_if_index))
    return clib_error_return (0, "loopback delete failed");

  if (vnet_create_loopback_interface (&sw_if_index, mac, 1, instance))
    return clib_error_return (0, "loopback recreate failed");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  hw_if_index = hw->hw_if_index;
  if (hw->output_node_index != output_node_index)
    {
      error = clib_error_return (0, "nodes not recycled");
      goto done;
    }

  vlib_worker_thread_barrier_release (vm);
  vlib_worker_thread_barrier_sync (vm);

  hw = vnet_get_hw_interface (vnm, hw_if_index);
  error = test_interface_node_recycle_check (vm, hw, &n_threads);

done:
  vnet_delete_loopback_interface (sw_if_index);
  if (!error)
    vlib_cli_output (vm, "node-recycle: passed on %u threads", n_threads);
  return error;
}

VLIB_CLI_COMMAND (test_interface_node_recycle_command, static) = {
  .path = "test interface node-recycle",
  .short_help = "test interface node-recycle",
  .function = test_interface_node_recycle_command_fn,
};

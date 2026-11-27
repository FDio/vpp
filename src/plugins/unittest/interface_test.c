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

static u32 node_recycle_hw_if_index = ~0;

static clib_error_t *
test_interface_node_recycle_verify (vlib_main_t *vm)
{
  vnet_interface_output_runtime_t *rt;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_node_runtime_t *nrt;
  vnet_hw_interface_t *hw;
  u32 nodes[2], n_threads = 0;

  if (node_recycle_hw_if_index == ~0)
    return clib_error_return (0, "run node-recycle first");

  hw = vnet_get_hw_interface (vnm, node_recycle_hw_if_index);
  nodes[0] = hw->output_node_index;
  nodes[1] = hw->tx_node_index;

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
      n_threads++;
    }

  if (vnet_delete_loopback_interface (hw->sw_if_index))
    return clib_error_return (0, "loopback delete failed");
  node_recycle_hw_if_index = ~0;

  vlib_cli_output (vm, "node-recycle verify: passed on %u threads", n_threads);
  return 0;
}

/* The barrier is held for the whole command, so the workers get the nodes
 * registered here only after it returns. Delete and recycle them before
 * that. Verify is a separate command that runs after the barrier release. */
static clib_error_t *
test_interface_node_recycle_command_fn (vlib_main_t *vm, unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, output_node_index, instance;
  vnet_hw_interface_t *hw;
  u8 mac[6] = {};

  if (unformat (input, "verify"))
    return test_interface_node_recycle_verify (vm);

  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "test needs at least one worker");
  if (node_recycle_hw_if_index != ~0)
    return clib_error_return (0, "run node-recycle verify first");

  if (vnet_create_loopback_interface (&sw_if_index, mac, 0, 0))
    return clib_error_return (0, "loopback create failed");
  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  output_node_index = hw->output_node_index;
  instance = hw->dev_instance;

  foreach_vlib_main ()
    if (this_vlib_main != vm && output_node_index < vec_len (this_vlib_main->node_main.nodes))
      {
	vnet_delete_loopback_interface (sw_if_index);
	return clib_error_return (0, "nodes already on workers, old loopback recycled?");
      }

  if (vnet_delete_loopback_interface (sw_if_index))
    return clib_error_return (0, "loopback delete failed");

  /* Interface indices are reused, so use another instance for verify to
   * tell the new runtime data from the old */
  if (vnet_create_loopback_interface (&sw_if_index, mac, 1, instance + 1))
    return clib_error_return (0, "loopback recreate failed");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw->output_node_index != output_node_index)
    {
      vnet_delete_loopback_interface (sw_if_index);
      return clib_error_return (0, "nodes not recycled");
    }
  node_recycle_hw_if_index = hw->hw_if_index;

  vlib_cli_output (vm, "node-recycle: recycled nodes not yet on workers");
  return 0;
}

VLIB_CLI_COMMAND (test_interface_node_recycle_command, static) = {
  .path = "test interface node-recycle",
  .short_help = "test interface node-recycle [verify]",
  .function = test_interface_node_recycle_command_fn,
};

/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <vnet/bonding/node.h>
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/rx_machine.h>
#include <vnet/bonding/lacp/tx_machine.h>
#include <vnet/bonding/lacp/ptx_machine.h>
#include <vnet/bonding/lacp/mux_machine.h>

static clib_error_t *
show_lacp (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = &vnet_main;
  slave_if_t *sif;
  lacp_state_struct *state_entry;
  u32 hw_if_index, *sw_if_indices = 0;
  int i;
  uword *p;
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *sw;
  f64 now;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  sw = pool_elt_at_index (im->sw_interfaces, hw_if_index);
	  p = hash_get (bm->neighbor_by_sw_if_index, sw->sw_if_index);
	  if (!p)
	    {
	      error = clib_error_return (0, "interface is not enslaved");
	      goto done;
	    }
	  sif = pool_elt_at_index (bm->neighbors, p[0]);
	  vec_add1 (sw_if_indices, sif->sw_if_index);
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (sw_if_indices) == 0)
    {
      pool_foreach (sif, bm->neighbors,
		    vec_add1 (sw_if_indices, sif->sw_if_index);
	);
    }

  now = vlib_time_now (vm);
  for (i = 0; i < vec_len (sw_if_indices); i++)
    {
      p = hash_get (bm->neighbor_by_sw_if_index, sw_if_indices[i]);
      sif = pool_elt_at_index (bm->neighbors, p[0]);
      if ((sif->port_enabled == 0) || (sif->lacp_enabled == 0))
	continue;
      vlib_cli_output (vm, "  %U", format_vnet_sw_if_index_name,
		       vnet_get_main (), sif->sw_if_index);
      vlib_cli_output (vm, "    debug: %d", sif->debug);
      vlib_cli_output (vm, "    port moved: %d", sif->port_moved);
      vlib_cli_output (vm, "    ready_n: %d", sif->ready_n);
      vlib_cli_output (vm, "    ready: %d", sif->ready);
      vlib_cli_output (vm, "    Actor");
      vlib_cli_output (vm, "      system: %U",
		       format_ethernet_address, sif->actor.system);
      vlib_cli_output (vm, "      system priority: %u",
		       ntohs (sif->actor.system_priority));
      vlib_cli_output (vm, "      key: %u", ntohs (sif->actor.key));
      vlib_cli_output (vm, "      port priority: %u",
		       ntohs (sif->actor.port_priority));
      vlib_cli_output (vm, "      port number: %u",
		       ntohs (sif->actor.port_number));
      vlib_cli_output (vm, "      state: 0x%x", sif->actor.state);

      state_entry = (lacp_state_struct *) & lacp_state_array;
      while (state_entry->str)
	{
	  if (sif->actor.state & (1 << state_entry->bit))
	    vlib_cli_output (vm, "        %s (%d)", state_entry->str,
			     state_entry->bit);
	  state_entry++;
	}

      vlib_cli_output (vm, "    Partner");
      vlib_cli_output (vm, "      system: %U",
		       format_ethernet_address, sif->partner.system);
      vlib_cli_output (vm, "      system priority: %u",
		       ntohs (sif->partner.system_priority));
      vlib_cli_output (vm, "      key: %u", ntohs (sif->partner.key));
      vlib_cli_output (vm, "      port priority: %u",
		       ntohs (sif->partner.port_priority));
      vlib_cli_output (vm, "      port number: %u",
		       ntohs (sif->partner.port_number));
      vlib_cli_output (vm, "      state: 0x%x", sif->partner.state);

      state_entry = (lacp_state_struct *) & lacp_state_array;
      while (state_entry->str)
	{
	  if (sif->partner.state & (1 << state_entry->bit))
	    vlib_cli_output (vm, "        %s (%d)", state_entry->str,
			     state_entry->bit);
	  state_entry++;
	}

      if (sif->wait_while_timer == 0.0)
	vlib_cli_output (vm, "      wait while timer: not running");
      else
	vlib_cli_output (vm, "      wait while timer: %=10.2f seconds",
			 sif->wait_while_timer - now);
      if (sif->current_while_timer == 0.0)
	vlib_cli_output (vm, "      current while timer: not running");
      else
	vlib_cli_output (vm, "      current while timer: %=10.2f seconds",
			 sif->current_while_timer - now);
      if (sif->periodic_timer == 0.0)
	vlib_cli_output (vm, "      periodic timer: not running");
      else
	vlib_cli_output (vm, "      periodic timer: %=10.2f seconds",
			 sif->periodic_timer - now);
      vlib_cli_output (vm, "    RX-state: %U", format_rx_sm_state,
		       sif->rx_state);
      vlib_cli_output (vm, "    PTX-state: %U", format_ptx_sm_state,
		       sif->ptx_state);
      vlib_cli_output (vm, "    MUX-state: %U", format_mux_sm_state,
		       sif->mux_state);
      vlib_cli_output (vm, "    TX-state: %U", format_tx_sm_state,
		       sif->tx_state);
      vlib_cli_output (vm, "\n");
    }

done:
  vec_free (sw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_lacp_command, static) = {
  .path = "show lacp",
  .short_help = "show lacp [<interface>]",
  .function = show_lacp,
};
/* *INDENT-ON* */

static clib_error_t *
debug_lacp_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  bond_main_t *bm = &bond_main;
  u8 onoff = 0;
  u8 input_found = 0;
  u32 hw_if_index = ~0;
  uword *p;
  slave_if_t *sif;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *sw;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      if (input_found)
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
      else if (unformat (line_input, "on"))
	{
	  input_found = 1;
	  onoff = 1;
	}
      else if (unformat (line_input, "off"))
	{
	  input_found = 1;
	  onoff = 0;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!input_found)
    return clib_error_return (0, "must specify on or off");

  if (hw_if_index != ~0)
    {
      sw = pool_elt_at_index (im->sw_interfaces, hw_if_index);
      p = hash_get (bm->neighbor_by_sw_if_index, sw->sw_if_index);
      if (!p)
	return (clib_error_return (0, "Please enslave the interface first"));
      sif = pool_elt_at_index (bm->neighbors, p[0]);
      sif->debug = onoff;
    }
  else
    bm->debug = onoff;

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (debug_lacp_command, static) = {
    .path = "debug lacp",
    .short_help = "debug lacp <interface> <on | off>",
    .function = debug_lacp_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

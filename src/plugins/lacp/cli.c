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
#include <lacp/node.h>

int
lacp_dump_ifs (lacp_interface_details_t ** out_lacpifs)
{
  vnet_main_t *vnm = vnet_get_main ();
  bond_main_t *bm = &bond_main;
  member_if_t *mif;
  bond_if_t *bif;
  vnet_hw_interface_t *hi;
  lacp_interface_details_t *r_lacpifs = NULL;
  lacp_interface_details_t *lacpif = NULL;

  /* *INDENT-OFF* */
  pool_foreach (mif, bm->neighbors) {
    if (mif->lacp_enabled == 0)
      continue;
    vec_add2(r_lacpifs, lacpif, 1);
    clib_memset (lacpif, 0, sizeof (*lacpif));
    lacpif->sw_if_index = mif->sw_if_index;
    hi = vnet_get_hw_interface (vnm, mif->hw_if_index);
    clib_memcpy(lacpif->interface_name, hi->name,
                MIN (ARRAY_LEN (lacpif->interface_name) - 1,
                     vec_len (hi->name)));
    bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);
    hi = vnet_get_hw_interface (vnm, bif->hw_if_index);
    clib_memcpy(lacpif->bond_interface_name, hi->name,
                MIN (ARRAY_LEN (lacpif->bond_interface_name) - 1,
                     vec_len (hi->name)));
    clib_memcpy (lacpif->actor_system, mif->actor.system, 6);
    lacpif->actor_system_priority = mif->actor.system_priority;
    lacpif->actor_key = mif->actor.key;
    lacpif->actor_port_priority = mif->actor.port_priority;
    lacpif->actor_port_number = mif->actor.port_number;
    lacpif->actor_state = mif->actor.state;
    clib_memcpy (lacpif->partner_system, mif->partner.system, 6);
    lacpif->partner_system_priority = mif->partner.system_priority;
    lacpif->partner_key = mif->partner.key;
    lacpif->partner_port_priority = mif->partner.port_priority;
    lacpif->partner_port_number = mif->partner.port_number;
    lacpif->partner_state = mif->partner.state;
    lacpif->rx_state = mif->rx_state;
    lacpif->tx_state = mif->tx_state;
    lacpif->ptx_state = mif->ptx_state;
    lacpif->mux_state = mif->mux_state;
  }
  /* *INDENT-ON* */

  *out_lacpifs = r_lacpifs;

  return 0;
}

static void
show_lacp (vlib_main_t * vm, u32 * sw_if_indices)
{
  int i;
  member_if_t *mif;
  bond_if_t *bif;

  if (!sw_if_indices)
    return;

  vlib_cli_output (vm, "%-55s %-32s %-32s", " ", "actor state",
		   "partner state");
  vlib_cli_output (vm, "%-25s %-12s %-16s %-31s  %-31s", "interface name",
		   "sw_if_index", "bond interface",
		   "exp/def/dis/col/syn/agg/tim/act",
		   "exp/def/dis/col/syn/agg/tim/act");

  for (i = 0; i < vec_len (sw_if_indices); i++)
    {
      mif = bond_get_member_by_sw_if_index (sw_if_indices[i]);
      if (!mif || (mif->lacp_enabled == 0))
	continue;
      bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);
      vlib_cli_output (vm,
		       "%-25U %-12d %-16U %3x %3x %3x %3x %3x %3x %3x %3x "
		       "%4x %3x %3x %3x %3x %3x %3x %3x",
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       mif->sw_if_index, mif->sw_if_index,
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       bif->sw_if_index, lacp_bit_test (mif->actor.state, 7),
		       lacp_bit_test (mif->actor.state, 6),
		       lacp_bit_test (mif->actor.state, 5),
		       lacp_bit_test (mif->actor.state, 4),
		       lacp_bit_test (mif->actor.state, 3),
		       lacp_bit_test (mif->actor.state, 2),
		       lacp_bit_test (mif->actor.state, 1),
		       lacp_bit_test (mif->actor.state, 0),
		       lacp_bit_test (mif->partner.state, 7),
		       lacp_bit_test (mif->partner.state, 6),
		       lacp_bit_test (mif->partner.state, 5),
		       lacp_bit_test (mif->partner.state, 4),
		       lacp_bit_test (mif->partner.state, 3),
		       lacp_bit_test (mif->partner.state, 2),
		       lacp_bit_test (mif->partner.state, 1),
		       lacp_bit_test (mif->partner.state, 0));
      vlib_cli_output (vm,
		       "  LAG ID: "
		       "[(%04x,%02x-%02x-%02x-%02x-%02x-%02x,%04x,%04x,%04x), "
		       "(%04x,%02x-%02x-%02x-%02x-%02x-%02x,%04x,%04x,%04x)]",
		       ntohs (mif->actor.system_priority),
		       mif->actor.system[0], mif->actor.system[1],
		       mif->actor.system[2], mif->actor.system[3],
		       mif->actor.system[4], mif->actor.system[5],
		       ntohs (mif->actor.key),
		       ntohs (mif->actor.port_priority),
		       ntohs (mif->actor.port_number),
		       ntohs (mif->partner.system_priority),
		       mif->partner.system[0], mif->partner.system[1],
		       mif->partner.system[2], mif->partner.system[3],
		       mif->partner.system[4], mif->partner.system[5],
		       ntohs (mif->partner.key),
		       ntohs (mif->partner.port_priority),
		       ntohs (mif->partner.port_number));
      vlib_cli_output (vm,
		       "  RX-state: %U, TX-state: %U, "
		       "MUX-state: %U, PTX-state: %U",
		       format_rx_sm_state, mif->rx_state, format_tx_sm_state,
		       mif->tx_state, format_mux_sm_state, mif->mux_state,
		       format_ptx_sm_state, mif->ptx_state);
    }
}

static void
show_lacp_details (vlib_main_t * vm, u32 * sw_if_indices)
{
  lacp_main_t *lm = &lacp_main;
  member_if_t *mif;
  lacp_state_struct *state_entry;
  int i;
  f64 now;

  vlib_cli_output (vm, "Number of interfaces: %d", lm->lacp_int);
  if (!sw_if_indices)
    return;

  now = vlib_time_now (vm);
  for (i = 0; i < vec_len (sw_if_indices); i++)
    {
      mif = bond_get_member_by_sw_if_index (sw_if_indices[i]);
      if (!mif || (mif->lacp_enabled == 0))
	continue;
      vlib_cli_output (vm, "  %U", format_vnet_sw_if_index_name,
		       vnet_get_main (), mif->sw_if_index);
      vlib_cli_output (vm, "    Good LACP PDUs received: %llu",
		       mif->pdu_received);
      vlib_cli_output (vm, "    Bad LACP PDUs received: %llu",
		       mif->bad_pdu_received);
      vlib_cli_output (vm, "    LACP PDUs sent: %llu", mif->pdu_sent);
      if (lacp_timer_is_running (mif->last_lacpdu_recd_time))
	vlib_cli_output (vm,
			 "    last LACP PDU received: %10.2f seconds ago",
			 now - mif->last_lacpdu_recd_time);
      if (lacp_timer_is_running (mif->last_lacpdu_sent_time))
	vlib_cli_output (vm, "    last LACP PDU sent: %10.2f seconds ago",
			 now - mif->last_lacpdu_sent_time);
      vlib_cli_output (vm, "    Good Marker PDUs received: %llu",
		       mif->marker_pdu_received);
      vlib_cli_output (vm, "    Bad Marker PDUs received: %llu",
		       mif->marker_bad_pdu_received);
      if (lacp_timer_is_running (mif->last_marker_pdu_recd_time))
	vlib_cli_output (vm,
			 "    last Marker PDU received: %10.2f seconds ago",
			 now - mif->last_marker_pdu_recd_time);
      if (lacp_timer_is_running (mif->last_marker_pdu_sent_time))
	vlib_cli_output (vm, "    last Marker PDU sent: %10.2f seconds ago",
			 now - mif->last_marker_pdu_sent_time);
      vlib_cli_output (vm, "    debug: %d", mif->debug);
      vlib_cli_output (vm, "    loopback port: %d", mif->loopback_port);
      vlib_cli_output (vm, "    port_enabled: %d", mif->port_enabled);
      vlib_cli_output (vm, "    port moved: %d", mif->port_moved);
      vlib_cli_output (vm, "    ready_n: %d", mif->ready_n);
      vlib_cli_output (vm, "    ready: %d", mif->ready);
      vlib_cli_output (vm, "    Actor");
      vlib_cli_output (vm, "      system: %U",
		       format_ethernet_address, mif->actor.system);
      vlib_cli_output (vm, "      system priority: %u",
		       ntohs (mif->actor.system_priority));
      vlib_cli_output (vm, "      key: %u", ntohs (mif->actor.key));
      vlib_cli_output (vm, "      port priority: %u",
		       ntohs (mif->actor.port_priority));
      vlib_cli_output (vm, "      port number: %u",
		       ntohs (mif->actor.port_number));
      vlib_cli_output (vm, "      state: 0x%x", mif->actor.state);

      state_entry = (lacp_state_struct *) & lacp_state_array;
      while (state_entry->str)
	{
	  if (mif->actor.state & (1 << state_entry->bit))
	    vlib_cli_output (vm, "        %s (%d)", state_entry->str,
			     state_entry->bit);
	  state_entry++;
	}

      vlib_cli_output (vm, "    Partner");
      vlib_cli_output (vm, "      system: %U",
		       format_ethernet_address, mif->partner.system);
      vlib_cli_output (vm, "      system priority: %u",
		       ntohs (mif->partner.system_priority));
      vlib_cli_output (vm, "      key: %u", ntohs (mif->partner.key));
      vlib_cli_output (vm, "      port priority: %u",
		       ntohs (mif->partner.port_priority));
      vlib_cli_output (vm, "      port number: %u",
		       ntohs (mif->partner.port_number));
      vlib_cli_output (vm, "      state: 0x%x", mif->partner.state);

      state_entry = (lacp_state_struct *) & lacp_state_array;
      while (state_entry->str)
	{
	  if (mif->partner.state & (1 << state_entry->bit))
	    vlib_cli_output (vm, "        %s (%d)", state_entry->str,
			     state_entry->bit);
	  state_entry++;
	}

      if (!lacp_timer_is_running (mif->wait_while_timer))
	vlib_cli_output (vm, "      wait while timer: not running");
      else
	vlib_cli_output (vm, "      wait while timer: %10.2f seconds",
			 mif->wait_while_timer - now);
      if (!lacp_timer_is_running (mif->current_while_timer))
	vlib_cli_output (vm, "      current while timer: not running");
      else
	vlib_cli_output (vm, "      current while timer: %10.2f seconds",
			 mif->current_while_timer - now);
      if (!lacp_timer_is_running (mif->periodic_timer))
	vlib_cli_output (vm, "      periodic timer: not running");
      else
	vlib_cli_output (vm, "      periodic timer: %10.2f seconds",
			 mif->periodic_timer - now);
      vlib_cli_output (vm, "    RX-state: %U", format_rx_sm_state,
		       mif->rx_state);
      vlib_cli_output (vm, "    TX-state: %U", format_tx_sm_state,
		       mif->tx_state);
      vlib_cli_output (vm, "    MUX-state: %U", format_mux_sm_state,
		       mif->mux_state);
      vlib_cli_output (vm, "    PTX-state: %U", format_ptx_sm_state,
		       mif->ptx_state);
      vlib_cli_output (vm, "\n");
    }
}

static clib_error_t *
show_lacp_fn (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = &vnet_main;
  member_if_t *mif;
  clib_error_t *error = 0;
  u8 details = 0;
  u32 sw_if_index, *sw_if_indices = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  mif = bond_get_member_by_sw_if_index (sw_if_index);
	  if (!mif)
	    {
	      error = clib_error_return (0, "interface is not a member");
	      goto done;
	    }
	  vec_add1 (sw_if_indices, mif->sw_if_index);
	}
      else if (unformat (input, "details"))
	details = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (sw_if_indices) == 0)
    {
      pool_foreach (mif, bm->neighbors)
	vec_add1 (sw_if_indices, mif->sw_if_index);
    }

  if (details)
    show_lacp_details (vm, sw_if_indices);
  else
    show_lacp (vm, sw_if_indices);

done:
  vec_free (sw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_lacp_command, static) = {
  .path = "show lacp",
  .short_help = "show lacp [<interface>] [details]",
  .function = show_lacp_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
debug_lacp_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  lacp_main_t *lm = &lacp_main;
  u8 onoff = 0;
  u8 input_found = 0;
  u32 sw_if_index = ~0;
  member_if_t *mif;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
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

  if (sw_if_index != ~0)
    {
      mif = bond_get_member_by_sw_if_index (sw_if_index);
      if (!mif)
	return (clib_error_return
		(0, "Please add the member interface first"));
      mif->debug = onoff;
    }
  else
    lm->debug = onoff;

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

clib_error_t *
lacp_cli_init (vlib_main_t * vm)
{
  lacp_main_t *lm = &lacp_main;

  lm->vlib_main = vm;
  lm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (lacp_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vlibmemory/api.h>
#include <vnet/vnet_msg_enum.h>
#include <dhcp/dhcp6_packet.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6.h>
#include <float.h>
#include <math.h>

typedef struct
{
  u32 sw_if_index;
  ip6_address_t address;
  u32 preferred_lt;
  u32 valid_lt;
  f64 due_time;
} address_info_t;

typedef struct
{
  u8 enabled;
  u32 server_index;
  u32 T1;
  u32 T2;
  f64 T1_due_time;
  f64 T2_due_time;
  u32 address_count;
  u8 rebinding;
} client_state_t;

typedef struct
{
  address_info_t *address_pool;
  client_state_t *client_state_by_sw_if_index;
  u32 n_clients;
  f64 max_valid_due_time;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  api_main_t *api_main;
  u32 node_index;
} dhcp6_client_cp_main_t;

static dhcp6_client_cp_main_t dhcp6_client_cp_main;

enum
{
  RD_CP_EVENT_INTERRUPT,
  RD_CP_EVENT_DISABLE,
};

static void
send_client_message_start_stop (u32 sw_if_index, u32 server_index,
				u8 msg_type, address_info_t * address_list,
				u8 start)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  dhcp6_send_client_message_params_t params = { 0, };
  dhcp6_send_client_message_params_address_t *addresses = 0, *addr;
  u32 i;

  ASSERT (sw_if_index < vec_len (rm->client_state_by_sw_if_index) &&
	  rm->client_state_by_sw_if_index[sw_if_index].enabled);
  client_state_t *client_state =
    &rm->client_state_by_sw_if_index[sw_if_index];

  params.sw_if_index = sw_if_index;
  params.server_index = server_index;
  params.msg_type = msg_type;
  if (start)
    {
      if (msg_type == DHCPV6_MSG_SOLICIT)
	{
	  params.irt = 1;
	  params.mrt = 120;
	}
      else if (msg_type == DHCPV6_MSG_REQUEST)
	{
	  params.irt = 1;
	  params.mrt = 30;
	  params.mrc = 10;
	}
      else if (msg_type == DHCPV6_MSG_RENEW)
	{
	  params.irt = 10;
	  params.mrt = 600;
	  f64 current_time = vlib_time_now (rm->vlib_main);
	  i32 diff_time = client_state->T2 - current_time;
	  if (diff_time < 0)
	    diff_time = 0;
	  params.mrd = diff_time;
	}
      else if (msg_type == DHCPV6_MSG_REBIND)
	{
	  params.irt = 10;
	  params.mrt = 600;
	  f64 current_time = vlib_time_now (rm->vlib_main);
	  i32 diff_time = rm->max_valid_due_time - current_time;
	  if (diff_time < 0)
	    diff_time = 0;
	  params.mrd = diff_time;
	}
      else if (msg_type == DHCPV6_MSG_RELEASE)
	{
	  params.mrc = 1;
	}
    }

  params.T1 = 0;
  params.T2 = 0;
  if (vec_len (address_list) != 0)
    vec_validate (addresses, vec_len (address_list) - 1);
  for (i = 0; i < vec_len (address_list); i++)
    {
      address_info_t *address = &address_list[i];
      addr = &addresses[i];
      addr->valid_lt = address->valid_lt;
      addr->preferred_lt = address->preferred_lt;
      addr->address = address->address;
    }
  params.addresses = addresses;

  dhcp6_send_client_message (rm->vlib_main, sw_if_index, !start, &params);

  vec_free (params.addresses);
}

static void interrupt_process (void);

static u32
ip6_enable (u32 sw_if_index)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  clib_error_t *rv;

  rv = enable_ip6_interface (rm->vlib_main, sw_if_index);

  return rv != 0;
}

static u8
ip6_addresses_equal (ip6_address_t * address1, ip6_address_t * address2)
{
  if (address1->as_u64[0] != address2->as_u64[0])
    return 0;
  return address1->as_u64[1] == address2->as_u64[1];
}

static clib_error_t *
dhcp6_reply_event_handler (vl_api_dhcp6_reply_event_t * mp)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;
  client_state_t *client_state;
  ip6_address_t *address;
  u32 sw_if_index;
  u32 n_addresses;
  vl_api_dhcp6_address_info_t *api_address;
  u32 inner_status_code;
  u32 status_code;
  u32 server_index;
  f64 current_time;
  clib_error_t *error = 0;
  u32 i;

  current_time = vlib_time_now (vm);

  sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index >= vec_len (rm->client_state_by_sw_if_index))
    return 0;

  client_state = &rm->client_state_by_sw_if_index[sw_if_index];

  if (!client_state->enabled)
    return 0;

  server_index = ntohl (mp->server_index);

  n_addresses = ntohl (mp->n_addresses);

  inner_status_code = ntohs (mp->inner_status_code);
  status_code = ntohs (mp->status_code);

  if (mp->msg_type == DHCPV6_MSG_API_ADVERTISE
      && client_state->server_index == ~0)
    {
      address_info_t *address_list = 0, *address_info;

      if (inner_status_code == DHCPV6_STATUS_NOADDRS_AVAIL)
	{
	  clib_warning
	    ("Advertise message arrived with NoAddrsAvail status code");
	  return 0;
	}

      if (n_addresses > 0)
	vec_validate (address_list, n_addresses - 1);
      for (i = 0; i < n_addresses; i++)
	{
	  api_address = &mp->addresses[i];
	  address = (ip6_address_t *) api_address->address;

	  address_info = &address_list[i];
	  address_info->address = *address;
	  address_info->preferred_lt = 0;
	  address_info->valid_lt = 0;
	}

      client_state->server_index = server_index;

      send_client_message_start_stop (sw_if_index, server_index,
				      DHCPV6_MSG_REQUEST, address_list, 1);
      vec_free (address_list);
    }

  if (mp->msg_type != DHCPV6_MSG_API_REPLY)
    return 0;

  if (!client_state->rebinding && client_state->server_index != server_index)
    {
      clib_warning ("Reply message arrived with Server ID different "
		    "from that in Request or Renew message");
      return 0;
    }

  if (inner_status_code == DHCPV6_STATUS_NOADDRS_AVAIL)
    {
      clib_warning ("Reply message arrived with NoAddrsAvail status code");
      if (n_addresses > 0)
	{
	  clib_warning
	    ("Invalid Reply message arrived: It contains NoAddrsAvail "
	     "status code but also contains addresses");
	  return 0;
	}
    }

  if (status_code == DHCPV6_STATUS_UNSPEC_FAIL)
    {
      clib_warning ("Reply message arrived with UnspecFail status code");
      return 0;
    }

  send_client_message_start_stop (sw_if_index, server_index,
				  mp->msg_type, 0, 0);

  for (i = 0; i < n_addresses; i++)
    {
      address_info_t *address_info = 0;
      u32 valid_time;
      u32 preferred_time;

      api_address = &mp->addresses[i];

      address = (ip6_address_t *) api_address->address;

      if (ip6_address_is_link_local_unicast (address))
	continue;

      valid_time = ntohl (api_address->valid_time);
      preferred_time = ntohl (api_address->preferred_time);

      if (preferred_time > valid_time)
	continue;

      u8 address_already_present = 0;
      /* *INDENT-OFF* */
      pool_foreach (address_info, rm->address_pool,
      ({
        if (address_info->sw_if_index != sw_if_index)
          ;
        else if (!ip6_addresses_equal (&address_info->address, address))
          ;
        else
          {
            address_already_present = 1;
            goto address_pool_foreach_out;
          }
      }));
      /* *INDENT-ON* */
    address_pool_foreach_out:

      if (address_already_present)
	{
	  address_info->preferred_lt = preferred_time;
	  address_info->valid_lt = valid_time;
	  address_info->due_time = current_time;
	  /* Renew the lease at the preferred time, if non-zero */
	  address_info->due_time += (preferred_time > 0) ?
	    preferred_time : valid_time;

	  if (address_info->due_time > rm->max_valid_due_time)
	    rm->max_valid_due_time = address_info->due_time;
	  continue;
	}

      if (valid_time == 0)
	continue;

      pool_get (rm->address_pool, address_info);
      address_info->sw_if_index = sw_if_index;
      address_info->address = *address;
      address_info->preferred_lt = preferred_time;
      address_info->valid_lt = valid_time;
      address_info->due_time = current_time;
      /* Renew the lease at the preferred time, if non-zero */
      address_info->due_time += (preferred_time > 0) ?
	preferred_time : valid_time;

      if (address_info->due_time > rm->max_valid_due_time)
	rm->max_valid_due_time = address_info->due_time;
      rm->client_state_by_sw_if_index[sw_if_index].address_count++;

      error = ip6_add_del_interface_address (vm, sw_if_index,
					     &address_info->address, 64, 0);
      if (error)
	clib_warning ("Failed to add interface address");
    }

  client_state->server_index = server_index;
  client_state->T1 = ntohl (mp->T1);
  client_state->T2 = ntohl (mp->T2);
  if (client_state->T1 != 0)
    client_state->T1_due_time = current_time + client_state->T1;
  if (client_state->T2 != 0)
    client_state->T2_due_time = current_time + client_state->T2;
  client_state->rebinding = 0;

  interrupt_process ();

  return error;
}

static address_info_t *
create_address_list (u32 sw_if_index)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  address_info_t *address_info, *address_list = 0;;

  /* *INDENT-OFF* */
  pool_foreach (address_info, rm->address_pool,
  ({
    if (address_info->sw_if_index == sw_if_index)
      {
        u32 pos = vec_len (address_list);
        vec_validate (address_list, pos);
        clib_memcpy (&address_list[pos], address_info, sizeof (*address_info));
      }
  }));
  /* *INDENT-ON* */

  return address_list;
}

VNET_DHCP6_REPLY_EVENT_FUNCTION (dhcp6_reply_event_handler);

static uword
dhcp6_client_cp_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			 vlib_frame_t * f)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  address_info_t *address_info;
  client_state_t *client_state;
  f64 sleep_time = 1e9;
  clib_error_t *error;
  f64 current_time;
  f64 due_time;
  uword event_type;
  uword *event_data = 0;
  int i;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      if (event_type == RD_CP_EVENT_DISABLE)
	{
	  vlib_node_set_state (vm, rm->node_index, VLIB_NODE_STATE_DISABLED);
	  sleep_time = 1e9;
	  continue;
	}

      current_time = vlib_time_now (vm);
      do
	{
	  due_time = current_time + 1e9;
          /* *INDENT-OFF* */
          pool_foreach (address_info, rm->address_pool,
          ({
            if (address_info->due_time > current_time)
              {
                if (address_info->due_time < due_time)
                  due_time = address_info->due_time;
              }
            else
              {
                u32 sw_if_index = address_info->sw_if_index;
                error = ip6_add_del_interface_address (vm, sw_if_index,
                                                       &address_info->address,
                                                       64, 1);
                if (error)
                    clib_warning ("Failed to delete interface address");
                pool_put (rm->address_pool, address_info);
                /* make sure ip6 stays enabled */
                ip6_enable (sw_if_index);
                client_state = &rm->client_state_by_sw_if_index[sw_if_index];
                if (--client_state->address_count == 0)
                  {
                    client_state->rebinding = 0;
                    client_state->server_index = ~0;
                    send_client_message_start_stop (sw_if_index, ~0,
                                                    DHCPV6_MSG_SOLICIT,
                                                    0, 1);
                  }
              }
          }));
          /* *INDENT-ON* */
	  for (i = 0; i < vec_len (rm->client_state_by_sw_if_index); i++)
	    {
	      client_state_t *cs = &rm->client_state_by_sw_if_index[i];
	      if (cs->enabled && cs->server_index != ~0)
		{
		  if (cs->T2_due_time > current_time)
		    {
		      if (cs->T2_due_time < due_time)
			due_time = cs->T2_due_time;
		      if (cs->T1_due_time > current_time)
			{
			  if (cs->T1_due_time < due_time)
			    due_time = cs->T1_due_time;
			}
		      else
			{
			  cs->T1_due_time = DBL_MAX;
			  address_info_t *address_list;
			  address_list = create_address_list (i);
			  cs->rebinding = 1;
			  send_client_message_start_stop (i, cs->server_index,
							  DHCPV6_MSG_RENEW,
							  address_list, 1);
			  vec_free (address_list);
			}
		    }
		  else
		    {
		      cs->T2_due_time = DBL_MAX;
		      address_info_t *address_list;
		      address_list = create_address_list (i);
		      cs->rebinding = 1;
		      send_client_message_start_stop (i, ~0,
						      DHCPV6_MSG_REBIND,
						      address_list, 1);
		      vec_free (address_list);
		    }
		}
	    }
	  current_time = vlib_time_now (vm);
	}
      while (due_time < current_time);

      sleep_time = due_time - current_time;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp6_client_cp_process_node) = {
    .function = dhcp6_client_cp_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dhcp6-client-cp-process",
};
/* *INDENT-ON* */

static void
interrupt_process (void)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;

  vlib_process_signal_event (vm, dhcp6_client_cp_process_node.index,
			     RD_CP_EVENT_INTERRUPT, 0);
}

static void
disable_process (void)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;

  vlib_process_signal_event (vm, dhcp6_client_cp_process_node.index,
			     RD_CP_EVENT_DISABLE, 0);
}

static void
enable_process (void)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;
  vlib_node_t *node;

  node = vec_elt (vm->node_main.nodes, rm->node_index);

  vlib_node_set_state (vm, rm->node_index, VLIB_NODE_STATE_POLLING);
  vlib_start_process (vm, node->runtime_index);
}

static clib_error_t *
dhcp6_addresses_show_command_function (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  dhcp6_client_cp_main_t *dm = &dhcp6_client_cp_main;
  clib_error_t *error = 0;
  address_info_t *address_info;
  f64 current_time = vlib_time_now (vm);

  /* *INDENT-OFF* */
  pool_foreach (address_info, dm->address_pool,
  ({
    vlib_cli_output (vm, "address: %U, "
                     "preferred lifetime: %u, valid lifetime: %u "
                     "(%f remaining)",
                     format_ip6_address, &address_info->address,
                     address_info->preferred_lt, address_info->valid_lt,
                     address_info->due_time - current_time);
  }));
  /* *INDENT-ON* */

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp6_addresses_show_command, static) = {
  .path = "show dhcp6 addresses",
  .short_help = "show dhcp6 addresses",
  .function = dhcp6_addresses_show_command_function,
};
/* *INDENT-ON* */

static clib_error_t *
dhcp6_clients_show_command_function (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  clib_error_t *error = 0;
  client_state_t *cs;
  f64 current_time = vlib_time_now (vm);
  char buf1[256];
  char buf2[256];
  const char *rebinding;
  u32 i;

  for (i = 0; i < vec_len (rm->client_state_by_sw_if_index); i++)
    {
      cs = &rm->client_state_by_sw_if_index[i];
      if (cs->enabled)
	{
	  if (cs->T1_due_time != DBL_MAX && cs->T1_due_time > current_time)
	    {
	      sprintf (buf1, "%u remaining",
		       (u32) round (cs->T1_due_time - current_time));
	    }
	  else
	    sprintf (buf1, "timeout");
	  if (cs->T2_due_time != DBL_MAX && cs->T2_due_time > current_time)
	    sprintf (buf2, "%u remaining",
		     (u32) round (cs->T2_due_time - current_time));
	  else
	    sprintf (buf2, "timeout");
	  if (cs->rebinding)
	    rebinding = ", REBINDING";
	  else
	    rebinding = "";
	  if (cs->T1)
	    vlib_cli_output (vm,
			     "sw_if_index: %u, T1: %u (%s), "
			     "T2: %u (%s), server index: %d%s", i,
			     cs->T1, buf1, cs->T2, buf2,
			     cs->server_index, rebinding);
	  else
	    vlib_cli_output (vm, "sw_if_index: %u%s", i, rebinding);
	}
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp6_clients_show_command, static) = {
  .path = "show dhcp6 clients",
  .short_help = "show dhcp6 clients",
  .function = dhcp6_clients_show_command_function,
};
/* *INDENT-ON* */

int
dhcp6_client_enable_disable (u32 sw_if_index, u8 enable)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  vlib_main_t *vm = rm->vlib_main;
  client_state_t *client_state;
  client_state_t empty_config = { 0 };
  address_info_t *address_info;
  clib_error_t *error;

  if (!vnet_sw_interface_is_api_valid (vnm, sw_if_index))
    {
      clib_warning ("Invalid sw_if_index");
      return 1;
    }

  vec_validate_init_empty (rm->client_state_by_sw_if_index, sw_if_index,
			   empty_config);
  client_state = &rm->client_state_by_sw_if_index[sw_if_index];

  u8 old_enabled = client_state->enabled;
  if (enable)
    client_state->enabled = 1;
  client_state->server_index = ~0;

  if (!old_enabled && enable)
    {
      rm->n_clients++;
      if (rm->n_clients == 1)
	{
	  enable_process ();
	  dhcp6_clients_enable_disable (1);
	}

      ip6_enable (sw_if_index);
      send_client_message_start_stop (sw_if_index, ~0, DHCPV6_MSG_SOLICIT,
				      0, 1);
    }
  else if (old_enabled && !enable)
    {
      send_client_message_start_stop (sw_if_index, ~0, ~0, 0, 0);

      rm->n_clients--;
      if (rm->n_clients == 0)
	{
	  dhcp6_clients_enable_disable (0);
	  disable_process ();
	}

      /* *INDENT-OFF* */
      pool_foreach (address_info, rm->address_pool,
      ({
        if (address_info->sw_if_index == sw_if_index)
          {
            ASSERT (sw_if_index < vec_len (rm->client_state_by_sw_if_index) &&
                    rm->client_state_by_sw_if_index[sw_if_index].enabled);
            client_state_t *client_state =
              &rm->client_state_by_sw_if_index[sw_if_index];
            send_client_message_start_stop (sw_if_index,
                                            client_state->server_index,
                                            DHCPV6_MSG_RELEASE, address_info,
                                            1);
            error = ip6_add_del_interface_address (vm, sw_if_index,
                                                   &address_info->address,
                                                   64, 1);
            if (error)
                clib_warning ("Failed to delete interface address");
            pool_put (rm->address_pool, address_info);
          }
      }));
      /* *INDENT-ON* */
    }

  if (!enable)
    client_state->enabled = 0;

  return 0;
}

static clib_error_t *
dhcp6_client_enable_disable_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u8 enable = 1;
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unexpected input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  unformat_free (line_input);

  if (sw_if_index != ~0)
    {
      if (dhcp6_client_enable_disable (sw_if_index, enable) != 0)
	error = clib_error_return (0, "Invalid sw_if_index");
    }
  else
    error = clib_error_return (0, "Missing sw_if_index");

done:
  return error;
}

/*?
 * This command is used to enable/disable DHCPv6 client
 * on particular interface.
 *
 * @cliexpar
 * @parblock
 * Example of how to enable DHCPv6 client:
 * @cliexcmd{dhcp6 client GigabitEthernet2/0/0}
 * Example of how to disable DHCPv6 client:
 * @cliexcmd{dhcp6 client GigabitEthernet2/0/0 disable}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp6_client_enable_disable_command, static) = {
  .path = "dhcp6 client",
  .short_help = "dhcp6 client <interface> [disable]",
  .function = dhcp6_client_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcp_ia_na_client_cp_init (vlib_main_t * vm)
{
  dhcp6_client_cp_main_t *rm = &dhcp6_client_cp_main;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();
  rm->api_main = &api_main;
  rm->node_index = dhcp6_client_cp_process_node.index;

  return NULL;
}

VLIB_INIT_FUNCTION (dhcp_ia_na_client_cp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

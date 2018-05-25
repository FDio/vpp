#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/vnet_msg_enum.h>
#include <vnet/dhcp/dhcp6_packet.h>
#include <vnet/dhcp/dhcp6_pd_client_dp.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6.h>
#include <float.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

#include <vlibapi/api_helper_macros.h>

#define foreach_dhcp6_pd_client_cp_msg                                        \
_(DHCP6_PD_CLIENT_ENABLE_DISABLE, dhcp6_pd_client_enable_disable)             \
_(IP6_PD_ADDRESSES_SET, ip6_pd_addresses_set)

typedef struct
{
  u32 sw_if_index;
  ip6_address_t prefix;
  u8 prefix_length;
  u32 preferred_lt;
  u32 valid_lt;
  f64 due_time;
} prefix_info_t;


typedef struct
{
  u8 enabled;
  u32 server_index;
  u32 T1;
  u32 T2;
  f64 T1_due_time;
  f64 T2_due_time;
} client_state_t;

typedef struct
{
  prefix_info_t *prefix_pool;
  client_state_t *client_state_by_sw_if_index;
  u32 n_clients;
  u32 *target_interface_list;
  u32 active_prefix_index;
  f64 max_valid_due_time;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  api_main_t *api_main;
  u32 node_index;
} dhcp6_pd_client_cp_main_t;

dhcp6_pd_client_cp_main_t dhcp6_pd_client_cp_main;

static u32
get_interface_mac_address (u32 sw_if_index, u8 mac[])
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vnet_sw_interface_t *si;
  ethernet_interface_t *eth_if = 0;

  if (!vnet_sw_interface_is_api_valid (rm->vnet_main, sw_if_index))
    {
      clib_warning ("Invalid sw_if_index");
      return 1;
    }

  si = vnet_get_sup_sw_interface (rm->vnet_main, sw_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    eth_if = ethernet_get_interface (&ethernet_main, si->hw_if_index);

  clib_memcpy (mac, eth_if->address, 6);

  return 0;
}

/*
 * for disable: prefix_index = ~0
 */
void
reset_active_prefix (u32 prefix_index)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  u32 sw_if_index, i;
  u8 mac[6];

  ASSERT (prefix_index == ~0 ||
	  !pool_is_free_index (rm->prefix_pool, prefix_index));
  u32 old_index = rm->active_prefix_index;
  rm->active_prefix_index = prefix_index;

  if (old_index == prefix_index)
    return;

  for (i = 0; i < vec_len (rm->target_interface_list); i++)
    {
      sw_if_index = rm->target_interface_list[i];
      if (get_interface_mac_address (sw_if_index, mac) != 0)
	{
	  clib_warning ("Error getting MAC address");
	}
      else
	{
	  ip6_address_t addr;
	  /* Invert the "u" bit */
	  addr.as_u8[8] = mac[0] ^ (1 << 1);
	  addr.as_u8[9] = mac[1];
	  addr.as_u8[10] = mac[2];
	  addr.as_u8[11] = 0xFF;
	  addr.as_u8[12] = 0xFE;
	  addr.as_u8[13] = mac[3];
	  addr.as_u8[14] = mac[4];
	  addr.as_u8[15] = mac[5];
	  if (old_index != ~0)
	    {
	      addr.as_u64[0] = rm->prefix_pool[old_index].prefix.as_u64[0];
	      ip6_add_del_interface_address (rm->vlib_main, sw_if_index,
					     &addr, 64, 1);
	    }
	  if (prefix_index != ~0)
	    {
	      addr.as_u64[0] = rm->prefix_pool[prefix_index].prefix.as_u64[0];
	      ip6_add_del_interface_address (rm->vlib_main, sw_if_index,
					     &addr, 64, 0);
	    }
	}
    }
}

void
find_new_active_prefix (void)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;

  u32 index = pool_next_index (rm->prefix_pool, -1);
  reset_active_prefix (index);
}

enum
{
  RD_CP_EVENT_INTERRUPT,
  RD_CP_EVENT_DISABLE,
};

#define vl_api_dhcp6_pd_client_enable_disable_t_print vl_noop_handler
#define vl_api_ip6_pd_addresses_set_t_print vl_noop_handler

static void
send_client_message_start_stop (u32 sw_if_index, u32 server_index,
				u8 msg_type, prefix_info_t * prefix_list,
				u8 start)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  dhcp6_pd_send_client_message_params_t params = { 0, };
  dhcp6_pd_send_client_message_params_prefix_t *prefixes = 0, *pref;
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
  if (vec_len (prefix_list) != 0)
    vec_validate (prefixes, vec_len (prefix_list) - 1);
  for (i = 0; i < vec_len (prefix_list); i++)
    {
      prefix_info_t *prefix = &prefix_list[i];
      pref = &prefixes[i];
      pref->valid_lt = prefix->valid_lt;
      pref->preferred_lt = prefix->preferred_lt;
      pref->prefix = prefix->prefix;
      pref->prefix_length = prefix->prefix_length;
    }
  params.prefixes = prefixes;

  dhcp6_pd_send_client_message (rm->vlib_main, sw_if_index, !start, &params);

  vec_free (params.prefixes);
}

static void interrupt_process (void);

static u32
ip6_enable (u32 sw_if_index)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  clib_error_t *rv;

  rv = enable_ip6_interface (rm->vlib_main, sw_if_index);

  return rv != 0;
}

static u8
ip6_prefixes_equal (ip6_address_t * prefix1, ip6_address_t * prefix2, u8 len)
{
  if (len >= 64)
    {
      if (prefix1->as_u64[0] != prefix2->as_u64[0])
	return 0;
      if (len == 64)
	return 1;
      return prefix1->as_u64[1] >> (128 - len) ==
	prefix2->as_u64[1] >> (128 - len);
    }
  return prefix1->as_u64[0] >> (64 - len) == prefix2->as_u64[0] >> (64 - len);
}

static clib_error_t *
dhcp6_pd_reply_event_handler (vl_api_dhcp6_pd_reply_event_t * mp)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;
  client_state_t *client_state;
  ip6_address_t *prefix;
  u32 sw_if_index;
  u32 n_prefixes;
  vl_api_dhcp6_pd_prefix_info_t *api_prefix;
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

  n_prefixes = ntohl (mp->n_prefixes);

  if (mp->msg_type == DHCPV6_MSG_ADVERTISE)
    {
      prefix_info_t *prefix_list = 0, *prefix_info;
      u8 prefix_length;
      u32 server_index;

      server_index = ntohl (mp->server_index);

      vec_validate (prefix_list, n_prefixes - 1);
      for (i = 0; i < n_prefixes; i++)
	{
	  api_prefix = &mp->prefixes[i];
	  prefix = (ip6_address_t *) api_prefix->prefix;
	  prefix_length = api_prefix->prefix_length;

	  prefix_info = &prefix_list[i];
	  prefix_info->prefix = *prefix;
	  prefix_info->prefix_length = prefix_length;
	  prefix_info->preferred_lt = 0;
	  prefix_info->valid_lt = 0;
	}

      send_client_message_start_stop (sw_if_index, server_index,
				      DHCPV6_MSG_REQUEST, prefix_list, 1);
      vec_free (prefix_list);
    }

  if (mp->msg_type != DHCPV6_MSG_REPLY)
    return 0;

  for (i = 0; i < n_prefixes; i++)
    {
      prefix_info_t *prefix_info = 0;
      u8 prefix_length;
      u32 valid_time;
      u32 preferred_time;

      api_prefix = &mp->prefixes[i];

      prefix = (ip6_address_t *) api_prefix->prefix;
      prefix_length = api_prefix->prefix_length;

      if (ip6_address_is_link_local_unicast (prefix))
	continue;

      valid_time = ntohl (api_prefix->valid_time);
      preferred_time = ntohl (api_prefix->preferred_time);
      prefix_length = api_prefix->prefix_length;

      if (preferred_time > valid_time)
	continue;

      u8 address_prefix_present = 0;
      /* *INDENT-OFF* */
      pool_foreach (prefix_info, rm->prefix_pool,
      ({
        if (prefix_info->sw_if_index != sw_if_index)
          ;
        else if (prefix_info->prefix_length != prefix_length)
          ;
        else if (!ip6_prefixes_equal (&prefix_info->prefix, prefix,
                                 prefix_length))
          ;
        else
          {
            address_prefix_present = 1;
            goto prefix_pool_foreach_out;
          }
      }));
      /* *INDENT-ON* */
    prefix_pool_foreach_out:

      if (address_prefix_present)
	{
	  f64 remaining_life_time = prefix_info->due_time - current_time;
	  if (valid_time > 2 * 60 * 60 || valid_time > remaining_life_time)
	    prefix_info->due_time = current_time + valid_time;
	  else if (remaining_life_time > 2 * 60 * 60)
	    prefix_info->due_time = current_time + 2 * 60 * 60;
	  continue;
	}

      if (valid_time == 0)
	continue;

      pool_get (rm->prefix_pool, prefix_info);
      prefix_info->sw_if_index = sw_if_index;
      prefix_info->prefix_length = prefix_length;
      prefix_info->prefix = *prefix;
      prefix_info->preferred_lt = preferred_time;
      prefix_info->valid_lt = valid_time;
      prefix_info->due_time = current_time + valid_time;

      clib_warning ("Interface %u obtained prefix lease %U/%d lifetime %u:%u",
		    prefix_info->sw_if_index, format_ip6_address,
		    &prefix_info->prefix, prefix_info->prefix_length,
		    prefix_info->preferred_lt, prefix_info->valid_lt);

      if (rm->active_prefix_index == ~0)
	find_new_active_prefix ();
    }

  client_state->server_index = ntohl (mp->server_index);
  client_state->T1 = ntohl (mp->T1);
  client_state->T2 = ntohl (mp->T2);
  client_state->T1_due_time = current_time + client_state->T1;
  client_state->T2_due_time = current_time + client_state->T2;

  interrupt_process ();

  return error;
}

static prefix_info_t *
create_prefix_list (u32 sw_if_index)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  prefix_info_t *prefix_info, *prefix_list = 0;;

  /* *INDENT-OFF* */
  pool_foreach (prefix_info, rm->prefix_pool,
  ({
    if (prefix_info->sw_if_index == sw_if_index)
      {
        u32 pos = vec_len (prefix_list);
        vec_validate (prefix_list, pos);
        clib_memcpy (&prefix_list[pos], prefix_info, sizeof (*prefix_info));
      }
  }));
  /* *INDENT-ON* */

  return prefix_list;
}

VNET_DHCP6_PD_REPLY_EVENT_FUNCTION (dhcp6_pd_reply_event_handler);

static uword
dhcp6_pd_client_cp_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			    vlib_frame_t * f)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  prefix_info_t *prefix_info;
  f64 sleep_time = 1e9;
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
	  u8 need_new_active_prefix = 0;
          /* *INDENT-OFF* */
          pool_foreach (prefix_info, rm->prefix_pool,
          ({
            if (prefix_info->due_time > current_time)
              {
                if (prefix_info->due_time < due_time)
                  due_time = prefix_info->due_time;
              }
            else
              {
                pool_put (rm->prefix_pool, prefix_info);
                if (prefix_info - rm->prefix_pool == rm->active_prefix_index)
                  need_new_active_prefix = 1;
              }
          }));
          if (need_new_active_prefix)
            find_new_active_prefix ();
          /* *INDENT-ON* */
	  for (i = 0; i < vec_len (rm->client_state_by_sw_if_index); i++)
	    {
	      client_state_t *cs = &rm->client_state_by_sw_if_index[i];
	      if (cs->enabled && cs->server_index != ~0)
		{
		  if (cs->T1_due_time > current_time)
		    {
		      if (cs->T1_due_time < due_time)
			due_time = cs->T1_due_time;
		    }
		  else
		    {
		      cs->T1_due_time = DBL_MAX;
		      prefix_info_t *prefix_list;
		      prefix_list = create_prefix_list (i);
		      send_client_message_start_stop (i, cs->server_index,
						      DHCPV6_MSG_RENEW,
						      prefix_list, 1);
		      vec_free (prefix_list);
		    }
		  if (cs->T2_due_time > current_time)
		    {
		      if (cs->T2_due_time < due_time)
			due_time = cs->T2_due_time;
		    }
		  else
		    {
		      cs->T2_due_time = DBL_MAX;
		      prefix_info_t *prefix_list;
		      prefix_list = create_prefix_list (i);
		      send_client_message_start_stop (i, ~0,
						      DHCPV6_MSG_REBIND,
						      prefix_list, 1);
		      vec_free (prefix_list);
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
VLIB_REGISTER_NODE (dhcp6_pd_client_cp_process_node) = {
    .function = dhcp6_pd_client_cp_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dhcp6-pd-client-cp-process",
};
/* *INDENT-ON* */

static void
interrupt_process (void)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;

  vlib_process_signal_event (vm, dhcp6_pd_client_cp_process_node.index,
			     RD_CP_EVENT_INTERRUPT, 0);
}

static void
disable_process (void)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;

  vlib_process_signal_event (vm, dhcp6_pd_client_cp_process_node.index,
			     RD_CP_EVENT_DISABLE, 0);
}

static void
enable_process (void)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;
  vlib_node_t *node;

  node = vec_elt (vm->node_main.nodes, rm->node_index);

  vlib_node_set_state (vm, rm->node_index, VLIB_NODE_STATE_POLLING);
  vlib_start_process (vm, node->runtime_index);
}

static int
ip6_pd_addresses_set (u32 * sw_if_indices)
{

  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;

  reset_active_prefix (~0);
  vec_free (rm->target_interface_list);
  rm->target_interface_list = sw_if_indices;
  find_new_active_prefix ();

  return 0;
}

static void
vl_api_ip6_pd_addresses_set_t_handler (vl_api_ip6_pd_addresses_set_t * mp)
{
  vl_api_ip6_pd_addresses_set_reply_t *rmp;
  u32 *sw_if_indices = 0;
  int i;
  int n;
  int rv = 0;

  n = ntohl (mp->n_interfaces);
  for (i = 0; i < n; i++)
    {
      mp->sw_if_indices[i] = ntohl (mp->sw_if_indices[i]);
      if (!vnet_sw_if_index_is_api_valid (mp->sw_if_indices[i]))
	{
	  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	  goto bad_sw_if_index;
	}
    }
  vec_validate (sw_if_indices, n - 1);
  memcpy (sw_if_indices, mp->sw_if_indices, sizeof (u32) * n);

  rv = ip6_pd_addresses_set (sw_if_indices);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

static clib_error_t *
ip6_pd_addresses_add_del_command_function (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u32 *sw_if_indices = 0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	vec_add1 (sw_if_indices, sw_if_index);
      else if (unformat (input, "del"))
	add = 0;
      else
	{
	  error = clib_error_return (0, "unexpected input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_indices != 0 && add == 0)
    error = clib_error_return (0, "Interface list cannot be specified "
			       "with 'del' keyword");
  else if (sw_if_indices == 0 && add == 1)
    error = clib_error_return (0, "Expecting either interface list "
			       "or 'del' keyword");
  else
    {
      if (ip6_pd_addresses_set (sw_if_indices) != 0)
	error = clib_error_return (0, "Error configuring addresses using PD");
    }

done:
  return error;
}

/*?
 * This command is used to add/delete IPv6 address
 * using prefix obtained from DHCPv6 PD
 *
 * @cliexpar
 * @parblock
 * Example of how to add IPv6 PD addresses on two interfaces:
 * @cliexcmd{set ip6 pd addresses GigabitEthernet2/0/0 GigabitEthernet3/0/0}
 * Example of how to delete all IPv6 PD addresses:
 * @cliexcmd{set ip6 pd addresses del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_pd_addresses_add_del_command, static) = {
  .path = "set ip6 pd addresses",
  .short_help = "set ip6 pd addresses (<interface>+ | del)",
  .function = ip6_pd_addresses_add_del_command_function,
};
/* *INDENT-ON* */

static clib_error_t *
ip6_pd_prefixes_show_command_function (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  clib_error_t *error = 0;
  prefix_info_t *prefix_info;
  f64 current_time = vlib_time_now (vm);

  /* *INDENT-OFF* */
  pool_foreach (prefix_info, rm->prefix_pool,
  ({
    vlib_cli_output (vm, "sw_if_index: %u, prefix: %U/%d, "
                     "preferred lifetime: %u, valid lifetime: %u "
                     "(%f remaining)",
                     prefix_info->sw_if_index, format_ip6_address,
                     &prefix_info->prefix, prefix_info->prefix_length,
                     prefix_info->preferred_lt, prefix_info->valid_lt,
                     prefix_info->due_time - current_time);
  }));
  /* *INDENT-ON* */

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_pd_prefixes_show_command, static) = {
  .path = "show ip6 pd prefixes",
  .short_help = "show ip6 pd prefixes",
  .function = ip6_pd_prefixes_show_command_function,
};
/* *INDENT-ON* */

static clib_error_t *
ip6_pd_clients_show_command_function (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  clib_error_t *error = 0;
  client_state_t *cs;
  f64 current_time = vlib_time_now (vm);
  u32 i;

  for (i = 0; i < vec_len (rm->client_state_by_sw_if_index); i++)
    {
      cs = &rm->client_state_by_sw_if_index[i];
      if (cs->enabled)
	{
	  vlib_cli_output (vm, "sw_if_index: %u, T1: %u (%f remaining), "
			   "T2: %u (%f remaining), server index: %u",
			   i, cs->T1, cs->T1_due_time - current_time, cs->T2,
			   cs->T2_due_time - current_time, cs->server_index);
	}
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_pd_clients_show_command, static) = {
  .path = "show ip6 pd clients",
  .short_help = "show ip6 pd clients",
  .function = ip6_pd_clients_show_command_function,
};
/* *INDENT-ON* */

static int
dhcp6_pd_client_enable_disable (u32 sw_if_index, u8 enable)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  client_state_t *client_state;
  client_state_t empty_config = { 0 };
  prefix_info_t *prefix_info;

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

      u8 need_new_active_prefix = 0;
      /* *INDENT-OFF* */
      pool_foreach (prefix_info, rm->prefix_pool,
      ({
        if (prefix_info->sw_if_index == sw_if_index)
          {
            ASSERT (sw_if_index < vec_len (rm->client_state_by_sw_if_index) &&
                    rm->client_state_by_sw_if_index[sw_if_index].enabled);
            client_state_t *client_state =
              &rm->client_state_by_sw_if_index[sw_if_index];
            send_client_message_start_stop (sw_if_index,
                                            client_state->server_index,
                                            DHCPV6_MSG_RELEASE, prefix_info,
                                            1);
            pool_put (rm->prefix_pool, prefix_info);
            if (prefix_info - rm->prefix_pool == rm->active_prefix_index)
              need_new_active_prefix = 1;
          }
      }));
      /* *INDENT-ON* */
      if (need_new_active_prefix)
	find_new_active_prefix ();
    }

  if (!enable)
    client_state->enabled = 0;

  return 0;
}

static clib_error_t *
dhcp6_pd_client_enable_disable_command_fn (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u8 enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unexpected input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index != ~0)
    {
      if (dhcp6_pd_client_enable_disable (sw_if_index, enable) != 0)
	error = clib_error_return (0, "Invalid sw_if_index");
    }
  else
    error = clib_error_return (0, "Missing sw_if_index");

done:
  return error;
}

/*?
 * This command is used to enable/disable DHCPv6 PD client
 * on particular interface.
 *
 * @cliexpar
 * @parblock
 * Example of how to enable DHCPv6 PD client:
 * @cliexcmd{dhcp6 pd client GigabitEthernet2/0/0}
 * Example of how to disable DHCPv6 PD client:
 * @cliexcmd{dhcp6 pd client GigabitEthernet2/0/0 disable}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp6_pd_client_enable_disable_command, static) = {
  .path = "dhcp6 pd client",
  .short_help = "dhcp6 pd client <interface> [disable]",
  .function = dhcp6_pd_client_enable_disable_command_fn,
};
/* *INDENT-ON* */

static void
  vl_api_dhcp6_pd_client_enable_disable_t_handler
  (vl_api_dhcp6_pd_client_enable_disable_t * mp)
{
  vl_api_dhcp6_pd_client_enable_disable_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  rv = dhcp6_pd_client_enable_disable (sw_if_index, mp->enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/dhcp/dhcp6_pd_client_cp.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_dhcp6_pd_client_cp;
#undef _
}

static clib_error_t *
dhcp_pd_client_cp_init (vlib_main_t * vm)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  api_main_t *am = &api_main;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();
  rm->api_main = am;
  rm->node_index = dhcp6_pd_client_cp_process_node.index;
  rm->active_prefix_index = ~0;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0/* do NOT trace! */);
  foreach_dhcp6_pd_client_cp_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_INIT_FUNCTION (dhcp_pd_client_cp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

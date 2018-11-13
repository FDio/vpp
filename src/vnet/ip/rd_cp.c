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
#include <vnet/ip/ip6.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vnet/fib/fib_table.h>
#include <signal.h>
#include <math.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

#include <vlibapi/api_helper_macros.h>

#define foreach_rd_cp_msg                                                     \
_(IP6_ND_ADDRESS_AUTOCONFIG, ip6_nd_address_autoconfig)

typedef struct
{
  u32 sw_if_index;
  u8 address_length;
  ip6_address_t address;
  f64 due_time;
} slaac_address_t;

typedef struct
{
  u32 sw_if_index;
  ip6_address_t router_address;
  f64 due_time;
} default_route_t;

typedef struct
{
  u8 enabled;
  u8 install_default_routes;
} interface_config_t;

typedef struct
{
  u8 enabled;
  u8 events_on;

  interface_config_t *config_by_sw_if_index;
  slaac_address_t *slaac_address_pool;
  default_route_t *default_route_pool;

  /* binary API client */
  u8 api_connected;
  svm_queue_t *vl_input_queue;
  u32 my_client_index;

  /* logging */
  vlib_log_class_t log_class;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  api_main_t *api_main;
  u32 node_index;
} rd_cp_main_t;

rd_cp_main_t rd_cp_main;

enum
{
  RD_CP_EVENT_INTERRUPT,
};

#define vl_api_ip6_nd_address_autoconfig_t_print vl_noop_handler

static void
router_solicitation_start_stop (u32 sw_if_index, u8 start)
{
  rd_cp_main_t *rm = &rd_cp_main;
  icmp6_send_router_solicitation_params_t params = { 0, };

  if (start)
    {
      params.irt = 1;
      params.mrt = 120;
    }

  icmp6_send_router_solicitation (rm->vlib_main, sw_if_index, !start,
				  &params);
}

static void interrupt_process (void);

static int
add_slaac_address (vlib_main_t * vm, u32 sw_if_index, u8 address_length,
		   ip6_address_t * address, f64 due_time)
{
  rd_cp_main_t *rm = &rd_cp_main;
  slaac_address_t *slaac_address;
  clib_error_t *rv = 0;

  pool_get (rm->slaac_address_pool, slaac_address);

  slaac_address->sw_if_index = sw_if_index;
  slaac_address->address_length = address_length;
  slaac_address->address = *address;
  slaac_address->due_time = due_time;

  rv =
    ip6_add_del_interface_address (vm, sw_if_index, &slaac_address->address,
				   address_length, 0);

  return rv != 0;
}

static void
add_default_route (vlib_main_t * vm, u32 sw_if_index,
		   ip6_address_t * next_hop_address, f64 due_time)
{
  rd_cp_main_t *rm = &rd_cp_main;
  default_route_t *default_route;

  pool_get (rm->default_route_pool, default_route);

  default_route->sw_if_index = sw_if_index;
  default_route->router_address = *next_hop_address;
  default_route->due_time = due_time;

  {
    u32 fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6,
							 default_route->
							 sw_if_index);
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP6,
    };
    ip46_address_t nh = {
      .ip6 = default_route->router_address,
    };
    fib_table_entry_update_one_path (fib_index, &pfx,
				     FIB_SOURCE_API,
				     FIB_ENTRY_FLAG_NONE,
				     DPO_PROTO_IP6,
				     &nh,
				     default_route->sw_if_index,
				     0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  }
}

static int
remove_slaac_address (vlib_main_t * vm, slaac_address_t * slaac_address)
{
  rd_cp_main_t *rm = &rd_cp_main;
  clib_error_t *rv = 0;

  rv = ip6_add_del_interface_address (vm, slaac_address->sw_if_index,
				      &slaac_address->address,
				      slaac_address->address_length, 1);

  pool_put (rm->slaac_address_pool, slaac_address);

  return rv != 0;
}

static void
remove_default_route (vlib_main_t * vm, default_route_t * default_route)
{
  rd_cp_main_t *rm = &rd_cp_main;

  {
    u32 fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6,
							 default_route->
							 sw_if_index);
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP6,
    };
    ip46_address_t nh = {
      .ip6 = default_route->router_address,
    };
    fib_table_entry_path_remove (fib_index, &pfx,
				 FIB_SOURCE_API,
				 DPO_PROTO_IP6,
				 &nh,
				 default_route->sw_if_index,
				 0, 1, FIB_ROUTE_PATH_FLAG_NONE);
  }

  pool_put (rm->default_route_pool, default_route);
}

static u32
get_interface_mac_address (u32 sw_if_index, u8 mac[])
{
  rd_cp_main_t *rm = &rd_cp_main;
  vnet_sw_interface_t *si;
  ethernet_interface_t *eth_if = 0;

  if (!vnet_sw_interface_is_api_valid (rm->vnet_main, sw_if_index))
    {
      vlib_log_warn (rm->log_class, "Invalid sw_if_index");
      return 1;
    }

  si = vnet_get_sup_sw_interface (rm->vnet_main, sw_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    eth_if = ethernet_get_interface (&ethernet_main, si->hw_if_index);

  if (!eth_if)
    {
      vlib_log_warn (rm->log_class, "Failed to get hardware interface");
      return 1;
    }

  _clib_memcpy (mac, eth_if->address, 6);

  return 0;
}

static u32
ip6_enable (u32 sw_if_index)
{
  rd_cp_main_t *rm = &rd_cp_main;
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

#define PREFIX_FLAG_A (1 << 6)
#define PREFIX_FLAG_L (1 << 7)

static clib_error_t *
ip6_ra_report_handler (void *data)
{
  rd_cp_main_t *rm = &rd_cp_main;
  vlib_main_t *vm = rm->vlib_main;
  clib_error_t *error = 0;
  ra_report_t *r = data;
  interface_config_t *if_config;
  default_route_t *default_route;
  slaac_address_t *slaac_address;
  u32 sw_if_index;
  u16 router_lifetime_in_sec;
  u32 n_prefixes;
  ra_report_prefix_info_t *prefix;
  u8 mac[6];
  f64 current_time;
  u32 i;

  current_time = vlib_time_now (vm);

  sw_if_index = r->sw_if_index;

  if (sw_if_index >= vec_len (rm->config_by_sw_if_index))
    return 0;
  if_config = &rm->config_by_sw_if_index[sw_if_index];

  if (if_config->install_default_routes)
    {
      router_lifetime_in_sec = r->router_lifetime_in_sec;
      u8 route_already_present = 0;
      /* *INDENT-OFF* */
      pool_foreach (default_route, rm->default_route_pool,
      ({
        if (default_route->sw_if_index != sw_if_index)
          ;
        else if (0 != memcmp (&default_route->router_address,
                              r->router_address, 16))
          ;
        else
          {
            route_already_present = 1;
            goto default_route_pool_foreach_out;
          }
      }));
      /* *INDENT-ON* */
    default_route_pool_foreach_out:

      if (!route_already_present)
	{
	  if (router_lifetime_in_sec != 0)
	    add_default_route (vm, sw_if_index, (void *) r->router_address,
			       current_time + router_lifetime_in_sec);
	}
      else
	{
	  if (router_lifetime_in_sec != 0)
	    default_route->due_time = current_time + router_lifetime_in_sec;
	  else
	    remove_default_route (vm, default_route);
	}
    }

  if (get_interface_mac_address (sw_if_index, mac) != 0)
    {
      vlib_log_warn (rm->log_class, "Error getting MAC address");
      return clib_error_return (0, "Error getting MAC address");
    }

  if (!if_config->enabled)
    return 0;

  n_prefixes = vec_len (r->prefixes);
  for (i = 0; i < n_prefixes; i++)
    {
      ip6_address_t *dst_address;
      u8 prefix_length;
      u32 valid_time;
      u32 preferred_time;
      f64 due_time;

      prefix = &r->prefixes[i];

      if (!(prefix->flags & PREFIX_FLAG_A))
	continue;

      dst_address = &prefix->dst_address;
      prefix_length = prefix->dst_address_length;

      if (ip6_address_is_link_local_unicast (dst_address))
	continue;

      valid_time = prefix->valid_time;
      preferred_time = prefix->preferred_time;

      if (preferred_time > valid_time)
	continue;

      if (prefix_length != 64)
	continue;

      u8 address_already_present = 0;
      /* *INDENT-OFF* */
      pool_foreach (slaac_address, rm->slaac_address_pool,
      ({
        if (slaac_address->sw_if_index != sw_if_index)
          ;
        else if (slaac_address->address_length != prefix_length)
          ;
        else if (!ip6_prefixes_equal (&slaac_address->address, dst_address,
                                 prefix_length))
          ;
        else
          {
            address_already_present = 1;
            goto slaac_address_pool_foreach_out;
          }
      }));
      /* *INDENT-ON* */
    slaac_address_pool_foreach_out:

      if (address_already_present)
	{
	  f64 remaining_life_time = slaac_address->due_time - current_time;
	  if (valid_time > 2 * 60 * 60 || valid_time > remaining_life_time)
	    slaac_address->due_time = current_time + valid_time;
	  else if (remaining_life_time > 2 * 60 * 60)
	    slaac_address->due_time = current_time + 2 * 60 * 60;
	  continue;
	}

      if (valid_time == 0)
	continue;

      due_time = current_time + valid_time;

      ip6_address_t addr;
      addr.as_u64[0] = dst_address->as_u64[0];
      /* Invert the "u" bit */
      addr.as_u8[8] = mac[0] ^ (1 << 1);
      addr.as_u8[9] = mac[1];
      addr.as_u8[10] = mac[2];
      addr.as_u8[11] = 0xFF;
      addr.as_u8[12] = 0xFE;
      addr.as_u8[13] = mac[3];
      addr.as_u8[14] = mac[4];
      addr.as_u8[15] = mac[5];

      add_slaac_address (vm, sw_if_index, prefix_length, &addr, due_time);
    }

  interrupt_process ();

  return error;
}

VNET_IP6_NEIGHBOR_RA_FUNCTION (ip6_ra_report_handler);

static uword
rd_cp_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword *event_data = 0;
  rd_cp_main_t *rm = &rd_cp_main;
  slaac_address_t *slaac_address;
  default_route_t *default_route;
  f64 sleep_time = 1e9;
  f64 current_time;
  f64 due_time;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vlib_process_get_events (vm, &event_data);

      vec_reset_length (event_data);

      current_time = vlib_time_now (vm);
      do
	{
	  due_time = current_time + 1e9;
          /* *INDENT-OFF* */
          pool_foreach (slaac_address, rm->slaac_address_pool,
          ({
            if (slaac_address->due_time > current_time)
              {
                if (slaac_address->due_time < due_time)
                  due_time = slaac_address->due_time;
              }
            else
              {
                remove_slaac_address (vm, slaac_address);
                /* make sure ip6 stays enabled */
                ip6_enable (slaac_address->sw_if_index);
              }
          }));
          pool_foreach (default_route, rm->default_route_pool,
          ({
            if (default_route->due_time > current_time)
              {
                if (default_route->due_time < due_time)
                  due_time = default_route->due_time;
              }
            else
              remove_default_route (vm, default_route);
          }));
          /* *INDENT-ON* */
	  current_time = vlib_time_now (vm);
	}
      while (due_time < current_time);

      sleep_time = due_time - current_time;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (rd_cp_process_node) = {
    .function = rd_cp_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "rd-cp-process",
};
/* *INDENT-ON* */

static void
interrupt_process (void)
{
  rd_cp_main_t *rm = &rd_cp_main;
  vlib_main_t *vm = rm->vlib_main;

  vlib_process_signal_event (vm, rd_cp_process_node.index,
			     RD_CP_EVENT_INTERRUPT, 0);
}

static int
set_address_autoconfig (u32 sw_if_index, u8 enable, u8 install_default_routes)
{
  rd_cp_main_t *rm = &rd_cp_main;
  vlib_main_t *vm = rm->vlib_main;
  vnet_main_t *vnm = rm->vnet_main;
  interface_config_t *if_config;
  interface_config_t empty_config = { 0, 0 };
  slaac_address_t *slaac_address;
  default_route_t *default_route;

  if (!enable)
    install_default_routes = 0;

  if (!vnet_sw_interface_is_api_valid (vnm, sw_if_index))
    {
      vlib_log_warn (rm->log_class, "Invalid sw_if_index");
      return 1;
    }

  if (!rm->enabled)
    {
      /* process kickoff */
      interrupt_process ();
      rm->enabled = 1;
    }

  vec_validate_init_empty (rm->config_by_sw_if_index, sw_if_index,
			   empty_config);
  if_config = &rm->config_by_sw_if_index[sw_if_index];

  if (!if_config->enabled && enable)
    ip6_enable (sw_if_index);

  if ((!if_config->enabled && enable)
      || (!if_config->install_default_routes && install_default_routes))
    router_solicitation_start_stop (sw_if_index, 1);
  else if (if_config->enabled && !enable)
    router_solicitation_start_stop (sw_if_index, 0);

  if (if_config->enabled && !enable)
    {
      /* *INDENT-OFF* */
      pool_foreach (slaac_address, rm->slaac_address_pool,
      ({
          remove_slaac_address (vm, slaac_address);
      }));
      /* *INDENT-ON* */
    }
  if (if_config->install_default_routes && !install_default_routes)
    {
      /* *INDENT-OFF* */
      pool_foreach (default_route, rm->default_route_pool,
      ({
          remove_default_route (vm, default_route);
      }));
      /* *INDENT-ON* */
    }

  if_config->enabled = enable;
  if_config->install_default_routes = install_default_routes;

  return 0;
}

static clib_error_t *
ip6_nd_address_autoconfig (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  rd_cp_main_t *rm = &rd_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u8 enable = 1;
  u8 default_route = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      if (unformat (input, "default-route"))
	default_route = 1;
      if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (sw_if_index != ~0)
    {
      if (set_address_autoconfig (sw_if_index, enable, default_route) != 0)
	error = clib_error_return (0, "Invalid sw_if_index");
    }
  else
    error = clib_error_return (0, "Missing sw_if_index");

  return error;
}

/*?
 * This command is used to enable ND address autoconfiguration
 * on particular interface including setting up default routes.
 *
 * @cliexpar
 * @parblock
 * Example of how to enable ND address autoconfiguration:
 * @cliexcmd{ip6 nd address autoconfig GigabitEthernet2/0/0}
 * Example of how to enable ND address autoconfiguration
 * with setting up default routes:
 * @cliexcmd{ip6 nd address autoconfig GigabitEthernet2/0/0 default-route}
 * Example of how to disable ND address autoconfiguration:
 * @cliexcmd{ip6 nd address autoconfig GigabitEthernet2/0/0 disable}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_nd_address_autoconfig_command, static) = {
  .path = "ip6 nd address autoconfig",
  .short_help = "ip6 nd address autoconfig <interface> [default-route|disable]",
  .function = ip6_nd_address_autoconfig,
};
/* *INDENT-ON* */

static void
vl_api_ip6_nd_address_autoconfig_t_handler (vl_api_ip6_nd_address_autoconfig_t
					    * mp)
{
  vl_api_ip6_nd_address_autoconfig_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  rv =
    set_address_autoconfig (sw_if_index, mp->enable,
			    mp->install_default_routes);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/ip/rd_cp.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_rd_cp;
#undef _
}

static clib_error_t *
rd_cp_init (vlib_main_t * vm)
{
  rd_cp_main_t *rm = &rd_cp_main;
  api_main_t *am = &api_main;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();
  rm->api_main = am;
  rm->node_index = rd_cp_process_node.index;

  rm->log_class = vlib_log_register_class ("rd_cp", 0);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0/* do NOT trace! */);
  foreach_rd_cp_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_INIT_FUNCTION (rd_cp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

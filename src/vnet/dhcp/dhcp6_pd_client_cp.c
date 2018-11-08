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
#include <vnet/dhcp/dhcp6_packet.h>
#include <vnet/dhcp/dhcp6_pd_client_dp.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6.h>
#include <float.h>
#include <math.h>
#include <string.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

#include <vlibapi/api_helper_macros.h>

#define foreach_dhcp6_pd_client_cp_msg                                        \
_(DHCP6_PD_CLIENT_ENABLE_DISABLE, dhcp6_pd_client_enable_disable)             \
_(IP6_ADD_DEL_ADDRESS_USING_PREFIX, ip6_add_del_address_using_prefix)

#define vl_api_dhcp6_pd_client_enable_disable_t_print vl_noop_handler
#define vl_api_ip6_add_del_address_using_prefix_t_print vl_noop_handler

typedef struct
{
  u32 prefix_group_index;
  uword opaque_data;		// used by prefix publisher
  ip6_address_t prefix;
  u8 prefix_length;
  u32 preferred_lt;
  u32 valid_lt;
  f64 due_time;
} prefix_info_t;

typedef struct
{
  u8 enabled;
  u32 prefix_group_index;
  u32 server_index;
  u32 T1;
  u32 T2;
  f64 T1_due_time;
  f64 T2_due_time;
  u32 prefix_count;
  u8 rebinding;
} client_state_t;

typedef struct
{
  client_state_t *client_state_by_sw_if_index;
  clib_bitmap_t *prefix_ownership_bitmap;
  u32 n_clients;
  f64 max_valid_due_time;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  api_main_t *api_main;
  u32 node_index;
} dhcp6_pd_client_cp_main_t;

static dhcp6_pd_client_cp_main_t dhcp6_pd_client_cp_main;

typedef struct
{
  prefix_info_t *prefix_pool;
  const u8 **prefix_group_name_by_index;
} ip6_prefix_main_t;

static ip6_prefix_main_t ip6_prefix_main;

typedef struct
{
  /* config */
  u32 sw_if_index;
  u32 prefix_group_index;
  ip6_address_t address;
  u8 prefix_length;

  /* state */
  u8 configured_in_data_plane;
} ip6_address_info_t;

typedef struct
{
  ip6_address_info_t *addresses;
  u32 *active_prefix_index_by_prefix_group_index;
} ip6_address_with_prefix_main_t;

static ip6_address_with_prefix_main_t ip6_address_with_prefix_main;

enum
{
  DHCPV6_PD_EVENT_INTERRUPT,
  DHCPV6_PD_EVENT_DISABLE,
};

static_always_inline u32
active_prefix_index_by_prefix_group_index_get (u32 prefix_group_index)
{
  ip6_address_with_prefix_main_t *apm = &ip6_address_with_prefix_main;

  if (prefix_group_index >=
      vec_len (apm->active_prefix_index_by_prefix_group_index))
    return ~0;

  return apm->active_prefix_index_by_prefix_group_index[prefix_group_index];
}

static_always_inline void
active_prefix_index_by_prefix_group_index_set (u32 prefix_group_index,
					       u32 prefix_index)
{
  ip6_address_with_prefix_main_t *apm = &ip6_address_with_prefix_main;
  static const u32 empty = ~0;

  ASSERT (prefix_group_index != ~0);

  if (prefix_index == ~0
      && prefix_group_index >=
      vec_len (apm->active_prefix_index_by_prefix_group_index))
    return;

  vec_validate_init_empty (apm->active_prefix_index_by_prefix_group_index,
			   prefix_group_index, empty);
  apm->active_prefix_index_by_prefix_group_index[prefix_group_index] =
    prefix_index;
}

static_always_inline u8
is_dhcpv6_pd_prefix (prefix_info_t * prefix_info)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  u32 prefix_index;

  prefix_index = prefix_info - pm->prefix_pool;
  return clib_bitmap_get (rm->prefix_ownership_bitmap, prefix_index);
}

static_always_inline void
set_is_dhcpv6_pd_prefix (prefix_info_t * prefix_info, u8 value)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  u32 prefix_index;

  prefix_index = prefix_info - pm->prefix_pool;
  rm->prefix_ownership_bitmap =
    clib_bitmap_set (rm->prefix_ownership_bitmap, prefix_index, value);
}

static void
cp_ip6_address_prefix_add_del_handler (u32 prefix_index, u8 is_add);

static void
notify_prefix_add_del (u32 prefix_index, u8 is_add)
{
  // TODO: use registries
  cp_ip6_address_prefix_add_del_handler (prefix_index, is_add);
}

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
      return clib_net_to_host_u64 (prefix1->as_u64[1]) >> (128 - len) ==
	clib_net_to_host_u64 (prefix2->as_u64[1]) >> (128 - len);
    }
  return clib_net_to_host_u64 (prefix1->as_u64[0]) >> (64 - len) ==
    clib_net_to_host_u64 (prefix2->as_u64[0]) >> (64 - len);
}

static clib_error_t *
dhcp6_pd_reply_event_handler (vl_api_dhcp6_pd_reply_event_t * mp)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  vlib_main_t *vm = rm->vlib_main;
  client_state_t *client_state;
  ip6_address_t *prefix;
  u32 sw_if_index;
  u32 n_prefixes;
  vl_api_dhcp6_pd_prefix_info_t *api_prefix;
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

  n_prefixes = ntohl (mp->n_prefixes);

  inner_status_code = ntohs (mp->inner_status_code);
  status_code = ntohs (mp->status_code);

  if (mp->msg_type == DHCPV6_MSG_ADVERTISE
      && client_state->server_index == ~0)
    {
      prefix_info_t *prefix_list = 0, *prefix_info;
      u8 prefix_length;

      if (inner_status_code == DHCPV6_STATUS_NOPREFIX_AVAIL)
	{
	  clib_warning
	    ("Advertise message arrived with NoPrefixAvail status code");
	  return 0;
	}

      if (n_prefixes > 0)
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

      client_state->server_index = server_index;

      send_client_message_start_stop (sw_if_index, server_index,
				      DHCPV6_MSG_REQUEST, prefix_list, 1);
      vec_free (prefix_list);
    }

  if (mp->msg_type != DHCPV6_MSG_REPLY)
    return 0;

  if (!client_state->rebinding && client_state->server_index != server_index)
    {
      clib_warning ("Reply message arrived with Server ID different "
		    "from that in Request or Renew message");
      return 0;
    }

  if (inner_status_code == DHCPV6_STATUS_NOPREFIX_AVAIL)
    {
      clib_warning ("Reply message arrived with NoPrefixAvail status code");
      if (n_prefixes > 0)
	{
	  clib_warning
	    ("Invalid Reply message arrived: It contains NoPrefixAvail "
	     "status code but also contains prefixes");
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
      pool_foreach (prefix_info, pm->prefix_pool,
      ({
        if (is_dhcpv6_pd_prefix (prefix_info) &&
            prefix_info->opaque_data == sw_if_index &&
            prefix_info->prefix_length == prefix_length &&
            ip6_prefixes_equal (&prefix_info->prefix, prefix, prefix_length))
          {
            address_prefix_present = 1;
            goto prefix_pool_foreach_out;
          }
      }));
      /* *INDENT-ON* */
    prefix_pool_foreach_out:

      if (address_prefix_present)
	{
	  prefix_info->preferred_lt = preferred_time;
	  prefix_info->valid_lt = valid_time;
	  prefix_info->due_time = current_time + valid_time;
	  if (prefix_info->due_time > rm->max_valid_due_time)
	    rm->max_valid_due_time = prefix_info->due_time;
	  continue;
	}

      if (valid_time == 0)
	continue;

      pool_get (pm->prefix_pool, prefix_info);
      prefix_info->prefix_group_index = client_state->prefix_group_index;
      set_is_dhcpv6_pd_prefix (prefix_info, 1);
      prefix_info->opaque_data = sw_if_index;
      prefix_info->prefix_length = prefix_length;
      prefix_info->prefix = *prefix;
      prefix_info->preferred_lt = preferred_time;
      prefix_info->valid_lt = valid_time;
      prefix_info->due_time = current_time + valid_time;
      if (prefix_info->due_time > rm->max_valid_due_time)
	rm->max_valid_due_time = prefix_info->due_time;
      rm->client_state_by_sw_if_index[sw_if_index].prefix_count++;

      u32 prefix_index = prefix_info - pm->prefix_pool;
      notify_prefix_add_del (prefix_index, 1);
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

static prefix_info_t *
create_prefix_list (u32 sw_if_index)
{
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  prefix_info_t *prefix_info, *prefix_list = 0;;

  /* *INDENT-OFF* */
  pool_foreach (prefix_info, pm->prefix_pool,
  ({
    if (is_dhcpv6_pd_prefix (prefix_info) &&
        prefix_info->opaque_data == sw_if_index)
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
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  prefix_info_t *prefix_info;
  client_state_t *client_state;
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

      if (event_type == DHCPV6_PD_EVENT_DISABLE)
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
          pool_foreach (prefix_info, pm->prefix_pool,
          ({
            if (is_dhcpv6_pd_prefix (prefix_info))
              {
                if (prefix_info->due_time > current_time)
                  {
                    if (prefix_info->due_time < due_time)
                      due_time = prefix_info->due_time;
                  }
                else
                  {
                    u32 prefix_index = prefix_info - pm->prefix_pool;
                    notify_prefix_add_del (prefix_index, 0);
                    u32 sw_if_index = prefix_info->opaque_data;
                    set_is_dhcpv6_pd_prefix (prefix_info, 0);
                    pool_put (pm->prefix_pool, prefix_info);
                    client_state = &rm->client_state_by_sw_if_index[sw_if_index];
                    if (--client_state->prefix_count == 0)
                      {
                        client_state->rebinding = 0;
                        client_state->server_index = ~0;
                        send_client_message_start_stop (sw_if_index, ~0,
                                                        DHCPV6_MSG_SOLICIT,
                                                        0, 1);
                      }
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
			  prefix_info_t *prefix_list;
			  prefix_list = create_prefix_list (i);
			  send_client_message_start_stop (i, cs->server_index,
							  DHCPV6_MSG_RENEW,
							  prefix_list, 1);
			  vec_free (prefix_list);
			}
		    }
		  else
		    {
		      cs->T2_due_time = DBL_MAX;
		      prefix_info_t *prefix_list;
		      prefix_list = create_prefix_list (i);
		      cs->rebinding = 1;
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
			     DHCPV6_PD_EVENT_INTERRUPT, 0);
}

static void
disable_process (void)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vlib_main_t *vm = rm->vlib_main;

  vlib_process_signal_event (vm, dhcp6_pd_client_cp_process_node.index,
			     DHCPV6_PD_EVENT_DISABLE, 0);
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

static u32
cp_ip6_construct_address (ip6_address_info_t * address_info, u32 prefix_index,
			  ip6_address_t * r_addr)
{
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  prefix_info_t *prefix;
  u64 mask, addr0, pref;

  addr0 = clib_net_to_host_u64 (address_info->address.as_u64[0]);
  prefix = &pm->prefix_pool[prefix_index];
  if (prefix->prefix_length > 64)
    {
      clib_warning ("Prefix length is bigger that 64 bits");
      return 1;
    }
  mask = ((u64) 1 << (64 - prefix->prefix_length)) - 1;
  addr0 &= mask;
  pref = clib_host_to_net_u64 (prefix->prefix.as_u64[0]);
  pref &= ~mask;
  addr0 |= pref;
  r_addr->as_u64[0] = clib_host_to_net_u64 (addr0);
  r_addr->as_u64[1] = address_info->address.as_u64[1];

  return 0;
}

static void
cp_ip6_address_add_del_now (ip6_address_info_t * address_info, u8 is_add)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 prefix_index;
  ip6_address_t addr;
  clib_error_t *error;

  if (address_info->prefix_group_index != ~0)
    prefix_index =
      active_prefix_index_by_prefix_group_index_get
      (address_info->prefix_group_index);
  else
    prefix_index = ~0;

  if (is_add && !address_info->configured_in_data_plane)
    {
      if (prefix_index != ~0)
	{
	  if (cp_ip6_construct_address (address_info, prefix_index, &addr) !=
	      0)
	    return;
	  error =
	    ip6_add_del_interface_address (vm, address_info->sw_if_index,
					   &addr, address_info->prefix_length,
					   0 /* add */ );
	  if (error)
	    clib_warning ("Failed adding IPv6 address: %U",
			  format_clib_error, error);
	  else
	    address_info->configured_in_data_plane = 1;
	}
      else
	{
	  if (address_info->prefix_group_index == ~0)
	    {
	      error =
		ip6_add_del_interface_address (vm, address_info->sw_if_index,
					       &address_info->address,
					       address_info->prefix_length,
					       0 /* add */ );
	      if (error)
		clib_warning ("Failed adding IPv6 address: %U",
			      format_clib_error, error);
	      else
		address_info->configured_in_data_plane = 1;
	    }
	}
    }
  else if (!is_add && address_info->configured_in_data_plane)
    {
      if (prefix_index == ~0)
	{
	  if (address_info->prefix_group_index == ~0)
	    {
	      error =
		ip6_add_del_interface_address (vm, address_info->sw_if_index,
					       &address_info->address,
					       address_info->prefix_length,
					       1 /* del */ );
	      if (error)
		clib_warning ("Failed deleting IPv6 address: %U",
			      format_clib_error, error);
	      address_info->configured_in_data_plane = 0;
	    }
	  else
	    clib_warning ("Deleting address with prefix "
			  "but active prefix index is not set");
	}
      else
	{
	  if (cp_ip6_construct_address (address_info, prefix_index, &addr) !=
	      0)
	    return;
	  error =
	    ip6_add_del_interface_address (vm, address_info->sw_if_index,
					   &addr, address_info->prefix_length,
					   1 /* del */ );
	  if (error)
	    clib_warning ("Failed deleting IPv6 address: %U",
			  format_clib_error, error);
	  address_info->configured_in_data_plane = 0;
	}
    }
}

static u32
cp_ip6_address_find_new_active_prefix (u32 prefix_group_index,
				       u32 ignore_prefix_index)
{
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  prefix_info_t *prefix_info;

  /* *INDENT-OFF* */
  pool_foreach (prefix_info, pm->prefix_pool,
  ({
    if (prefix_info->prefix_group_index == prefix_group_index &&
        prefix_info - pm->prefix_pool != ignore_prefix_index)
        return prefix_info - pm->prefix_pool;
  }));
  /* *INDENT-ON* */
  return ~0;
}

static void
cp_ip6_address_prefix_add_del_handler (u32 prefix_index, u8 is_add)
{
  ip6_address_with_prefix_main_t *apm = &ip6_address_with_prefix_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  ip6_address_info_t *address_info;
  prefix_info_t *prefix;
  u32 new_prefix_index;
  u32 prefix_group_index;
  u32 i;

  prefix = &pm->prefix_pool[prefix_index];
  prefix_group_index = prefix->prefix_group_index;

  if (is_add)
    {
      if (active_prefix_index_by_prefix_group_index_get
	  (prefix_group_index) == ~0)
	{
	  active_prefix_index_by_prefix_group_index_set
	    (prefix_group_index, prefix_index);
	  for (i = 0; i < vec_len (apm->addresses); i++)
	    {
	      address_info = &apm->addresses[i];
	      if (address_info->prefix_group_index == prefix_group_index)
		cp_ip6_address_add_del_now (address_info, 1 /* add */ );
	    }
	}
    }
  else
    {
      if (active_prefix_index_by_prefix_group_index_get
	  (prefix_group_index) == prefix_index)
	{
	  for (i = 0; i < vec_len (apm->addresses); i++)
	    {
	      address_info = &apm->addresses[i];
	      if (address_info->prefix_group_index == prefix_group_index)
		cp_ip6_address_add_del_now (address_info, 0 /* del */ );
	    }
	  active_prefix_index_by_prefix_group_index_set
	    (prefix_group_index, ~0);
	  new_prefix_index =
	    cp_ip6_address_find_new_active_prefix (prefix_group_index,
						   prefix_index);
	  if (new_prefix_index != ~0)
	    {
	      active_prefix_index_by_prefix_group_index_set
		(prefix_group_index, new_prefix_index);
	      for (i = 0; i < vec_len (apm->addresses); i++)
		{
		  address_info = &apm->addresses[i];
		  if (address_info->prefix_group_index == prefix_group_index)
		    cp_ip6_address_add_del_now (address_info, 1 /* add */ );
		}
	    }
	}
    }
}

static u32
prefix_group_find_or_create (const u8 * name, u8 create)
{
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  u32 free_index = ~0;
  u8 *name_dup;
  u32 i;

  for (i = 0; i < vec_len (pm->prefix_group_name_by_index); i++)
    {
      if (pm->prefix_group_name_by_index[i] == 0)
	free_index = i;
      else if (0 ==
	       strcmp ((const char *) pm->prefix_group_name_by_index[i],
		       (const char *) name))
	return i;
    }
  if (!create)
    return ~0;
  name_dup = (u8 *) strdup ((const char *) name);
  if (free_index != ~0)
    {
      pm->prefix_group_name_by_index[free_index] = name_dup;
      return free_index;
    }
  else
    {
      vec_add1 (pm->prefix_group_name_by_index, name_dup);
      return vec_len (pm->prefix_group_name_by_index) - 1;
    }
}

static int
cp_ip6_address_add_del (u32 sw_if_index, const u8 * prefix_group,
			ip6_address_t address, u8 prefix_length, u8 is_add)
{

  ip6_address_with_prefix_main_t *apm = &ip6_address_with_prefix_main;
  vnet_main_t *vnm = vnet_get_main ();
  ip6_address_info_t *address_info;
  u32 prefix_group_index;
  u32 n;

  if (!vnet_sw_interface_is_api_valid (vnm, sw_if_index))
    {
      clib_warning ("Invalid sw_if_index");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (prefix_group != 0 && prefix_group[0] != '\0')
    {
      if (strnlen ((const char *) prefix_group, 64) == 64)
	return VNET_API_ERROR_INVALID_VALUE;

      prefix_group_index = prefix_group_find_or_create (prefix_group, 1);
    }
  else
    prefix_group_index = ~0;

  n = vec_len (apm->addresses);

  vec_foreach (address_info, apm->addresses)
  {
    if (address_info->sw_if_index == sw_if_index &&
	address_info->prefix_group_index == prefix_group_index &&
	address_info->prefix_length == prefix_length &&
	0 == memcmp (&address_info->address, &address, 16))
      {
	if (is_add)
	  return VNET_API_ERROR_DUPLICATE_IF_ADDRESS;
	cp_ip6_address_add_del_now (address_info, 0 /* del */ );
	*address_info = apm->addresses[n - 1];
	_vec_len (apm->addresses) = n - 1;
	return 0;
      }
  }

  if (!is_add)
    return VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;

  vec_validate (apm->addresses, n);
  address_info = &apm->addresses[n];
  address_info->sw_if_index = sw_if_index;
  address_info->prefix_group_index = prefix_group_index;
  address_info->address = address;
  address_info->prefix_length = prefix_length;
  cp_ip6_address_add_del_now (address_info, 1 /* add */ );

  return 0;
}

static void
  vl_api_ip6_add_del_address_using_prefix_t_handler
  (vl_api_ip6_add_del_address_using_prefix_t * mp)
{
  vl_api_ip6_add_del_address_using_prefix_reply_t *rmp;
  u32 sw_if_index;
  ip6_address_t address;
  u8 prefix_length;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  memcpy (address.as_u8, mp->address, 16);
  prefix_length = mp->prefix_length;

  rv =
    cp_ip6_address_add_del (sw_if_index, mp->prefix_group, address,
			    prefix_length, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

static clib_error_t *
cp_ip6_address_add_del_command_function (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u8 *prefix_group = 0;
  ip6_address_t address;
  u32 prefix_length;
  u8 address_set = 0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
      else if (unformat (input, "prefix group %s", &prefix_group));
      else
	if (unformat
	    (input, "%U/%d", unformat_ip6_address, &address, &prefix_length))
	address_set = 1;
      else if (unformat (input, "del"))
	add = 0;
      else
	{
	  error = clib_error_return (0, "unexpected input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    error = clib_error_return (0, "Missing sw_if_index");
  else if (address_set == 0)
    error = clib_error_return (0, "Missing address");
  else
    {
      if (cp_ip6_address_add_del
	  (sw_if_index, prefix_group, address, prefix_length, add) != 0)
	error = clib_error_return (0, "Error adding or removing address");
    }

done:
  return error;
}

/*?
 * This command is used to add/delete IPv6 address
 * potentially using available prefix from specified prefix group
 *
 * @cliexpar
 * @parblock
 * Example of how to add IPv6 address:
 * @cliexcmd{set ip6 address GigabitEthernet2/0/0
 *           prefix group my-prefix-group ::7/64}
 * Example of how to delete IPv6 address:
 * @cliexcmd{set ip6 address GigabitEthernet2/0/0
 *           prefix group my-prefix-group ::7/64 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_address_add_del_command, static) = {
  .path = "set ip6 address",
  .short_help = "set ip6 address <interface> [prefix group <string>] "
                "<address> [del]",
  .function = cp_ip6_address_add_del_command_function,
};
/* *INDENT-ON* */

static clib_error_t *
cp_ip6_addresses_show_command_function (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  ip6_address_with_prefix_main_t *apm = &ip6_address_with_prefix_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  ip6_address_info_t *address_info;
  const u8 *prefix_group;
  clib_error_t *error = 0;
  int i;

  for (i = 0; i < vec_len (apm->addresses); i++)
    {
      address_info = &apm->addresses[i];
      if (address_info->prefix_group_index == ~0)
	prefix_group = (const u8 *) "NONE";
      else
	prefix_group =
	  pm->prefix_group_name_by_index[address_info->prefix_group_index];
      vlib_cli_output (vm,
		       "sw_if_index: %u, prefix_group: %s, address: %U/%d",
		       address_info->sw_if_index, prefix_group,
		       format_ip6_address, &address_info->address,
		       address_info->prefix_length);
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_addresses_show_command, static) = {
  .path = "show ip6 addresses",
  .short_help = "show ip6 addresses",
  .function = cp_ip6_addresses_show_command_function,
};
/* *INDENT-ON* */

static clib_error_t *
cp_ip6_prefixes_show_command_function (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  clib_error_t *error = 0;
  prefix_info_t *prefix_info;
  const u8 *prefix_group;
  f64 current_time = vlib_time_now (vm);

  /* *INDENT-OFF* */
  pool_foreach (prefix_info, pm->prefix_pool,
  ({
    prefix_group =
      pm->prefix_group_name_by_index[prefix_info->prefix_group_index];
    vlib_cli_output (vm, "opaque_data: %lu, prefix: %U/%d, prefix group: %s, "
                     "preferred lifetime: %u, valid lifetime: %u "
                     "(%f remaining)",
                     prefix_info->opaque_data, format_ip6_address,
                     &prefix_info->prefix, prefix_info->prefix_length,
                     prefix_group,
                     prefix_info->preferred_lt, prefix_info->valid_lt,
                     prefix_info->due_time - current_time);
  }));
  /* *INDENT-ON* */

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_prefixes_show_command, static) = {
  .path = "show ip6 prefixes",
  .short_help = "show ip6 prefixes",
  .function = cp_ip6_prefixes_show_command_function,
};
/* *INDENT-ON* */

static clib_error_t *
ip6_pd_clients_show_command_function (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  clib_error_t *error = 0;
  client_state_t *cs;
  f64 current_time = vlib_time_now (vm);
  const u8 *prefix_group;
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
	  prefix_group =
	    pm->prefix_group_name_by_index[cs->prefix_group_index];
	  if (cs->T1)
	    vlib_cli_output (vm,
			     "sw_if_index: %u, prefix group: %s, T1: %u (%s), "
			     "T2: %u (%s), server index: %d%s", i,
			     prefix_group, cs->T1, buf1, cs->T2, buf2,
			     cs->server_index, rebinding);
	  else
	    vlib_cli_output (vm, "sw_if_index: %u, prefix group: %s%s", i,
			     prefix_group, rebinding);
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
dhcp6_pd_client_enable_disable (u32 sw_if_index, const u8 * prefix_group,
				u8 enable)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  ip6_prefix_main_t *pm = &ip6_prefix_main;
  vnet_main_t *vnm = rm->vnet_main;
  client_state_t *client_state;
  static client_state_t empty_config = {
    0
  };
  prefix_info_t *prefix_info;
  prefix_info_t *prefix_list = 0;
  u32 prefix_group_index;

  if (!vnet_sw_interface_is_api_valid (vnm, sw_if_index))
    {
      clib_warning ("Invalid sw_if_index");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  vec_validate_init_empty (rm->client_state_by_sw_if_index, sw_if_index,
			   empty_config);
  client_state = &rm->client_state_by_sw_if_index[sw_if_index];

  u8 old_enabled = client_state->enabled;

  if (enable)
    {
      if (strnlen ((const char *) prefix_group, 64) == 64
	  || prefix_group[0] == '\0')
	return VNET_API_ERROR_INVALID_VALUE;
      prefix_group_index =
	prefix_group_find_or_create (prefix_group, !old_enabled);
      if (old_enabled
	  && prefix_group_index != client_state->prefix_group_index)
	return VNET_API_ERROR_INVALID_VALUE;
    }

  if (!old_enabled && enable)
    {
      client_state->enabled = 1;
      client_state->prefix_group_index = prefix_group_index;
      ASSERT (client_state->prefix_group_index != ~0);
      client_state->server_index = ~0;

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

      vec_validate (prefix_list, 0);

      /* *INDENT-OFF* */
      pool_foreach (prefix_info, pm->prefix_pool,
      ({
        if (is_dhcpv6_pd_prefix (prefix_info) &&
            prefix_info->opaque_data == sw_if_index)
          {
            ASSERT (sw_if_index < vec_len (rm->client_state_by_sw_if_index) &&
                    rm->client_state_by_sw_if_index[sw_if_index].enabled);
            client_state_t *client_state =
              &rm->client_state_by_sw_if_index[sw_if_index];
            prefix_list[0] = *prefix_info;
            send_client_message_start_stop (sw_if_index,
                                            client_state->server_index,
                                            DHCPV6_MSG_RELEASE, prefix_list,
                                            1);
            u32 prefix_index = prefix_info - pm->prefix_pool;
            notify_prefix_add_del (prefix_index, 0);
            set_is_dhcpv6_pd_prefix (prefix_info, 0);
            pool_put (pm->prefix_pool, prefix_info);
          }
      }));
      /* *INDENT-ON* */

      vec_free (prefix_list);

      memset (client_state, 0, sizeof (*client_state));
    }

  return 0;
}

static clib_error_t *
dhcp6_pd_client_enable_disable_command_fn (vlib_main_t *
					   vm,
					   unformat_input_t
					   * input, vlib_cli_command_t * cmd)
{
  dhcp6_pd_client_cp_main_t *rm = &dhcp6_pd_client_cp_main;
  vnet_main_t *vnm = rm->vnet_main;
  clib_error_t *error = 0;
  u8 *prefix_group = 0;
  u32 sw_if_index = ~0;
  u8 enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "prefix group %s", &prefix_group));
      else if (unformat (input, "disable"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unexpected input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (prefix_group == 0 && enable)
    error = clib_error_return (0, "Prefix group must be set when enabling");
  else if (sw_if_index != ~0)
    {
      if (dhcp6_pd_client_enable_disable (sw_if_index, prefix_group, enable)
	  != 0)
	error = clib_error_return (0, "Invalid sw_if_index or prefix group");
    }
  else
    error = clib_error_return (0, "Missing sw_if_index");

done:
  vec_free (prefix_group);

  return error;
}

/*?
 * This command is used to enable/disable DHCPv6 PD client
 * on particular interface.
 *
 * @cliexpar
 * @parblock
 * Example of how to enable DHCPv6 PD client:
 * @cliexcmd{dhcp6 pd client GigabitEthernet2/0/0 prefix group my-pd-group}
 * Example of how to disable DHCPv6 PD client:
 * @cliexcmd{dhcp6 pd client GigabitEthernet2/0/0 disable}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp6_pd_client_enable_disable_command, static) = {
  .path = "dhcp6 pd client",
  .short_help = "dhcp6 pd client <interface> (prefix group <string> | disable)",
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

  rv =
    dhcp6_pd_client_enable_disable (sw_if_index, mp->prefix_group,
				    mp->enable);

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

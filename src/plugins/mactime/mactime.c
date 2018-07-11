/*
 * mactime.c - time-based src mac address filtration
 *
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
#include <vnet/plugin/plugin.h>
#include <mactime/mactime.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <mactime/mactime_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <mactime/mactime_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <mactime/mactime_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <mactime/mactime_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <mactime/mactime_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

mactime_main_t mactime_main;

/** \file time-base src-mac filter device-input feature arc implementation
 */

/* List of message types that this plugin understands */

#define foreach_mactime_plugin_api_msg                  \
_(MACTIME_ENABLE_DISABLE, mactime_enable_disable)       \
_(MACTIME_ADD_DEL_RANGE, mactime_add_del_range)

static void
feature_init (mactime_main_t * mm)
{
  if (mm->feature_initialized == 0)
    {
      /* Create the lookup table */
      clib_bihash_init_8_8 (&mm->lookup_table, "mactime lookup table",
			    mm->lookup_table_num_buckets,
			    mm->lookup_table_memory_size);
      clib_timebase_init (&mm->timebase, mm->timezone_offset,
			  CLIB_TIMEBASE_DAYLIGHT_USA);
      mm->allow_counters.name = "allow";
      mm->allow_counters.stat_segment_name = "/mactime/allow";
      mm->drop_counters.name = "drop";
      mm->drop_counters.stat_segment_name = "/mactime/drop";
      mm->feature_initialized = 1;
    }
}

/** Action function shared between message handler and debug CLI
*/
int
mactime_enable_disable (mactime_main_t * mm, u32 sw_if_index,
			int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  feature_init (mm);

  /* Utterly wrong? */
  if (pool_is_free_index (mm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (mm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "mactime",
			       sw_if_index, enable_disable, 0, 0);
  vnet_feature_enable_disable ("interface-output", "mactime-tx",
			       sw_if_index, enable_disable, 0, 0);
  return rv;
}

static clib_error_t *
mactime_enable_disable_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  mactime_main_t *mm = &mactime_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 mm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = mactime_enable_disable (mm, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "mactime_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mactime_enable_disable_command, static) =
{
  .path = "mactime enable-disable",
  .short_help =
  "mactime enable-disable <interface-name> [disable]",
  .function = mactime_enable_disable_command_fn,
};
/* *INDENT-ON* */


/** Enable / disable time-base src mac filtration on an interface
 */

static void vl_api_mactime_enable_disable_t_handler
  (vl_api_mactime_enable_disable_t * mp)
{
  vl_api_mactime_enable_disable_reply_t *rmp;
  mactime_main_t *mm = &mactime_main;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = mactime_enable_disable (mm, ntohl (mp->sw_if_index),
			       (int) (mp->enable_disable));
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_MACTIME_ENABLE_DISABLE_REPLY);
}

/** Create a lookup table entry for the indicated mac address
 */
void
mactime_send_create_entry_message (u8 * mac_address)
{
  mactime_main_t *mm = &mactime_main;
  api_main_t *am;
  vl_shmem_hdr_t *shmem_hdr;
  u8 *name;
  vl_api_mactime_add_del_range_t *mp;

  am = &api_main;
  shmem_hdr = am->shmem_hdr;
  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MACTIME_ADD_DEL_RANGE + mm->msg_id_base);
  name = format (0, "mac-%U", format_mac_address, mac_address);

  memcpy (mp->device_name, name, vec_len (name));
  memcpy (mp->mac_address, mac_address, sizeof (mp->mac_address));
  /* $$$ config: create allow / drop / range */
  mp->allow = 1;
  mp->is_add = 1;
  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) & mp);
}

/** Add or delete static / dynamic accept/drop configuration for a src mac
 */

static void vl_api_mactime_add_del_range_t_handler
  (vl_api_mactime_add_del_range_t * mp)
{
  mactime_main_t *mm = &mactime_main;
  vl_api_mactime_add_del_range_reply_t *rmp;
  mactime_device_t *dp;
  clib_bihash_kv_8_8_t kv;
  int found = 1;
  clib_bihash_8_8_t *lut = &mm->lookup_table;
  int i, rv = 0;

  feature_init (mm);

  memset (&kv, 0, sizeof (kv));
  memcpy (&kv.key, mp->mac_address, sizeof (mp->mac_address));

  /* See if we have a lookup table entry for this src mac address */
  if (clib_bihash_search_8_8 (lut, &kv, &kv) < 0)
    found = 0;

  /* Add an entry? */
  if (mp->is_add)
    {
      /* Create the device entry? */
      if (found == 0)
	{
	  pool_get (mm->devices, dp);
	  memset (dp, 0, sizeof (*dp));
	  vlib_validate_combined_counter (&mm->allow_counters,
					  dp - mm->devices);
	  vlib_zero_combined_counter (&mm->allow_counters, dp - mm->devices);
	  vlib_validate_combined_counter (&mm->drop_counters,
					  dp - mm->devices);
	  vlib_zero_combined_counter (&mm->drop_counters, dp - mm->devices);
	  mp->device_name[ARRAY_LEN (mp->device_name) - 1] = 0;
	  dp->device_name = format (0, "%s%c", mp->device_name, 0);
	  memcpy (dp->mac_address, mp->mac_address, sizeof (mp->mac_address));
	  for (i = 0; i < clib_net_to_host_u32 (mp->count); i++)
	    {
	      clib_timebase_range_t _r, *r = &_r;
	      r->start = mp->ranges[i].start;
	      r->end = mp->ranges[i].end;
	      vec_add1 (dp->ranges, r[0]);
	    }
	  /* If we found some time ranges */
	  if (i)
	    {
	      /* Set allow/drop based on msg flags */
	      if (mp->drop)
		dp->flags = MACTIME_DEVICE_FLAG_DYNAMIC_DROP;
	      if (mp->allow)
		dp->flags = MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW;
	    }
	  else
	    {
	      /* no ranges, it's a static allow/drop */
	      if (mp->drop)
		dp->flags = MACTIME_DEVICE_FLAG_STATIC_DROP;
	      if (mp->allow)
		dp->flags = MACTIME_DEVICE_FLAG_STATIC_ALLOW;
	    }

	  /* Add the hash table entry */
	  kv.value = dp - mm->devices;
	  clib_bihash_add_del_8_8 (lut, &kv, 1 /* is_add */ );
	}
      else			/* add more ranges */
	{
	  dp = pool_elt_at_index (mm->devices, kv.value);
	  for (i = 0; i < clib_net_to_host_u32 (mp->count); i++)
	    {
	      clib_timebase_range_t _r, *r = &_r;
	      r->start = mp->ranges[i].start;
	      r->end = mp->ranges[i].end;
	      vec_add1 (dp->ranges, r[0]);
	    }
	}
    }
  else				/* delete case */
    {
      if (found == 0)
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto reply;
	}

      /* find the device entry */
      dp = pool_elt_at_index (mm->devices, kv.value);

      /* Remove it from the lookup table */
      clib_bihash_add_del_8_8 (lut, &kv, 0 /* is_add */ );
      vec_free (dp->ranges);
      pool_put (mm->devices, dp);
    }

reply:
  REPLY_MACRO (VL_API_MACTIME_ADD_DEL_RANGE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
mactime_plugin_api_hookup (vlib_main_t * vm)
{
  mactime_main_t *mm = &mactime_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_mactime_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <mactime/mactime_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (mactime_main_t * mm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_mactime;
#undef _
}

static clib_error_t *
mactime_init (vlib_main_t * vm)
{
  mactime_main_t *mm = &mactime_main;
  clib_error_t *error = 0;
  u8 *name;

  mm->vlib_main = vm;
  mm->vnet_main = vnet_get_main ();

  name = format (0, "mactime_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = mactime_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (mm, &api_main);

  vec_free (name);

  mm->lookup_table_num_buckets = MACTIME_NUM_BUCKETS;
  mm->lookup_table_memory_size = MACTIME_MEMORY_SIZE;
  mm->timezone_offset = -5;	/* US EST / EDT */
  return error;
}

VLIB_INIT_FUNCTION (mactime_init);

static clib_error_t *
mactime_config (vlib_main_t * vm, unformat_input_t * input)
{
  mactime_main_t *mm = &mactime_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "lookup-table-buckets %u",
		    &mm->lookup_table_num_buckets))
	;
      else if (unformat (input, "lookup-table-memory %U",
			 unformat_memory_size, &mm->lookup_table_memory_size))
	;
      else if (unformat (input, "timezone_offset %d", &mm->timezone_offset))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (mactime_config, "mactime");

/* *INDENT-OFF* */
VNET_FEATURE_INIT (mactime, static) =
{
  .arc_name = "device-input",
  .node_name = "mactime",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (mactime_tx, static) =
{
  .arc_name = "interface-output",
  .node_name = "mactime-tx",
  .runs_before = VNET_FEATURES ("interface-tx"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Time-based MAC source-address filter",
};
/* *INDENT-ON* */

static clib_error_t *
show_mactime_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mactime_main_t *mm = &mactime_main;
  mactime_device_t *dp;
  u8 *macstring = 0;
  char *status_string;
  u32 *pool_indices = 0;
  int verbose = 0;
  int current_status = 99;
  int i, j;
  f64 now;
  vlib_counter_t allow, drop;
  ethernet_arp_ip4_entry_t *n, *pool;

  vec_reset_length (mm->arp_cache_copy);
  pool = ip4_neighbors_pool ();

  /* *INDENT-OFF* */
  pool_foreach (n, pool,
  ({
    vec_add1 (mm->arp_cache_copy, n[0]);
  }));
  /* *INDENT-ON* */

  now = clib_timebase_now (&mm->timebase);

  if (PREDICT_FALSE ((now - mm->sunday_midnight) > 86400.0 * 7.0))
    mm->sunday_midnight = clib_timebase_find_sunday_midnight (now);

  if (unformat (input, "verbose %d", &verbose))
    ;

  if (unformat (input, "verbose"))
    verbose = 1;

  if (verbose)
    vlib_cli_output (vm, "Time now: %U", format_clib_timebase_time, now);

  /* *INDENT-OFF* */
  pool_foreach (dp, mm->devices,
  ({
    vec_add1 (pool_indices, dp - mm->devices);
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "%-15s %18s %14s %10s %10s %10s",
		   "Device Name", "Addresses", "Status",
		   "AllowPkt", "AllowByte", "DropPkt");

  for (i = 0; i < vec_len (pool_indices); i++)
    {
      dp = pool_elt_at_index (mm->devices, pool_indices[i]);

      /* Check dynamic ranges */
      for (j = 0; j < vec_len (dp->ranges); j++)
	{
	  clib_timebase_range_t *r = dp->ranges + j;
	  f64 start0, end0;

	  start0 = r->start + mm->sunday_midnight;
	  end0 = r->end + mm->sunday_midnight;
	  if (verbose > 1)
	    vlib_cli_output (vm, "  Range %d: %U - %U", j,
			     format_clib_timebase_time, start0,
			     format_clib_timebase_time, end0);

	  if (now >= start0 && now <= end0)
	    {
	      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
		current_status = 3;
	      else
		current_status = 2;
	      if (verbose)
		{
		  vlib_cli_output (vm, "  Time in range %d:", j);
		  vlib_cli_output (vm, "     %U - %U",
				   format_clib_timebase_time, start0,
				   format_clib_timebase_time, end0);
		}
	      goto print;
	    }
	}
      if (verbose && j)
	vlib_cli_output (vm, "  No range match.");
      if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_DROP)
	current_status = 0;
      if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_ALLOW)
	current_status = 1;
      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
	current_status = 2;
      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_DROP)
	current_status = 3;

    print:
      vec_reset_length (macstring);
      macstring = format (0, "%U", format_mac_address, dp->mac_address);
      switch (current_status)
	{
	case 0:
	  status_string = "static drop";
	  break;
	case 1:
	  status_string = "static allow";
	  break;
	case 2:
	  status_string = "dynamic drop";
	  break;
	case 3:
	  status_string = "dynamic allow";
	  break;
	default:
	  status_string = "code bug!";
	  break;
	}
      vlib_get_combined_counter (&mm->allow_counters, dp - mm->devices,
				 &allow);
      vlib_get_combined_counter (&mm->drop_counters, dp - mm->devices, &drop);
      vlib_cli_output (vm, "%-15s %18s %14s %10lld %10lld %10lld",
		       dp->device_name, macstring, status_string,
		       allow.packets, allow.bytes, drop.packets);
      /* This is really only good for small N... */
      for (j = 0; j < vec_len (mm->arp_cache_copy); j++)
	{
	  n = mm->arp_cache_copy + j;
	  if (!memcmp (dp->mac_address, n->ethernet_address,
		       sizeof (n->ethernet_address)))
	    {
	      vlib_cli_output (vm, "%17s%U", " ", format_ip4_address,
			       &n->ip4_address);
	    }
	}
    }
  vec_free (macstring);
  vec_free (pool_indices);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_mactime_command, static) =
{
  .path = "show mactime",
  .short_help = "show mactime [verbose]",
  .function = show_mactime_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
clear_mactime_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mactime_main_t *mm = &mactime_main;

  if (mm->feature_initialized == 0)
    return clib_error_return (0, "feature not enabled");

  vlib_clear_combined_counters (&mm->allow_counters);
  vlib_clear_combined_counters (&mm->drop_counters);
  vlib_cli_output (vm, "Mactime counters cleared...");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_mactime_command, static) =
{
  .path = "clear mactime",
  .short_help = "clear mactime counters",
  .function = clear_mactime_command_fn,
};
/* *INDENT-ON* */



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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
#include <vnet/format_fns.h>
#include <mactime/mactime.api_enum.h>
#include <mactime/mactime.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <vnet/ip-neighbor/ip_neighbor.h>

mactime_main_t mactime_main;

/** \file mactime.c
 * time-base src-mac filter device-input feature arc implementation
 */

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
			  CLIB_TIMEBASE_DAYLIGHT_USA,
			  &(mm->vlib_main->clib_time));
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
  static u8 url_init_done;

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
  if (url_init_done == 0)
    {
      mactime_url_init (mm->vlib_main);
      url_init_done = 1;
    }

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
      else if (unformat (input, "sw_if_index %d", &sw_if_index))
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

static void
vl_api_mactime_dump_t_handler (vl_api_mactime_dump_t * mp)
{
  vl_api_mactime_details_t *ep;
  vl_api_mactime_dump_reply_t *rmp;
  mactime_device_t *dev;
  mactime_main_t *mm = &mactime_main;
  vl_api_registration_t *rp;
  int rv = 0, i;
  u32 his_table_epoch = clib_net_to_host_u32 (mp->my_table_epoch);
  u32 message_size;
  u32 name_len;
  u32 nranges;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  if (his_table_epoch == mm->device_table_epoch)
    {
      rv = VNET_API_ERROR_NO_CHANGE;
      goto send_reply;
    }

  /* *INDENT-OFF* */
  pool_foreach (dev, mm->devices)
   {
    message_size = sizeof(*ep) + vec_len(dev->device_name) +
      vec_len(dev->ranges) * sizeof(ep->ranges[0]);

    ep = vl_msg_api_alloc (message_size);
    memset (ep, 0, message_size);
    ep->_vl_msg_id = clib_host_to_net_u16 (VL_API_MACTIME_DETAILS
                                           + mm->msg_id_base);
    ep->context = mp->context;
    /* Index is the key for the stats segment combined counters */
    ep->pool_index = clib_host_to_net_u32 (dev - mm->devices);

    clib_memcpy_fast (ep->mac_address, dev->mac_address,
                      sizeof (ep->mac_address));
    ep->data_quota = clib_host_to_net_u64 (dev->data_quota);
    ep->data_used_in_range = clib_host_to_net_u64 (dev->data_used_in_range);
    ep->flags = clib_host_to_net_u32 (dev->flags);
    nranges = vec_len (dev->ranges);
    ep->nranges = clib_host_to_net_u32 (nranges);

    for (i = 0; i < vec_len (dev->ranges); i++)
      {
        ep->ranges[i].start = dev->ranges[i].start;
        ep->ranges[i].end = dev->ranges[i].end;
      }

    name_len = vec_len (dev->device_name);
    name_len = (name_len < ARRAY_LEN(ep->device_name)) ?
      name_len : ARRAY_LEN(ep->device_name) - 1;

    clib_memcpy_fast (ep->device_name, dev->device_name,
                      name_len);
    ep->device_name [ARRAY_LEN(ep->device_name) -1] = 0;
    vl_api_send_msg (rp, (u8 *)ep);
  }
  /* *INDENT-OFF* */

 send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_MACTIME_DUMP_REPLY,
  ({
    rmp->table_epoch = clib_host_to_net_u32 (mm->device_table_epoch);
  }));
  /* *INDENT-ON* */
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

  am = vlibapi_get_main ();
  shmem_hdr = am->shmem_hdr;
  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
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
  u64 data_quota;
  int i, rv = 0;

  feature_init (mm);

  /*
   * Change the table epoch. Skip 0 so clients can code my_table_epoch = 0
   * to receive a full dump.
   */
  mm->device_table_epoch++;
  if (PREDICT_FALSE (mm->device_table_epoch == 0))
    mm->device_table_epoch++;

  data_quota = clib_net_to_host_u64 (mp->data_quota);

  clib_memset (&kv, 0, sizeof (kv));
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
	  clib_memset (dp, 0, sizeof (*dp));
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
	      if (mp->allow_quota)
		dp->flags = MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA;
	    }
	  else
	    {
	      /* no ranges, it's a static allow/drop */
	      if (mp->drop)
		dp->flags = MACTIME_DEVICE_FLAG_STATIC_DROP;
	      if (mp->allow)
		dp->flags = MACTIME_DEVICE_FLAG_STATIC_ALLOW;
	    }
	  if (mp->no_udp_10001)
	    dp->flags |= MACTIME_DEVICE_FLAG_DROP_UDP_10001;

	  dp->data_quota = data_quota;

	  /* Add the hash table entry */
	  kv.value = dp - mm->devices;
	  clib_bihash_add_del_8_8 (lut, &kv, 1 /* is_add */ );
	}
      else			/* add more ranges, flags, etc. */
	{
	  dp = pool_elt_at_index (mm->devices, kv.value);

	  for (i = 0; i < clib_net_to_host_u32 (mp->count); i++)
	    {
	      clib_timebase_range_t _r, *r = &_r;
	      r->start = mp->ranges[i].start;
	      r->end = mp->ranges[i].end;
	      vec_add1 (dp->ranges, r[0]);
	    }

	  if (vec_len (dp->ranges))
	    {
	      /* Set allow/drop based on msg flags */
	      if (mp->drop)
		dp->flags = MACTIME_DEVICE_FLAG_DYNAMIC_DROP;
	      if (mp->allow)
		dp->flags = MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW;
	      if (mp->allow_quota)
		dp->flags = MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA;
	    }
	  else
	    {
	      /* no ranges, it's a static allow/drop */
	      if (mp->drop)
		dp->flags = MACTIME_DEVICE_FLAG_STATIC_DROP;
	      if (mp->allow)
		dp->flags = MACTIME_DEVICE_FLAG_STATIC_ALLOW;
	    }
	  if (mp->no_udp_10001)
	    dp->flags |= MACTIME_DEVICE_FLAG_DROP_UDP_10001;

	  dp->data_quota = data_quota;
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

#include <mactime/mactime.api.c>
static clib_error_t *
mactime_init (vlib_main_t * vm)
{
  mactime_main_t *mm = &mactime_main;

  mm->vlib_main = vm;
  mm->vnet_main = vnet_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base = setup_message_id_table ();

  mm->lookup_table_num_buckets = MACTIME_NUM_BUCKETS;
  mm->lookup_table_memory_size = MACTIME_MEMORY_SIZE;
  mm->timezone_offset = -5;	/* US EST / EDT */
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (mactime_init) =
{
  .runs_after = VLIB_INITS("ip_neighbor_init"),
};
/* *INDENT-ON* */

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
VNET_FEATURE_INIT (mactime_tx, static) = {
  .arc_name = "interface-output",
  .node_name = "mactime-tx",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Time-based MAC Source Address Filter",
};
/* *INDENT-ON* */

u8 *
format_bytes_with_width (u8 * s, va_list * va)
{
  uword nbytes = va_arg (*va, u64);
  int width = va_arg (*va, int);
  f64 nbytes_f64;
  u8 *fmt;
  char *suffix = "";

  if (width > 0)
    fmt = format (0, "%%%d.3f%%s%c", width, 0);
  else
    fmt = format (0, "%%.3f%%s%c", 0);

  if (nbytes > (1024ULL * 1024ULL * 1024ULL))
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0 * 1024.0 * 1024.0);
      suffix = "G";
    }
  else if (nbytes > (1024ULL * 1024ULL))
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0 * 1024.0);
      suffix = "M";
    }
  else if (nbytes > 1024ULL)
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0);
      suffix = "K";
    }
  else
    {
      nbytes_f64 = (f64) nbytes;
      suffix = "B";
    }

  s = format (s, (char *) fmt, nbytes_f64, suffix);
  vec_free (fmt);
  return s;
}

static walk_rc_t
mactime_ip_neighbor_copy (index_t ipni, void *ctx)
{
  mactime_main_t *mm = ctx;

  vec_add1 (mm->arp_cache_copy, ipni);

  return (WALK_CONTINUE);
}

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
  ip_neighbor_t *ipn;

  if (mm->feature_initialized == 0)
    return clib_error_return
      (0,
       "Feature not initialized, suggest 'help mactime enable-disable'...");

  vec_reset_length (mm->arp_cache_copy);
  /* Walk all ip4 neighbours on all interfaces */
  ip_neighbor_walk (AF_IP4, ~0, mactime_ip_neighbor_copy, mm);

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
  pool_foreach (dp, mm->devices)
   {
    vec_add1 (pool_indices, dp - mm->devices);
  }
  /* *INDENT-ON* */

  vlib_cli_output (vm, "%-15s %18s %14s %10s %11s %13s",
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
	      else if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
		current_status = 5;
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
      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
	current_status = 4;

    print:
      vec_reset_length (macstring);
      macstring =
	format (macstring, "%U", format_mac_address, dp->mac_address);
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
	case 4:
	  status_string = "d-quota inact";
	  break;
	case 5:
	  status_string = "d-quota activ";
	  break;
	default:
	  status_string = "code bug!";
	  break;
	}
      vlib_get_combined_counter (&mm->allow_counters, dp - mm->devices,
				 &allow);
      vlib_get_combined_counter (&mm->drop_counters, dp - mm->devices, &drop);
      vlib_cli_output (vm, "%-15s %18s %14s %10lld %U %13lld",
		       dp->device_name, macstring, status_string,
		       allow.packets, format_bytes_with_width, allow.bytes,
		       10, drop.packets);
      if (dp->data_quota > 0)
	vlib_cli_output (vm, "%-54s %s%U %s%U", " ", "Quota ",
			 format_bytes_with_width, dp->data_quota, 10,
			 "Use ", format_bytes_with_width,
			 dp->data_used_in_range, 8);
      /* This is really only good for small N... */
      for (j = 0; j < vec_len (mm->arp_cache_copy); j++)
	{
	  ipn = ip_neighbor_get (mm->arp_cache_copy[j]);
	  if (!memcmp
	      (dp->mac_address, ipn->ipn_mac.bytes, sizeof (ipn->ipn_mac)))
	    {
	      vlib_cli_output (vm, "%17s%U", " ", format_ip46_address,
			       ip_neighbor_get_ip (ipn), IP46_TYPE_IP4);
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
    return clib_error_return
      (0,
       "Feature not initialized, suggest 'help mactime enable-disable'...");

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

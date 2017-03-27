/*
 * l2_fib.c : layer 2 forwarding table (aka mac table)
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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


#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/cli.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_learn.h>
#include <vnet/l2/l2_bd.h>

#include <vppinfra/bihash_template.c>

/**
 * @file
 * @brief Ethernet MAC Address FIB Table Management.
 *
 * The MAC Address forwarding table for bridge-domains is called the l2fib.
 * Entries are added automatically as part of mac learning, but MAC Addresses
 * entries can also be added manually.
 *
 */

typedef struct
{

  /* hash table */
  BVT (clib_bihash) mac_table;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2fib_main_t;

l2fib_main_t l2fib_main;


/** Format sw_if_index. If the value is ~0, use the text "N/A" */
u8 *
format_vnet_sw_if_index_name_with_NA (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 sw_if_index = va_arg (*args, u32);
  if (sw_if_index == ~0)
    return format (s, "N/A");
  else
    return format (s, "%U",
		   format_vnet_sw_interface_name, vnm,
		   vnet_get_sw_interface (vnm, sw_if_index));
}

void
l2fib_table_dump (u32 bd_index, l2fib_entry_key_t ** l2fe_key,
		  l2fib_entry_result_t ** l2fe_res)
{
  l2fib_main_t *msm = &l2fib_main;
  BVT (clib_bihash) * h = &msm->mac_table;
  clib_bihash_bucket_t *b;
  BVT (clib_bihash_value) * v;
  l2fib_entry_key_t key;
  l2fib_entry_result_t result;
  int i, j, k;

  for (i = 0; i < h->nbuckets; i++)
    {
      b = &h->buckets[i];
      if (b->offset == 0)
	continue;
      v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (v->kvp[k].key == ~0ULL && v->kvp[k].value == ~0ULL)
		continue;

	      key.raw = v->kvp[k].key;
	      result.raw = v->kvp[k].value;

	      if ((bd_index == ~0) || (bd_index == key.fields.bd_index))
		{
		  vec_add1 (*l2fe_key, key);
		  vec_add1 (*l2fe_res, result);
		}
	    }
	  v++;
	}
    }
}

/** Display the contents of the l2fib. */
static clib_error_t *
show_l2fib (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  l2fib_main_t *msm = &l2fib_main;
  l2_bridge_domain_t *bd_config;
  BVT (clib_bihash) * h = &msm->mac_table;
  clib_bihash_bucket_t *b;
  BVT (clib_bihash_value) * v;
  l2fib_entry_key_t key;
  l2fib_entry_result_t result;
  u32 first_entry = 1;
  u64 total_entries = 0;
  int i, j, k;
  u8 verbose = 0;
  u8 raw = 0;
  u32 bd_id, bd_index = ~0;
  u8 now = (u8) (vlib_time_now (vm) / 60);
  u8 *s = 0;

  if (unformat (input, "raw"))
    raw = 1;
  else if (unformat (input, "verbose"))
    verbose = 1;
  else if (unformat (input, "bd_index %d", &bd_index))
    verbose = 1;
  else if (unformat (input, "bd_id %d", &bd_id))
    {
      uword *p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p)
	{
	  verbose = 1;
	  bd_index = p[0];
	}
      else
	{
	  vlib_cli_output (vm, "no such bridge domain id");
	  return 0;
	}
    }

  for (i = 0; i < h->nbuckets; i++)
    {
      b = &h->buckets[i];
      if (b->offset == 0)
	continue;
      v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (v->kvp[k].key == ~0ULL && v->kvp[k].value == ~0ULL)
		continue;

	      if (verbose && first_entry)
		{
		  first_entry = 0;
		  vlib_cli_output (vm,
				   "%=19s%=7s%=7s%=8s%=9s%=7s%=7s%=5s%=30s",
				   "Mac-Address", "BD-Idx", "If-Idx",
				   "BSN-ISN", "Age(min)", "static", "filter",
				   "bvi", "Interface-Name");
		}

	      key.raw = v->kvp[k].key;
	      result.raw = v->kvp[k].value;

	      if (verbose
		  & ((bd_index >> 31) || (bd_index == key.fields.bd_index)))
		{
		  bd_config = vec_elt_at_index (l2input_main.bd_configs,
						key.fields.bd_index);

		  if (bd_config->mac_age && !result.fields.static_mac)
		    {
		      i16 delta = now - result.fields.timestamp;
		      delta += delta < 0 ? 256 : 0;
		      s = format (s, "%d", delta);
		    }
		  else
		    s = format (s, "-");

		  vlib_cli_output (vm,
				   "%=19U%=7d%=7d %3d/%-3d%=9v%=7s%=7s%=5s%=30U",
				   format_ethernet_address, key.fields.mac,
				   key.fields.bd_index,
				   result.fields.sw_if_index == ~0
				   ? -1 : result.fields.sw_if_index,
				   result.fields.bd_sn, result.fields.int_sn,
				   s, result.fields.static_mac ? "*" : "-",
				   result.fields.filter ? "*" : "-",
				   result.fields.bvi ? "*" : "-",
				   format_vnet_sw_if_index_name_with_NA,
				   msm->vnet_main, result.fields.sw_if_index);
		  vec_reset_length (s);
		}
	      total_entries++;
	    }
	  v++;
	}
    }

  if (total_entries == 0)
    vlib_cli_output (vm, "no l2fib entries");
  else
    vlib_cli_output (vm, "%lld l2fib entries", total_entries);

  if (raw)
    vlib_cli_output (vm, "Raw Hash Table:\n%U\n",
		     BV (format_bihash), h, 1 /* verbose */ );

  vec_free (s);
  return 0;
}

/*?
 * This command dispays the MAC Address entries of the L2 FIB table.
 * Output can be filtered to just get the number of MAC Addresses or display
 * each MAC Address for all bridge domains or just a single bridge domain.
 *
 * @cliexpar
 * Example of how to display the number of MAC Address entries in the L2
 * FIB table:
 * @cliexstart{show l2fib}
 * 3 l2fib entries
 * @cliexend
 * Example of how to display all the MAC Address entries in the L2
 * FIB table:
 * @cliexstart{show l2fib verbose}
 *     Mac Address     BD Idx           Interface           Index  static  filter  bvi  refresh  timestamp
 *  52:54:00:53:18:33    1      GigabitEthernet0/8/0.200      3       0       0     0      0         0
 *  52:54:00:53:18:55    1      GigabitEthernet0/8/0.200      3       1       0     0      0         0
 *  52:54:00:53:18:77    1                 N/A                -1      1       1     0      0         0
 * 3 l2fib entries
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_l2fib_cli, static) = {
  .path = "show l2fib",
  .short_help = "show l2fib [verbose | bd_id <nn> | bd_index <nn> | raw]",
  .function = show_l2fib,
};
/* *INDENT-ON* */


/* Remove all entries from the l2fib */
void
l2fib_clear_table (uint keep_static)
{
  l2fib_main_t *mp = &l2fib_main;

  if (keep_static)
    {
      /* TODO: remove only non-static entries */
    }
  else
    {
      /* Remove all entries */
      BV (clib_bihash_free) (&mp->mac_table);
      BV (clib_bihash_init) (&mp->mac_table, "l2fib mac table",
			     L2FIB_NUM_BUCKETS, L2FIB_MEMORY_SIZE);
    }

  l2learn_main.global_learn_count = 0;
}

/** Clear all entries in L2FIB.
 * @TODO: Later we may want a way to remove only the non-static entries
 */
static clib_error_t *
clear_l2fib (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2fib_clear_table (0);
  return 0;
}

/*?
 * This command clears all the MAC Address entries from the L2 FIB table.
 *
 * @cliexpar
 * Example of how to clear the L2 FIB Table:
 * @cliexcmd{clear l2fib}
 * Example to show the L2 FIB Table has been cleared:
 * @cliexstart{show l2fib verbose}
 * no l2fib entries
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_l2fib_cli, static) = {
  .path = "clear l2fib",
  .short_help = "clear l2fib",
  .function = clear_l2fib,
};
/* *INDENT-ON* */


/**
 * Add an entry to the l2fib.
 * If the entry already exists then overwrite it
 */
void
l2fib_add_entry (u64 mac,
		 u32 bd_index,
		 u32 sw_if_index, u32 static_mac, u32 filter_mac, u32 bvi_mac)
{
  l2fib_entry_key_t key;
  l2fib_entry_result_t result;
  __attribute__ ((unused)) u32 bucket_contents;
  l2fib_main_t *mp = &l2fib_main;
  BVT (clib_bihash_kv) kv;

  /* set up key */
  key.raw = l2fib_make_key ((u8 *) & mac, bd_index);

  /* set up result */
  result.raw = 0;		/* clear all fields */
  result.fields.sw_if_index = sw_if_index;
  result.fields.static_mac = static_mac;
  result.fields.filter = filter_mac;
  result.fields.bvi = bvi_mac;
  if (!static_mac)
    {
      l2_input_config_t *int_config = l2input_intf_config (sw_if_index);
      l2_bridge_domain_t *bd_config =
	vec_elt_at_index (l2input_main.bd_configs,
			  bd_index);
      result.fields.int_sn = int_config->seq_num;
      result.fields.bd_sn = bd_config->seq_num;
    }

  kv.key = key.raw;
  kv.value = result.raw;

  BV (clib_bihash_add_del) (&mp->mac_table, &kv, 1 /* is_add */ );

  /* increment counter if dynamically learned mac */
  if (result.fields.static_mac)
    {
      l2learn_main.global_learn_count++;
    }
}

/**
 * Add an entry to the L2FIB.
 * The CLI format is:
 *    l2fib add <mac> <bd> <intf> [static] [bvi]
 *    l2fib add <mac> <bd> filter
 * Note that filter and bvi entries are always static
 */
static clib_error_t *
l2fib_add (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u64 mac;
  u32 bd_id;
  u32 bd_index;
  u32 sw_if_index = ~0;
  u32 filter_mac = 0;
  u32 static_mac = 0;
  u32 bvi_mac = 0;
  uword *p;

  if (!unformat_user (input, unformat_ethernet_address, &mac))
    {
      error = clib_error_return (0, "expected mac address `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expected bridge domain ID `%U'",
				 format_unformat_error, input);
      goto done;
    }

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (!p)
    {
      error = clib_error_return (0, "bridge domain ID %d invalid", bd_id);
      goto done;
    }
  bd_index = p[0];

  if (unformat (input, "filter"))
    {
      filter_mac = 1;
      static_mac = 1;

    }
  else
    {

      if (!unformat_user
	  (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  error = clib_error_return (0, "unknown interface `%U'",
				     format_unformat_error, input);
	  goto done;
	}
      if (unformat (input, "static"))
	{
	  static_mac = 1;
	}
      else if (unformat (input, "bvi"))
	{
	  bvi_mac = 1;
	  static_mac = 1;
	}
    }

  l2fib_add_entry (mac, bd_index, sw_if_index, static_mac, filter_mac,
		   bvi_mac);

done:
  return error;
}

/*?
 * This command adds a MAC Address entry to the L2 FIB table
 * of an existing bridge-domain. The MAC Address can be static
 * or dynamic. This command also allows a filter to be added,
 * such that packets with given MAC Addresses (source mac or
 * destination mac match) are dropped.
 *
 * @cliexpar
 * Example of how to add a dynamic MAC Address entry to the L2 FIB table
 * of a bridge-domain (where 200 is the bridge-domain-id):
 * @cliexcmd{l2fib add 52:54:00:53:18:33 200 GigabitEthernet0/8/0.200}
 * Example of how to add a static MAC Address entry to the L2 FIB table
 * of a bridge-domain (where 200 is the bridge-domain-id):
 * @cliexcmd{l2fib add 52:54:00:53:18:55 200 GigabitEthernet0/8/0.200 static}
 * Example of how to add a filter such that a packet with the given MAC
 * Address will be dropped in a given bridge-domain (where 200 is the
 * bridge-domain-id):
 * @cliexcmd{l2fib add 52:54:00:53:18:77 200 filter}
 * Example of show command of the provisioned MAC Addresses and filters:
 * @cliexstart{show l2fib verbose}
 *     Mac Address     BD Idx           Interface           Index  static  filter  bvi  refresh  timestamp
 *  52:54:00:53:18:33    1      GigabitEthernet0/8/0.200      3       0       0     0      0         0
 *  52:54:00:53:18:55    1      GigabitEthernet0/8/0.200      3       1       0     0      0         0
 *  52:54:00:53:18:77    1                 N/A                -1      1       1     0      0         0
 * 3 l2fib entries
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_add_cli, static) = {
  .path = "l2fib add",
  .short_help = "l2fib add <mac> <bridge-domain-id> filter | <intf> [static | bvi]",
  .function = l2fib_add,
};
/* *INDENT-ON* */


static clib_error_t *
l2fib_test_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u64 mac, save_mac;
  u32 bd_index = 0;
  u32 sw_if_index = 8;
  u32 filter_mac = 0;
  u32 bvi_mac = 0;
  u32 is_add = 0;
  u32 is_del = 0;
  u32 is_check = 0;
  u32 count = 1;
  int mac_set = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mac %U", unformat_ethernet_address, &mac))
	mac_set = 1;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "check"))
	is_check = 1;
      else if (unformat (input, "count %d", &count))
	;
      else
	break;
    }

  if (mac_set == 0)
    return clib_error_return (0, "mac not set");

  if (is_add == 0 && is_del == 0 && is_check == 0)
    return clib_error_return (0,
			      "noop: pick at least one of (add,del,check)");

  save_mac = mac;

  if (is_add)
    {
      for (i = 0; i < count; i++)
	{
	  u64 tmp;
	  l2fib_add_entry (mac, bd_index, sw_if_index, mac,
			   filter_mac, bvi_mac);
	  tmp = clib_net_to_host_u64 (mac);
	  tmp >>= 16;
	  tmp++;
	  tmp <<= 16;
	  mac = clib_host_to_net_u64 (tmp);
	}
    }

  if (is_check)
    {
      BVT (clib_bihash_kv) kv;
      l2fib_main_t *mp = &l2fib_main;

      mac = save_mac;

      for (i = 0; i < count; i++)
	{
	  u64 tmp;
	  kv.key = l2fib_make_key ((u8 *) & mac, bd_index);
	  if (BV (clib_bihash_search) (&mp->mac_table, &kv, &kv))
	    {
	      clib_warning ("key %U AWOL", format_ethernet_address, &mac);
	      break;
	    }
	  tmp = clib_net_to_host_u64 (mac);
	  tmp >>= 16;
	  tmp++;
	  tmp <<= 16;
	  mac = clib_host_to_net_u64 (tmp);
	}
    }

  if (is_del)
    {
      for (i = 0; i < count; i++)
	{
	  u64 tmp;

	  l2fib_del_entry (mac, bd_index);

	  tmp = clib_net_to_host_u64 (mac);
	  tmp >>= 16;
	  tmp++;
	  tmp <<= 16;
	  mac = clib_host_to_net_u64 (tmp);
	}
    }

  return error;
}

/*?
 * The set of '<em>test l2fib</em>' commands allow the L2 FIB table of the default
 * bridge domain (bridge-domain-id of 0) to be modified.
 *
 * @cliexpar
 * @parblock
 * Example of how to add a set of 4 sequential MAC Address entries to L2
 * FIB table of the default bridge-domain:
 * @cliexcmd{test l2fib add mac 52:54:00:53:00:00 count 4}
 *
 * Show the set of 4 sequential MAC Address entries that were added:
 * @cliexstart{show l2fib verbose}
 *     Mac Address     BD Idx           Interface           Index  static  filter  bvi  refresh  timestamp
 * 52:54:00:53:00:00    0       GigabitEthernet0/8/0.300     8       0       0     0      0         0
 * 52:54:00:53:00:01    0       GigabitEthernet0/8/0.300     8       0       0     0      0         0
 * 52:54:00:53:00:03    0       GigabitEthernet0/8/0.300     8       0       0     0      0         0
 * 52:54:00:53:00:02    0       GigabitEthernet0/8/0.300     8       0       0     0      0         0
 * 4 l2fib entries
 * @cliexend
 *
 * Example of how to check that the set of 4 sequential MAC Address
 * entries were added to L2 FIB table of the default
 * bridge-domain. Used a count of 5 to produce an error:
 *
 * @cliexcmd{test l2fib check mac 52:54:00:53:00:00 count 5}
 * The output of the check command is in the log files. Log file
 * location may vary based on your OS and Version:
 *
 * <b><em># tail -f /var/log/messages | grep l2fib_test_command_fn</em></b>
 *
 * Sep  7 17:15:24 localhost vnet[4952]: l2fib_test_command_fn:446: key 52:54:00:53:00:04 AWOL
 *
 * Example of how to delete a set of 4 sequential MAC Address entries
 * from L2 FIB table of the default bridge-domain:
 * @cliexcmd{test l2fib del mac 52:54:00:53:00:00 count 4}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_test_command, static) = {
  .path = "test l2fib",
  .short_help = "test l2fib [add|del|check] mac <base-addr> count <nn>",
  .function = l2fib_test_command_fn,
};
/* *INDENT-ON* */


/**
 * Delete an entry from the l2fib.
 * Return 0 if the entry was deleted, or 1 if it was not found
 */
u32
l2fib_del_entry (u64 mac, u32 bd_index)
{

  l2fib_entry_result_t result;
  l2fib_main_t *mp = &l2fib_main;
  BVT (clib_bihash_kv) kv;

  /* set up key */
  kv.key = l2fib_make_key ((u8 *) & mac, bd_index);

  if (BV (clib_bihash_search) (&mp->mac_table, &kv, &kv))
    return 1;

  result.raw = kv.value;

  /* decrement counter if dynamically learned mac */
  if (result.fields.static_mac)
    {
      if (l2learn_main.global_learn_count > 0)
	{
	  l2learn_main.global_learn_count--;
	}
    }

  /* Remove entry from hash table */
  BV (clib_bihash_add_del) (&mp->mac_table, &kv, 0 /* is_add */ );
  return 0;
}

/**
 * Delete an entry from the L2FIB.
 * The CLI format is:
 *    l2fib del <mac> <bd-id>
 */
static clib_error_t *
l2fib_del (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u64 mac;
  u32 bd_id;
  u32 bd_index;
  uword *p;

  if (!unformat_user (input, unformat_ethernet_address, &mac))
    {
      error = clib_error_return (0, "expected mac address `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expected bridge domain ID `%U'",
				 format_unformat_error, input);
      goto done;
    }

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (!p)
    {
      error = clib_error_return (0, "bridge domain ID %d invalid", bd_id);
      goto done;
    }
  bd_index = p[0];

  /* Delete the entry */
  if (l2fib_del_entry (mac, bd_index))
    {
      error = clib_error_return (0, "mac entry not found");
      goto done;
    }

done:
  return error;
}

/*?
 * This command deletes an existing MAC Address entry from the L2 FIB
 * table of an existing bridge-domain.
 *
 * @cliexpar
 * Example of how to delete a MAC Address entry from the L2 FIB table of a bridge-domain (where 200 is the bridge-domain-id):
 * @cliexcmd{l2fib del 52:54:00:53:18:33 200}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_del_cli, static) = {
  .path = "l2fib del",
  .short_help = "l2fib del <mac> <bridge-domain-id>",
  .function = l2fib_del,
};
/* *INDENT-ON* */

/**
    Kick off ager to scan MACs to age/delete MAC entries
*/
void
l2fib_start_ager_scan (vlib_main_t * vm)
{
  l2_bridge_domain_t *bd_config;
  int enable = 0;

  /* check if there is at least one bd with mac aging enabled */
  vec_foreach (bd_config, l2input_main.bd_configs)
    if (bd_config->bd_id != ~0 && bd_config->mac_age != 0)
    enable = 1;

  vlib_process_signal_event (vm, l2fib_mac_age_scanner_process_node.index,
			     enable ? L2_MAC_AGE_PROCESS_EVENT_START :
			     L2_MAC_AGE_PROCESS_EVENT_ONE_PASS, 0);
}

/**
    Flush all learned MACs from an interface
*/
void
l2fib_flush_int_mac (vlib_main_t * vm, u32 sw_if_index)
{
  l2_input_config_t *int_config;
  int_config = l2input_intf_config (sw_if_index);
  int_config->seq_num += 1;
  l2fib_start_ager_scan (vm);
}

/**
    Flush all learned MACs in a bridge domain
*/
void
l2fib_flush_bd_mac (vlib_main_t * vm, u32 bd_index)
{
  l2_bridge_domain_t *bd_config;
  vec_validate (l2input_main.bd_configs, bd_index);
  bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
  bd_config->seq_num += 1;
  l2fib_start_ager_scan (vm);
}

/**
    Flush MACs, except static ones, associated with an interface
    The CLI format is:
    l2fib flush-mac interface <if-name>
*/
static clib_error_t *
l2fib_flush_mac_int (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  l2fib_flush_int_mac (vm, sw_if_index);

done:
  return error;
}

/*?
 * This command kick off ager to delete all existing MAC Address entries,
 * except static ones, associated with an interface from the L2 FIB table.
 *
 * @cliexpar
 * Example of how to flush MAC Address entries learned on an interface from the L2 FIB table:
 * @cliexcmd{l2fib flush-mac interface GigabitEthernet2/1/0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_flush_mac_int_cli, static) = {
  .path = "l2fib flush-mac interface",
  .short_help = "l2fib flush-mac interface <if-name>",
  .function = l2fib_flush_mac_int,
};
/* *INDENT-ON* */

/**
    Flush bridge-domain MACs except static ones.
    The CLI format is:
    l2fib flush-mac bridge-domain <bd-id>
*/
static clib_error_t *
l2fib_flush_mac_bd (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p)
    bd_index = *p;
  else
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  l2fib_flush_bd_mac (vm, bd_index);

done:
  return error;
}

/*?
 * This command kick off ager to delete all existing MAC Address entries,
 * except static ones, in a bridge domain from the L2 FIB table.
 *
 * @cliexpar
 * Example of how to flush MAC Address entries learned in a bridge domain from the L2 FIB table:
 * @cliexcmd{l2fib flush-mac bridge-domain 1000}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_flush_mac_bd_cli, static) = {
  .path = "l2fib flush-mac bridge-domain",
  .short_help = "l2fib flush-mac bridge-domain <bd-id>",
  .function = l2fib_flush_mac_bd,
};
/* *INDENT-ON* */


BVT (clib_bihash) * get_mac_table (void)
{
  l2fib_main_t *mp = &l2fib_main;
  return &mp->mac_table;
}

static uword
l2fib_mac_age_scanner_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			       vlib_frame_t * f)
{
  uword event_type, *event_data = 0;
  l2fib_main_t *msm = &l2fib_main;
  l2_input_config_t *int_config;
  l2_bridge_domain_t *bd_config;
  BVT (clib_bihash) * h = &msm->mac_table;
  clib_bihash_bucket_t *b;
  BVT (clib_bihash_value) * v;
  l2fib_entry_key_t key;
  l2fib_entry_result_t result;
  int i, j, k;
  bool enabled = 0;
  f64 start_time, last_run_duration = 0, t;
  i16 delta;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, 60 - last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case ~0:
	  break;
	case L2_MAC_AGE_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case L2_MAC_AGE_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	case L2_MAC_AGE_PROCESS_EVENT_ONE_PASS:
	  enabled = 0;
	  break;
	default:
	  ASSERT (0);
	}
      last_run_duration = start_time = vlib_time_now (vm);
      for (i = 0; i < h->nbuckets; i++)
	{
	  /* Allow no more than 10us without a pause */
	  t = vlib_time_now (vm);
	  if (t > start_time + 10e-6)
	    {
	      vlib_process_suspend (vm, 100e-6);	/* suspend for 100 us */
	      start_time = vlib_time_now (vm);
	    }

	  if (i < (h->nbuckets - 3))
	    {
	      b = &h->buckets[i + 3];
	      CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
	      b = &h->buckets[i + 1];
	      if (b->offset)
		{
		  v = BV (clib_bihash_get_value) (h, b->offset);
		  CLIB_PREFETCH (v, CLIB_CACHE_LINE_BYTES, LOAD);
		}
	    }

	  b = &h->buckets[i];
	  if (b->offset == 0)
	    continue;
	  v = BV (clib_bihash_get_value) (h, b->offset);
	  for (j = 0; j < (1 << b->log2_pages); j++)
	    {
	      for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
		{
		  if (v->kvp[k].key == ~0ULL && v->kvp[k].value == ~0ULL)
		    continue;

		  key.raw = v->kvp[k].key;
		  result.raw = v->kvp[k].value;

		  if (result.fields.static_mac)
		    continue;

		  int_config =
		    l2input_intf_config (result.fields.sw_if_index);
		  bd_config =
		    vec_elt_at_index (l2input_main.bd_configs,
				      key.fields.bd_index);

		  if ((result.fields.int_sn != int_config->seq_num) ||
		      (result.fields.bd_sn != bd_config->seq_num))
		    {
		      void *p = &key.fields.mac;
		      l2fib_del_entry (*(u64 *) p, key.fields.bd_index);
		      continue;
		    }

		  if (bd_config->mac_age == 0)
		    continue;

		  delta = (u8) (start_time / 60) - result.fields.timestamp;
		  delta += delta < 0 ? 256 : 0;

		  if (delta > bd_config->mac_age)
		    {
		      void *p = &key.fields.mac;
		      l2fib_del_entry (*(u64 *) p, key.fields.bd_index);
		    }
		}
	      v++;
	    }
	}
      last_run_duration = vlib_time_now (vm) - last_run_duration;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2fib_mac_age_scanner_process_node) = {
    .function = l2fib_mac_age_scanner_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "l2fib-mac-age-scanner-process",
};
/* *INDENT-ON* */

clib_error_t *
l2fib_init (vlib_main_t * vm)
{
  l2fib_main_t *mp = &l2fib_main;
  l2fib_entry_key_t test_key;
  u8 test_mac[6];

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Create the hash table  */
  BV (clib_bihash_init) (&mp->mac_table, "l2fib mac table",
			 L2FIB_NUM_BUCKETS, L2FIB_MEMORY_SIZE);

  /* verify the key constructor is good, since it is endian-sensitive */
  memset (test_mac, 0, sizeof (test_mac));
  test_mac[0] = 0x11;
  test_key.raw = 0;
  test_key.raw = l2fib_make_key ((u8 *) & test_mac, 0x1234);
  ASSERT (test_key.fields.mac[0] == 0x11);
  ASSERT (test_key.fields.bd_index == 0x1234);

  return 0;
}

VLIB_INIT_FUNCTION (l2fib_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

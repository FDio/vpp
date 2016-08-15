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
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_learn.h>
#include <vnet/l2/l2_bd.h>

#include <vppinfra/bihash_template.c>

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

/** Display the contents of the l2fib */
static clib_error_t *
show_l2fib (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  l2fib_main_t *msm = &l2fib_main;
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
				   "%=19s%=7s%=30s%=7s%=8s%=8s%=5s%=9s%=11s",
				   "Mac Address", "BD Idx", "Interface",
				   "Index", "static", "filter", "bvi",
				   "refresh", "timestamp");
		}

	      key.raw = v->kvp[k].key;
	      result.raw = v->kvp[k].value;

	      if (verbose
		  & ((bd_index >> 31) || (bd_index == key.fields.bd_index)))
		{
		  vlib_cli_output (vm,
				   "%=19U%=7d%=30U%=7d%=8d%=8d%=5d%=9d%=11X",
				   format_ethernet_address, key.fields.mac,
				   key.fields.bd_index,
				   format_vnet_sw_if_index_name_with_NA,
				   msm->vnet_main, result.fields.sw_if_index,
				   result.fields.sw_if_index == ~0
				   ? -1 : result.fields.sw_if_index,
				   result.fields.static_mac,
				   result.fields.filter,
				   result.fields.bvi,
				   result.fields.refresh,
				   result.fields.timestamp);
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

  return 0;
}

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

/** Clear all entries in L2FIB
 * TODO: Later we may want a way to remove only the non-static entries
 */
static clib_error_t *
clear_l2fib (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2fib_clear_table (0);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_l2fib_cli, static) = {
  .path = "clear l2fib",
  .short_help = "Clear l2fib mac forwarding entries",
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
 * Add an entry to the L2FIB
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_add_cli, static) = {
  .path = "l2fib add",
  .short_help = "Add l2fib mac forwarding entry  <mac> <bd-id> filter | <intf> [static | bvi]",
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_test_command, static) = {
  .path = "test l2fib",
  .short_help = "test l2fib [del] mac <base-addr> count <nn>",
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
 * Delete an entry from the L2FIB
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2fib_del_cli, static) = {
  .path = "l2fib del",
  .short_help = "Delete l2fib mac forwarding entry  <mac> <bd-id>",
  .function = l2fib_del,
};
/* *INDENT-ON* */


BVT (clib_bihash) * get_mac_table (void)
{
  l2fib_main_t *mp = &l2fib_main;
  return &mp->mac_table;
}

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

/*
 * Copyright (c) 2025 IPng Networks GmbH and/or its affiliates.
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

#include <vxlan/vxlan.h>
#include <vnet/l2/l2_fib.h>

void
vxlan_l2fib_init (void)
{
  vxlan_main_t *vxm = &vxlan_main;
  clib_bihash_init_8_8 (&vxm->vxlan_l2fib_table, "vxlan-l2fib",
			L2FIB_NUM_BUCKETS, L2FIB_MEMORY_SIZE);
}

int
vxlan_l2fib_add_entry (const u8 *mac, u32 sw_if_index,
		       const ip46_address_t *dst, u8 is_ip6)
{
  vxlan_main_t *vxm = &vxlan_main;
  clib_bihash_kv_8_8_t kv;
  vxlan_l2fib_entry_t *entry;

  /* Allocate entry */
  pool_get_aligned (vxm->vxlan_l2fib_pool, entry, CLIB_CACHE_LINE_BYTES);
  clib_memset (entry, 0, sizeof (*entry));

  /* Fill entry */
  entry->dst = *dst;
  clib_memcpy_fast (entry->mac, mac, sizeof (entry->mac));
  entry->sw_if_index = sw_if_index;
  entry->is_ip6 = is_ip6;

  /* Set up key using MAC + sw_if_index */
  kv.key = vxlan_l2fib_make_key (mac, sw_if_index);
  kv.value = entry - vxm->vxlan_l2fib_pool;

  /* Add to VXLAN hash table */
  return clib_bihash_add_del_8_8 (&vxm->vxlan_l2fib_table, &kv, 1);
}

int
vxlan_l2fib_del_entry (const u8 *mac, u32 sw_if_index)
{
  vxlan_main_t *vxm = &vxlan_main;
  clib_bihash_kv_8_8_t kv;

  /* Set up key */
  kv.key = vxlan_l2fib_make_key (mac, sw_if_index);

  /* Check if entry exists */
  if (clib_bihash_search_8_8 (&vxm->vxlan_l2fib_table, &kv, &kv))
    return 1; /* Not found */

  /* Free the entry */
  vxlan_l2fib_entry_t *entry =
    pool_elt_at_index (vxm->vxlan_l2fib_pool, kv.value);
  pool_put (vxm->vxlan_l2fib_pool, entry);

  /* Remove from VXLAN hash table */
  return clib_bihash_add_del_8_8 (&vxm->vxlan_l2fib_table, &kv, 0);
}

vxlan_l2fib_entry_t *
vxlan_l2fib_lookup (const u8 *mac, u32 sw_if_index)
{
  vxlan_main_t *vxm = &vxlan_main;
  clib_bihash_kv_8_8_t kv;

  /* Set up key */
  kv.key = vxlan_l2fib_make_key (mac, sw_if_index);

  /* Lookup */
  if (clib_bihash_search_8_8 (&vxm->vxlan_l2fib_table, &kv, &kv))
    {
      return NULL; /* Not found */
    }

  return pool_elt_at_index (vxm->vxlan_l2fib_pool, kv.value);
}

void
vxlan_l2fib_walk (vxlan_l2fib_walk_cb_t cb, void *ctx)
{
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_l2fib_entry_t *entry;

  pool_foreach (entry, vxm->vxlan_l2fib_pool)
    {
      if (cb (entry, ctx))
	break; /* callback requested early termination */
    }
}

typedef struct
{
  u32 sw_if_index;
  u32 *entries_to_delete;
} vxlan_l2fib_cleanup_walk_ctx_t;

static int
vxlan_l2fib_cleanup_walk_cb (vxlan_l2fib_entry_t *entry, void *arg)
{
  vxlan_l2fib_cleanup_walk_ctx_t *ctx = arg;

  if (entry->sw_if_index == ctx->sw_if_index)
    {
      vec_add1 (ctx->entries_to_delete, entry - vxlan_main.vxlan_l2fib_pool);
    }
  return 0; /* continue walking */
}

static void
vxlan_l2fib_cleanup_entries_for_interface (u32 sw_if_index)
{
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_l2fib_cleanup_walk_ctx_t ctx = {
    .sw_if_index = sw_if_index,
    .entries_to_delete = 0,
  };
  u32 *entry_index;
  vxlan_l2fib_entry_t *entry;

  /* Walk the pool and collect entries to delete */
  vxlan_l2fib_walk (vxlan_l2fib_cleanup_walk_cb, &ctx);

  /* Delete the collected entries */
  vec_foreach (entry_index, ctx.entries_to_delete)
    {
      entry = pool_elt_at_index (vxm->vxlan_l2fib_pool, *entry_index);
      vxlan_l2fib_del_entry (entry->mac, entry->sw_if_index);
    }

  vec_free (ctx.entries_to_delete);
}

/**
 * vxlan_interface_add_del
 *
 * Registered to receive interface Add and delete notifications
 */
static clib_error_t *
vxlan_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    {
      /* Interface is being deleted, clean up any VXLAN L2FIB entries */
      vlib_worker_thread_barrier_sync (vlib_get_main ());
      vxlan_l2fib_cleanup_entries_for_interface (sw_if_index);
      vlib_worker_thread_barrier_release (vlib_get_main ());
    }

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (vxlan_interface_add_del);

/* CLI command for managing VXLAN dynamic destinations */
static clib_error_t *
vxlan_l2fib_add_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u8 mac[6];
  u32 sw_if_index = ~0;
  ip46_address_t dst = ip46_address_initializer;
  u8 is_add = 1;
  u8 is_ip6 = 0;
  u8 mac_set = 0;
  u8 dst_set = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "mac %U", unformat_ethernet_address, mac))
	mac_set = 1;
      else if (unformat_user (line_input, unformat_vnet_sw_interface, vnm,
			      &sw_if_index))
	;
      else if (unformat (line_input, "dst %U", unformat_ip46_address, &dst,
			 IP46_TYPE_ANY))
	{
	  is_ip6 = ip46_address_is_ip4 (&dst) ? 0 : 1;
	  dst_set = 1;
	}
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* Validate required parameters */
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface must be specified");
      goto done;
    }
  if (!mac_set)
    {
      error = clib_error_return (0, "mac address must be specified");
      goto done;
    }

  if (is_add && !dst_set)
    {
      error = clib_error_return (0, "destination address must be specified");
      goto done;
    }

  /* Check if this is a replace operation */
  u8 is_replace = 0;
  if (is_add)
    {
      vxlan_l2fib_entry_t *existing = vxlan_l2fib_lookup (mac, sw_if_index);
      if (existing)
	is_replace = 1;
    }

  /* Call the API function */
  int rv = vxlan_l2fib_api_add_del (sw_if_index, mac, &dst, is_ip6, is_add);

  if (rv != 0)
    {
      error = clib_error_return (0, "%s", vxlan_l2fib_api_error_string (rv));
      goto done;
    }

  /* Print success message */
  if (is_add)
    {
      vlib_cli_output (vm, "%s VXLAN dynamic destination for %U on %U dst %U",
		       is_replace ? "Replaced" : "Added",
		       format_ethernet_address, mac,
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       sw_if_index, format_ip46_address, &dst, IP46_TYPE_ANY);
    }
  else
    {
      vlib_cli_output (vm, "Deleted VXLAN dynamic destination for %U on %U",
		       format_ethernet_address, mac,
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       sw_if_index);
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (vxlan_l2fib_add_del_command, static) = {
  .path = "vxlan l2fib",
  .short_help = "vxlan l2fib <interface> mac <mac> dst <ip> [del]",
  .function = vxlan_l2fib_add_del_command_fn,
};

static clib_error_t *
show_vxlan_l2fib_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_l2fib_entry_t *entry;
  u32 sw_if_index_filter = ~0;

  /* Parse command line arguments */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interface %U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index_filter))
	;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index_filter != ~0)
    vlib_cli_output (vm, "VXLAN Dynamic L2FIB entries for interface %U:",
		     format_vnet_sw_if_index_name, vnm, sw_if_index_filter);
  else
    vlib_cli_output (vm, "VXLAN Dynamic L2FIB entries:");

  if (pool_elts (vxm->vxlan_l2fib_pool) == 0)
    {
      vlib_cli_output (vm, "No dynamic entries");
      return 0;
    }

  vlib_cli_output (vm, "%=19s %=15s %=15s %=8s %=8s", "MAC", "Interface",
		   "Destination", "Port", "VNI");

  u32 entries_shown = 0;
  pool_foreach (entry, vxm->vxlan_l2fib_pool)
    {
      /* Filter by interface if specified */
      if (sw_if_index_filter != ~0 && entry->sw_if_index != sw_if_index_filter)
	continue;

      /* Get tunnel info from sw_if_index */
      u32 tunnel_index = vnet_vxlan_get_tunnel_index (entry->sw_if_index);
      vxlan_tunnel_t *tunnel = NULL;
      if (tunnel_index != ~0)
	tunnel = &vxm->tunnels[tunnel_index];

      if (tunnel)
	{
	  vlib_cli_output (
	    vm, "%=19U %=15U %=15U %=8d %=8d", format_ethernet_address,
	    entry->mac, format_vnet_sw_if_index_name, vnet_get_main (),
	    entry->sw_if_index, format_ip46_address, &entry->dst,
	    IP46_TYPE_ANY, tunnel->dst_port, tunnel->vni);
	}
      else
	{
	  vlib_cli_output (vm, "%=19U %=15U %=15U %=8s %=8s",
			   format_ethernet_address, entry->mac,
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   entry->sw_if_index, format_ip46_address,
			   &entry->dst, IP46_TYPE_ANY, "unknown", "unknown");
	}
      entries_shown++;
    }

  vlib_cli_output (vm, "Dynamic L2FIB entries: %d", entries_shown);

  return 0;
}

VLIB_CLI_COMMAND (show_vxlan_l2fib_command, static) = {
  .path = "show vxlan l2fib",
  .short_help = "show vxlan l2fib [interface <name>]",
  .function = show_vxlan_l2fib_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

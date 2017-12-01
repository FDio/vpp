/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief Common utility functions for IPv4, IPv6 and L2 LISP-GPE tunnels.
 *
 */

#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_fwd_entry.h>
#include <vnet/lisp-gpe/lisp_gpe_adjacency.h>
#include <vnet/lisp-gpe/lisp_gpe_tenant.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_internal.h>

/** LISP-GPE global state */
lisp_gpe_main_t lisp_gpe_main;


/** CLI command to add/del forwarding entry. */
static clib_error_t *
lisp_gpe_add_del_fwd_entry_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  ip_address_t lloc, rloc;
  clib_error_t *error = 0;
  gid_address_t _reid, *reid = &_reid, _leid, *leid = &_leid;
  u8 reid_set = 0, leid_set = 0, is_negative = 0, dp_table_set = 0,
    vni_set = 0;
  u32 vni = 0, dp_table = 0, action = ~0, w;
  locator_pair_t pair, *pairs = 0;
  int rv;

  memset (leid, 0, sizeof (*leid));
  memset (reid, 0, sizeof (*reid));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "leid %U", unformat_gid_address, leid))
	{
	  leid_set = 1;
	}
      else if (unformat (line_input, "reid %U", unformat_gid_address, reid))
	{
	  reid_set = 1;
	}
      else if (unformat (line_input, "vni %u", &vni))
	{
	  gid_address_vni (leid) = vni;
	  gid_address_vni (reid) = vni;
	  vni_set = 1;
	}
      else if (unformat (line_input, "vrf %u", &dp_table))
	{
	  dp_table_set = 1;
	}
      else if (unformat (line_input, "bd %u", &dp_table))
	{
	  dp_table_set = 1;
	}
      else if (unformat (line_input, "negative action %U",
			 unformat_negative_mapping_action, &action))
	{
	  is_negative = 1;
	}
      else if (unformat (line_input, "loc-pair %U %U w %d",
			 unformat_ip_address, &lloc,
			 unformat_ip_address, &rloc, &w))
	{
	  ip_address_copy (&pair.lcl_loc, &lloc);
	  ip_address_copy (&pair.rmt_loc, &rloc);
	  pair.weight = w;
	  pair.priority = 0;
	  vec_add1 (pairs, pair);
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  vlib_cli_output (vm, "parse error: '%U'",
			   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!reid_set)
    {
      vlib_cli_output (vm, "remote eid must be set!");
      goto done;
    }

  if (gid_address_type (reid) != GID_ADDR_NSH && (!vni_set || !dp_table_set))
    {
      vlib_cli_output (vm, "vni and vrf/bd must be set!");
      goto done;
    }

  if (is_negative)
    {
      if (~0 == action)
	{
	  vlib_cli_output (vm, "no action set for negative tunnel!");
	  goto done;
	}
    }
  else
    {
      if (vec_len (pairs) == 0)
	{
	  vlib_cli_output (vm, "expected ip4/ip6 locators");
	  goto done;
	}
    }

  if (!leid_set)
    {
      /* if leid not set, make sure it's the same AFI like reid */
      gid_address_type (leid) = gid_address_type (reid);
      if (GID_ADDR_IP_PREFIX == gid_address_type (reid))
	gid_address_ip_version (leid) = gid_address_ip_version (reid);
    }

  /* add fwd entry */
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  memset (a, 0, sizeof (a[0]));

  a->is_add = is_add;
  a->is_negative = is_negative;
  a->vni = vni;
  a->table_id = dp_table;
  gid_address_copy (&a->lcl_eid, leid);
  gid_address_copy (&a->rmt_eid, reid);
  a->locator_pairs = pairs;
  a->action = action;

  rv = vnet_lisp_gpe_add_del_fwd_entry (a, 0);
  if (0 != rv)
    {
      vlib_cli_output (vm, "failed to %s gpe tunnel!",
		       is_add ? "add" : "delete");
    }

done:
  unformat_free (line_input);
  vec_free (pairs);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_gpe_add_del_fwd_entry_command, static) = {
  .path = "gpe entry",
  .short_help = "gpe entry add/del vni <vni> vrf/bd <id> [leid <leid>]"
      "reid <reid> [loc-pair <lloc> <rloc> w <weight>] "
      "[negative action <action>]",
  .function = lisp_gpe_add_del_fwd_entry_command_fn,
};
/* *INDENT-ON* */

/** Check if LISP-GPE is enabled. */
u8
vnet_lisp_gpe_enable_disable_status (void)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  return lgm->is_en;
}

/** Enable/disable LISP-GPE. */
clib_error_t *
vnet_lisp_gpe_enable_disable (vnet_lisp_gpe_enable_disable_args_t * a)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  if (a->is_en)
    {
      lgm->is_en = 1;
    }
  else
    {
      /* remove all entries */
      vnet_lisp_gpe_fwd_entry_flush ();

      /* disable all l3 ifaces */
      lisp_gpe_tenant_flush ();

      lgm->is_en = 0;
    }

  return 0;
}

/** Set GPE encapsulation mode. */
int
vnet_gpe_set_encap_mode (gpe_encap_mode_t mode)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  if (mode >= GPE_ENCAP_COUNT)
    return VNET_API_ERROR_INVALID_GPE_MODE;

  if (pool_elts (lgm->lisp_fwd_entry_pool) != 0)
    return VNET_API_ERROR_LISP_GPE_ENTRIES_PRESENT;

  lgm->encap_mode = mode;
  return 0;
}

/** CLI command to set GPE encap */
static clib_error_t *
gpe_set_encap_mode_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  gpe_encap_mode_t mode = GPE_ENCAP_COUNT;
  vnet_api_error_t rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "lisp"))
	mode = GPE_ENCAP_LISP;
      else if (unformat (line_input, "vxlan"))
	mode = GPE_ENCAP_VXLAN;
      else
	{
	  return clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	}
    }
  rv = vnet_gpe_set_encap_mode (mode);
  if (rv)
    {
      return clib_error_return (0,
				"Error: invalid mode or GPE entries are present!");
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gpe_set_encap_mode_command, static) = {
  .path = "gpe encap",
  .short_help = "gpe encap [lisp|vxlan]",
  .function = gpe_set_encap_mode_command_fn,
};
/* *INDENT-ON* */

/** Format GPE encap mode. */
u8 *
format_vnet_gpe_encap_mode (u8 * s, va_list * args)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  switch (lgm->encap_mode)
    {
    case GPE_ENCAP_LISP:
      return format (s, "lisp");
    case GPE_ENCAP_VXLAN:
      return format (s, "vxlan");
    default:
      return 0;
    }
  return 0;
}

/** CLI command to show GPE encap */
static clib_error_t *
gpe_show_encap_mode_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "encap mode: %U", format_vnet_gpe_encap_mode);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gpe_show_encap_mode_command, static) = {
  .path = "show gpe encap",
  .short_help = "show GPE encapulation mode",
  .function = gpe_show_encap_mode_command_fn,
};
/* *INDENT-ON* */

/** CLI command to enable/disable LISP-GPE. */
static clib_error_t *
lisp_gpe_enable_disable_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_en = 1;
  vnet_lisp_gpe_enable_disable_args_t _a, *a = &_a;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected enable | disable");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_en = 1;
      else if (unformat (line_input, "disable"))
	is_en = 0;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
  a->is_en = is_en;
  error = vnet_lisp_gpe_enable_disable (a);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_disable_lisp_gpe_command, static) = {
  .path = "gpe",
  .short_help = "gpe [enable|disable]",
  .function = lisp_gpe_enable_disable_command_fn,
};
/* *INDENT-ON* */

/** CLI command to show LISP-GPE interfaces. */
static clib_error_t *
lisp_show_iface_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  hash_pair_t *p;

  vlib_cli_output (vm, "%=10s%=12s", "vrf", "hw_if_index");

  /* *INDENT-OFF* */
  hash_foreach_pair (p, lgm->l3_ifaces.hw_if_index_by_dp_table, ({
    vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
  }));
  /* *INDENT-ON* */

  if (0 != lgm->l2_ifaces.hw_if_index_by_dp_table)
    {
      vlib_cli_output (vm, "%=10s%=12s", "bd_id", "hw_if_index");
      /* *INDENT-OFF* */
      hash_foreach_pair (p, lgm->l2_ifaces.hw_if_index_by_dp_table, ({
        vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_iface_command) = {
    .path = "show gpe interface",
    .short_help = "show gpe interface",
    .function = lisp_show_iface_command_fn,
};
/* *INDENT-ON* */

/** CLI command to show GPE fwd native route path. */
static clib_error_t *
gpe_show_native_fwd_rpath_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  fib_route_path_t *rpath;

  if (vec_len (lgm->native_fwd_rpath[IP4]))
    {
      vec_foreach (rpath, lgm->native_fwd_rpath[IP4])
      {
	vlib_cli_output (vm, "nh: %U fib_index %u sw_if_index %u",
			 format_ip46_address, &rpath->frp_addr,
			 IP46_TYPE_IP4, rpath->frp_fib_index,
			 rpath->frp_sw_if_index);
      }
    }
  if (vec_len (lgm->native_fwd_rpath[IP6]))
    {
      vec_foreach (rpath, lgm->native_fwd_rpath[IP6])
      {
	vlib_cli_output (vm, "nh: %U fib_index %u sw_if_index %u",
			 format_ip46_address, &rpath->frp_addr, IP46_TYPE_IP6,
			 rpath->frp_fib_index, rpath->frp_sw_if_index);
      }
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gpe_show_native_fwd_rpath_command) = {
    .path = "show gpe native-forward",
    .short_help = "show gpe native-forward",
    .function = gpe_show_native_fwd_rpath_command_fn,
};
/* *INDENT-ON* */

void
gpe_update_native_fwd_path (u8 ip_version)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  lisp_gpe_fwd_entry_t *lfe;
  fib_prefix_t fib_prefix;
  u32 *lfei;

  vec_foreach (lfei, lgm->native_fwd_lfes[ip_version])
  {
    lfe = pool_elt_at_index (lgm->lisp_fwd_entry_pool, lfei[0]);
    ip_prefix_to_fib_prefix (&lfe->key->rmt.ippref, &fib_prefix);
    fib_table_entry_update (lfe->eid_fib_index, &fib_prefix, FIB_SOURCE_LISP,
			    FIB_ENTRY_FLAG_NONE,
			    lgm->native_fwd_rpath[ip_version]);
  }
}

int
vnet_gpe_add_del_native_fwd_rpath (vnet_gpe_native_fwd_rpath_args_t * a)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  fib_route_path_t *rpath;
  u8 ip_version;

  ip_version = a->rpath.frp_proto == DPO_PROTO_IP4 ? IP4 : IP6;

  if (a->is_add)
    {
      vec_add1 (lgm->native_fwd_rpath[ip_version], a->rpath);
    }
  else
    {
      vec_foreach (rpath, lgm->native_fwd_rpath[ip_version])
      {
	if (!fib_route_path_cmp (rpath, &a->rpath))
	  {
	    vec_del1 (lgm->native_fwd_rpath[ip_version],
		      rpath - lgm->native_fwd_rpath[ip_version]);
	    break;
	  }
      }
    }
  gpe_update_native_fwd_path (ip_version);
  return 0;
}

/**
 * CLI command to add action for native forward.
 */
static clib_error_t *
gpe_native_forward_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_api_error_t rv;
  fib_route_path_t rpath;
  u32 table_id = ~0;
  vnet_gpe_native_fwd_rpath_args_t _a, *a = &_a;
  u8 is_add = 1;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset (&rpath, 0, sizeof (rpath));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "via %U %U",
			 unformat_ip4_address,
			 &rpath.frp_addr.ip4,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP4;
	}
      else if (unformat (line_input, "via %U %U",
			 unformat_ip6_address,
			 &rpath.frp_addr.ip6,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP6;
	}
      else if (unformat (line_input, "via %U",
			 unformat_ip4_address, &rpath.frp_addr.ip4))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP4;
	}
      else if (unformat (line_input, "via %U",
			 unformat_ip6_address, &rpath.frp_addr.ip6))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP6;
	}
      else
	{
	  return clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	}
    }

  if ((u32) ~ 0 == table_id)
    {
      rpath.frp_fib_index = 0;
    }
  else
    {
      rpath.frp_fib_index =
	fib_table_find (dpo_proto_to_fib (rpath.frp_proto), table_id);
      if ((u32) ~ 0 == rpath.frp_fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
    }

  a->rpath = rpath;
  a->is_add = is_add;

  rv = vnet_gpe_add_del_native_fwd_rpath (a);
  if (rv)
    {
      return clib_error_return (0, "Error: couldn't add path!");
    }

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gpe_native_forward_command) = {
    .path = "gpe native-forward",
    .short_help = "gpe native-forward [del] via <nh-ip-addr> [iface] "
	"[table <table>]",
    .function = gpe_native_forward_command_fn,
};
/* *INDENT-ON* */

/** Format LISP-GPE status. */
u8 *
format_vnet_lisp_gpe_status (u8 * s, va_list * args)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  return format (s, "%s", lgm->is_en ? "enabled" : "disabled");
}

/** LISP-GPE init function. */
clib_error_t *
lisp_gpe_init (vlib_main_t * vm)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  clib_error_t *error = 0;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  lgm->vnet_main = vnet_get_main ();
  lgm->vlib_main = vm;
  lgm->im4 = &ip4_main;
  lgm->im6 = &ip6_main;
  lgm->lm4 = &ip4_main.lookup_main;
  lgm->lm6 = &ip6_main.lookup_main;
  lgm->encap_mode = GPE_ENCAP_LISP;

  lgm->lisp_gpe_fwd_entries =
    hash_create_mem (0, sizeof (lisp_gpe_fwd_entry_key_t), sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe,
			 lisp_gpe_ip4_input_node.index, 1 /* is_ip4 */ );
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe6,
			 lisp_gpe_ip6_input_node.index, 0 /* is_ip4 */ );

  lgm->lisp_stats_index_by_key =
    hash_create_mem (0, sizeof (lisp_stats_key_t), sizeof (uword));
  memset (&lgm->counters, 0, sizeof (lgm->counters));
  lgm->counters.name = "LISP counters";

  return 0;
}

gpe_encap_mode_t
vnet_gpe_get_encap_mode (void)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  return lgm->encap_mode;
}

static clib_error_t *
lisp_gpe_test_send_nsh_packet (u8 * file_name)
{
  vlib_frame_t *f;
  vlib_buffer_t *b;
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  pcap_main_t pm;
  clib_error_t *error = 0;

  if (!file_name)
    return clib_error_create ("no pcap file specified!");

  memset (&pm, 0, sizeof (pm));
  pm.file_name = (char *) file_name;
  error = pcap_read (&pm);
  if (error)
    return error;

  u32 bi;
  if (vlib_buffer_alloc (lgm->vlib_main, &bi, 1) != 1)
    return clib_error_create ("cannot allocate memory!");

  b = vlib_get_buffer (lgm->vlib_main, bi);
  tunnel_lookup_t *nsh_ifaces = &lgm->nsh_ifaces;
  uword *hip;
  vnet_hw_interface_t *hi;

  hip = hash_get (nsh_ifaces->hw_if_index_by_dp_table, 0);
  if (hip == 0)
    return clib_error_create ("The NSH 0 interface doesn't exist");

  hi = vnet_get_hw_interface (lgm->vnet_main, hip[0]);

  vnet_buffer (b)->sw_if_index[VLIB_TX] = hi->sw_if_index;
  u8 *p = vlib_buffer_put_uninit (b, vec_len (pm.packets_read[0]));
  clib_memcpy (p, pm.packets_read[0], vec_len (pm.packets_read[0]));
  vlib_buffer_pull (b, sizeof (ethernet_header_t));

  vlib_node_t *n = vlib_get_node_by_name (lgm->vlib_main,
					  (u8 *) "interface-tx");
  f = vlib_get_frame_to_node (lgm->vlib_main, n->index);
  u32 *to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (lgm->vlib_main, n->index, f);

  return error;
}

static clib_error_t *
lisp_test_nsh_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u8 *file_name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pcap %v", &file_name))
	{
	  error = lisp_gpe_test_send_nsh_packet (file_name);
	  goto done;
	}
      else
	{
	  error = clib_error_create ("unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_test_nsh_command, static) = {
  .path = "test one nsh",
  .short_help = "test gpe nsh pcap <path-to-pcap-file>",
  .function = lisp_test_nsh_command_fn,
};
/* *INDENT-ON* */

VLIB_INIT_FUNCTION (lisp_gpe_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

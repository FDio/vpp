/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/lisp-cp/control.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

static clib_error_t *
lisp_show_adjacencies_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  lisp_adjacency_t *adjs, *adj;
  vlib_cli_output (vm, "%s %40s\n", "leid", "reid");
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 vni = ~0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "vni %d", &vni))
	;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'",
			   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (~0 == vni)
    {
      vlib_cli_output (vm, "error: no vni specified!");
      goto done;
    }

  adjs = vnet_lisp_adjacencies_get_by_vni (vni);

  vec_foreach (adj, adjs)
  {
    vlib_cli_output (vm, "%U %40U\n", format_gid_address, &adj->leid,
		     format_gid_address, &adj->reid);
  }
  vec_free (adjs);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_adjacencies_command) = {
    .path = "show lisp adjacencies",
    .short_help = "show lisp adjacencies",
    .function = lisp_show_adjacencies_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_add_del_map_server_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  int rv = 0;
  u8 is_add = 1, ip_set = 0;
  ip_address_t ip;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "%U", unformat_ip_address, &ip))
	ip_set = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'",
			   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!ip_set)
    {
      vlib_cli_output (vm, "map-server ip address not set!");
      goto done;
    }

  rv = vnet_lisp_add_del_map_server (&ip, is_add);
  if (!rv)
    vlib_cli_output (vm, "failed to %s map-server!",
		     is_add ? "add" : "delete");

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_add_del_map_server_command) = {
    .path = "lisp map-server",
    .short_help = "lisp map-server add|del <ip>",
    .function = lisp_add_del_map_server_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_add_del_local_eid_command_fn (vlib_main_t * vm, unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  gid_address_t eid;
  gid_address_t *eids = 0;
  clib_error_t *error = 0;
  u8 *locator_set_name = 0;
  u32 locator_set_index = 0, map_index = 0;
  uword *p;
  vnet_lisp_add_del_mapping_args_t _a, *a = &_a;
  int rv = 0;
  u32 vni = 0;
  u8 *key = 0;
  u32 key_id = 0;

  memset (&eid, 0, sizeof (eid));
  memset (a, 0, sizeof (*a));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "eid %U", unformat_gid_address, &eid))
	;
      else if (unformat (line_input, "vni %d", &vni))
	gid_address_vni (&eid) = vni;
      else if (unformat (line_input, "secret-key %_%v%_", &key))
	;
      else if (unformat (line_input, "key-id %U", unformat_hmac_key_id,
			 &key_id))
	;
      else if (unformat (line_input, "locator-set %_%v%_", &locator_set_name))
	{
	  p = hash_get_mem (lcm->locator_set_index_by_name, locator_set_name);
	  if (!p)
	    {
	      error = clib_error_return (0, "locator-set %s doesn't exist",
					 locator_set_name);
	      goto done;
	    }
	  locator_set_index = p[0];
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }
  /* XXX treat batch configuration */

  if (GID_ADDR_SRC_DST == gid_address_type (&eid))
    {
      error =
	clib_error_return (0, "src/dst is not supported for local EIDs!");
      goto done;
    }

  if (key && (0 == key_id))
    {
      vlib_cli_output (vm, "invalid key_id!");
      goto done;;
    }

  gid_address_copy (&a->eid, &eid);
  a->is_add = is_add;
  a->locator_set_index = locator_set_index;
  a->local = 1;
  a->key = key;
  a->key_id = key_id;

  rv = vnet_lisp_add_del_local_mapping (a, &map_index);
  if (0 != rv)
    {
      error = clib_error_return (0, "failed to %s local mapping!",
				 is_add ? "add" : "delete");
    }
done:
  vec_free (eids);
  if (locator_set_name)
    vec_free (locator_set_name);
  gid_address_free (&a->eid);
  vec_free (a->key);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_add_del_local_eid_command) = {
    .path = "lisp eid-table",
    .short_help = "lisp eid-table add/del [vni <vni>] eid <eid> "
      "locator-set <locator-set> [key <secret-key> key-id sha1|sha256 ]",
    .function = lisp_add_del_local_eid_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_eid_table_map_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  u8 is_add = 1, is_l2 = 0;
  u32 vni = 0, dp_id = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "vni %d", &vni))
	;
      else if (unformat (line_input, "vrf %d", &dp_id))
	;
      else if (unformat (line_input, "bd %d", &dp_id))
	is_l2 = 1;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }
  vnet_lisp_eid_table_map (vni, dp_id, is_l2, is_add);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_eid_table_map_command) = {
    .path = "lisp eid-table map",
    .short_help = "lisp eid-table map [del] vni <vni> vrf <vrf> | bd <bdi>",
    .function = lisp_eid_table_map_command_fn,
};
/* *INDENT-ON* */

/**
 * Handler for add/del remote mapping CLI.
 *
 * @param vm vlib context
 * @param input input from user
 * @param cmd cmd
 * @return pointer to clib error structure
 */
static clib_error_t *
lisp_add_del_remote_mapping_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1, del_all = 0;
  locator_t rloc, *rlocs = 0, *curr_rloc = 0;
  gid_address_t eid;
  u8 eid_set = 0;
  u32 vni, action = ~0, p, w;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset (&eid, 0, sizeof (eid));
  memset (&rloc, 0, sizeof (rloc));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del-all"))
	del_all = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	;
      else if (unformat (line_input, "eid %U", unformat_gid_address, &eid))
	eid_set = 1;
      else if (unformat (line_input, "vni %u", &vni))
	{
	  gid_address_vni (&eid) = vni;
	}
      else if (unformat (line_input, "p %d w %d", &p, &w))
	{
	  if (!curr_rloc)
	    {
	      clib_warning
		("No RLOC configured for setting priority/weight!");
	      goto done;
	    }
	  curr_rloc->priority = p;
	  curr_rloc->weight = w;
	}
      else if (unformat (line_input, "rloc %U", unformat_ip_address,
			 &gid_address_ip (&rloc.address)))
	{
	  /* since rloc is stored in ip prefix we need to set prefix length */
	  ip_prefix_t *pref = &gid_address_ippref (&rloc.address);

	  u8 version = gid_address_ip_version (&rloc.address);
	  ip_prefix_len (pref) = ip_address_max_len (version);

	  vec_add1 (rlocs, rloc);
	  curr_rloc = &rlocs[vec_len (rlocs) - 1];
	}
      else if (unformat (line_input, "action %U",
			 unformat_negative_mapping_action, &action))
	;
      else
	{
	  clib_warning ("parse error");
	  goto done;
	}
    }

  if (!eid_set)
    {
      clib_warning ("missing eid!");
      goto done;
    }

  if (!del_all)
    {
      if (is_add && (~0 == action) && 0 == vec_len (rlocs))
	{
	  clib_warning ("no action set for negative map-reply!");
	  goto done;
	}
    }
  else
    {
      vnet_lisp_clear_all_remote_adjacencies ();
      goto done;
    }

  /* TODO build src/dst with seid */

  /* if it's a delete, clean forwarding */
  if (!is_add)
    {
      vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
      memset (a, 0, sizeof (a[0]));
      gid_address_copy (&a->reid, &eid);
      if (vnet_lisp_add_del_adjacency (a))
	{
	  clib_warning ("failed to delete adjacency!");
	  goto done;
	}
    }

  /* add as static remote mapping, i.e., not authoritative and infinite
   * ttl */
  if (is_add)
    {
      vnet_lisp_add_del_mapping_args_t _map_args, *map_args = &_map_args;
      memset (map_args, 0, sizeof (map_args[0]));
      gid_address_copy (&map_args->eid, &eid);
      map_args->action = action;
      map_args->is_static = 1;
      map_args->authoritative = 0;
      map_args->ttl = ~0;
      rv = vnet_lisp_add_mapping (map_args, rlocs, NULL, NULL);
    }
  else
    rv = vnet_lisp_del_mapping (&eid, NULL);

  if (rv)
    clib_warning ("failed to %s remote mapping!", is_add ? "add" : "delete");

done:
  vec_free (rlocs);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (lisp_add_del_remote_mapping_command) =
{
.path = "lisp remote-mapping",.short_help =
    "lisp remote-mapping add|del [del-all] vni <vni> "
    "eid <est-eid> [action <no-action|natively-forward|"
    "send-map-request|drop>] rloc <dst-locator> p <prio> w <weight> "
    "[rloc <dst-locator> ... ]",.function =
    lisp_add_del_remote_mapping_command_fn,};

/**
 * Handler for add/del adjacency CLI.
 */
static clib_error_t *
lisp_add_del_adjacency_command_fn (vlib_main_t * vm, unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
  u8 is_add = 1;
  ip_prefix_t *reid_ippref, *leid_ippref;
  gid_address_t leid, reid;
  u8 *dmac = gid_address_mac (&reid);
  u8 *smac = gid_address_mac (&leid);
  u8 reid_set = 0, leid_set = 0;
  u32 vni;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset (&reid, 0, sizeof (reid));
  memset (&leid, 0, sizeof (leid));

  leid_ippref = &gid_address_ippref (&leid);
  reid_ippref = &gid_address_ippref (&reid);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	;
      else if (unformat (line_input, "reid %U",
			 unformat_ip_prefix, reid_ippref))
	{
	  gid_address_type (&reid) = GID_ADDR_IP_PREFIX;
	  reid_set = 1;
	}
      else if (unformat (line_input, "reid %U", unformat_mac_address, dmac))
	{
	  gid_address_type (&reid) = GID_ADDR_MAC;
	  reid_set = 1;
	}
      else if (unformat (line_input, "vni %u", &vni))
	{
	  gid_address_vni (&leid) = vni;
	  gid_address_vni (&reid) = vni;
	}
      else if (unformat (line_input, "leid %U",
			 unformat_ip_prefix, leid_ippref))
	{
	  gid_address_type (&leid) = GID_ADDR_IP_PREFIX;
	  leid_set = 1;
	}
      else if (unformat (line_input, "leid %U", unformat_mac_address, smac))
	{
	  gid_address_type (&leid) = GID_ADDR_MAC;
	  leid_set = 1;
	}
      else
	{
	  clib_warning ("parse error");
	  goto done;
	}
    }

  if (!reid_set || !leid_set)
    {
      clib_warning ("missing remote or local eid!");
      goto done;
    }

  if ((gid_address_type (&leid) != gid_address_type (&reid))
      || (gid_address_type (&reid) == GID_ADDR_IP_PREFIX
	  && ip_prefix_version (reid_ippref)
	  != ip_prefix_version (leid_ippref)))
    {
      clib_warning ("remote and local EIDs are of different types!");
      goto done;
    }

  memset (a, 0, sizeof (a[0]));
  gid_address_copy (&a->leid, &leid);
  gid_address_copy (&a->reid, &reid);
  a->is_add = is_add;

  if (vnet_lisp_add_del_adjacency (a))
    clib_warning ("failed to %s adjacency!", is_add ? "add" : "delete");

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_add_del_adjacency_command) = {
    .path = "lisp adjacency",
    .short_help = "lisp adjacency add|del vni <vni> reid <remote-eid> "
      "leid <local-eid>",
    .function = lisp_add_del_adjacency_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_map_request_mode_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _i, *i = &_i;
  map_request_mode_t mr_mode = _MR_MODE_MAX;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, i))
    return 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "dst-only"))
	mr_mode = MR_MODE_DST_ONLY;
      else if (unformat (i, "src-dst"))
	mr_mode = MR_MODE_SRC_DST;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  goto done;
	}
    }

  if (_MR_MODE_MAX == mr_mode)
    {
      clib_warning ("No LISP map request mode entered!");
      goto done;
    }

  vnet_lisp_set_map_request_mode (mr_mode);

done:
  unformat_free (i);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_map_request_mode_command) = {
    .path = "lisp map-request mode",
    .short_help = "lisp map-request mode dst-only|src-dst",
    .function = lisp_map_request_mode_command_fn,
};
/* *INDENT-ON* */


static u8 *
format_lisp_map_request_mode (u8 * s, va_list * args)
{
  u32 mode = va_arg (*args, u32);

  switch (mode)
    {
    case 0:
      return format (0, "dst-only");
    case 1:
      return format (0, "src-dst");
    }
  return 0;
}

static clib_error_t *
lisp_show_map_request_mode_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "map-request mode: %U", format_lisp_map_request_mode,
		   vnet_lisp_get_map_request_mode ());
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_map_request_mode_command) = {
    .path = "show lisp map-request mode",
    .short_help = "show lisp map-request mode",
    .function = lisp_show_map_request_mode_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_show_map_resolvers_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  lisp_msmr_t *mr;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  vec_foreach (mr, lcm->map_resolvers)
  {
    vlib_cli_output (vm, "%U", format_ip_address, &mr->address);
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_map_resolvers_command) = {
    .path = "show lisp map-resolvers",
    .short_help = "show lisp map-resolvers",
    .function = lisp_show_map_resolvers_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_pitr_set_locator_set_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  u8 locator_name_set = 0;
  u8 *locator_set_name = 0;
  u8 is_add = 1;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ls %_%v%_", &locator_set_name))
	locator_name_set = 1;
      else if (unformat (line_input, "disable"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "parse error");
	  goto done;
	}
    }

  if (!locator_name_set)
    {
      clib_warning ("No locator set specified!");
      goto done;
    }
  rv = vnet_lisp_pitr_set_locator_set (locator_set_name, is_add);
  if (0 != rv)
    {
      error = clib_error_return (0, "failed to %s pitr!",
				 is_add ? "add" : "delete");
    }

done:
  if (locator_set_name)
    vec_free (locator_set_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_pitr_set_locator_set_command) = {
    .path = "lisp pitr",
    .short_help = "lisp pitr [disable] ls <locator-set-name>",
    .function = lisp_pitr_set_locator_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_show_pitr_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls;
  u8 *tmp_str = 0;

  vlib_cli_output (vm, "%=20s%=16s",
		   "pitr", lcm->lisp_pitr ? "locator-set" : "");

  if (!lcm->lisp_pitr)
    {
      vlib_cli_output (vm, "%=20s", "disable");
      return 0;
    }

  if (~0 == lcm->pitr_map_index)
    {
      tmp_str = format (0, "N/A");
    }
  else
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->pitr_map_index);
      if (~0 != m->locator_set_index)
	{
	  ls =
	    pool_elt_at_index (lcm->locator_set_pool, m->locator_set_index);
	  tmp_str = format (0, "%s", ls->name);
	}
      else
	{
	  tmp_str = format (0, "N/A");
	}
    }
  vec_add1 (tmp_str, 0);

  vlib_cli_output (vm, "%=20s%=16s", "enable", tmp_str);

  vec_free (tmp_str);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_pitr_command) = {
    .path = "show lisp pitr",
    .short_help = "Show pitr",
    .function = lisp_show_pitr_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_eid_entry (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  lisp_cp_main_t *lcm = va_arg (*args, lisp_cp_main_t *);
  mapping_t *mapit = va_arg (*args, mapping_t *);
  locator_set_t *ls = va_arg (*args, locator_set_t *);
  gid_address_t *gid = &mapit->eid;
  u32 ttl = mapit->ttl;
  u8 aut = mapit->authoritative;
  u32 *loc_index;
  u8 first_line = 1;
  u8 *loc;

  u8 *type = ls->local ? format (0, "local(%s)", ls->name)
    : format (0, "remote");

  if (vec_len (ls->locator_indices) == 0)
    {
      s = format (s, "%-35U%-30s%-20u%-u", format_gid_address, gid,
		  type, ttl, aut);
    }
  else
    {
      vec_foreach (loc_index, ls->locator_indices)
      {
	locator_t *l = pool_elt_at_index (lcm->locator_pool, loc_index[0]);
	if (l->local)
	  loc = format (0, "%U", format_vnet_sw_if_index_name, vnm,
			l->sw_if_index);
	else
	  loc = format (0, "%U", format_ip_address,
			&gid_address_ip (&l->address));

	if (first_line)
	  {
	    s = format (s, "%-35U%-20s%-30v%-20u%-u\n", format_gid_address,
			gid, type, loc, ttl, aut);
	    first_line = 0;
	  }
	else
	  s = format (s, "%55s%v\n", "", loc);
      }
    }
  return s;
}

static clib_error_t *
lisp_show_eid_table_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *mapit;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 mi;
  gid_address_t eid;
  u8 print_all = 1;
  u8 filter = 0;
  clib_error_t *error = NULL;

  memset (&eid, 0, sizeof (eid));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "eid %U", unformat_gid_address, &eid))
	print_all = 0;
      else if (unformat (line_input, "local"))
	filter = 1;
      else if (unformat (line_input, "remote"))
	filter = 2;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vlib_cli_output (vm, "%-35s%-20s%-30s%-20s%-s",
		   "EID", "type", "locators", "ttl", "autoritative");

  if (print_all)
    {
      /* *INDENT-OFF* */
      pool_foreach (mapit, lcm->mapping_pool,
      ({
        if (mapit->pitr_set)
          continue;

        locator_set_t * ls = pool_elt_at_index (lcm->locator_set_pool,
                                                mapit->locator_set_index);
        if (filter && !((1 == filter && ls->local) ||
          (2 == filter && !ls->local)))
          {
            continue;
          }
        vlib_cli_output (vm, "%U", format_eid_entry, lcm->vnet_main,
                         lcm, mapit, ls);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &eid);
      if ((u32) ~ 0 == mi)
	goto done;

      mapit = pool_elt_at_index (lcm->mapping_pool, mi);
      locator_set_t *ls = pool_elt_at_index (lcm->locator_set_pool,
					     mapit->locator_set_index);

      if (filter && !((1 == filter && ls->local) ||
		      (2 == filter && !ls->local)))
	{
	  goto done;
	}

      vlib_cli_output (vm, "%U,", format_eid_entry, lcm->vnet_main,
		       lcm, mapit, ls);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_cp_show_eid_table_command) = {
    .path = "show lisp eid-table",
    .short_help = "Shows EID table",
    .function = lisp_show_eid_table_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_enable_disable_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_enabled = 0;
  u8 is_set = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	{
	  is_set = 1;
	  is_enabled = 1;
	}
      else if (unformat (line_input, "disable"))
	is_set = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!is_set)
    {
      error = clib_error_return (0, "state not set");
      goto done;
    }

  vnet_lisp_enable_disable (is_enabled);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_cp_enable_disable_command) = {
    .path = "lisp",
    .short_help = "lisp [enable|disable]",
    .function = lisp_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_map_register_enable_disable_command_fn (vlib_main_t * vm,
					     unformat_input_t * input,
					     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_enabled = 0;
  u8 is_set = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	{
	  is_set = 1;
	  is_enabled = 1;
	}
      else if (unformat (line_input, "disable"))
	is_set = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   line_input);
	  goto done;
	}
    }

  if (!is_set)
    {
      vlib_cli_output (vm, "state not set!");
      goto done;
    }

  vnet_lisp_map_register_enable_disable (is_enabled);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_map_register_enable_disable_command) = {
    .path = "lisp map-register",
    .short_help = "lisp map-register [enable|disable]",
    .function = lisp_map_register_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_rloc_probe_enable_disable_command_fn (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_enabled = 0;
  u8 is_set = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	{
	  is_set = 1;
	  is_enabled = 1;
	}
      else if (unformat (line_input, "disable"))
	is_set = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   line_input);
	  goto done;
	}
    }

  if (!is_set)
    {
      vlib_cli_output (vm, "state not set!");
      goto done;
    }

  vnet_lisp_rloc_probe_enable_disable (is_enabled);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_rloc_probe_enable_disable_command) = {
    .path = "lisp rloc-probe",
    .short_help = "lisp rloc-probe [enable|disable]",
    .function = lisp_rloc_probe_enable_disable_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_lisp_status (u8 * s, va_list * args)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return format (s, "%s", lcm->is_enabled ? "enabled" : "disabled");
}

static clib_error_t *
lisp_show_status_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  u8 *msg = 0;
  msg = format (msg, "feature: %U\ngpe: %U\n",
		format_lisp_status, format_vnet_lisp_gpe_status);
  vlib_cli_output (vm, "%v", msg);
  vec_free (msg);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_status_command) = {
    .path = "show lisp status",
    .short_help = "show lisp status",
    .function = lisp_show_status_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_show_eid_table_map_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  hash_pair_t *p;
  unformat_input_t _line_input, *line_input = &_line_input;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  uword *vni_table = 0;
  u8 is_l2 = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "l2"))
	{
	  vni_table = lcm->bd_id_by_vni;
	  is_l2 = 1;
	}
      else if (unformat (line_input, "l3"))
	{
	  vni_table = lcm->table_id_by_vni;
	  is_l2 = 0;
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!vni_table)
    {
      vlib_cli_output (vm, "Error: expected l2|l3 param!\n");
      goto done;
    }

  vlib_cli_output (vm, "%=10s%=10s", "VNI", is_l2 ? "BD" : "VRF");

  /* *INDENT-OFF* */
  hash_foreach_pair (p, vni_table,
  ({
    vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
  }));
  /* *INDENT-ON* */

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_eid_table_map_command) = {
    .path = "show lisp eid-table map",
    .short_help = "show lisp eid-table l2|l3",
    .function = lisp_show_eid_table_map_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_add_del_locator_set_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  vnet_main_t *vnm = lgm->vnet_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  clib_error_t *error = 0;
  u8 *locator_set_name = 0;
  locator_t locator, *locators = 0;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  u32 ls_index = 0;
  int rv = 0;

  memset (&locator, 0, sizeof (locator));
  memset (a, 0, sizeof (a[0]));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %_%v%_", &locator_set_name))
	is_add = 1;
      else if (unformat (line_input, "del %_%v%_", &locator_set_name))
	is_add = 0;
      else if (unformat (line_input, "iface %U p %d w %d",
			 unformat_vnet_sw_interface, vnm,
			 &locator.sw_if_index, &locator.priority,
			 &locator.weight))
	{
	  locator.local = 1;
	  vec_add1 (locators, locator);
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  a->name = locator_set_name;
  a->locators = locators;
  a->is_add = is_add;
  a->local = 1;

  rv = vnet_lisp_add_del_locator_set (a, &ls_index);
  if (0 != rv)
    {
      error = clib_error_return (0, "failed to %s locator-set!",
				 is_add ? "add" : "delete");
    }

done:
  vec_free (locators);
  if (locator_set_name)
    vec_free (locator_set_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_cp_add_del_locator_set_command) = {
    .path = "lisp locator-set",
    .short_help = "lisp locator-set add/del <name> [iface <iface-name> "
        "p <priority> w <weight>]",
    .function = lisp_add_del_locator_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_add_del_locator_in_set_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  vnet_main_t *vnm = lgm->vnet_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  clib_error_t *error = 0;
  u8 *locator_set_name = 0;
  u8 locator_set_name_set = 0;
  locator_t locator, *locators = 0;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  u32 ls_index = 0;

  memset (&locator, 0, sizeof (locator));
  memset (a, 0, sizeof (a[0]));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "locator-set %_%v%_", &locator_set_name))
	locator_set_name_set = 1;
      else if (unformat (line_input, "iface %U p %d w %d",
			 unformat_vnet_sw_interface, vnm,
			 &locator.sw_if_index, &locator.priority,
			 &locator.weight))
	{
	  locator.local = 1;
	  vec_add1 (locators, locator);
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!locator_set_name_set)
    {
      error = clib_error_return (0, "locator_set name not set!");
      goto done;
    }

  a->name = locator_set_name;
  a->locators = locators;
  a->is_add = is_add;
  a->local = 1;

  vnet_lisp_add_del_locator (a, 0, &ls_index);

done:
  vec_free (locators);
  vec_free (locator_set_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_cp_add_del_locator_in_set_command) = {
    .path = "lisp locator",
    .short_help = "lisp locator add/del locator-set <name> iface <iface-name> "
                  "p <priority> w <weight>",
    .function = lisp_add_del_locator_in_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_cp_show_locator_sets_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  locator_set_t *lsit;
  locator_t *loc;
  u32 *locit;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  vlib_cli_output (vm, "%s%=16s%=16s%=16s", "Locator-set", "Locator",
		   "Priority", "Weight");

  /* *INDENT-OFF* */
  pool_foreach (lsit, lcm->locator_set_pool,
  ({
    u8 * msg = 0;
    int next_line = 0;
    if (lsit->local)
      {
        msg = format (msg, "%v", lsit->name);
      }
    else
      {
        msg = format (msg, "<%s-%d>", "remote", lsit - lcm->locator_set_pool);
      }
    vec_foreach (locit, lsit->locator_indices)
      {
        if (next_line)
          {
            msg = format (msg, "%16s", " ");
          }
        loc = pool_elt_at_index (lcm->locator_pool, locit[0]);
        if (loc->local)
          msg = format (msg, "%16d%16d%16d\n", loc->sw_if_index, loc->priority,
                        loc->weight);
        else
          msg = format (msg, "%16U%16d%16d\n", format_ip_address,
                        &gid_address_ip(&loc->address), loc->priority,
                        loc->weight);
        next_line = 1;
      }
    vlib_cli_output (vm, "%v", msg);
    vec_free (msg);
  }));
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_cp_show_locator_sets_command) = {
    .path = "show lisp locator-set",
    .short_help = "Shows locator-sets",
    .function = lisp_cp_show_locator_sets_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_add_del_map_resolver_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1, addr_set = 0;
  ip_address_t ip_addr;
  clib_error_t *error = 0;
  int rv = 0;
  vnet_lisp_add_del_map_resolver_args_t _a, *a = &_a;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "%U", unformat_ip_address, &ip_addr))
	addr_set = 1;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!addr_set)
    {
      error = clib_error_return (0, "Map-resolver address must be set!");
      goto done;
    }

  a->is_add = is_add;
  a->address = ip_addr;
  rv = vnet_lisp_add_del_map_resolver (a);
  if (0 != rv)
    {
      error = clib_error_return (0, "failed to %s map-resolver!",
				 is_add ? "add" : "delete");
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_add_del_map_resolver_command) = {
    .path = "lisp map-resolver",
    .short_help = "lisp map-resolver add/del <ip_address>",
    .function = lisp_add_del_map_resolver_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lisp_add_del_mreq_itr_rlocs_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u8 *locator_set_name = 0;
  clib_error_t *error = 0;
  int rv = 0;
  vnet_lisp_add_del_mreq_itr_rloc_args_t _a, *a = &_a;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add %_%v%_", &locator_set_name))
	is_add = 1;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  a->is_add = is_add;
  a->locator_set_name = locator_set_name;
  rv = vnet_lisp_add_del_mreq_itr_rlocs (a);
  if (0 != rv)
    {
      error = clib_error_return (0, "failed to %s map-request itr-rlocs!",
				 is_add ? "add" : "delete");
    }

done:
  vec_free (locator_set_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_add_del_map_request_command) = {
    .path = "lisp map-request itr-rlocs",
    .short_help = "lisp map-request itr-rlocs add/del <locator_set_name>",
    .function = lisp_add_del_mreq_itr_rlocs_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_show_mreq_itr_rlocs_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *loc_set;

  vlib_cli_output (vm, "%=20s", "itr-rlocs");

  if (~0 == lcm->mreq_itr_rlocs)
    {
      return 0;
    }

  loc_set = pool_elt_at_index (lcm->locator_set_pool, lcm->mreq_itr_rlocs);

  vlib_cli_output (vm, "%=20s", loc_set->name);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_map_request_command) = {
    .path = "show lisp map-request itr-rlocs",
    .short_help = "Shows map-request itr-rlocs",
    .function = lisp_show_mreq_itr_rlocs_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_use_petr_set_locator_set_command_fn (vlib_main_t * vm,
					  unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
  u8 is_add = 1, ip_set = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip_address_t ip;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip_address, &ip))
	ip_set = 1;
      else if (unformat (line_input, "disable"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "parse error");
	  goto done;
	}
    }

  if (!ip_set)
    {
      clib_warning ("No petr IP specified!");
      goto done;
    }

  if (vnet_lisp_use_petr (&ip, is_add))
    {
      error = clib_error_return (0, "failed to %s petr!",
				 is_add ? "add" : "delete");
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_use_petr_set_locator_set_command) = {
    .path = "lisp use-petr",
    .short_help = "lisp use-petr [disable] <petr-ip>",
    .function = lisp_use_petr_set_locator_set_command_fn,
};

static clib_error_t *
lisp_show_petr_command_fn (vlib_main_t * vm,
                           unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls;
  locator_t *loc;
  u8 *tmp_str = 0;
  u8 use_petr = lcm->flags & LISP_FLAG_USE_PETR;
  vlib_cli_output (vm, "%=20s%=16s", "petr", use_petr ? "ip" : "");

  if (!use_petr)
    {
      vlib_cli_output (vm, "%=20s", "disable");
      return 0;
    }

  if (~0 == lcm->petr_map_index)
    {
      tmp_str = format (0, "N/A");
    }
  else
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->petr_map_index);
      if (~0 != m->locator_set_index)
        {
          ls = pool_elt_at_index(lcm->locator_set_pool, m->locator_set_index);
          loc = pool_elt_at_index (lcm->locator_pool, ls->locator_indices[0]);
          tmp_str = format (0, "%U", format_ip_address, &loc->address);
        }
      else
        {
          tmp_str = format (0, "N/A");
        }
    }
  vec_add1 (tmp_str, 0);

  vlib_cli_output (vm, "%=20s%=16s", "enable", tmp_str);

  vec_free (tmp_str);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_petr_command) = {
    .path = "show lisp petr",
    .short_help = "Show petr",
    .function = lisp_show_petr_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

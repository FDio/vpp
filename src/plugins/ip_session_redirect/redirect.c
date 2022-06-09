/* Copyright (c) 2021 Cisco and/or its affiliates.
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
 * limitations under the License. */
#include <vlib/vlib.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/in_out_acl.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include "ip_session_redirect.h"

ip_session_redirect_main_t ip_session_redirect_main;

static int
ip_session_redirect_stack (ip_session_redirect_t *ipr)
{
  dpo_id_t dpo = DPO_INVALID;

  fib_path_list_contribute_forwarding (ipr->pl, ipr->payload_type,
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &dpo);
  dpo_stack_from_node (ipr->parent_node_index, &ipr->dpo, &dpo);
  dpo_reset (&dpo);

  /* update session with new next_index
   * we abuse opaque_index to help delete, see ip_session_redirect_del() below
   */
  return vnet_classify_add_del_session (
    &vnet_classify_main, ipr->table_index, ipr->match_and_table_index,
    ipr->dpo.dpoi_next_node /* hit_next_index */, ipr->opaque_index,
    0 /* advance */, CLASSIFY_ACTION_SET_METADATA,
    ipr->dpo.dpoi_index /* metadata */, 1 /* is_add */);
}

static ip_session_redirect_t *
ip_session_redirect_find (ip_session_redirect_main_t *im, u32 table_index,
			  const u8 *match)
{
  /* we are adding the table index at the end of the match string so we
   * can disambiguiate identical matches in different tables in
   * im->session_by_match_and_table_index */
  u8 *match_and_table_index = vec_dup (match);
  vec_add (match_and_table_index, (void *) &table_index, 4);
  uword *p =
    hash_get_mem (im->session_by_match_and_table_index, match_and_table_index);
  vec_free (match_and_table_index);
  if (!p)
    return 0;
  return pool_elt_at_index (im->pool, p[0]);
}

int
ip_session_redirect_add (vlib_main_t *vm, u32 table_index, const u8 *match,
			 const fib_route_path_t *rpaths, u32 opaque_index,
			 int is_punt)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  fib_forward_chain_type_t payload_type;
  ip_session_redirect_t *ipr;
  const char *pname;

  payload_type = fib_forw_chain_type_from_dpo_proto (rpaths[0].frp_proto);
  switch (payload_type)
    {
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
      pname = is_punt ? "ip4-punt-acl" : "ip4-inacl";
      break;
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
      pname = is_punt ? "ip6-punt-acl" : "ip6-inacl";
      break;
    default:
      return VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
    }

  ipr = ip_session_redirect_find (im, table_index, match);
  if (ipr)
    {
      /* update to an existing session */
      fib_path_list_child_remove (ipr->pl, ipr->sibling);
      dpo_reset (&ipr->dpo);
    }
  else
    {
      /* allocate a new entry */
      pool_get (im->pool, ipr);
      fib_node_init (&ipr->node, im->fib_node_type);
      ipr->match_and_table_index = vec_dup ((u8 *) match);
      /* we are adding the table index at the end of the match string so we
       * can disambiguiate identical matches in different tables in
       * im->session_by_match_and_table_index */
      vec_add (ipr->match_and_table_index, (void *) &table_index, 4);
      ipr->table_index = table_index;
      hash_set_mem (im->session_by_match_and_table_index,
		    ipr->match_and_table_index, ipr - im->pool);
    }

  ipr->payload_type = payload_type;
  ipr->pl = fib_path_list_create (
    FIB_PATH_LIST_FLAG_SHARED | FIB_PATH_LIST_FLAG_NO_URPF, rpaths);
  ipr->sibling =
    fib_path_list_child_add (ipr->pl, im->fib_node_type, ipr - im->pool);
  ipr->parent_node_index = vlib_get_node_by_name (vm, (u8 *) pname)->index;
  ipr->opaque_index = opaque_index;

  return ip_session_redirect_stack (ipr);
}

int
ip_session_redirect_del (vlib_main_t *vm, const u32 table_index,
			 const u8 *match)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  vnet_classify_main_t *cm = &vnet_classify_main;
  ip_session_redirect_t *ipr;
  int rv;

  ipr = ip_session_redirect_find (im, table_index, match);
  if (!ipr)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = vnet_classify_add_del_session (
    cm, ipr->table_index, ipr->match_and_table_index, 0 /* hit_next_index */,
    0 /* opaque_index */, 0 /* advance */, 0 /* action */, 0 /* metadata */,
    0 /* is_add */);
  if (rv)
    return rv;

  hash_unset_mem (im->session_by_match_and_table_index,
		  ipr->match_and_table_index);
  vec_free (ipr->match_and_table_index);
  fib_path_list_child_remove (ipr->pl, ipr->sibling);
  dpo_reset (&ipr->dpo);
  pool_put (im->pool, ipr);
  return 0;
}

static u8 *
format_ip_session_redirect (u8 *s, va_list *args)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  ip_session_redirect_t *ipr = va_arg (*args, ip_session_redirect_t *);
  index_t ipri = ipr - im->pool;
  s = format (s, "[%u] table %d key %U opaque_index 0x%x\n", ipri,
	      ipr->table_index, format_hex_bytes, ipr->match_and_table_index,
	      vec_len (ipr->match_and_table_index) - 4, ipr->opaque_index);
  s = format (s, " via:\n");
  s = format (s, "  %U", format_fib_path_list, ipr->pl, 2);
  s = format (s, " forwarding\n");
  s = format (s, "  %U", format_dpo_id, &ipr->dpo, 0);
  return s;
}

static clib_error_t *
ip_session_redirect_show_cmd (vlib_main_t *vm, unformat_input_t *main_input,
			      vlib_cli_command_t *cmd)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_classify_main_t *cm = &vnet_classify_main;
  ip_session_redirect_t *ipr;
  clib_error_t *error = 0;
  u32 table_index = ~0;
  u8 *match = 0;
  u8 *s = 0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "all"))
	;
      else if (unformat (line_input, "table %u", &table_index))
	;
      else if (unformat (line_input, "match %U", unformat_classify_match, cm,
			 &match, table_index))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto out;
	}
    }

  if (match)
    {
      ipr = ip_session_redirect_find (im, table_index, match);
      if (!ipr)
	vlib_cli_output (vm, "none", format_ip_session_redirect, ipr);
      else
	vlib_cli_output (vm, "%U", format_ip_session_redirect, ipr);
    }
  else
    {
      pool_foreach (ipr, im->pool)
	s = format (s, "%U\n", format_ip_session_redirect, ipr);
      vec_add1 (s, 0);
      vlib_cli_output (vm, (char *) s);
      vec_free (s);
    }

out:
  vec_free (match);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ip_session_redirect_show_command, static) = {
  .path = "show ip session redirect",
  .function = ip_session_redirect_show_cmd,
  .short_help = "show ip session redirect <all|table <table-index> <match>>",
};

static clib_error_t *
ip_session_redirect_cmd (vlib_main_t *vm, unformat_input_t *main_input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_classify_main_t *cm = &vnet_classify_main;
  dpo_proto_t payload_proto = DPO_PROTO_IP4;
  fib_route_path_t *rpaths = 0, rpath;
  clib_error_t *error = 0;
  u32 opaque_index = ~0;
  u32 table_index = ~0;
  int is_punt = 0;
  int is_add = 1;
  u8 *match = 0;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "punt"))
	is_punt = 1;
      else if (unformat (line_input, "table %u", &table_index))
	;
      else if (unformat (line_input, "opaque-index %u", &opaque_index))
	;
      else if (unformat (line_input, "match %U", unformat_classify_match, cm,
			 &match, table_index))
	;
      else if (unformat (line_input, "via %U", unformat_fib_route_path, &rpath,
			 &payload_proto))
	vec_add1 (rpaths, rpath);
      else
	{
	  error = unformat_parse_error (line_input);
	  goto out;
	}
    }

  if (~0 == table_index || 0 == match)
    {
      error = clib_error_create ("missing table index or match");
      goto out;
    }

  if (is_add)
    {
      if (0 == rpaths)
	{
	  error = clib_error_create ("missing path");
	  goto out;
	}
      rv = ip_session_redirect_add (vm, table_index, match, rpaths,
				    opaque_index, is_punt);
    }
  else
    {
      rv = ip_session_redirect_del (vm, table_index, match);
    }

  if (rv)
    error = clib_error_create ("failed with error %d", rv);

out:
  vec_free (rpaths);
  vec_free (match);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ip_session_redirect_command, static) = {
  .path = "ip session redirect",
  .function = ip_session_redirect_cmd,
  .short_help = "ip session redirect [add] [punt] table <index> match <match> "
		"via <path> | del table <index> match <match>"
};

static fib_node_t *
ip_session_redirect_get_node (fib_node_index_t index)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  ip_session_redirect_t *ipr = pool_elt_at_index (im->pool, index);
  return &ipr->node;
}

static ip_session_redirect_t *
ip_session_redirect_get_from_node (fib_node_t *node)
{
  return (
    ip_session_redirect_t *) (((char *) node) -
			      STRUCT_OFFSET_OF (ip_session_redirect_t, node));
}

static void
ip_session_redirect_last_lock_gone (fib_node_t *node)
{
  /* the lifetime of the entry is managed by the table. */
  ASSERT (0);
}

/* A back walk has reached this entry */
static fib_node_back_walk_rc_t
ip_session_redirect_back_walk_notify (fib_node_t *node,
				      fib_node_back_walk_ctx_t *ctx)
{
  int rv;
  ip_session_redirect_t *ipr = ip_session_redirect_get_from_node (node);
  rv = ip_session_redirect_stack (ipr);
  ASSERT (0 == rv);
  if (rv)
    clib_warning ("ip_session_redirect_stack() error %d", rv);
  return FIB_NODE_BACK_WALK_CONTINUE;
}

static const fib_node_vft_t ip_session_redirect_vft = {
  .fnv_get = ip_session_redirect_get_node,
  .fnv_last_lock = ip_session_redirect_last_lock_gone,
  .fnv_back_walk = ip_session_redirect_back_walk_notify,
};

static clib_error_t *
ip_session_redirect_init (vlib_main_t *vm)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  im->session_by_match_and_table_index =
    hash_create_vec (0, sizeof (u8), sizeof (u32));
  im->fib_node_type = fib_node_register_new_type ("ip-session-redirect",
						  &ip_session_redirect_vft);
  return 0;
}

VLIB_INIT_FUNCTION (ip_session_redirect_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IP session redirect",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

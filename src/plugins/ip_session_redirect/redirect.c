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
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  dpo_id_t dpo = DPO_INVALID;
  index_t ipri = ipr - im->pool;

  fib_path_list_contribute_forwarding (ipr->pl, ipr->payload_type,
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &dpo);
  dpo_stack_from_node (ipr->parent_node_index, &ipr->dpo, &dpo);
  dpo_reset (&dpo);

  /* update session with new next_index
   * we abuse opaque_index to help delete, see ip_session_redirect_del() below
   */
  return vnet_classify_add_del_session (
    &vnet_classify_main, ipr->table_index, ipr->match,
    ipr->dpo.dpoi_next_node /* hit_next_index */, ipri /* opaque_index */,
    0 /* advance */, CLASSIFY_ACTION_SET_METADATA,
    ipr->dpo.dpoi_index /* metadata */, 1 /* is_add */);
}

static int
ip_session_redirect_find (ip_session_redirect_main_t *im,
			  const u32 table_index, const u8 *match,
			  ip_session_redirect_t **ipr)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *table;
  const vnet_classify_entry_t *e;
  u64 hash;

  if (pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_TABLE;

  table = pool_elt_at_index (cm->tables, table_index);

  if (vec_len (match) !=
      (table->skip_n_vectors + table->match_n_vectors) * sizeof (u32x4))
    return VNET_API_ERROR_INVALID_VALUE;

  /* we abuse opaque_index to store the pool index of ip_session_redirect_t so
   * that on delete, when we find the classifier entry (session) we can
   * retrieve the corresponding ip_session_redirect_t */
  hash = vnet_classify_hash_packet (table, match);
  e = vnet_classify_find_entry (table, match, hash, 0);
  if (!e)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *ipr = pool_elt_at_index (im->pool, e->opaque_index);
  ASSERT (table_index == (*ipr)->table_index);
  ASSERT (vec_cmp (match, (*ipr)->match) == 0);
  return 0;
}

int
ip_session_redirect_add (vlib_main_t *vm, const u32 table_index,
			 const u8 *match, const fib_route_path_t *rpaths,
			 int is_punt)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  fib_forward_chain_type_t payload_type;
  ip_session_redirect_t *ipr;
  const char *pname;
  int rv;

  rv = ip_session_redirect_find (im, table_index, match, &ipr);
  switch (rv)
    {
    case 0:
      /* entry already exists: remove current path */
      fib_path_list_child_remove (ipr->pl, ipr->sibling);
      dpo_reset (&ipr->dpo);
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      /* allocate a new entry */
      pool_get (im->pool, ipr);
      fib_node_init (&ipr->node, im->fib_node_type);
      ipr->match = vec_dup ((u8 *) match);
      ipr->table_index = table_index;
      break;
    default:
      /* error... */
      return rv;
    }

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

  ipr->payload_type = payload_type;
  ipr->pl = fib_path_list_create (
    FIB_PATH_LIST_FLAG_SHARED | FIB_PATH_LIST_FLAG_NO_URPF, rpaths);
  ipr->sibling =
    fib_path_list_child_add (ipr->pl, im->fib_node_type, ipr - im->pool);
  ipr->parent_node_index = vlib_get_node_by_name (vm, (u8 *) pname)->index;

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

  rv = ip_session_redirect_find (im, table_index, match, &ipr);
  if (rv)
    return rv;

  rv = vnet_classify_add_del_session (
    cm, ipr->table_index, match, 0 /* hit_next_index */, 0 /* opaque_index */,
    0 /* advance */, 0 /* action */, 0 /* metadata */, 0 /* is_add */);
  if (rv)
    return rv;

  u8 *match_ = (void *) ipr->match;
  vec_free (match_);

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
  s = format (s, "[%u] table %d key %U\n", ipri, ipr->table_index,
	      format_hex_bytes, ipr->match, vec_len (ipr->match));
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
  ip_session_redirect_t *ipr;
  u8 *s = 0;

  pool_foreach (ipr, im->pool)
    s = format (s, "%U\n", format_ip_session_redirect, ipr);

  vec_add1 (s, 0);
  vlib_cli_output (vm, (char *) s);
  vec_free (s);
  return 0;
}

VLIB_CLI_COMMAND (ip_session_redirect_show_command, static) = {
  .path = "show ip session redirect",
  .function = ip_session_redirect_show_cmd,
  .short_help = "show ip session redirect",
};

static clib_error_t *
ip_session_redirect_cmd (vlib_main_t *vm, unformat_input_t *main_input,
			 vlib_cli_command_t *cmd)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t *rpaths = 0, rpath;
  dpo_proto_t payload_proto = DPO_PROTO_IP4;
  clib_error_t *error = 0;
  u8 *match = 0;
  u32 table_index = ~0;
  int is_add = 1;
  int is_punt = 0;
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
      else if (unformat (line_input, "table %d", &table_index))
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
      rv = ip_session_redirect_add (vm, table_index, match, rpaths, is_punt);
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

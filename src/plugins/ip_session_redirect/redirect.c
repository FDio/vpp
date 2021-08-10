/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vnet/fib/fib_path_list.h>
#include <vnet/classify/vnet_classify.h>
#include "ip_session_redirect.h"

ip_session_redirect_main_t ip_session_redirect_main;

static void
ip_session_redirect_stack (ip_session_redirect_t *ipr)
{
  dpo_id_t dpo = DPO_INVALID;
  const char *pname;
  vlib_node_t *pnode;
  int rv;

  fib_path_list_contribute_forwarding (ipr->pl, ipr->payload_type,
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &dpo);

  switch (ipr->payload_type)
    {
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
      pname = "ip4-inacl";
      break;
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
      pname = "ip6-inacl";
      break;
    default:
      ASSERT (0);
      return;
    }

  pnode = vlib_get_node_by_name (vlib_get_main (), (u8 *) pname);
  dpo_stack_from_node (pnode->index, &ipr->dpo, &dpo);
  dpo_reset (&dpo);

  /* update session with new next_index */
  rv = vnet_classify_add_del_session (
    &vnet_classify_main, ipr->table_index, ipr->match,
    ipr->dpo.dpoi_next_node /* hit_next_index */, 0 /* opaque_index */,
    0 /* advance */, CLASSIFY_ACTION_SET_METADATA,
    ipr->dpo.dpoi_index /* metadata */, 1 /* is_add */);
  ASSERT (0 == rv);
  if (rv)
    clib_warning ("vnet_classify_add_del_session() failed with error %d", rv);
}

u32
ip_session_redirect_add (const u32 table_index, const u8 *match,
			 const fib_route_path_t *rpaths)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  ip_session_redirect_t *ipr;
  index_t ipri;

  pool_get (im->pool, ipr);
  ipri = ipr - im->pool;

  fib_node_init (&ipr->node, im->fib_node_type);
  ipr->payload_type = fib_forw_chain_type_from_dpo_proto (rpaths[0].frp_proto);
  ipr->pl = fib_path_list_create (
    FIB_PATH_LIST_FLAG_SHARED | FIB_PATH_LIST_FLAG_NO_URPF, rpaths);
  ipr->sibling = fib_path_list_child_add (ipr->pl, im->fib_node_type, ipri);
  ipr->table_index = table_index;
  ipr->match = match;

  ip_session_redirect_stack (ipr);

  return ipri;
}

void
ip_session_redirect_del (u32 ipri)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  ip_session_redirect_t *ipr = pool_elt_at_index (im->pool, ipri);
  int rv = vnet_classify_add_del_session (
    &vnet_classify_main, ipr->table_index, ipr->match, 0 /* hit_next_index */,
    0 /* opaque_index */, 0 /* advance */, 0 /* action */, 0 /* metadata */,
    0 /* is_add */);
  ASSERT (0 == rv);
  if (rv)
    clib_warning ("vnet_classify_add_del_session() failed with error %d", rv);

  u8 *matchp = (void *) ipr->match;
  vec_free (matchp);

  fib_path_list_child_remove (ipr->pl, ipr->sibling);
  dpo_reset (&ipr->dpo);
  pool_put (im->pool, ipr);
}

static u8 *
format_ip_session_redirect (u8 *s, va_list *args)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  ip_session_redirect_t *ipr = va_arg (*args, ip_session_redirect_t *);
  u32 ipri = ipr - im->pool;
  s = format (s, "[%d] table %d key %U\n", ipri, ipr->table_index,
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
  u32 table_index = ~0, index = ~0;
  int is_add = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del %d", &index))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
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

  if (is_add)
    {
      if (~0 == table_index || 0 == match || 0 == rpaths)
	{
	  error = clib_error_create ("add: missing parameter");
	  goto out;
	}
      index = ip_session_redirect_add (table_index, match, rpaths);
      vlib_cli_output (vm, "index: %d", index);
    }
  else
    {
      if (~0 == index)
	{
	  error = clib_error_create ("del: missing index");
	  goto out;
	}
      ip_session_redirect_del (index);
    }

out:
  vec_free (rpaths);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ip_session_redirect_command, static) = {
  .path = "ip session redirect",
  .function = ip_session_redirect_cmd,
  .short_help = "ip session redirect [add] table <index> match <match> "
		"via <path> | del index <index>"
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
  ip_session_redirect_t *ipr = ip_session_redirect_get_from_node (node);
  ip_session_redirect_stack (ipr);
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
  im->fib_node_type = fib_node_register_new_type (&ip_session_redirect_vft);
  return 0;
}

VLIB_INIT_FUNCTION (ip_session_redirect_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

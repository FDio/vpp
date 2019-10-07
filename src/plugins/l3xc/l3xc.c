/*
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

#include <plugins/l3xc/l3xc.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_path_list.h>

/**
 * FIB node type the attachment is registered
 */
fib_node_type_t l3xc_fib_node_type;

/**
 * Pool of L3XC objects
 */
l3xc_t *l3xc_pool;

/**
 * DB of L3XC objects
 */
static u32 *l3xc_db[FIB_PROTOCOL_IP_MAX];

index_t
l3xc_find (u32 sw_if_index, fib_protocol_t fproto)
{
  if (vec_len (l3xc_db[fproto]) <= sw_if_index)
    return ~0;

  return (l3xc_db[fproto][sw_if_index]);
}

static void
l3xc_db_add (u32 sw_if_index, fib_protocol_t fproto, index_t l3xci)
{
  vec_validate_init_empty (l3xc_db[fproto], sw_if_index, ~0);

  l3xc_db[fproto][sw_if_index] = l3xci;
}

static void
l3xc_db_remove (u32 sw_if_index, fib_protocol_t fproto)
{
  vec_validate_init_empty (l3xc_db[fproto], sw_if_index, ~0);

  l3xc_db[fproto][sw_if_index] = ~0;
}

static void
l3xc_stack (l3xc_t * l3xc)
{
  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  dpo_id_t via_dpo = DPO_INVALID;

  fib_path_list_contribute_forwarding (l3xc->l3xc_pl,
				       (FIB_PROTOCOL_IP4 == l3xc->l3xc_proto ?
					FIB_FORW_CHAIN_TYPE_UNICAST_IP4 :
					FIB_FORW_CHAIN_TYPE_UNICAST_IP6),
				       FIB_PATH_LIST_FWD_FLAG_NONE, &via_dpo);

  dpo_stack_from_node ((FIB_PROTOCOL_IP4 == l3xc->l3xc_proto ?
			l3xc_ip4_node.index :
			l3xc_ip6_node.index), &l3xc->l3xc_dpo, &via_dpo);
  dpo_reset (&via_dpo);
}

int
l3xc_update (u32 sw_if_index, u8 is_ip6, const fib_route_path_t * rpaths)
{
  fib_protocol_t fproto;
  l3xc_t *l3xc;
  u32 l3xci;

  fproto = (is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);

  l3xci = l3xc_find (sw_if_index, fproto);

  if (INDEX_INVALID == l3xci)
    {
      /*
       * create a new x-connect
       */
      pool_get_aligned_zero (l3xc_pool, l3xc, CLIB_CACHE_LINE_BYTES);

      l3xci = l3xc - l3xc_pool;
      fib_node_init (&l3xc->l3xc_node, l3xc_fib_node_type);
      l3xc->l3xc_sw_if_index = sw_if_index;
      l3xc->l3xc_proto = fproto;

      /*
       * create and become a child of a path list so we get poked when
       * the forwarding changes and stack on the DPO the path-list provides
       */
      l3xc->l3xc_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					     FIB_PATH_LIST_FLAG_NO_URPF),
					    rpaths);
      l3xc->l3xc_sibling = fib_path_list_child_add (l3xc->l3xc_pl,
						    l3xc_fib_node_type,
						    l3xci);
      l3xc_stack (l3xc);

      /*
       * add this new policy to the DB and enable the feature on input interface
       */
      l3xc_db_add (sw_if_index, fproto, l3xci);

      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "l3xc-input-ip4" :
				    "l3xc-input-ip6"),
				   l3xc->l3xc_sw_if_index,
				   1, &l3xci, sizeof (l3xci));
    }
  else
    {
      /*
       * update an existing x-connect.
       * - add the path to the path-list and swap our ancestry
       */
      l3xc = l3xc_get (l3xci);

      if (FIB_NODE_INDEX_INVALID != l3xc->l3xc_pl)
	{
	  fib_path_list_child_remove (l3xc->l3xc_pl, l3xc->l3xc_sibling);
	}

      l3xc->l3xc_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					     FIB_PATH_LIST_FLAG_NO_URPF),
					    rpaths);

      l3xc->l3xc_sibling = fib_path_list_child_add (l3xc->l3xc_pl,
						    l3xc_fib_node_type,
						    l3xci);
    }
  return (0);
}

int
l3xc_delete (u32 sw_if_index, u8 is_ip6)
{
  fib_protocol_t fproto;
  l3xc_t *l3xc;
  u32 l3xci;

  fproto = (is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);

  l3xci = l3xc_find (sw_if_index, fproto);

  if (INDEX_INVALID == l3xci)
    {
      /*
       * no such policy
       */
      return (VNET_API_ERROR_INVALID_VALUE);
    }
  else
    {
      l3xc = l3xc_get (l3xci);

      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "l3xc-input-ip4" :
				    "l3xc-input-ip6"),
				   l3xc->l3xc_sw_if_index,
				   0, &l3xci, sizeof (l3xci));

      fib_path_list_child_remove (l3xc->l3xc_pl, l3xc->l3xc_sibling);

      l3xc_db_remove (l3xc->l3xc_sw_if_index, fproto);
      pool_put (l3xc_pool, l3xc);
    }

  return (0);
}

static clib_error_t *
l3xc_cmd (vlib_main_t * vm,
	  unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  u32 sw_if_index, is_del, is_ip6;
  dpo_proto_t payload_proto;
  vnet_main_t *vnm;
  int rv = 0;

  is_ip6 = is_del = 0;
  sw_if_index = ~0;
  vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "ip6"))
	is_ip6 = 1;
      else if (unformat (line_input, "ip4"))
	is_ip6 = 0;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	vec_add1 (rpaths, rpath);
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  if (~0 == sw_if_index)
    {
      vlib_cli_output (vm, "Specify an input interface");
      goto out;
    }
  if (vec_len (rpaths) == 0)
    {
      vlib_cli_output (vm, "Specify some paths");
      goto out;
    }

  if (!is_del)
    {
      rv = l3xc_update (sw_if_index, is_ip6, rpaths);

      if (rv)
	{
	  vlib_cli_output (vm, "Failed: %d", rv);
	  goto out;
	}
    }
  else
    {
      l3xc_delete (sw_if_index, is_ip6);
    }

out:
  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Create an L3XC policy.
 */
VLIB_CLI_COMMAND (l3xc_cmd_node, static) = {
  .path = "l3xc",
  .function = l3xc_cmd,
  .short_help = "l3xc [add|del] <INTERFACE> via ...",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static u8 *
format_l3xc (u8 * s, va_list * args)
{
  l3xc_t *l3xc = va_arg (*args, l3xc_t *);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "l3xc:[%d]: %U",
	      l3xc - l3xc_pool, format_vnet_sw_if_index_name,
	      vnm, l3xc->l3xc_sw_if_index);
  s = format (s, "\n");
  if (FIB_NODE_INDEX_INVALID == l3xc->l3xc_pl)
    {
      s = format (s, "no forwarding");
    }
  else
    {
      s = fib_path_list_format (l3xc->l3xc_pl, s);

      s = format (s, "\n  %U", format_dpo_id, &l3xc->l3xc_dpo, 4);
    }

  return (s);
}

void
l3xc_walk (l3xc_walk_cb_t cb, void *ctx)
{
  u32 l3xci;

  /* *INDENT-OFF* */
  pool_foreach_index(l3xci, l3xc_pool,
  ({
    if (!cb(l3xci, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
l3xc_show_cmd (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l3xc_t *l3xc;

  /* *INDENT-OFF* */
  pool_foreach(l3xc, l3xc_pool,
  ({
    vlib_cli_output(vm, "%U", format_l3xc, l3xc);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l3xc_show_cmd_node, static) = {
  .path = "show l3xc",
  .function = l3xc_show_cmd,
  .short_help = "show l3xc",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static fib_node_t *
l3xc_get_node (fib_node_index_t index)
{
  l3xc_t *l3xc = l3xc_get (index);
  return (&(l3xc->l3xc_node));
}

static l3xc_t *
l3xc_get_from_node (fib_node_t * node)
{
  return ((l3xc_t *) (((char *) node) -
		      STRUCT_OFFSET_OF (l3xc_t, l3xc_node)));
}

static void
l3xc_last_lock_gone (fib_node_t * node)
{
}

/*
 * A back walk has reached this L3XC policy
 */
static fib_node_back_walk_rc_t
l3xc_back_walk_notify (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  l3xc_stack (l3xc_get_from_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t l3xc_vft = {
  .fnv_get = l3xc_get_node,
  .fnv_last_lock = l3xc_last_lock_gone,
  .fnv_back_walk = l3xc_back_walk_notify,
};

static clib_error_t *
l3xc_init (vlib_main_t * vm)
{
  l3xc_fib_node_type = fib_node_register_new_type (&l3xc_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (l3xc_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <plugins/svs/svs.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

u32 *svs_itf_db[FIB_PROTOCOL_IP_MAX];

static fib_source_t svs_fib_src;

int
svs_table_add (fib_protocol_t fproto, u32 table_id)
{
  fib_table_find_or_create_and_lock (fproto, table_id, svs_fib_src);

  return (0);
}

int
svs_table_delete (fib_protocol_t fproto, u32 table_id)
{
  u32 fib_index, ii;

  fib_index = fib_table_find (fproto, table_id);

  vec_foreach_index (ii, svs_itf_db[fproto])
  {
    if (svs_itf_db[fproto][ii] == fib_index)
      return VNET_API_ERROR_INSTANCE_IN_USE;
  }

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_table_unlock (fib_index, fproto, svs_fib_src);

  return (0);
}

static int
svs_route_add_i (u32 fib_index, const fib_prefix_t * pfx, u32 src_fib_index)
{
  dpo_id_t dpo = DPO_INVALID;


  lookup_dpo_add_or_lock_w_fib_index (src_fib_index,
				      fib_proto_to_dpo (pfx->fp_proto),
				      LOOKUP_UNICAST,
				      LOOKUP_INPUT_SRC_ADDR,
				      LOOKUP_TABLE_FROM_CONFIG, &dpo);

  fib_table_entry_special_dpo_add (fib_index, pfx,
				   svs_fib_src,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  dpo_unlock (&dpo);

  return (0);
}

int
svs_route_add (u32 table_id, const fib_prefix_t * pfx, u32 source_table_id)
{
  u32 fib_index, src_fib_index;
  int rv;

  fib_index = fib_table_find (pfx->fp_proto, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  src_fib_index = fib_table_find (pfx->fp_proto, source_table_id);

  if (~0 == src_fib_index)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  rv = svs_route_add_i (fib_index, pfx, src_fib_index);

  return (rv);
}

int
svs_route_delete (u32 table_id, const fib_prefix_t * pfx)
{
  u32 fib_index;

  fib_index = fib_table_find (pfx->fp_proto, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_table_entry_special_remove (fib_index, pfx, svs_fib_src);

  return (0);
}

int
svs_enable (fib_protocol_t fproto, u32 table_id, u32 sw_if_index)
{
  fib_prefix_t pfx = {
    .fp_proto = fproto,
  };
  u32 fib_index;

  fib_index = fib_table_find (fproto, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  /*
   * now we know which interface the table will serve, we can add the default
   * route to use the table that the interface is bound to.
   */
  svs_route_add_i (fib_index, &pfx,
		   fib_table_get_index_for_sw_if_index (fproto, sw_if_index));

  vec_validate_init_empty (svs_itf_db[fproto], sw_if_index, ~0);

  svs_itf_db[fproto][sw_if_index] = fib_index;

  vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				"ip4-unicast" :
				"ip6-unicast"),
			       (FIB_PROTOCOL_IP4 == fproto ?
				"svs-ip4" :
				"svs-ip6"), sw_if_index, 1, NULL, 0);

  return (0);
}

static void
svs_table_bind (fib_protocol_t fproto, u32 sw_if_index, u32 itf_fib_index)
{
  /*
   * update the default route to use the interface's newly bound FIB
   */
  u32 svs_fib_index;

  if (sw_if_index >= vec_len (svs_itf_db[FIB_PROTOCOL_IP6]))
    return;

  svs_fib_index = svs_itf_db[FIB_PROTOCOL_IP6][sw_if_index];

  if (~0 != svs_fib_index)
    {
      fib_prefix_t pfx = {
	.fp_proto = fproto,
      };

      svs_route_add (svs_fib_index, &pfx, itf_fib_index);
    }
  /*
   * else
   *  no SVS enable on this interface
   */
}

static void
svs_ip6_table_bind (ip6_main_t * im,
		    uword opaque,
		    u32 sw_if_index, u32 new_fib_index, u32 old_fib_index)
{
  svs_table_bind (FIB_PROTOCOL_IP6, sw_if_index, new_fib_index);
}

static void
svs_ip4_table_bind (ip4_main_t * im,
		    uword opaque,
		    u32 sw_if_index, u32 new_fib_index, u32 old_fib_index)
{
  svs_table_bind (FIB_PROTOCOL_IP4, sw_if_index, new_fib_index);
}

int
svs_disable (fib_protocol_t fproto, u32 table_id, u32 sw_if_index)
{
  fib_prefix_t pfx = {
    .fp_proto = fproto,
  };
  u32 fib_index;

  fib_index = fib_table_find (fproto, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (sw_if_index >= vec_len (svs_itf_db[fproto]))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  svs_itf_db[fproto][sw_if_index] = ~0;

  vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				"ip4-unicast" :
				"ip6-unicast"),
			       (FIB_PROTOCOL_IP4 == fproto ?
				"svs-ip4" :
				"svs-ip6"), sw_if_index, 0, NULL, 0);

  fib_table_entry_special_remove (fib_index, &pfx, svs_fib_src);

  return (0);
}

void
svs_walk (svs_walk_fn_t fn, void *ctx)
{
  fib_protocol_t fproto;
  u32 ii, fib_index;

  FOR_EACH_FIB_IP_PROTOCOL (fproto)
  {
    vec_foreach_index (ii, svs_itf_db[fproto])
    {
      fib_index = svs_itf_db[fproto][ii];

      if (~0 != fib_index)
	{
	  if (WALK_CONTINUE != fn (fproto,
				   fib_table_get_table_id (fib_index, fproto),
				   ii, ctx))
	    return;
	}
    }
  }
}

typedef enum svs_next_t_
{
  SVS_NEXT_DROP,
  SVS_N_NEXT,
} svs_next_t;

typedef struct svs_input_trace_t_
{
  u32 fib_index;
} svs_input_trace_t;

always_inline uword
svs_input_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, fib_protocol_t fproto)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const load_balance_t *lb0;
	  const lookup_dpo_t *lk0;
	  u32 bi0, sw_if_index0;
	  const dpo_id_t *dpo0;
	  vlib_buffer_t *b0;
	  svs_next_t next0;
	  index_t lbi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      ip4_header_t *ip0;

	      ip0 = vlib_buffer_get_current (b0);
	      lbi0 =
		ip4_fib_forwarding_lookup (svs_itf_db[fproto][sw_if_index0],
					   &ip0->src_address);
	    }
	  else
	    {
	      ip6_header_t *ip0;

	      ip0 = vlib_buffer_get_current (b0);
	      lbi0 = ip6_fib_table_fwding_lookup (svs_itf_db[fproto]
						  [sw_if_index0],
						  &ip0->src_address);
	    }
	  lb0 = load_balance_get (lbi0);
	  dpo0 = load_balance_get_fwd_bucket (lb0, 0);
	  lk0 = lookup_dpo_get (dpo0->dpoi_index);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lk0->lkd_fib_index;

	  vnet_feature_next (&next0, b0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      svs_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->fib_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
svs_input_ip4 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return svs_input_inline (vm, node, frame, FIB_PROTOCOL_IP4);
}

static uword
svs_input_ip6 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return svs_input_inline (vm, node, frame, FIB_PROTOCOL_IP6);
}

static u8 *
format_svs_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  svs_input_trace_t *t = va_arg (*args, svs_input_trace_t *);

  s = format (s, " fib_index %d", t->fib_index);
  return s;
}

VLIB_REGISTER_NODE (svs_ip4_node) =
{
  .function = svs_input_ip4,
  .name = "svs-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_svs_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SVS_N_NEXT,
  .next_nodes =
  {
    [SVS_NEXT_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (svs_ip6_node) =
{
  .function = svs_input_ip6,
  .name = "svs-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_svs_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .next_nodes =
  {
    [SVS_NEXT_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (svs_ip4_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "svs-ip4",
};

VNET_FEATURE_INIT (svs_ip6_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "svs-ip6",
};

static clib_error_t *
svs_table_cli (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  fib_protocol_t fproto;
  u32 table_id;
  u8 add;

  fproto = FIB_PROTOCOL_IP4;
  table_id = ~0;
  add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (input, "table-id %d", &table_id))
	;
      else
	break;
    }

  if (~0 == table_id)
    return clib_error_return (0, "table-id must be specified");

  if (add)
    svs_table_add (fproto, table_id);
  else
    svs_table_delete (fproto, table_id);

  return (NULL);
}

VLIB_CLI_COMMAND (svs_table_cmd_cli, static) = {
    .path = "svs table",
    .short_help = "Source VRF select table [add|delete] [ip4|ip6] table-id X",
    .function = svs_table_cli,
};

static clib_error_t *
svs_enable_cli (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 sw_if_index, table_id;
  fib_protocol_t fproto;
  vnet_main_t *vnm;
  u8 enable;

  vnm = vnet_get_main ();
  sw_if_index = table_id = ~0;
  fproto = FIB_PROTOCOL_IP4;
  enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (input, "table-id %d", &table_id))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (~0 == table_id)
    return clib_error_return (0, "table-id must be specified");

  if (enable)
    svs_enable (fproto, table_id, sw_if_index);
  else
    svs_disable (fproto, table_id, sw_if_index);

  return (NULL);
}

VLIB_CLI_COMMAND (svs_enable_cli_cmd, static) = {
    .path = "svs enable",
    .short_help = "Source VRF select [enable|disable] [ip4|ip6] <table-id> X <interface>",
    .function = svs_enable_cli,
};

static clib_error_t *
svs_route_cli (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 table_id, src_table_id;
  fib_prefix_t pfx;
  int rv;
  u8 add;
  u8 pfx_set = 0;

  src_table_id = table_id = ~0;
  add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "table-id %d", &table_id))
	;
      else if (unformat (input, "src-table-id %d", &src_table_id))
	;
      else if (unformat (input, "%U/%d",
			 unformat_ip4_address, &pfx.fp_addr.ip4, &pfx.fp_len))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx_set = 1;
	}
      else if (unformat (input, "%U/%d",
			 unformat_ip6_address, &pfx.fp_addr.ip6, &pfx.fp_len))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx_set = 1;
	}
      else
	break;
    }

  if (~0 == table_id)
    return clib_error_return (0, "table-id must be specified");
  if (~0 == src_table_id)
    return clib_error_return (0, "src-table-id must be specified");
  if (!pfx_set)
    return clib_error_return (0, "prefix must be specified");

  if (add)
    rv = svs_route_add (table_id, &pfx, src_table_id);
  else
    rv = svs_route_delete (table_id, &pfx);

  if (rv != 0)
    return clib_error_return (0,
			      "failed, rv=%d:%U",
			      (int) rv, format_vnet_api_errno, rv);

  return (NULL);
}

VLIB_CLI_COMMAND (svs_route_cmd_cli, static) = {
    .path = "svs route",
    .short_help = "Source VRF select route [add|delete] <table-id> <prefix> <src-table-id>",
    .function = svs_route_cli,
};

static clib_error_t *
svs_show_cli (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  fib_protocol_t fproto;
  u32 ii;

  vlib_cli_output (vm, "Source VRF select interface to fib-index mappings:");
  FOR_EACH_FIB_IP_PROTOCOL (fproto)
  {
    vlib_cli_output (vm, " %U", format_fib_protocol, fproto);
    vec_foreach_index (ii, svs_itf_db[fproto])
    {
      if (~0 != svs_itf_db[fproto][ii])
	vlib_cli_output (vm, "  %U -> %d", format_vnet_sw_if_index_name,
			 vnet_get_main (), ii, svs_itf_db[fproto][ii]);
    }
  }
  return (NULL);
}

VLIB_CLI_COMMAND (svs_show_cli_cmd, static) = {
  .path = "show svs",
  .short_help = "Source VRF select show",
  .function = svs_show_cli,
};

static clib_error_t *
svs_init (vlib_main_t * vm)
{
  ip6_table_bind_callback_t cbt6 = {
    .function = svs_ip6_table_bind,
  };
  vec_add1 (ip6_main.table_bind_callbacks, cbt6);

  ip4_table_bind_callback_t cbt4 = {
    .function = svs_ip4_table_bind,
  };
  vec_add1 (ip4_main.table_bind_callbacks, cbt4);

  svs_fib_src = fib_source_allocate ("svs",
				     FIB_SOURCE_PRIORITY_LOW,
				     FIB_SOURCE_BH_SIMPLE);

  return (NULL);
}

VLIB_INIT_FUNCTION (svs_init);

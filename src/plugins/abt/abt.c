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

#include <plugins/abt/abt.h>
#include <plugins/acl/exports.h>
#include <vpp/app/version.h>

typedef struct abt_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (marker);
  /**
   * ACLs index to match
   */
  u32 *at_acls;

  /**
   * Allocated client index for ACL lookup
   */
  u32 at_lc_index;

  /**
   * The protocol for the attachment. i.e. the protocol
   * of the packets that are being forwarded
   */
  fib_protocol_t at_proto;
} abt_t;

/**
 * Pool of ABT interface attachment objects
 */
static abt_t *abt_pool;

/**
 * A per interface vector of attachedments
 */
static u32 *abt_per_itf[FIB_PROTOCOL_MAX];

/**
 * ABT ACL module user id returned during the initialization
 */
static u32 abt_acl_user_id;

static inline abt_t *
abt_get (u32 index)
{
  return (pool_elt_at_index (abt_pool, index));
}

#define ABT_FEAT_NAME(proto)    \
  (FIB_PROTOCOL_IP4 == fproto ? \
   "abt-input-ip4" :            \
   "abt-input-ip6")

int
abt_attach (u32 sw_if_index, fib_protocol_t fproto, u32 * acls)
{
  abt_t *at;
  u32 ati;

  ASSERT (vec_len (acls));

  vec_validate_init_empty (abt_per_itf[fproto], sw_if_index, INDEX_INVALID);

  ati = abt_per_itf[fproto][sw_if_index];

  if (INDEX_INVALID == ati)
    {
      /*
       * construt a new attachemnt object
       */
      pool_get_aligned (abt_pool, at, CLIB_CACHE_LINE_BYTES);

      abt_per_itf[fproto][sw_if_index] = at - abt_pool;
      at->at_proto = fproto;
      at->at_acls = NULL;

      /* if this is the first ABT, we need to acquire an ACL lookup context */
      at->at_lc_index =
	acl_plugin_get_lookup_context_index (abt_acl_user_id, sw_if_index, 0);

      /*
       * when enabling ACLs we need to enable the interface input feature
       */
      vnet_feature_enable_disable ("device-input",
				   ABT_FEAT_NAME (fproto),
				   sw_if_index, 1, NULL, 0);
    }
  else
    {
      at = abt_get (ati);
      vec_free (at->at_acls);
    }
  at->at_acls = vec_dup (acls);

  /* Prepare and set the list of ACLs for lookup within the context */
  acl_plugin_set_acl_vec_for_context (at->at_lc_index, at->at_acls);

  return (0);
}

int
abt_detach (u32 sw_if_index, fib_protocol_t fproto)
{
  abt_t *at;

  if (vec_len (abt_per_itf[fproto]) < sw_if_index)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  at = abt_get (abt_per_itf[fproto][sw_if_index]);

  /*
   * when deleting the last ABT polciy on the interface
   * we need to disable the interface input feature
   */
  vnet_feature_enable_disable ("device-input",
			       ABT_FEAT_NAME (fproto),
			       sw_if_index, 0, NULL, 0);

  /* Return the lookup context, invalidate its id in our records */
  acl_plugin_put_lookup_context_index (at->at_lc_index);

  /*
   * return the object
   */
  abt_per_itf[fproto][sw_if_index] = INDEX_INVALID;
  pool_put (abt_pool, at);

  return (0);
}

static u8 *
format_abt_intf_attach (u8 * s, va_list * args)
{
  abt_t *at = va_arg (*args, abt_t *);
  u32 *ai;

  s = format (s, "abt-interface-attach: %U acls:[",
	      format_fib_protocol, at->at_proto, at->at_acls);
  vec_foreach (ai, at->at_acls)
  {
    s = format (s, "%d ", *ai);
  }
  s = format (s, "]");

  return (s);
}

static clib_error_t *
abt_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 acl_index, sw_if_index, *acls;
  fib_protocol_t fproto;
  vnet_main_t *vnm;
  u32 is_del;

  acls = NULL;
  is_del = 0;
  sw_if_index = acl_index = ~0;
  vnm = vnet_get_main ();
  fproto = FIB_PROTOCOL_MAX;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "add"))
	is_del = 0;
      else if (unformat (input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (input, "acl %d", &acl_index))
	vec_add1 (acls, acl_index);
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == acl_index)
    {
      return (clib_error_return (0, "invalid acl ID:%d", acl_index));
    }
  if (~0 == sw_if_index)
    {
      return (clib_error_return (0, "invalid interface name"));
    }
  if (FIB_PROTOCOL_MAX == fproto)
    {
      return (clib_error_return (0, "Specify either ip4 or ip6"));
    }

  if (is_del)
    abt_detach (sw_if_index, fproto);
  else
    abt_attach (sw_if_index, fproto, acls);

  vec_free (acls);

  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Attach an ABT policy to an interface.
 */
VLIB_CLI_COMMAND (abt_cmd_node, static) = {
  .path = "abt attach",
  .function = abt_cmd,
  .short_help = "abt attach <ip4|ip6> [del] acl <value> <interface>",
};
VLIB_CLI_COMMAND (abt_trace_cmd_node, static) = {
  .path = "trace add acl",
  .function = abt_cmd,
  .short_help = "trace add <ip4|ip6> [del] acl <value> <interface>",
};
/* *INDENT-ON* */

static clib_error_t *
abt_show_attach_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const abt_t *at;
  u32 sw_if_index, ati;
  fib_protocol_t fproto;
  vnet_main_t *vnm;

  sw_if_index = ~0;
  vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == sw_if_index)
    {
      vlib_cli_output (vm, "specify an interface");
    }

  /* *INDENT-OFF* */
  FOR_EACH_FIB_IP_PROTOCOL(fproto)
  {
    if (sw_if_index < vec_len(abt_per_itf[fproto]))
      {
        ati = abt_per_itf[fproto][sw_if_index];
        if (INDEX_INVALID != ati) {
          at = abt_get(ati);
          vlib_cli_output(vm, " %U", format_abt_intf_attach, at);
        }
      }
  }
  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abt_show_attach_cmd_node, static) = {
  .path = "show abt attach",
  .function = abt_show_attach_cmd,
  .short_help = "show abt attach <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

always_inline uword
abt_input_inline (vlib_main_t * vm,
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
	  fa_5tuple_opaque_t fa_5tuple0;
	  const abt_t *at0;
	  u32 bi0, sw_if_index0, next0, ati0;
	  vlib_buffer_t *b0;
	  u32 match_acl_index = ~0;
	  u32 match_acl_pos = ~0;
	  u32 match_rule_index = ~0;
	  u32 trace_bitmap = 0;
	  u8 action;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  ASSERT (vec_len (abt_per_itf[fproto]) > sw_if_index0);
	  ati0 = abt_per_itf[fproto][sw_if_index0];

	  ASSERT (INDEX_INVALID != ati0);
	  at0 = abt_get (ati0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vlib_add_trace (vm, node, b0, 0);
	    }

	  /*
	   * if any of the ACLs attached to this interface match, then
	   * set the trace bit in the buffer
	   */
	  acl_plugin_fill_5tuple (at0->at_lc_index, b0,
				  (FIB_PROTOCOL_IP6 == fproto),
				  1, 1, &fa_5tuple0);

	  if (acl_plugin_match_5tuple (at0->at_lc_index,
				       &fa_5tuple0,
				       (FIB_PROTOCOL_IP6 == fproto),
				       &action,
				       &match_acl_pos,
				       &match_acl_index,
				       &match_rule_index, &trace_bitmap))
	    {
	      /* match */
	      b0->flags |= VLIB_BUFFER_IS_TRACED;
	    }

	  vnet_feature_next (sw_if_index0, &next0, b0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
abt_input_ip4 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abt_input_inline (vm, node, frame, FIB_PROTOCOL_IP4);
}

static uword
abt_input_ip6 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abt_input_inline (vm, node, frame, FIB_PROTOCOL_IP6);
}

static u8 *
format_abt_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (abt_ip4_node) =
{
  .function = abt_input_ip4,
  .name = "abt-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_abt_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (abt_ip6_node) =
{
  .function = abt_input_ip6,
  .name = "abt-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_abt_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
};

VNET_FEATURE_INIT (abt_ip4_feat, static) =
{
  .arc_name = "device-input",
  .node_name = "abt-input-ip4",
};

VNET_FEATURE_INIT (abt_ip6_feat, static) =
{
  .arc_name = "device-input",
  .node_name = "abt-input-ip6",
};
/* *INDENT-ON* */

static clib_error_t *
abt_init (vlib_main_t * vm)
{
  clib_error_t *acl_init_res = acl_plugin_exports_init ();
  if (acl_init_res)
    return (acl_init_res);

  abt_acl_user_id =
    acl_plugin_register_user_module ("ABT plugin", "sw_if_index", NULL);

  return (NULL);
}

VLIB_INIT_FUNCTION (abt_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "ACL based Tracing",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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

#include <plugins/abf/abf.h>
#include <vnet/fib/fib_path_list.h>
#include <plugins/acl/exports.h>


/**
 * Attachment data for an ABF policy to an interface
 */
typedef struct abf_itf_attach_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (marker);
  /**
   * The ACL and DPO are cached for fast DP access
   */
  /**
   * ACL index to match
   */
  u32 aia_acl;

  /**
   * The DPO actually used for forwarding
   */
  dpo_id_t aia_dpo;

  /**
   * Linkage into the FIB graph
   */
  fib_node_t aia_node;

  /**
   * The VPP index of the ABF policy
   */
  u32 aia_abf;

  /**
   * Sibling index on the policy's path list
   */
  u32 aia_sibling;

  /**
   * The protocol for the attachment. i.e. the protocol
   * of the packets that are being forwarded
   */
  fib_protocol_t aia_proto;

  /**
   * The priority of this policy for attachment.
   * The lower the value the higher the priority.
   * The higher priority policies are matched first.
   */
  u32 aia_prio;
} abf_itf_attach_t;

/**
 * Forward declarations;
 */
extern vlib_node_registration_t abf_ip4_node;
extern vlib_node_registration_t abf_ip6_node;

/**
 * FIB node registered type for the bonds
 */
static fib_node_type_t abf_itf_attach_fib_node_type;

/**
 * Pool of ABF interface attachment objects
 */
static abf_itf_attach_t *abf_itf_attach_pool;

/**
 * A per interface vector of attached policies. used in the data-plane
 */
static u32 **abf_per_itf[FIB_PROTOCOL_MAX];

/**
 * A DB of attachments; key={abf_index,sw_if_index}
 */
static uword *abf_itf_attach_db;

static inline abf_itf_attach_t *
abf_itf_attach_get (u32 index)
{
  return (pool_elt_at_index (abf_itf_attach_pool, index));
}

static u64
abf_itf_attach_mk_key (u32 abf_index, u32 sw_if_index)
{
  u64 key;

  key = abf_index;
  key = key << 32;
  key |= sw_if_index;

  return (key);
}

static abf_itf_attach_t *
abf_itf_attach_db_find (u32 abf_index, u32 sw_if_index)
{
  uword *p;
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  p = hash_get (abf_itf_attach_db, key);

  if (NULL != p)
    return (pool_elt_at_index (abf_itf_attach_pool, p[0]));

  return (NULL);
}

static void
abf_itf_attach_db_add (u32 abf_index, u32 sw_if_index, abf_itf_attach_t * aia)
{
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  hash_set (abf_itf_attach_db, key, aia - abf_itf_attach_pool);
}

static void
abf_itf_attach_db_del (u32 abf_index, u32 sw_if_index)
{
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  hash_unset (abf_itf_attach_db, key);
}

static void
abf_itf_attach_stack (abf_itf_attach_t * aia)
{
  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  dpo_id_t via_dpo = DPO_INVALID;
  abf_t *abf;

  abf = abf_get (aia->aia_abf);

  fib_path_list_contribute_forwarding (abf->abf_pl,
				       (FIB_PROTOCOL_IP4 == aia->aia_proto ?
					FIB_FORW_CHAIN_TYPE_UNICAST_IP4 :
					FIB_FORW_CHAIN_TYPE_UNICAST_IP6),
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE,
				       &via_dpo);

  dpo_stack_from_node ((FIB_PROTOCOL_IP4 == aia->aia_proto ?
			abf_ip4_node.index :
			abf_ip6_node.index), &aia->aia_dpo, &via_dpo);
  dpo_reset (&via_dpo);
}

static int
abf_cmp_attach_for_sort (void *v1, void *v2)
{
  const abf_itf_attach_t *aia1;
  const abf_itf_attach_t *aia2;

  aia1 = abf_itf_attach_get (*(u32 *) v1);
  aia2 = abf_itf_attach_get (*(u32 *) v2);

  return (aia1->aia_prio - aia2->aia_prio);
}

int
abf_attach (fib_protocol_t fproto,
	    u32 policy_id, u32 priority, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  u32 abfi, aiai;
  abf_t *abf;

  abfi = abf_find (policy_id);

  ASSERT (INDEX_INVALID != abfi);
  abf = abf_get (abfi);

  /*
   * check this is not a duplicate
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL != aia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * construt a new attachemnt object
   */
  pool_get (abf_itf_attach_pool, aia);

  fib_node_init (&aia->aia_node, abf_itf_attach_fib_node_type);
  aia->aia_prio = priority;
  aia->aia_proto = fproto;
  aia->aia_acl = abf->abf_acl;
  aia->aia_abf = abfi;
  aiai = aia - abf_itf_attach_pool;
  abf_itf_attach_db_add (policy_id, sw_if_index, aia);

  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  abf_itf_attach_stack (aia);

  /*
   * Insert the policy on the interfaces list.
   */
  vec_validate_init_empty (abf_per_itf[fproto], sw_if_index, NULL);
  vec_add1 (abf_per_itf[fproto][sw_if_index], aia - abf_itf_attach_pool);
  if (1 == vec_len (abf_per_itf[fproto][sw_if_index]))
    {
      /*
       * when enabling the first ABF polciy on the interface
       * we need to enable the interface input feature
       */
      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "abf-input-ip4" :
				    "abf-input-ip6"),
				   sw_if_index, 1, NULL, 0);
    }
  else
    {
      vec_sort_with_function (abf_per_itf[fproto][sw_if_index],
			      abf_cmp_attach_for_sort);
    }

  /*
   * become a child of the ABF poilcy so we are notified when
   * its forwarding changes.
   */
  aia->aia_sibling = fib_node_child_add (abf_fib_node_type,
					 abfi,
					 abf_itf_attach_fib_node_type, aiai);

  return (0);
}

int
abf_detach (fib_protocol_t fproto, u32 policy_id, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  u32 index;

  /*
   * check this is a valid attahment
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL == aia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * first remove from the interface's vecotr
   */
  ASSERT (abf_per_itf[fproto]);
  ASSERT (abf_per_itf[fproto][sw_if_index]);

  index = vec_search (abf_per_itf[fproto][sw_if_index],
		      aia - abf_itf_attach_pool);

  ASSERT (index != ~0);
  vec_del1 (abf_per_itf[fproto][sw_if_index], index);

  if (0 == vec_len (abf_per_itf[fproto][sw_if_index]))
    {
      /*
       * when deleting the last ABF polciy on the interface
       * we need to disable the interface input feature
       */
      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "abf-input-ip4" :
				    "abf-input-ip6"),
				   sw_if_index, 0, NULL, 0);
    }
  else
    {
      vec_sort_with_function (abf_per_itf[fproto][sw_if_index],
			      abf_cmp_attach_for_sort);
    }

  /*
   * remove the dependency on the policy
   */
  fib_node_child_remove (abf_fib_node_type, aia->aia_abf, aia->aia_sibling);

  /*
   * remove the attahcment from the DB
   */
  abf_itf_attach_db_del (policy_id, sw_if_index);

  /*
   * release our locks on FIB forwarding data
   */
  dpo_reset (&aia->aia_dpo);

  /*
   * return the object
   */
  pool_put (abf_itf_attach_pool, aia);

  return (0);
}

static u8 *
format_abf_intf_attach (u8 * s, va_list * ap)
{
  abf_itf_attach_t *aia = va_arg (*ap, abf_itf_attach_t *);
  abf_t *abf;

  abf = abf_get (aia->aia_abf);
  s = format (s, "abf-interface-attach: policy:%d prioity:%d",
	      abf->abf_id, aia->aia_prio);
  s = format (s, "\n  %U", format_dpo_id, &aia->aia_dpo, 2);

  return (s);
}

static clib_error_t *
abf_attach_cmd (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id, sw_if_index;
  fib_protocol_t fproto;
  u32 is_del, priority;
  vnet_main_t *vnm;

  is_del = 0;
  sw_if_index = policy_id = ~0;
  vnm = vnet_get_main ();
  fproto = FIB_PROTOCOL_MAX;
  priority = 0;

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
      else if (unformat (input, "policy %d", &policy_id))
	;
      else if (unformat (input, "priority %d", &priority))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == policy_id)
    {
      return (clib_error_return (0, "invalid policy ID:%d", policy_id));
    }
  if (~0 == sw_if_index)
    {
      return (clib_error_return (0, "invalid interface name"));
    }
  if (FIB_PROTOCOL_MAX == fproto)
    {
      return (clib_error_return (0, "Specify either ip4 or ip6"));
    }

  if (~0 == abf_find (policy_id))
    return (clib_error_return (0, "invalid policy ID:%d", policy_id));

  if (is_del)
    abf_detach (fproto, policy_id, sw_if_index);
  else
    abf_attach (fproto, policy_id, priority, sw_if_index);

  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (abf_attach_cmd_node, static) = {
  .path = "abf attach",
  .function = abf_attach_cmd,
  .short_help = "abf attach <ip4|ip6> [del] policy <value> <interface>",
  // this is not MP safe
};
/* *INDENT-ON* */

static clib_error_t *
abf_show_attach_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const abf_itf_attach_t *aia;
  u32 sw_if_index, *aiai;
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
    if (sw_if_index < vec_len(abf_per_itf[fproto]))
      {
        vec_foreach(aiai, abf_per_itf[fproto][sw_if_index])
          {
            aia = pool_elt_at_index(abf_itf_attach_pool, *aiai);
            vlib_cli_output(vm, "%U", format_abf_intf_attach, aia);
          }
      }
  }
  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_show_attach_cmd_node, static) = {
  .path = "show abf attach",
  .function = abf_show_attach_cmd,
  .short_help = "show abf attach <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

typedef enum abf_next_t_
{
  ABF_NEXT_DROP,
  ABF_N_NEXT,
} abf_next_t;

typedef struct abf_input_trace_t_
{
  abf_next_t next;
  index_t index;
} abf_input_trace_t;

always_inline uword
abf_input_inline (vlib_main_t * vm,
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
	  const u32 *attachments0, *aiai0;
	  const abf_itf_attach_t *aia0;
	  abf_next_t next0 = ABF_NEXT_DROP;
	  vlib_buffer_t *b0;
	  u32 bi0, sw_if_index0;
	  fa_5tuple_t fa_5tuple0;
	  u32 match_acl_index = ~0;
	  u32 match_rule_index = ~0;
	  u32 trace_bitmap = 0;
	  u8 action;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  ASSERT (vec_len (abf_per_itf[fproto]) > sw_if_index0);
	  attachments0 = abf_per_itf[fproto][sw_if_index0];

	  /*
	   * loop through each of the policies attached to this interface.
	   */
	  acl_plugin_fill_5tuple (b0, (FIB_PROTOCOL_IP6 == fproto),
				  1, 0, &fa_5tuple0);

	  vec_foreach (aiai0, attachments0)
	  {
	    aia0 = abf_itf_attach_get (*aiai0);
	    if (acl_plugin_single_acl_match_5tuple (aia0->aia_acl,
						    &fa_5tuple0,
						    (FIB_PROTOCOL_IP6 ==
						     fproto), &action,
						    &match_acl_index,
						    &match_rule_index,
						    &trace_bitmap))
	      {
		/*
		 * match:
		 *  follow the DPO chain
		 */
		next0 = aia0->aia_dpo.dpoi_next_node;
		vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
		  aia0->aia_dpo.dpoi_index;
		goto enqueue;
	      }
	  }
	  /*
	   * miss:
	   *  move on down the feature arc
	   */
	  vnet_feature_next (sw_if_index0, &next0, b0);

	enqueue:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      abf_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next = next0;
	      tr->index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
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
abf_input_ip4 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, FIB_PROTOCOL_IP4);
}

static uword
abf_input_ip6 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, FIB_PROTOCOL_IP6);
}

static u8 *
format_abf_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  abf_input_trace_t *t = va_arg (*args, abf_input_trace_t *);

  s = format (s, " next %d index %d", t->next, t->index);
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (abf_ip4_node) =
{
  .function = abf_input_ip4,.name = "abf-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  //.n_errors = ARRAY_LEN (acl_fa_error_strings),
  //.error_strings = acl_fa_error_strings,
  .n_next_nodes = ABF_N_NEXT,
  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (abf_ip6_node) =
{
  .function = abf_input_ip6,.name = "abf-input-ip6",
  .vector_size = sizeof (u32),
  // .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  //.n_errors = ARRAY_LEN (acl_fa_error_strings),
  //.error_strings = acl_fa_error_strings,
  .n_next_nodes = ABF_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (abf_ip4_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "abf-input-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

VNET_FEATURE_INIT (abf_ip6_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "abf-input-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};
/* *INDENT-ON* */

static fib_node_t *
abf_itf_attach_get_node (fib_node_index_t index)
{
  abf_itf_attach_t *aia = abf_itf_attach_get (index);
  return (&(aia->aia_node));
}

static abf_itf_attach_t *
abf_itf_attach_get_from_node (fib_node_t * node)
{
  return ((abf_itf_attach_t *) (((char *) node) -
				STRUCT_OFFSET_OF (abf_itf_attach_t,
						  aia_node)));
}

static void
abf_itf_attach_last_lock_gone (fib_node_t * node)
{
  /*
   * ABF interface attachments are leaves on the graph.
   * we do not manage locks from children.
   */
}

/*
 * abf_itf_attach_back_walk_notify
 *
 * A back walk has reached this BIER fmask
 */
static fib_node_back_walk_rc_t
abf_itf_attach_back_walk_notify (fib_node_t * node,
				 fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-stack the fmask on the n-eos of the via
   */
  abf_itf_attach_t *aia = abf_itf_attach_get_from_node (node);

  abf_itf_attach_stack (aia);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t abf_itf_attach_vft = {
  .fnv_get = abf_itf_attach_get_node,
  .fnv_last_lock = abf_itf_attach_last_lock_gone,
  .fnv_back_walk = abf_itf_attach_back_walk_notify,
};

static clib_error_t *
abf_itf_bond_init (vlib_main_t * vm)
{
  abf_itf_attach_fib_node_type =
    fib_node_register_new_type (&abf_itf_attach_vft);
  acl_plugin_exports_init ();

  return (NULL);
}

VLIB_INIT_FUNCTION (abf_itf_bond_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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

#include <plugins/abf/abf_itf_attach.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/match/match_set_dp.h>
#include <vnet/match/match_engine.h>

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
abf_itf_attach_t *abf_itf_attach_pool;

/**
 * Per interface values of match-set applications. used in the data-plane
 */
typedef struct abf_itf_t_
{
  index_t *ai_attachments;
  match_set_app_t ai_app;
  index_t ai_set;
  match_handle_t ai_hdl;
  match_list_t ai_ml;
} abf_itf_t;

const static abf_itf_t ABF_ITF_INVALID = {
  .ai_app = MATCH_SET_APP_INITIALISOR,
  .ai_hdl = ~0,
  .ai_set = INDEX_INVALID,
};

static abf_itf_t *abf_itfs[N_AF];

/**
 * A DB of attachments; key={abf_index,sw_if_index}
 */
static uword *abf_itf_attach_db;

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
  abf_policy_t *ap;

  ap = abf_policy_get (aia->aia_abf);

  fib_path_list_contribute_forwarding (ap->ap_pl,
				       (AF_IP4 == aia->aia_af ?
					FIB_FORW_CHAIN_TYPE_UNICAST_IP4 :
					FIB_FORW_CHAIN_TYPE_UNICAST_IP6),
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE,
				       &via_dpo);

  dpo_stack_from_node ((AF_IP4 == aia->aia_af ?
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

static void
abf_match_set_update (ip_address_family_t af, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  abf_policy_t *ap;
  abf_itf_t *ai;
  u32 *aiai;
  u8 *name;

  ai = &abf_itfs[af][sw_if_index];

  name = format (NULL, "abf-%U-%U",
		 format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
		 format_ip_address_family, af);

  if (~0 != ai->ai_hdl)
    match_list_free (&ai->ai_ml);

  match_list_init (&ai->ai_ml, name, vec_len (ai->ai_attachments));

  vec_foreach (aiai, ai->ai_attachments)
  {
    aia = abf_itf_attach_get (*aiai);
    ap = abf_policy_get (aia->aia_abf);
    ap->ap_rule.mr_result = *aiai;

    match_list_push_back (&ai->ai_ml, &ap->ap_rule);
  }

  if (~0 == ai->ai_hdl)
    {
      ai->ai_hdl = match_set_list_add (ai->ai_set, &ai->ai_ml, 0);

      match_set_apply (ai->ai_set,
		       MATCH_SEMANTIC_FIRST,
		       match_set_get_itf_tag_flags (sw_if_index),
		       &ai->ai_app);
    }
  else
    {
      if (match_list_length (&ai->ai_ml))
	match_set_list_replace (ai->ai_set, ai->ai_hdl, &ai->ai_ml, 0);
      else
	match_set_list_del (ai->ai_set, &ai->ai_hdl);
    }

  vec_free (name);
}

int
abf_itf_attach (ip_address_family_t af,
		u32 policy_id, u32 priority, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  abf_itf_t *ai;
  u32 api, aiai;

  api = abf_policy_find (policy_id);

  ASSERT (INDEX_INVALID != api);

  /*
   * check this is not a duplicate
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL != aia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * construct a new attachment object
   */
  pool_get (abf_itf_attach_pool, aia);

  fib_node_init (&aia->aia_node, abf_itf_attach_fib_node_type);
  aia->aia_prio = priority;
  aia->aia_af = af;
  aia->aia_abf = api;
  aia->aia_sw_if_index = sw_if_index;
  aiai = aia - abf_itf_attach_pool;
  abf_itf_attach_db_add (policy_id, sw_if_index, aia);

  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  abf_itf_attach_stack (aia);

  /*
   * Insert the policy on the interfaces list.
   */
  vec_validate_init_empty (abf_itfs[af], sw_if_index, ABF_ITF_INVALID);

  ai = &abf_itfs[af][sw_if_index];

  vec_add1 (ai->ai_attachments, aia - abf_itf_attach_pool);
  if (1 == vec_len (ai->ai_attachments))
    {
      /*
       * when enabling the first ABF policy on the interface
       * we need to enable the interface input feature
       */
      vnet_feature_enable_disable ((AF_IP4 == af ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (AF_IP4 == af ?
				    "abf-input-ip4" :
				    "abf-input-ip6"),
				   sw_if_index, 1, NULL, 0);

      /*
       * if this is the first ABF policy, we need to create the match-set
       * that will perform the matching
       */
      u8 *name = format (NULL, "abf-%U-%U",
			 format_vnet_sw_if_index_name, vnet_get_main (),
			 sw_if_index,
			 format_ip_address_family, af);
      ai->ai_set = match_set_create_and_lock (name,
					      MATCH_TYPE_MASK_N_TUPLE,
					      MATCH_BOTH,
					      ip_address_family_to_ether_type
					      (af), NULL);

      vec_free (name);
    }
  else
    {
      vec_sort_with_function (ai->ai_attachments, abf_cmp_attach_for_sort);
    }

  /* Prepare and set the list of ACLs for lookup within the context */
  abf_match_set_update (af, sw_if_index);

  /*
   * become a child of the ABF policy so we are notified when
   * its forwarding changes.
   */
  aia->aia_sibling = fib_node_child_add (abf_policy_fib_node_type,
					 api,
					 abf_itf_attach_fib_node_type, aiai);

  return (0);
}

int
abf_itf_detach (ip_address_family_t af, u32 policy_id, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  abf_itf_t *ai;
  u32 index;

  /*
   * check this is a valid attachment
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL == aia)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  ai = &abf_itfs[af][sw_if_index];

  /*
   * first remove from the interface's vector
   */
  index = vec_search (ai->ai_attachments, aia - abf_itf_attach_pool);

  ASSERT (index != ~0);
  vec_del1 (ai->ai_attachments, index);
  vec_sort_with_function (ai->ai_attachments, abf_cmp_attach_for_sort);

  /* Prepare and set the list of ACLs for lookup within the context */
  abf_match_set_update (af, sw_if_index);

  if (0 == vec_len (ai->ai_attachments))
    {
      /*
       * when deleting the last ABF policy on the interface
       * we need to disable the interface input feature
       */
      vnet_feature_enable_disable ((AF_IP4 == af ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (AF_IP4 == af ?
				    "abf-input-ip4" :
				    "abf-input-ip6"),
				   sw_if_index, 0, NULL, 0);

      /* free the match set */
      match_set_unlock (&ai->ai_set);
      ai->ai_set = ~0;
    }

  /*
   * remove the dependency on the policy
   */
  fib_node_child_remove (abf_policy_fib_node_type,
			 aia->aia_abf, aia->aia_sibling);

  /*
   * remove the attachment from the DB
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
format_abf_intf_attach (u8 * s, va_list * args)
{
  abf_itf_attach_t *aia = va_arg (*args, abf_itf_attach_t *);
  abf_policy_t *ap;

  ap = abf_policy_get (aia->aia_abf);
  s = format (s, "[%d] abf-interface-attach: %U policy:%d priority:%d",
	      aia - abf_itf_attach_pool,
	      format_ip_address_family, aia->aia_af,
	      ap->ap_id, aia->aia_prio);
  s = format (s, "\n  %U", format_dpo_id, &aia->aia_dpo, 2);

  return (s);
}

static clib_error_t *
abf_itf_attach_cmd (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id, sw_if_index;
  ip_address_family_t af;
  u32 is_del, priority;
  vnet_main_t *vnm;

  is_del = 0;
  sw_if_index = policy_id = ~0;
  vnm = vnet_get_main ();
  af = N_AF;
  priority = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "add"))
	is_del = 0;
      else if (unformat (input, "%U", unformat_ip_address_family, &af))
	;
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
  if (N_AF == af)
    {
      return (clib_error_return (0, "Specify either ip4 or ip6"));
    }

  if (~0 == abf_policy_find (policy_id))
    return (clib_error_return (0, "invalid policy ID:%d", policy_id));

  if (is_del)
    abf_itf_detach (af, policy_id, sw_if_index);
  else
    abf_itf_attach (af, policy_id, priority, sw_if_index);

  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (abf_itf_attach_cmd_node, static) = {
  .path = "abf attach",
  .function = abf_itf_attach_cmd,
  .short_help = "abf attach <ip4|ip6> [del] policy <value> <interface>",
  // this is not MP safe
};
/* *INDENT-ON* */

static u8 *
format_abf_attach_action (u8 * s, va_list * args)
{
  match_result_t mr = va_arg (*args, match_result_t);

  s = format (s, "%lld", mr);

  return (s);
}

static clib_error_t *
abf_show_attach_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const abf_itf_attach_t *aia;
  u32 sw_if_index, *aiai;
  fib_protocol_t fproto;
  vnet_main_t *vnm;
  abf_itf_t *ai;

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
    if (sw_if_index < vec_len(abf_itfs[fproto]))
      {
        ai = &abf_itfs[fproto][sw_if_index];

        if (!vec_len(ai->ai_attachments))
          continue;

        vlib_cli_output(vm, "%U:", format_fib_protocol, fproto);

        vec_foreach(aiai, ai->ai_attachments)
          {
            aia = pool_elt_at_index(abf_itf_attach_pool, *aiai);
            vlib_cli_output(vm, " %U", format_abf_intf_attach, aia);
          }
        vlib_cli_output(vm, " %U", format_match_list_w_result,
                        &ai->ai_ml, 3,
                        format_abf_attach_action);
        vlib_cli_output(vm, " %U", format_match_set, ai->ai_set);
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

void
abf_itf_attach_walk (abf_itf_attach_walk_cb_t cb, void *ctx)
{
  u32 aii;

  /* *INDENT-OFF* */
  pool_foreach_index(aii, abf_itf_attach_pool,
  ({
    if (!cb(aii, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

typedef enum abf_next_t_
{
  ABF_NEXT_DROP,
  ABF_N_NEXT,
} abf_next_t;

typedef struct abf_input_trace_t_
{
  abf_next_t next;
  index_t index;
  index_t result;
} abf_input_trace_t;

typedef enum
{
#define abf_error(n,s) ABF_ERROR_##n,
#include "abf_error.def"
#undef abf_error
  ABF_N_ERROR,
} abf_error_t;

always_inline uword
abf_input_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, ip_address_family_t af)
{
  u32 *from, n_left, sw_if_index0, matches, misses;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  const abf_itf_attach_t *aia;
  const match_set_app_t *app;
  match_result_t aiai;
  bool match;
  f64 now;

  b = bufs;
  next = nexts;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  matches = misses = 0;
  now = vlib_time_now (vm);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      app = &abf_itfs[af][sw_if_index0].ai_app;

      /* we don't care about the l2 offset, since we are always dealing
       * with IP packets. we appl ytis feature in the L3 input path,
       * consequently the buffer's current data is pointing at the
       * l3 header, hence the l3-offset is 0
       */
      match = match_match_one (vm, b[0], 0, 0, app, now, &aiai);

      if (match)
	{
	  /*
	   * match:
	   *  follow the DPO chain
	   */
	  aia = abf_itf_attach_get (aiai);
	  next[0] = aia->aia_dpo.dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = aia->aia_dpo.dpoi_index;
	  matches++;
	}
      else
	{
	  /*
	   * miss:
	   *  move on down the feature arc
	   */
	  vnet_feature_next_u16 (&next[0], b[0]);
	  misses++;
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  abf_input_trace_t *tr;

	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->next = next[0];
	  tr->result = match;
	  tr->index = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
	}

      n_left--;
      b++;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm,
			       (af = AF_IP6 ?
				abf_ip4_node.index :
				abf_ip6_node.index),
			       ABF_ERROR_MATCHED, matches);
  vlib_node_increment_counter (vm,
			       (af = AF_IP6 ?
				abf_ip4_node.index :
				abf_ip6_node.index),
			       ABF_ERROR_MISSED, misses);

  return frame->n_vectors;
}

static uword
abf_input_ip4 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, AF_IP4);
}

static uword
abf_input_ip6 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, AF_IP6);
}

static u8 *
format_abf_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  abf_input_trace_t *t = va_arg (*args, abf_input_trace_t *);

  s = format (s, " next %d index %d result %d", t->next, t->index, t->result);
  return s;
}

static char *abf_error_strings[] = {
#define abf_error(n,s) s,
#include "abf_error.def"
#undef abf_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (abf_ip4_node) =
{
  .function = abf_input_ip4,
  .name = "abf-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ABF_N_ERROR,
  .error_strings = abf_error_strings,
  .n_next_nodes = ABF_N_NEXT,
  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (abf_ip6_node) =
{
  .function = abf_input_ip6,
  .name = "abf-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = ABF_N_NEXT,

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

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (abf_itf_bond_init) =
{
  .runs_after = VLIB_INITS("acl_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

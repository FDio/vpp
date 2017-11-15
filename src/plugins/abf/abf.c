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

#include <vlib/vlib.h>
#include <vnet/fib/fib_path_list.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>

/**
 * An ACL based Forwading 'policy'.
 * This comprises the ACL index to match against and the forwarding
 * path to take if the match is successfull.
 *
 * ABF policies are then 'attached' to interfaces. An input feature
 * will run through the list of policies a match will divert the packet,
 * if all miss then we continues down the interface's feature arc
 */
typedef struct abf_t_
{
  /**
   * ACL index to match
   */
  u32 abf_acl;

  /**
   * The path-list describing how to forward in case of a match
   */
  fib_node_index_t abf_pl;

  /**
   * The policy ID - as configured by the client
   */
  u32 abf_id;

  /**
   * The DPO actually used for forwarding
   */
  dpo_id_t abf_dpo;
} abf_t;

/**
 * Forward declarations;
 */
extern vlib_node_registration_t abf_ip4_node;
extern vlib_node_registration_t abf_ip6_node;

/**
 * Pool of ABF objects
 */
static abf_t *abf_pool;

/**
 * DB of ABF policy objects
 *  - policy ID to index conversion.
 */
static uword *abf_db;

/**
 * A per interace vector of attached policies
 */
static u32 **abf_per_itf[FIB_PROTOCOL_MAX];

static abf_t *
abf_find (u32 policy_id)
{
  uword *p;

  p = hash_get(abf_db, policy_id);

  if (NULL != p)
    return (pool_elt_at_index(abf_pool, p[0]));

  return (NULL);
}

static void
abf_policy_update (u32 policy_id,
                   u32 acl_index,
                   const fib_route_path_t *rpaths)
{
  abf_t *abf;

  abf = abf_find(policy_id);

  if (NULL == abf)
    {
      pool_get(abf_pool, abf);

      abf->abf_acl = acl_index;
      abf->abf_id = policy_id;
      abf->abf_pl = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED |
                                          FIB_PATH_LIST_FLAG_NO_URPF),
                                         rpaths);
      fib_path_list_lock(abf->abf_pl);
    }
  else
    {

    }
}

static void
abf_policy_delete (u32 policy_id,
                   const fib_route_path_t *rpaths)
{
}

static void
abf_attach (fib_protocol_t fproto,
            u32 policy_id,
            u32 sw_if_index)
{
  abf_t *abf;

  abf = abf_find(policy_id);

  ASSERT(NULL != abf);

  /*
   * Insert the policy on the interfaces list.
   */
  vec_validate_init_empty(abf_per_itf[fproto], sw_if_index, 0);

  if (0 != abf_per_itf[sw_if_index])
    {
      if (~0 == vec_search(abf_per_itf[fproto][sw_if_index],
                           policy_id))
        {
          // FIXME - need to sort based on pritority
          vec_add1(abf_per_itf[fproto][sw_if_index], abf-abf_pool);
        }
    }
  else
    {
      vec_add1(abf_per_itf[fproto][sw_if_index], abf-abf_pool);
    }

  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  dpo_id_t via_dpo = DPO_INVALID;

  fib_path_list_contribute_forwarding(abf->abf_pl,
                                      (FIB_PROTOCOL_IP4 == fproto ?
                                       FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
                                       FIB_FORW_CHAIN_TYPE_UNICAST_IP6),
                                      &via_dpo);

  dpo_stack_from_node((FIB_PROTOCOL_IP4 == fproto ?
                       abf_ip4_node.index :
                       abf_ip6_node.index),
                      &abf->abf_dpo,
                      &via_dpo);
  dpo_reset(&via_dpo);
}

static void
abf_detach (fib_protocol_t fproto,
            u32 policy_id,
            u32 sw_if_index)
{
}

static clib_error_t *
abf_policy_cmd (vlib_main_t * vm,
                unformat_input_t * main_input,
                vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 acl_index, policy_id;
  fib_route_path_t *rpaths = NULL, rpath;
  u32 is_del;

  is_del = 0;
  acl_index = ~0;
  policy_id = ~0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "acl %d", &acl_index))
        ;
      else if (unformat (line_input, "%d", &policy_id))
        ;
      else if (unformat (line_input, "del"))
        is_del = 1;
      else if (unformat (line_input, "add"))
        is_del = 0;
      else
        return (clib_error_return (0, "unknown input '%U'",
                                   format_unformat_error, line_input));
    }

  if (~0 == policy_id)
    {
      vlib_cli_output (vm, "Policy ID");
      return 0;
    }

  if (!is_del)
    {
      if (~0 == acl_index)
        {
          vlib_cli_output (vm, "ACL index must be set");
          return 0;
        }

      abf_policy_update(policy_id, acl_index, rpaths);
    }
  else
    {
      abf_policy_delete(policy_id, rpaths);
    }

  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Create an ABF policy.
 */
VLIB_CLI_COMMAND (abf_policy_cmd_node, static) = {
  .path = "abf policy",
  .function = abf_policy_cmd,
  .short_help = "abf policy [add|del] acl <index> via ...",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static u8 *
format_abf (u8 * s, va_list * ap)
{
  abf_t *abf = va_arg(ap, abf_t *);

  s = format(s, "abf:[%d]: policy:%d acl:%d",
             abf - abf_pool,
             abf->abf_id,
             abf->abf_acl);
  s = format (s, "\n ");
  s = fib_path_list_format(abf->abf_pl, s);

  return (s);
}

static clib_error_t *
abf_show_policy_cmd (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
  u32 policy_id;
  abf_t *abf;

  policy_id = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &policy_id))
        ;
      else
        return (clib_error_return (0, "unknown input '%U'",
                                   format_unformat_error, input));
    }

  if (~0 == policy_id)
    {
      /* *INDENT-OFF* */
      pool_foreach(abf, abf_pool,
      ({
        vlib_cli_output(vm, "%U", format_abf, abf);
      }));
      /* *INDENT-OFF* */
    }
  else
    {
      abf = abf_find(policy_id);

      if (NULL != abf)
        vlib_cli_output(vm, "%U", format_abf, abf);
      else
        vlib_cli_output (vm, "Invalid policy ID:%d", policy_id);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_show_policy_cmd_node, static) = {
  .path = "show abf policy",
  .function = abf_show_policy_cmd,
  .short_help = "show abf policy <value>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */
static clib_error_t *
abf_attach_cmd (vlib_main_t * vm,
                unformat_input_t * input,
                vlib_cli_command_t * cmd)
{
  u32 policy_id, sw_if_index;
  fib_protocol_t fproto;
  vnet_main_t *vnm;
  u32 is_del;

  is_del = 0;
  sw_if_index = policy_id = ~0;
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
      else if (unformat (input, "policy %d", &policy_id))
        ;
      else if (unformat (input, "%U",
                         unformat_vnet_sw_interface, vnm,
                         &sw_if_index))
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

  if (NULL == abf_find(policy_id))
    return (clib_error_return (0, "invalid policy ID:%d", policy_id));

  if (is_del)
    abf_detach(fproto, policy_id, sw_if_index);
  else
    abf_attach(fproto, policy_id, sw_if_index);

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
};
/* *INDENT-ON* */

typedef enum abf_next_t_
  {
    ABF_NEXT_DROP,
    ABF_N_NEXT,
  } abf_next_t;

always_inline uword
abf_input_inline (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame,
                  fib_protocol_t fproto)
{
  u32 n_left_from, *from, *to_next, next_index;
  acl_main_t *am = &acl_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          abf_next_t next0 = ABF_NEXT_DROP;
          vlib_buffer_t *b0;
          u32 *policies0;
          u32 bi0, sw_if_index0, *abfi0;
          abf_t *abf0;
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

          ASSERT(vec_len(abf_per_itf[fproto]) > sw_if_index0);
          policies0 = abf_per_itf[fproto][sw_if_index0];

          /*
           * loop through each of the policies attached to this interface.
           */
          acl_fill_5tuple (am, b0, (FIB_PROTOCOL_IP6 == fproto),
                           1, 0, &fa_5tuple);

          vec_foreach(abfi0, policies0)
            {
              abf0 = pool_elt_at_index(abf_pool, *abfi0);

              if (single_acl_match_5tuple(am, abf0->abf_acl,
                                          &fa_5tuple,
                                          (FIB_PROTOCOL_IP6 == fproto),
                                          &action,
                                          &match_acl_index,
                                          &match_rule_index,
                                          &trace_bitmap))
                {
                  /*
                   * match:
                   *  follow the DPO chain
                   */
                  next0 = abf0->abf_dpo.dpoi_next_node;
                  vnet_buffer(b0)->ip.adj_index[VLIB_TX] =
                    abf0->abf_dpo.dpoi_index;
                  goto enqueue;
                }
            }
          /*
           * miss:
           *  move on down the feature arc
           */
          vnet_feature_next (sw_if_index0, &next0, b0);

        enqueue:
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
               vlib_node_runtime_t * node,
               vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, FIB_PROTOCOL_IP4);
}

static uword
abf_input_ip6 (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, FIB_PROTOCOL_IP6);
}

VLIB_REGISTER_NODE (abf_ip4_node) =
{
  .function = abf_input_ip4,
  .name = "abf-input-ip4",
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

VLIB_REGISTER_NODE (abf_ip6_node) =
{
  .function = abf_input_ip6,
  .name = "abf-input-ip6",
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
  .arc_name = "ip4-input",
  .node_name = "abf-input-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

VNET_FEATURE_INIT (abf_ip6_feat, static) =
{
  .arc_name = "ip6-input",
  .node_name = "abf-input-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

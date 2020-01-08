/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <acl/acl.h>

#include <vnet/match/match_set.h>
#include <vnet/match/match_engine.h>
#include <vnet/match/engines/classifier/match_classifier_dp.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_input.h>

typedef enum macip_next_t_
{
  MACIP_NEXT_MISS = 0,
  MACIP_N_NEXT,
} macip_next_t;

typedef struct macip_trace_t_
{
  macip_action_t action;
} macip_trace_t;

static u8 *
format_macip_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  macip_trace_t *t = va_arg (*args, macip_trace_t *);

  s = format (s, "%U", format_macip_action, t->action);

  return (s);
}

always_inline uword
macip_inline (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame, vnet_link_t linkt, vlib_rx_or_tx_t dir)
{
  match_set_result_t results[VLIB_FRAME_SIZE], *res;
  match_set_app_t apps[VLIB_FRAME_SIZE], *app;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 *from, n_left, sw_if_index0;
  const match_engine_vft_t *me;
  macip_acl_main_t *mm;

  mm = &macip_acl_main;
  b = bufs;
  app = apps;
  next = nexts;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;

  clib_memset (nexts, MACIP_NEXT_MISS, sizeof (nexts));

  vlib_get_buffers (vm, from, bufs, n_left);

  /* First pass: get the match table from the packet's sw-if-index */
  while (n_left > 0)
    {
      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[dir];
      app[0] = mm->macip_match_apps_by_sw_if_index[linkt][sw_if_index0];
      app++;
      n_left--;
      b++;
    }

  /* reset */
  n_left = frame->n_vectors;

  /* do the match */
  me = match_engine_get (MATCH_SEMANTIC_FIRST, MATCH_TYPE_MASK_SRC_IP_MAC);
  me->mev_match (vm, bufs, n_left, apps, results);

  res = results;
  b = bufs;

  while (n_left > 0)
    {
      macip_action_t action = MACIP_ACTION_DENY;

      if (MATCH_RESULT_MISS != res[0].msr_rule_index)
	{
	  /* there was was a hit against one of the rules in the list */
	  macip_action_t *actions = res[0].msr_user_ctx;

	  action = actions[res[0].msr_rule_index];

	  if (MACIP_ACTION_PERMIT == action)
	    vnet_feature_next_u16 (&next[0], b[0]);
	}
      /*
       * else
       *  we missed against all rules in the list, the default action is deny
       */

      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  macip_trace_t *t0;
	  t0 = vlib_add_trace (vm, node, b[0], sizeof (*t0));

	  t0->action = action;
	}

      n_left--;
      res++;
      b++;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_macip_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP4, VLIB_RX);
}

VLIB_NODE_FN (ip6_macip_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP6, VLIB_RX);
}

VLIB_NODE_FN (arp_macip_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_ARP, VLIB_RX);
}

VLIB_NODE_FN (l2_ip4_macip_input_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP4, VLIB_RX);
}

VLIB_NODE_FN (l2_ip6_macip_input_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP6, VLIB_RX);
}

VLIB_NODE_FN (l2_arp_macip_input_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_ARP, VLIB_RX);
}

VLIB_NODE_FN (ip4_macip_output_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP4, VLIB_TX);
}

VLIB_NODE_FN (ip6_macip_output_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP6, VLIB_TX);
}

VLIB_NODE_FN (l2_ip4_macip_output_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP4, VLIB_TX);
}

VLIB_NODE_FN (l2_ip6_macip_output_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_IP6, VLIB_TX);
}

VLIB_NODE_FN (l2_arp_macip_output_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return macip_inline (vm, node, frame, VNET_LINK_ARP, VLIB_TX);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_macip_input_node) =
{
  .name = "ip4-macip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "ip4-drop",
  }
};

VNET_FEATURE_INIT (ip4_macip_input_feat_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-macip-input",
  .runs_before = VNET_FEATURES ("ip4-source-check-via-rx"),
};

VLIB_REGISTER_NODE (arp_macip_input_node) =
{
  .name = "arp-macip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "ip4-drop",
  }
};

VNET_FEATURE_INIT (arp_macip_input_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "arp-macip-input",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

VLIB_REGISTER_NODE (ip4_macip_output_node) =
{
  .name = "ip4-macip-output",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "ip4-drop",
  }
};

VNET_FEATURE_INIT (ip4_macip_output_feat_node, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-macip-output",
  .runs_before = VNET_FEATURES ("ipsec4-output-feature"),
};

VLIB_REGISTER_NODE (ip6_macip_input_node) =
{
  .name = "ip6-macip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "ip6-drop",
  }
};

VNET_FEATURE_INIT (ip6_macip_input_feat_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-macip-input",
  .runs_before = VNET_FEATURES ("ip6-policer-classify"),
};

VLIB_REGISTER_NODE (ip6_macip_output_node) =
{
  .name = "ip6-macip-output",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "ip6-drop",
  }
};

VNET_FEATURE_INIT (ip6_macip_output_feat_node, static) =
{
  .arc_name = "ip6-output",
  .node_name = "ip6-macip-output",
  .runs_before = VNET_FEATURES ("ipsec6-output-feature"),
};

VLIB_REGISTER_NODE (l2_ip4_macip_input_node) =
{
  .name = "l2-ip4-macip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "error-drop",
  }
};

VNET_FEATURE_INIT (l2_ip4_macip_input_feat_node, static) =
{
  .arc_name = "l2-input-ip4",
  .node_name = "l2-ip4-macip-input",
};

VLIB_REGISTER_NODE (l2_ip6_macip_input_node) =
{
  .name = "l2-ip6-macip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "error-drop",
  }
};

VNET_FEATURE_INIT (l2_ip6_macip_input_feat_node, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "l2-ip6-macip-input",
};

VLIB_REGISTER_NODE (l2_arp_macip_input_node) =
{
  .name = "l2-arp-macip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "error-drop",
  }
};

VNET_FEATURE_INIT (l2_arp_macip_input_feat_node, static) =
{
  .arc_name = "l2-input-nonip",
  .node_name = "l2-arp-macip-input",
};

VLIB_REGISTER_NODE (l2_ip4_macip_output_node) =
{
  .name = "l2-ip4-macip-output",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "error-drop",
  }
};

VNET_FEATURE_INIT (l2_ip4_macip_output_feat_node, static) =
{
  .arc_name = "l2-output-ip4",
  .node_name = "l2-ip4-macip-output",
};

VLIB_REGISTER_NODE (l2_ip6_macip_output_node) =
{
  .name = "l2-ip6-macip-output",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "error-drop",
  }
};

VNET_FEATURE_INIT (l2_ip6_macip_output_feat_node, static) =
{
  .arc_name = "l2-output-ip6",
  .node_name = "l2-ip6-macip-output",
};

VLIB_REGISTER_NODE (l2_arp_macip_output_node) =
{
  .name = "l2-arp-macip-output",
  .vector_size = sizeof (u32),
  .format_trace = format_macip_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = MACIP_N_NEXT,
  .next_nodes = {
    [MACIP_NEXT_MISS] = "error-drop",
  }
};

VNET_FEATURE_INIT (l2_arp_macip_output_feat_node, static) =
{
  .arc_name = "l2-output-nonip",
  .node_name = "l2-arp-macip-output",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

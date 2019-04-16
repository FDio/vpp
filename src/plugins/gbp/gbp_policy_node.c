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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_policy_dpo.h>

#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>
#include <vnet/vxlan-gbp/vxlan_gbp.h>

#define foreach_gbp_policy                      \
  _(DENY,    "deny")                            \
  _(REFLECTION, "reflection")

typedef enum
{
#define _(sym,str) GBP_POLICY_ERROR_##sym,
  foreach_gbp_policy_error
#undef _
    GBP_POLICY_N_ERROR,
} gbp_policy_error_t;

static char *gbp_policy_error_strings[] = {
#define _(sym,string) string,
  foreach_gbp_policy_error
#undef _
};

typedef enum
{
  GBP_POLICY_NEXT_DROP,
  GBP_POLICY_N_NEXT,
} gbp_policy_next_t;

/**
 * per-packet trace data
 */
typedef struct gbp_policy_trace_t_
{
  /* per-pkt trace data */
  u32 sclass;
  u32 dst_epg;
  u32 acl_index;
  u32 allowed;
  u32 flags;
} gbp_policy_trace_t;

always_inline dpo_proto_t
ethertype_to_dpo_proto (u16 etype)
{
  etype = clib_net_to_host_u16 (etype);

  switch (etype)
    {
    case ETHERNET_TYPE_IP4:
      return (DPO_PROTO_IP4);
    case ETHERNET_TYPE_IP6:
      return (DPO_PROTO_IP6);
    }

  return (DPO_PROTO_NONE);
}

always_inline u32
gbp_rule_l2_redirect (const gbp_rule_t * gu, vlib_buffer_t * b0)
{
  const ethernet_header_t *eth0;
  const dpo_id_t *dpo;
  dpo_proto_t dproto;

  eth0 = vlib_buffer_get_current (b0);
  /* pop the ethernet header to prepare for L3 rewrite */
  vlib_buffer_advance (b0, vnet_buffer (b0)->l2.l2_len);

  dproto = ethertype_to_dpo_proto (eth0->type);
  dpo = &gu->gu_dpo[GBP_POLICY_NODE_L2][dproto];

  /* save the LB index for the next node and reset the IP flow hash
   * so it's recalculated */
  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo->dpoi_index;
  vnet_buffer (b0)->ip.flow_hash = 0;

  return (dpo->dpoi_next_node);
}

always_inline u8
gbp_policy_is_ethertype_allowed (const gbp_contract_t * gc0, u16 ethertype)
{
  u16 *et;

  vec_foreach (et, gc0->gc_allowed_ethertypes)
  {
    if (*et == ethertype)
      return (1);
  }
  return (0);
}

static uword
gbp_policy_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, u8 is_port_based)
{
  gbp_main_t *gm = &gbp_main;
  gbp_policy_main_t *gpm = &gbp_policy_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index, thread_index;
  u32 n_allow_intra, n_allow_a_bit, n_allow_sclass_1;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  thread_index = vm->thread_index;
  n_allow_intra = n_allow_a_bit = n_allow_sclass_1 = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const ethernet_header_t *h0;
	  const gbp_endpoint_t *ge0;
	  const gbp_contract_t *gc0;
	  gbp_policy_next_t next0;
	  gbp_contract_key_t key0;
	  u32 bi0, sw_if_index0;
	  vlib_buffer_t *b0;
	  index_t gci0;

	  gc0 = NULL;
	  next0 = GBP_POLICY_NEXT_DROP;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  /*
	   * Reflection check; in and out on an ivxlan tunnel
	   */
	  if ((~0 != vxlan_gbp_tunnel_by_sw_if_index (sw_if_index0)) &&
	      (vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_R))
	    {
	      goto trace;
	    }

	  /*
	   * If the A-bit is set then policy has already been applied
	   * and we skip enforcement here.
	   */
	  if (vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_A)
	    {
	      next0 = vnet_l2_feature_next (b0,
					    gpm->l2_output_feat_next
					    [is_port_based],
					    (is_port_based ?
					     L2OUTPUT_FEAT_GBP_POLICY_PORT :
					     L2OUTPUT_FEAT_GBP_POLICY_MAC));
	      n_allow_a_bit++;
	      key0.as_u32 = ~0;
	      goto trace;
	    }

	  /*
	   * determine the src and dst EPG
	   */
	  if (is_port_based)
	    ge0 = gbp_endpoint_find_itf (sw_if_index0);
	  else
	    ge0 = gbp_endpoint_find_mac (h0->dst_address,
					 vnet_buffer (b0)->l2.bd_index);

	  if (NULL != ge0)
	    key0.gck_dst = ge0->ge_fwd.gef_sclass;
	  else
	    {
	      /* If you cannot determine the destination EP then drop */
	      b0->error = node->errors[GBP_POLICY_ERROR_DROP_NO_DCLASS];
	      goto trace;
	    }
	  key0.gck_src = vnet_buffer2 (b0)->gbp.sclass;

	  if (SCLASS_INVALID != key0.gck_src)
	    {
	      if (PREDICT_FALSE (key0.gck_src == key0.gck_dst))
		{
		  /*
		   * intra-epg allowed
		   */
		  next0 =
		    vnet_l2_feature_next (b0,
					  gpm->l2_output_feat_next
					  [is_port_based],
					  (is_port_based ?
					   L2OUTPUT_FEAT_GBP_POLICY_PORT :
					   L2OUTPUT_FEAT_GBP_POLICY_MAC));
		  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
		  n_allow_intra++;
		}
	      else if (PREDICT_FALSE (key0.gck_src == 1 || key0.gck_dst == 1))
		{
		  /*
		   * sclass or dclass 1 allowed
		   */
		  next0 =
		    vnet_l2_feature_next (b0,
					  gpm->l2_output_feat_next
					  [is_port_based],
					  (is_port_based ?
					   L2OUTPUT_FEAT_GBP_POLICY_PORT :
					   L2OUTPUT_FEAT_GBP_POLICY_MAC));
		  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
		  n_allow_sclass_1++;
		}
	      else
		{
		  gci0 = gbp_contract_find (&key0);

		  if (INDEX_INVALID != gci0)
		    {
		      u32 rule_match_p0, trace_bitmap0;
		      fa_5tuple_opaque_t pkt_5tuple0;
		      u32 acl_pos_p0, acl_match_p0;
		      u8 is_ip60, l2_len0, action0;
		      const gbp_rule_t *gu;
		      u16 ether_type0;
		      const u8 *h0;

		      vlib_prefetch_combined_counter
			(&gbp_contract_drop_counters, thread_index, gci0);
		      vlib_prefetch_combined_counter
			(&gbp_contract_permit_counters, thread_index, gci0);

		      action0 = 0;
		      gc0 = gbp_contract_get (gci0);
		      l2_len0 = vnet_buffer (b0)->l2.l2_len;
		      h0 = vlib_buffer_get_current (b0);

		      ether_type0 = *(u16 *) (h0 + l2_len0 - 2);

		      if (!gbp_policy_is_ethertype_allowed (gc0, ether_type0))
			{
			  /*
			   * black list model so drop
			   */
			  b0->error =
			    node->errors[GBP_POLICY_ERROR_DROP_ETHER_TYPE];

			  vlib_increment_combined_counter
			    (&gbp_contract_drop_counters,
			     thread_index,
			     gci0, 1, vlib_buffer_length_in_chain (vm, b0));

			  goto trace;
			}

		      if ((ether_type0 ==
			   clib_net_to_host_u16 (ETHERNET_TYPE_IP6))
			  || (ether_type0 ==
			      clib_net_to_host_u16 (ETHERNET_TYPE_IP4)))
			{
			  is_ip60 =
			    (ether_type0 ==
			     clib_net_to_host_u16 (ETHERNET_TYPE_IP6)) ? 1 :
			    0;
			  /*
			   * tests against the ACL
			   */
			  acl_plugin_fill_5tuple_inline (gm->
							 acl_plugin.p_acl_main,
							 gc0->gc_lc_index, b0,
							 is_ip60,
							 /* is_input */ 0,
							 /* is_l2_path */ 1,
							 &pkt_5tuple0);
			  acl_plugin_match_5tuple_inline (gm->
							  acl_plugin.p_acl_main,
							  gc0->gc_lc_index,
							  &pkt_5tuple0,
							  is_ip60, &action0,
							  &acl_pos_p0,
							  &acl_match_p0,
							  &rule_match_p0,
							  &trace_bitmap0);

			  if (action0 > 0)
			    {
			      vnet_buffer2 (b0)->gbp.flags |=
				VXLAN_GBP_GPFLAGS_A;
			      gu =
				gbp_rule_get (gc0->gc_rules[rule_match_p0]);

			      switch (gu->gu_action)
				{
				case GBP_RULE_PERMIT:
				  next0 = vnet_l2_feature_next
				    (b0,
				     gpm->l2_output_feat_next
				     [is_port_based],
				     (is_port_based ?
				      L2OUTPUT_FEAT_GBP_POLICY_PORT :
				      L2OUTPUT_FEAT_GBP_POLICY_MAC));
				  break;
				case GBP_RULE_DENY:
				  next0 = GBP_POLICY_NEXT_DROP;
				  break;
				case GBP_RULE_REDIRECT:
				  next0 = gbp_rule_l2_redirect (gu, b0);
				  break;
				}
			    }
			}
		      if (next0 == GBP_POLICY_NEXT_DROP)
			{
			  vlib_increment_combined_counter
			    (&gbp_contract_drop_counters,
			     thread_index,
			     gci0, 1, vlib_buffer_length_in_chain (vm, b0));
			  b0->error =
			    node->errors[GBP_POLICY_ERROR_DROP_CONTRACT];
			}
		      else
			{
			  vlib_increment_combined_counter
			    (&gbp_contract_permit_counters,
			     thread_index,
			     gci0, 1, vlib_buffer_length_in_chain (vm, b0));
			}
		    }
		  else
		    {
		      b0->error =
			node->errors[GBP_POLICY_ERROR_DROP_NO_CONTRACT];
		    }
		}
	    }
	  else
	    {
	      /*
	       * the src EPG is not set when the packet arrives on an EPG
	       * uplink interface and we do not need to apply policy
	       */
	      next0 =
		vnet_l2_feature_next (b0,
				      gpm->l2_output_feat_next[is_port_based],
				      (is_port_based ?
				       L2OUTPUT_FEAT_GBP_POLICY_PORT :
				       L2OUTPUT_FEAT_GBP_POLICY_MAC));
	    }

	trace:
	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_policy_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sclass = key0.gck_src;
	      t->dst_epg = key0.gck_dst;
	      t->acl_index = (gc0 ? gc0->gc_acl_index : ~0);
	      t->allowed = (next0 != GBP_POLICY_NEXT_DROP);
	      t->flags = vnet_buffer2 (b0)->gbp.flags;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       GBP_POLICY_ERROR_ALLOW_INTRA, n_allow_intra);
  vlib_node_increment_counter (vm, node->node_index,
			       GBP_POLICY_ERROR_ALLOW_A_BIT, n_allow_a_bit);
  vlib_node_increment_counter (vm, node->node_index,
			       GBP_POLICY_ERROR_ALLOW_SCLASS_1,
			       n_allow_sclass_1);

  return frame->n_vectors;
}

VLIB_NODE_FN (gbp_policy_port_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return (gbp_policy_inline (vm, node, frame, 1));
}

VLIB_NODE_FN (gbp_policy_mac_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return (gbp_policy_inline (vm, node, frame, 0));
}

/* packet trace format function */
static u8 *
format_gbp_policy_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_policy_trace_t *t = va_arg (*args, gbp_policy_trace_t *);

  s =
    format (s, "sclass:%d, dst:%d, acl:%d allowed:%d flags:%U",
	    t->sclass, t->dst_epg, t->acl_index, t->allowed,
	    format_vxlan_gbp_header_gpflags, t->flags);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_policy_port_node) = {
  .name = "gbp-policy-port",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_policy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_policy_error_strings),
  .error_strings = gbp_policy_error_strings,

  .n_next_nodes = GBP_POLICY_N_NEXT,
  .next_nodes = {
    [GBP_POLICY_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (gbp_policy_mac_node) = {
  .name = "gbp-policy-mac",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_policy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_policy_error_strings),
  .error_strings = gbp_policy_error_strings,

  .n_next_nodes = GBP_POLICY_N_NEXT,
  .next_nodes = {
    [GBP_POLICY_NEXT_DROP] = "error-drop",
  },
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

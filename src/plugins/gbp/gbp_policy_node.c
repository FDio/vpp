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
#include <plugins/gbp/gbp_classify.h>
#include <plugins/gbp/gbp_policy.h>
#include <plugins/gbp/gbp_policy_dpo.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_ext_itf.h>
#include <plugins/gbp/gbp_contract.h>

#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>
#include <vnet/vxlan-gbp/vxlan_gbp.h>

typedef enum
{
  GBP_POLICY_NEXT_DROP,
  GBP_POLICY_N_NEXT,
} gbp_policy_next_t;

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
  vnet_buffer (b0)->ip.adj_index = dpo->dpoi_index;
  vnet_buffer (b0)->ip.flow_hash = 0;

  return (dpo->dpoi_next_node);
}

static_always_inline gbp_policy_next_t
gbp_policy_l2_feature_next (gbp_policy_main_t * gpm, vlib_buffer_t * b,
			    const gbp_policy_type_t type)
{
  u32 feat_bit;

  switch (type)
    {
    case GBP_POLICY_PORT:
      feat_bit = L2OUTPUT_FEAT_GBP_POLICY_PORT;
      break;
    case GBP_POLICY_MAC:
      feat_bit = L2OUTPUT_FEAT_GBP_POLICY_MAC;
      break;
    case GBP_POLICY_LPM:
      feat_bit = L2OUTPUT_FEAT_GBP_POLICY_LPM;
      break;
    default:
      return GBP_POLICY_NEXT_DROP;
    }

  return vnet_l2_feature_next (b, gpm->l2_output_feat_next[type], feat_bit);
}

static uword
gbp_policy_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, const gbp_policy_type_t type)
{
  gbp_main_t *gm = &gbp_main;
  gbp_policy_main_t *gpm = &gbp_policy_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 n_allow_intra, n_allow_a_bit, n_allow_sclass_1;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  n_allow_intra = n_allow_a_bit = n_allow_sclass_1 = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  gbp_rule_action_t action0 = GBP_RULE_DENY;
	  const ethernet_header_t *h0;
	  const gbp_endpoint_t *ge0;
	  gbp_contract_error_t err0;
	  u32 acl_match = ~0, rule_match = ~0;
	  gbp_policy_next_t next0;
	  gbp_contract_key_t key0;
	  u32 bi0, sw_if_index0;
	  vlib_buffer_t *b0;
	  gbp_rule_t *rule0;

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
	      next0 = gbp_policy_l2_feature_next (gpm, b0, type);
	      n_allow_a_bit++;
	      key0.as_u64 = ~0;
	      goto trace;
	    }

	  /*
	   * determine the src and dst EPG
	   */

	  /* zero out the key to ensure the pad space is clear */
	  key0.as_u64 = 0;
	  key0.gck_src = vnet_buffer2 (b0)->gbp.sclass;
	  key0.gck_dst = SCLASS_INVALID;

	  if (GBP_POLICY_LPM == type)
	    {
	      const ip4_address_t *ip4 = 0;
	      const ip6_address_t *ip6 = 0;
	      const dpo_proto_t proto =
		gbp_classify_get_ip_address (h0, &ip4, &ip6,
					     GBP_CLASSIFY_GET_IP_DST);
	      if (PREDICT_TRUE (DPO_PROTO_NONE != proto))
		{
		  const gbp_ext_itf_t *ext_itf =
		    gbp_ext_itf_get (sw_if_index0);
		  const gbp_policy_dpo_t *gpd =
		    gbp_classify_get_gpd (ip4, ip6,
					  ext_itf->gx_fib_index[proto]);
		  if (gpd)
		    key0.gck_dst = gpd->gpd_sclass;
		}
	    }
	  else
	    {
	      if (GBP_POLICY_PORT == type)
		ge0 = gbp_endpoint_find_itf (sw_if_index0);
	      else
		ge0 = gbp_endpoint_find_mac (h0->dst_address,
					     vnet_buffer (b0)->l2.bd_index);
	      if (NULL != ge0)
		key0.gck_dst = ge0->ge_fwd.gef_sclass;
	    }

	  if (SCLASS_INVALID == key0.gck_dst)
	    {
	      /* If you cannot determine the destination EP then drop */
	      b0->error = node->errors[GBP_CONTRACT_ERROR_DROP_NO_DCLASS];
	      goto trace;
	    }

	  key0.gck_src = vnet_buffer2 (b0)->gbp.sclass;
	  if (SCLASS_INVALID == key0.gck_src)
	    {
	      /*
	       * the src EPG is not set when the packet arrives on an EPG
	       * uplink interface and we do not need to apply policy
	       */
	      next0 = gbp_policy_l2_feature_next (gpm, b0, type);
	      goto trace;
	    }

	  key0.gck_scope =
	    gbp_bridge_domain_get_scope (vnet_buffer (b0)->l2.bd_index);

	  action0 =
	    gbp_contract_apply (vm, gm, &key0, b0, &rule0, &n_allow_intra,
				&n_allow_sclass_1, &acl_match, &rule_match,
				&err0, GBP_CONTRACT_APPLY_L2);
	  switch (action0)
	    {
	    case GBP_RULE_PERMIT:
	      next0 = gbp_policy_l2_feature_next (gpm, b0, type);
	      vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
	      break;
	    case GBP_RULE_REDIRECT:
	      next0 = gbp_rule_l2_redirect (rule0, b0);
	      vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
	      break;
	    case GBP_RULE_DENY:
	      next0 = GBP_POLICY_NEXT_DROP;
	      b0->error = node->errors[err0];
	      break;
	    }

	trace:
	  gbp_policy_trace (vm, node, b0, &key0, action0, acl_match,
			    rule_match);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       GBP_CONTRACT_ERROR_ALLOW_INTRA, n_allow_intra);
  vlib_node_increment_counter (vm, node->node_index,
			       GBP_CONTRACT_ERROR_ALLOW_A_BIT, n_allow_a_bit);
  vlib_node_increment_counter (vm, node->node_index,
			       GBP_CONTRACT_ERROR_ALLOW_SCLASS_1,
			       n_allow_sclass_1);

  return frame->n_vectors;
}

VLIB_NODE_FN (gbp_policy_port_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return (gbp_policy_inline (vm, node, frame, GBP_POLICY_PORT));
}

VLIB_NODE_FN (gbp_policy_mac_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return (gbp_policy_inline (vm, node, frame, GBP_POLICY_MAC));
}

VLIB_NODE_FN (gbp_policy_lpm_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return (gbp_policy_inline (vm, node, frame, GBP_POLICY_LPM));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_policy_port_node) = {
  .name = "gbp-policy-port",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_policy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_contract_error_strings),
  .error_strings = gbp_contract_error_strings,

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

  .n_errors = ARRAY_LEN(gbp_contract_error_strings),
  .error_strings = gbp_contract_error_strings,

  .n_next_nodes = GBP_POLICY_N_NEXT,
  .next_nodes = {
    [GBP_POLICY_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (gbp_policy_lpm_node) = {
  .name = "gbp-policy-lpm",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_policy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_contract_error_strings),
  .error_strings = gbp_contract_error_strings,

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

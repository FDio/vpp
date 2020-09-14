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
#include <plugins/gbp/gbp_policy.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>

gbp_policy_main_t gbp_policy_main;

/* packet trace format function */
u8 *
format_gbp_policy_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_policy_trace_t *t = va_arg (*args, gbp_policy_trace_t *);

  s =
    format (s,
	    "scope:%d sclass:%d, dclass:%d, action:%U flags:%U acl: %d rule: %d",
	    t->scope, t->sclass, t->dclass, format_gbp_rule_action, t->action,
	    format_vxlan_gbp_header_gpflags, t->flags, t->acl_match,
	    t->rule_match);

  return s;
}

static clib_error_t *
gbp_policy_init (vlib_main_t * vm)
{
  gbp_policy_main_t *gpm = &gbp_policy_main;
  clib_error_t *error = 0;

  /* Initialize the feature next-node indexes */
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "gbp-policy-port");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       gpm->l2_output_feat_next[GBP_POLICY_PORT]);

  node = vlib_get_node_by_name (vm, (u8 *) "gbp-policy-mac");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       gpm->l2_output_feat_next[GBP_POLICY_MAC]);

  node = vlib_get_node_by_name (vm, (u8 *) "gbp-policy-lpm");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       gpm->l2_output_feat_next[GBP_POLICY_LPM]);

  return error;
}

VLIB_INIT_FUNCTION (gbp_policy_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * Copyright (c) 2016-2018 Cisco and/or its affiliates.
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

#include "dataplane_node.h"
#include "dataplane_node_def.h"

VLIB_NODE_FN (acl_out_fa_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 0, 0);
}

VLIB_REGISTER_NODE (
  acl_out_fa_ip6_node) = { .name = "acl-plugin-out-ip6-fa",
			   .vector_size = sizeof (u32),
			   .format_trace = format_acl_plugin_trace,
			   .type = VLIB_NODE_TYPE_INTERNAL,
			   .n_errors = ARRAY_LEN (acl_fa_error_strings),
			   .error_strings = acl_fa_error_strings,
			   .n_next_nodes = ACL_FA_N_NEXT,
			   .next_nodes = {
			     [ACL_FA_ERROR_DROP] = "error-drop",
			   } };

VNET_FEATURE_INIT (acl_out_ip6_fa_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "acl-plugin-out-ip6-fa",
  .runs_before = VNET_FEATURES ("interface-output"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

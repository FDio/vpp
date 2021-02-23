/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

/*
 * Policy NAT.
 * Match packet against rule in a hash and translate according to given
 * instructions. Rules are kept in a flow-cache bihash. Instructions in a pool
 * of translation entries.
 *
 * All rules for a given interface/direction must use the same lookup pattern.
 * E.g. SA+SP.
 *
 * A dynamic NAT would punt to slow path on a miss in the flow cache, in this
 * case the miss behaviour is configurable. Default behaviour is pass packet
 * along unchanged.
 *
 * The data structures are shared and assuming that updates to the tables are
 * rare. Data-structures are protected depending on the API/CLI barriers.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <pnat/pnat.api_enum.h> /* For error counters */
#include "pnat_node.h"          /* Graph nodes */

VLIB_NODE_FN(pnat_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return pnat_node_inline(vm, node, frame, PNAT_IP4_INPUT, VLIB_RX);
}
VLIB_NODE_FN(pnat_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return pnat_node_inline(vm, node, frame, PNAT_IP4_OUTPUT, VLIB_TX);
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE(pnat_input_node) = {
    .name = "pnat-input",
    .vector_size = sizeof(u32),
    .format_trace = format_pnat_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = PNAT_N_ERROR,
    .error_counters = pnat_error_counters,
    .n_next_nodes = PNAT_N_NEXT,
    .next_nodes =
        {
            [PNAT_NEXT_DROP] = "error-drop",
        },
};

VLIB_REGISTER_NODE(pnat_output_node) = {
    .name = "pnat-output",
    .vector_size = sizeof(u32),
    .format_trace = format_pnat_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = PNAT_N_ERROR,
    .error_counters = pnat_error_counters,
    .sibling_of = "pnat-input",
};
#endif

/* Hook up features */
VNET_FEATURE_INIT(pnat_input, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "pnat-input",
    .runs_after = VNET_FEATURES("ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT(pnat_output, static) = {
    .arc_name = "ip4-output",
    .node_name = "pnat-output",
    .runs_after = VNET_FEATURES("ip4-sv-reassembly-output-feature"),
};

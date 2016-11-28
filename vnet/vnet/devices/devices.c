/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

static uword
device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (device_input_node) = {
  .function = device_input_fn,
  .name = "device-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_next_nodes = VNET_DEVICE_INPUT_N_NEXT_NODES,
  .next_nodes = VNET_DEVICE_INPUT_NEXT_NODES,
};

/* Table defines how much we need to advance current data pointer
   in the buffer if we shortcut to l3 nodes */

const u32 __attribute__((aligned (CLIB_CACHE_LINE_BYTES)))
device_input_next_node_advance[((VNET_DEVICE_INPUT_N_NEXT_NODES /
				CLIB_CACHE_LINE_BYTES) +1) * CLIB_CACHE_LINE_BYTES] =
{
      [VNET_DEVICE_INPUT_NEXT_IP4_INPUT] = sizeof (ethernet_header_t),
      [VNET_DEVICE_INPUT_NEXT_IP6_INPUT] = sizeof (ethernet_header_t),
      [VNET_DEVICE_INPUT_NEXT_MPLS_INPUT] = sizeof (ethernet_header_t),
};

VNET_FEATURE_ARC_INIT (device_input, static) =
{
  .arc_name  = "device-input",
  .start_nodes = VNET_FEATURES ("device-input"),
  .end_node = "ethernet-input",
  .arc_index_ptr = &feature_main.device_input_feature_arc_index,
};

VNET_FEATURE_INIT (l2_patch, static) = {
  .arc_name = "device-input",
  .node_name = "l2-patch",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (worker_handoff, static) = {
  .arc_name = "device-input",
  .node_name = "worker-handoff",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (span_input, static) = {
  .arc_name = "device-input",
  .node_name = "span-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (ethernet_input, static) = {
  .arc_name = "device-input",
  .node_name = "ethernet-input",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

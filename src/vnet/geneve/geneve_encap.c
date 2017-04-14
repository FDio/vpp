/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/geneve/geneve.h>


always_inline uword
geneve_encap_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame,
		    u32 is_ip4)
{

  /* TBD */

  return 1;

}


static uword
geneve4_encap (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return geneve_encap_inline (vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
geneve6_encap (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return geneve_encap_inline (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (geneve4_encap_node) = {
  .function = geneve4_encap,
  .name = "geneve4-encap",
  .vector_size = sizeof (u32),

  /* TBD */
};

VLIB_NODE_FUNCTION_MULTIARCH (geneve4_encap_node, geneve4_encap)

VLIB_REGISTER_NODE (geneve6_encap_node) = {
  .function = geneve6_encap,
  .name = "geneve6-encap",

  /* TBD */
};

VLIB_NODE_FUNCTION_MULTIARCH (geneve6_encap_node, geneve6_encap)

/*
 * decap.c: geneve tunnel decap packet processing
 *
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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/geneve/geneve.h>

vlib_node_registration_t geneve4_input_node;
vlib_node_registration_t geneve6_input_node;


always_inline uword
geneve_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame,
             u32 is_ip4)
{
  /* TBD */

  return 1;

}

static uword
geneve4_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return geneve_input(vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
geneve6_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return geneve_input(vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (geneve4_input_node) = {
  .function = geneve4_input,
  .name = "geneve4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  /* TBD */
};

VLIB_NODE_FUNCTION_MULTIARCH (geneve4_input_node, geneve4_input)

VLIB_REGISTER_NODE (geneve6_input_node) = {
  .function = geneve6_input,
  .name = "geneve6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  /* TBD */
};

VLIB_NODE_FUNCTION_MULTIARCH (geneve6_input_node, geneve6_input)



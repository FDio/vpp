/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vppinfra/serialize.h>

/* 
 * Serialize a vlib_node_main_t. Appends the result to vector.
 * Pass 0 to create a new vector, use vec_reset_length(vector)
 * to recycle a vector / avoid memory allocation, etc.
 * Switch heaps before/after to serialize into API client shared memory.
 */

u8 * vlib_node_serialize (vlib_node_main_t *nm, u8 * vector)
{
  serialize_main_t _sm, *sm=&_sm;
  vlib_node_t * node;
  int i, j;
  u8 * cstemp = 0;
  
  serialize_open_vector (sm, vector);
  
  serialize_likely_small_unsigned_integer (sm, vec_len(nm->nodes));
  for (i = 0; i < vec_len (nm->nodes); i++)
    {
      node = nm->nodes[i];
      vec_reset_length (cstemp);
      cstemp = vec_dup(node->name);
      vec_add1(cstemp, 0);
      serialize_cstring (sm, (char *)cstemp);
      serialize_likely_small_unsigned_integer (sm, vec_len(node->next_nodes));
      for (j = 0; j < vec_len (node->next_nodes); j++)
        serialize_likely_small_unsigned_integer (sm, node->next_nodes[j]);
    }
  vec_free(cstemp);
    
  return (serialize_close_vector (sm));
}

vlib_node_t ** vlib_node_unserialize (u8 * vector)
{
  serialize_main_t _sm, *sm=&_sm;
  u32 nnodes, nnexts;
  vlib_node_t * node;
  vlib_node_t ** nodes = 0;
  int i, j;

  serialize_open_vector (sm, vector);
  
  nnodes = unserialize_likely_small_unsigned_integer (sm);

  vec_validate (nodes, nnodes-1);

  for (i = 0; i < nnodes; i++)
    {
      node = 0;
      vec_validate (node,0);
      nodes[i] = node;
      unserialize_cstring (sm, (char **)&node->name);

      nnexts = unserialize_likely_small_unsigned_integer (sm);
      if (nnexts > 0)
          vec_validate (node->next_nodes, nnexts-1);
      for (j = 0; j < vec_len (node->next_nodes); j++)
        node->next_nodes[j] =
          unserialize_likely_small_unsigned_integer (sm);
    }
  return nodes;    
}


#if CLIB_DEBUG > 0

static clib_error_t *
test_node_serialize_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  vlib_node_main_t * nm = &vm->node_main;
  u8 * vector = 0;
  vlib_node_t ** nodes;
  vlib_node_t * node;
  vlib_node_t * next_node;
  int i, j;

  /* 
   * Keep the number of memcpy ops to a minimum (e.g. 1).
   * The current size of the serialized vector is
   * slightly under 4K.
   */
  vec_validate (vector, 4095);
  vec_reset_length (vector);

  vector = vlib_node_serialize (nm, vector);

  nodes = vlib_node_unserialize (vector);

  vec_free (vector);
  
  for (i = 0; i < vec_len(nodes); i++) 
    {
      node = nodes[i];
      
      vlib_cli_output (vm, "[%d] %s", i, node->name);
      for (j = 0; j < vec_len (node->next_nodes); j++)
        {
          if (node->next_nodes[j] != ~0)
            next_node = nodes[node->next_nodes[j]];
          vlib_cli_output (vm, "  [%d] %s", j, next_node->name);
        }
  }

  for (i = 0; i < vec_len(nodes); i++) 
    {
      vec_free (nodes[i]->name);
      vec_free (nodes[i]->next_nodes);
      vec_free (nodes[i]);
    }
  vec_free(nodes);

  return 0;
}

VLIB_CLI_COMMAND (test_node_serialize_node, static) = {
    .path = "test node serialize",
    .short_help = "test node serialize",
    .function = test_node_serialize_command_fn,
};
#endif

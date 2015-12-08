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
#include <vppinfra/format.h>
#include <vlib/vlib.h>

#include <vlib/threads.h>

/* Functions to call from gdb */

u32 vl(void *p)
{
  return vec_len (p);
}

uword pe (void *v)
{
  return (pool_elts(v));
}

int pifi (void *p, u32 index)
{
  return pool_is_free_index (p, index);
}

void debug_hex_bytes (u8 *s, u32 n)
{
  fformat (stderr, "%U\n", format_hex_bytes, s, n);
}

void vlib_dump_frame_ownership (void)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_node_main_t * nm = &vm->node_main;
  vlib_node_runtime_t * this_node_runtime;
  vlib_next_frame_t * nf;
  u32 first_nf_index;
  u32 index;
    
  vec_foreach(this_node_runtime, nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL])
    {
      first_nf_index = this_node_runtime->next_frame_index;

      for (index = first_nf_index; index < first_nf_index + 
             this_node_runtime->n_next_nodes; index++) 
        {
          vlib_node_runtime_t * owned_runtime;
          nf = vec_elt_at_index (vm->node_main.next_frames, index);
          if (nf->flags & VLIB_FRAME_OWNER) 
            {
              owned_runtime = vec_elt_at_index (nm->nodes_by_type[0],
                                                nf->node_runtime_index);
              fformat(stderr, 
                      "%s next index %d owns enqueue rights to %s\n",
                      nm->nodes[this_node_runtime->node_index]->name, 
                      index - first_nf_index, 
                      nm->nodes[owned_runtime->node_index]->name);
              fformat (stderr, "  nf index %d nf->frame_index %d\n",
                       nf - vm->node_main.next_frames, 
                       nf->frame_index);
            }
        }
    }
}

void vlib_runtime_index_to_node_name (u32 index)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_node_main_t * nm = &vm->node_main;
    
  if (index > vec_len (nm->nodes))
    {
      fformat(stderr, "%d out of range, max %d\n", vec_len(nm->nodes));
      return;
    }

  fformat(stderr, "node runtime index %d name %s\n", index, nm->nodes[index]->name);
}


static clib_error_t *
show_gdb_command_fn (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "vl(p) returns vec_len(p)");
  vlib_cli_output (vm, "pe(p) returns pool_elts(p)");
  vlib_cli_output (vm, "pifi(p, i) returns pool_is_free_index(p, i)");
  vlib_cli_output (vm, "debug_hex_bytes (ptr, n_bytes) dumps n_bytes in hex");
  vlib_cli_output (vm, "vlib_dump_frame_ownership() does what it says");
  vlib_cli_output (vm, "vlib_runtime_index_to_node_name (index) prints NN");

  return 0;
}

VLIB_CLI_COMMAND (show_gdb_funcs_command, static) = {
  .path = "show gdb",
  .short_help = "Describe functions which can be called from gdb",
  .function = show_gdb_command_fn,
};

/* Cafeteria plan, maybe you don't want these functions */
clib_error_t * 
gdb_func_init (vlib_main_t * vm) { return 0; } 

VLIB_INIT_FUNCTION (gdb_func_init);

/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

/** \file
 * Buffer trace trajectory utilities
 */

#include <vnet/vnet.h>

/**
 * Dump a trajectory trace, reasonably easy to call from gdb
 */
void
vnet_dump_trajectory_trace (vlib_main_t * vm, u32 bi)
{
#if VLIB_BUFFER_TRACE_TRAJECTORY > 0
  vlib_node_main_t *vnm = &vm->node_main;
  vlib_buffer_t *b;
  u16 *trace;
  u8 i;

  b = vlib_get_buffer (vm, bi);

  trace = vnet_buffer2 (b)->trajectory_trace;

  fformat (stderr, "Context trace for bi %d b 0x%llx, visited %d\n",
	   bi, b, vec_len (trace));

  for (i = 0; i < vec_len (trace); i++)
    {
      u32 node_index;

      node_index = trace[i];

      if (node_index > vec_len (vnm->nodes))
	{
	  fformat (stderr, "Skip bogus node index %d\n", node_index);
	  continue;
	}

      fformat (stderr, "%v (%d)\n", vnm->nodes[node_index]->name, node_index);
    }
#else
  fformat (stderr, "in vlib/buffers.h, "
	   "#define VLIB_BUFFER_TRACE_TRAJECTORY 1\n");

#endif
}

#if VLIB_BUFFER_TRACE_TRAJECTORY > 0

void
init_trajectory_trace (vlib_buffer_t * b)
{
  vec_validate (vnet_buffer2 (b)->trajectory_trace, 7);
  _vec_len (vnet_buffer2 (b)->trajectory_trace) = 0;
}

void
add_trajectory_trace (vlib_buffer_t * b, u32 node_index)
{
  vec_add1 (vnet_buffer2 (b)->trajectory_trace, (u16) node_index);
}

static clib_error_t *
trajectory_trace_init (vlib_main_t * vm)
{
  vlib_buffer_trace_trajectory_cb = add_trajectory_trace;
  vlib_buffer_trace_trajectory_init_cb = init_trajectory_trace;
  return 0;
}

VLIB_INIT_FUNCTION (trajectory_trace_init);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

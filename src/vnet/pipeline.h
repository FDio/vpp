/*
 * vnet/pipeline.h: software pipeline
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
 * Usage example.
 *
 * #define NSTAGES 3 or whatever
 *
 * If using an aux data vector - to hold bihash keys or some such:
 *
 * #define AUX_DATA_TYPE my_aux_data_t
 *
 * <Define pipeline stages>
 *
 * #include <vnet/pipeline.h>
 *
 * static uword my_node_fn (vlib_main_t * vm,
 *                               vlib_node_runtime_t * node,
 *                               vlib_frame_t * frame)
 * {
 *     return dispatch_pipeline (vm, node, frame);
 * }
 *
 */

#ifndef NSTAGES
#error files which #include <vnet/pipeline.h> must define NSTAGES
#endif

#ifndef STAGE_INLINE
#define STAGE_INLINE inline
#endif

/* Unless the user wants the aux data scheme, don't configure it */
#ifndef AUX_DATA_TYPE
#define AUX_DATA_ARG
#define AUX_DATA_DECL
#define AUX_DATA_PTR(pi)
#else
#define AUX_DATA_ARG ,##AUX_DATA_TYPE *ap
#define AUX_DATA_DECL AUX_DATA_TYPE aux_data[VLIB_FRAME_SIZE]
#define AUX_DATA_PTR(pi) ,aux_data +(pi)
#endif

/*
 * A prefetch stride of 2 is quasi-equivalent to doubling the number
 * of stages with every other pipeline stage empty.
 */

/*
 * This is a typical first pipeline stage, which prefetches
 * buffer metadata and the first line of pkt data.
 *
 * To use it:
 *  #define stage0 generic_stage0
 *
 * This implementation won't use the aux data argument
 */
static STAGE_INLINE void
generic_stage0 (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_buffer_t * b AUX_DATA_ARG)
{
  vlib_prefetch_buffer_header (b, STORE);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, STORE);
}

#if NSTAGES == 2

static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from;
  u32 n_left_from;
  int pi;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  AUX_DATA_DECL;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left_from);

  for (pi = 0; pi < NSTAGES - 1; pi++)
    {
      if (pi == n_left_from)
	break;
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
    }

  for (; pi < n_left_from; pi++)
    {
      stage0 (vm, node, bufs[pi]);
      nexts[pi - 1] =
	last_stage (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
    }

  for (; pi < (n_left_from + (NSTAGES - 1)); pi++)
    {
      if (((pi - 1) >= 0) && ((pi - 1) < n_left_from))
	nexts[pi - 1] =
	  last_stage (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}
#endif

#if NSTAGES == 3
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from;
  u32 n_left_from;
  int pi;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  AUX_DATA_DECL;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left_from);

  for (pi = 0; pi < NSTAGES - 1; pi++)
    {
      if (pi == n_left_from)
	break;
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      if (pi - 1 >= 0)
	stage1 (vm, node, bufs[pi - 1]);
    }

  for (; pi < n_left_from; pi++)
    {
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      nexts[pi - 2] =
	last_stage (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
    }

  for (; pi < (n_left_from + (NSTAGES - 1)); pi++)
    {
      if (((pi - 1) >= 0) && ((pi - 1) < n_left_from))
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (((pi - 2) >= 0) && ((pi - 2) < n_left_from))
	nexts[pi - 2] =
	  last_stage (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}
#endif

#if NSTAGES == 4
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from;
  u32 n_left_from;
  int pi;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  AUX_DATA_DECL;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left_from);

  for (pi = 0; pi < NSTAGES - 1; pi++)
    {
      if (pi == n_left_from)
	break;
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      if (pi - 1 >= 0)
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (pi - 2 >= 0)
	stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
    }

  for (; pi < n_left_from; pi++)
    {
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      nexts[pi - 3] =
	last_stage (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
    }

  for (; pi < (n_left_from + (NSTAGES - 1)); pi++)
    {
      if (((pi - 1) >= 0) && ((pi - 1) < n_left_from))
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (((pi - 2) >= 0) && ((pi - 2) < n_left_from))
	stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      if (((pi - 3) >= 0) && ((pi - 3) < n_left_from))
	nexts[pi - 3] =
	  last_stage (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}
#endif

#if NSTAGES == 5
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from;
  u32 n_left_from;
  int pi;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  AUX_DATA_DECL;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left_from);

  for (pi = 0; pi < NSTAGES - 1; pi++)
    {
      if (pi == n_left_from)
	break;
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      if (pi - 1 >= 0)
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (pi - 2 >= 0)
	stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      if (pi - 3 >= 0)
	stage3 (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
    }

  for (; pi < n_left_from; pi++)
    {
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      stage3 (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
      nexts[pi - 4] =
	last_stage (vm, node, bufs[pi - 4] AUX_DATA_PTR (pi - 4));
    }

  for (; pi < (n_left_from + (NSTAGES - 1)); pi++)
    {
      if (((pi - 1) >= 0) && ((pi - 1) < n_left_from))
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (((pi - 2) >= 0) && ((pi - 2) < n_left_from))
	stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      if (((pi - 3) >= 0) && ((pi - 3) < n_left_from))
	stage3 (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
      if (((pi - 4) >= 0) && ((pi - 4) < n_left_from))
	nexts[pi - 4] =
	  last_stage (vm, node, bufs[pi - 4] AUX_DATA_PTR (pi - 4));
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}
#endif

#if NSTAGES == 6
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from;
  u32 n_left_from;
  int pi;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  AUX_DATA_DECL;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left_from);

  for (pi = 0; pi < NSTAGES - 1; pi++)
    {
      if (pi == n_left_from)
	break;
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      if (pi - 1 >= 0)
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (pi - 2 >= 0)
	stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      if (pi - 3 >= 0)
	stage3 (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
      if (pi - 4 >= 0)
	stage4 (vm, node, bufs[pi - 4] AUX_DATA_PTR (pi - 4));
    }

  for (; pi < n_left_from; pi++)
    {
      stage0 (vm, node, bufs[pi] AUX_DATA_PTR (pi));
      stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      stage3 (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
      stage4 (vm, node, bufs[pi - 4] AUX_DATA_PTR (pi - 4));
      nexts[pi - 5] =
	last_stage (vm, node, bufs[pi - 5] AUX_DATA_PTR (pi - 5));
    }

  for (; pi < (n_left_from + (NSTAGES - 1)); pi++)
    {
      if (((pi - 1) >= 0) && ((pi - 1) < n_left_from))
	stage1 (vm, node, bufs[pi - 1] AUX_DATA_PTR (pi - 1));
      if (((pi - 2) >= 0) && ((pi - 2) < n_left_from))
	stage2 (vm, node, bufs[pi - 2] AUX_DATA_PTR (pi - 2));
      if (((pi - 3) >= 0) && ((pi - 3) < n_left_from))
	stage3 (vm, node, bufs[pi - 3] AUX_DATA_PTR (pi - 3));
      if (((pi - 4) >= 0) && ((pi - 4) < n_left_from))
	stage4 (vm, node, bufs[pi - 4] AUX_DATA_PTR (pi - 4));
      if (((pi - 5) >= 0) && ((pi - 5) < n_left_from))
	nexts[pi - 5] =
	  last_stage (vm, node, bufs[pi - 5] AUX_DATA_PTR (pi - 5));
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

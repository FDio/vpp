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

/*
 * A prefetch stride of 2 is quasi-equivalent to doubling the number
 * of stages with every other pipeline stage empty.
 */

/*
 * This is a typical first pipeline stage, which prefetches
 * buffer metadata and the first line of pkt data.
 * To use it:
 *  #define stage0 generic_stage0
 */
static STAGE_INLINE void
generic_stage0 (vlib_main_t * vm,
		vlib_node_runtime_t * node, u32 buffer_index)
{
  /* generic default stage 0 here */
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  vlib_prefetch_buffer_header (b, STORE);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, STORE);
}

#if NSTAGES == 2

static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index, next0;
  int pi, pi_limit;

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      pi_limit = clib_min (n_left_from, n_left_to_next);

      for (pi = 0; pi < NSTAGES - 1; pi++)
	{
	  if (pi == pi_limit)
	    break;
	  stage0 (vm, node, from[pi]);
	}

      for (; pi < pi_limit; pi++)
	{
	  stage0 (vm, node, from[pi]);
	  to_next[0] = from[pi - 1];
	  to_next++;
	  n_left_to_next--;
	  next0 = last_stage (vm, node, from[pi - 1]);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   from[pi - 1], next0);
	  n_left_from--;
	  if ((int) n_left_to_next < 0 && n_left_from > 0)
	    vlib_get_next_frame (vm, node, next_index, to_next,
				 n_left_to_next);
	}

      for (; pi < (pi_limit + (NSTAGES - 1)); pi++)
	{
	  if (((pi - 1) >= 0) && ((pi - 1) < pi_limit))
	    {
	      to_next[0] = from[pi - 1];
	      to_next++;
	      n_left_to_next--;
	      next0 = last_stage (vm, node, from[pi - 1]);
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       from[pi - 1], next0);
	      n_left_from--;
	      if ((int) n_left_to_next < 0 && n_left_from > 0)
		vlib_get_next_frame (vm, node, next_index, to_next,
				     n_left_to_next);
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      from += pi_limit;
    }
  return frame->n_vectors;
}
#endif

#if NSTAGES == 3
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index, next0;
  int pi, pi_limit;

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      pi_limit = clib_min (n_left_from, n_left_to_next);

      for (pi = 0; pi < NSTAGES - 1; pi++)
	{
	  if (pi == pi_limit)
	    break;
	  stage0 (vm, node, from[pi]);
	  if (pi - 1 >= 0)
	    stage1 (vm, node, from[pi - 1]);
	}

      for (; pi < pi_limit; pi++)
	{
	  stage0 (vm, node, from[pi]);
	  stage1 (vm, node, from[pi - 1]);
	  to_next[0] = from[pi - 2];
	  to_next++;
	  n_left_to_next--;
	  next0 = last_stage (vm, node, from[pi - 2]);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   from[pi - 2], next0);
	  n_left_from--;
	  if ((int) n_left_to_next < 0 && n_left_from > 0)
	    vlib_get_next_frame (vm, node, next_index, to_next,
				 n_left_to_next);
	}


      for (; pi < (pi_limit + (NSTAGES - 1)); pi++)
	{
	  if (((pi - 1) >= 0) && ((pi - 1) < pi_limit))
	    stage1 (vm, node, from[pi - 1]);
	  if (((pi - 2) >= 0) && ((pi - 2) < pi_limit))
	    {
	      to_next[0] = from[pi - 2];
	      to_next++;
	      n_left_to_next--;
	      next0 = last_stage (vm, node, from[pi - 2]);
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       from[pi - 2], next0);
	      n_left_from--;
	      if ((int) n_left_to_next < 0 && n_left_from > 0)
		vlib_get_next_frame (vm, node, next_index, to_next,
				     n_left_to_next);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      from += pi_limit;
    }
  return frame->n_vectors;
}
#endif

#if NSTAGES == 4
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index, next0;
  int pi, pi_limit;

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      pi_limit = clib_min (n_left_from, n_left_to_next);

      for (pi = 0; pi < NSTAGES - 1; pi++)
	{
	  if (pi == pi_limit)
	    break;
	  stage0 (vm, node, from[pi]);
	  if (pi - 1 >= 0)
	    stage1 (vm, node, from[pi - 1]);
	  if (pi - 2 >= 0)
	    stage2 (vm, node, from[pi - 2]);
	}

      for (; pi < pi_limit; pi++)
	{
	  stage0 (vm, node, from[pi]);
	  stage1 (vm, node, from[pi - 1]);
	  stage2 (vm, node, from[pi - 2]);
	  to_next[0] = from[pi - 3];
	  to_next++;
	  n_left_to_next--;
	  next0 = last_stage (vm, node, from[pi - 3]);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   from[pi - 3], next0);
	  n_left_from--;
	  if ((int) n_left_to_next < 0 && n_left_from > 0)
	    vlib_get_next_frame (vm, node, next_index, to_next,
				 n_left_to_next);
	}


      for (; pi < (pi_limit + (NSTAGES - 1)); pi++)
	{
	  if (((pi - 1) >= 0) && ((pi - 1) < pi_limit))
	    stage1 (vm, node, from[pi - 1]);
	  if (((pi - 2) >= 0) && ((pi - 2) < pi_limit))
	    stage2 (vm, node, from[pi - 2]);
	  if (((pi - 3) >= 0) && ((pi - 3) < pi_limit))
	    {
	      to_next[0] = from[pi - 3];
	      to_next++;
	      n_left_to_next--;
	      next0 = last_stage (vm, node, from[pi - 3]);
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       from[pi - 3], next0);
	      n_left_from--;
	      if ((int) n_left_to_next < 0 && n_left_from > 0)
		vlib_get_next_frame (vm, node, next_index, to_next,
				     n_left_to_next);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      from += pi_limit;
    }
  return frame->n_vectors;
}
#endif


#if NSTAGES == 5
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index, next0;
  int pi, pi_limit;

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      pi_limit = clib_min (n_left_from, n_left_to_next);

      for (pi = 0; pi < NSTAGES - 1; pi++)
	{
	  if (pi == pi_limit)
	    break;
	  stage0 (vm, node, from[pi]);
	  if (pi - 1 >= 0)
	    stage1 (vm, node, from[pi - 1]);
	  if (pi - 2 >= 0)
	    stage2 (vm, node, from[pi - 2]);
	  if (pi - 3 >= 0)
	    stage3 (vm, node, from[pi - 3]);
	}

      for (; pi < pi_limit; pi++)
	{
	  stage0 (vm, node, from[pi]);
	  stage1 (vm, node, from[pi - 1]);
	  stage2 (vm, node, from[pi - 2]);
	  stage3 (vm, node, from[pi - 3]);
	  to_next[0] = from[pi - 4];
	  to_next++;
	  n_left_to_next--;
	  next0 = last_stage (vm, node, from[pi - 4]);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   from[pi - 4], next0);
	  n_left_from--;
	  if ((int) n_left_to_next < 0 && n_left_from > 0)
	    vlib_get_next_frame (vm, node, next_index, to_next,
				 n_left_to_next);
	}


      for (; pi < (pi_limit + (NSTAGES - 1)); pi++)
	{
	  if (((pi - 1) >= 0) && ((pi - 1) < pi_limit))
	    stage1 (vm, node, from[pi - 1]);
	  if (((pi - 2) >= 0) && ((pi - 2) < pi_limit))
	    stage2 (vm, node, from[pi - 2]);
	  if (((pi - 3) >= 0) && ((pi - 3) < pi_limit))
	    stage3 (vm, node, from[pi - 3]);
	  if (((pi - 4) >= 0) && ((pi - 4) < pi_limit))
	    {
	      to_next[0] = from[pi - 4];
	      to_next++;
	      n_left_to_next--;
	      next0 = last_stage (vm, node, from[pi - 4]);
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       from[pi - 4], next0);
	      n_left_from--;
	      if ((int) n_left_to_next < 0 && n_left_from > 0)
		vlib_get_next_frame (vm, node, next_index, to_next,
				     n_left_to_next);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      from += pi_limit;
    }
  return frame->n_vectors;
}
#endif

#if NSTAGES == 6
static STAGE_INLINE uword
dispatch_pipeline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index, next0;
  int pi, pi_limit;

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      pi_limit = clib_min (n_left_from, n_left_to_next);

      for (pi = 0; pi < NSTAGES - 1; pi++)
	{
	  if (pi == pi_limit)
	    break;
	  stage0 (vm, node, from[pi]);
	  if (pi - 1 >= 0)
	    stage1 (vm, node, from[pi - 1]);
	  if (pi - 2 >= 0)
	    stage2 (vm, node, from[pi - 2]);
	  if (pi - 3 >= 0)
	    stage3 (vm, node, from[pi - 3]);
	  if (pi - 4 >= 0)
	    stage4 (vm, node, from[pi - 4]);
	}

      for (; pi < pi_limit; pi++)
	{
	  stage0 (vm, node, from[pi]);
	  stage1 (vm, node, from[pi - 1]);
	  stage2 (vm, node, from[pi - 2]);
	  stage3 (vm, node, from[pi - 3]);
	  stage4 (vm, node, from[pi - 4]);
	  to_next[0] = from[pi - 5];
	  to_next++;
	  n_left_to_next--;
	  next0 = last_stage (vm, node, from[pi - 5]);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   from[pi - 5], next0);
	  n_left_from--;
	  if ((int) n_left_to_next < 0 && n_left_from > 0)
	    vlib_get_next_frame (vm, node, next_index, to_next,
				 n_left_to_next);
	}


      for (; pi < (pi_limit + (NSTAGES - 1)); pi++)
	{
	  if (((pi - 1) >= 0) && ((pi - 1) < pi_limit))
	    stage1 (vm, node, from[pi - 1]);
	  if (((pi - 2) >= 0) && ((pi - 2) < pi_limit))
	    stage2 (vm, node, from[pi - 2]);
	  if (((pi - 3) >= 0) && ((pi - 3) < pi_limit))
	    stage3 (vm, node, from[pi - 3]);
	  if (((pi - 4) >= 0) && ((pi - 4) < pi_limit))
	    stage4 (vm, node, from[pi - 4]);
	  if (((pi - 5) >= 0) && ((pi - 5) < pi_limit))
	    {
	      to_next[0] = from[pi - 5];
	      to_next++;
	      n_left_to_next--;
	      next0 = last_stage (vm, node, from[pi - 5]);
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       from[pi - 5], next0);
	      n_left_from--;
	      if ((int) n_left_to_next < 0 && n_left_from > 0)
		vlib_get_next_frame (vm, node, next_index, to_next,
				     n_left_to_next);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      from += pi_limit;
    }
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

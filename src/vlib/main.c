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
/*
 * main.c: main vector processing loop
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <math.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

#include <vlib/unix/unix.h>
#include <vlib/unix/cj.h>

CJ_GLOBAL_LOG_PROTOTYPE;

/* Actually allocate a few extra slots of vector data to support
   speculative vector enqueues which overflow vector data in next frame. */
#define VLIB_FRAME_SIZE_ALLOC (VLIB_FRAME_SIZE + 4)

u32 wraps;

always_inline u32
vlib_frame_bytes (u32 n_scalar_bytes, u32 n_vector_bytes)
{
  u32 n_bytes;

  /* Make room for vlib_frame_t plus scalar arguments. */
  n_bytes = vlib_frame_vector_byte_offset (n_scalar_bytes);

  /* Make room for vector arguments.
     Allocate a few extra slots of vector data to support
     speculative vector enqueues which overflow vector data in next frame. */
#define VLIB_FRAME_SIZE_EXTRA 4
  n_bytes += (VLIB_FRAME_SIZE + VLIB_FRAME_SIZE_EXTRA) * n_vector_bytes;

  /* Magic number is first 32bit number after vector data.
     Used to make sure that vector data is never overrun. */
#define VLIB_FRAME_MAGIC (0xabadc0ed)
  n_bytes += sizeof (u32);

  /* Pad to cache line. */
  n_bytes = round_pow2 (n_bytes, CLIB_CACHE_LINE_BYTES);

  return n_bytes;
}

always_inline u32 *
vlib_frame_find_magic (vlib_frame_t * f, vlib_node_t * node)
{
  void *p = f;

  p += vlib_frame_vector_byte_offset (node->scalar_size);

  p += (VLIB_FRAME_SIZE + VLIB_FRAME_SIZE_EXTRA) * node->vector_size;

  return p;
}

static vlib_frame_size_t *
get_frame_size_info (vlib_node_main_t * nm,
		     u32 n_scalar_bytes, u32 n_vector_bytes)
{
  uword key = (n_scalar_bytes << 16) | n_vector_bytes;
  uword *p, i;

  p = hash_get (nm->frame_size_hash, key);
  if (p)
    i = p[0];
  else
    {
      i = vec_len (nm->frame_sizes);
      vec_validate (nm->frame_sizes, i);
      hash_set (nm->frame_size_hash, key, i);
    }

  return vec_elt_at_index (nm->frame_sizes, i);
}

static u32
vlib_frame_alloc_to_node (vlib_main_t * vm, u32 to_node_index,
			  u32 frame_flags)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_frame_size_t *fs;
  vlib_node_t *to_node;
  vlib_frame_t *f;
  u32 fi, l, n, scalar_size, vector_size;

  to_node = vlib_get_node (vm, to_node_index);

  scalar_size = to_node->scalar_size;
  vector_size = to_node->vector_size;

  fs = get_frame_size_info (nm, scalar_size, vector_size);
  n = vlib_frame_bytes (scalar_size, vector_size);
  if ((l = vec_len (fs->free_frame_indices)) > 0)
    {
      /* Allocate from end of free list. */
      fi = fs->free_frame_indices[l - 1];
      f = vlib_get_frame_no_check (vm, fi);
      _vec_len (fs->free_frame_indices) = l - 1;
    }
  else
    {
      f = clib_mem_alloc_aligned_no_fail (n, VLIB_FRAME_ALIGN);
      fi = vlib_frame_index_no_check (vm, f);
    }

  /* Poison frame when debugging. */
  if (CLIB_DEBUG > 0)
    clib_memset (f, 0xfe, n);

  /* Insert magic number. */
  {
    u32 *magic;

    magic = vlib_frame_find_magic (f, to_node);
    *magic = VLIB_FRAME_MAGIC;
  }

  f->frame_flags = VLIB_FRAME_IS_ALLOCATED | frame_flags;
  f->n_vectors = 0;
  f->scalar_size = scalar_size;
  f->vector_size = vector_size;
  f->flags = 0;

  fs->n_alloc_frames += 1;

  return fi;
}

/* Allocate a frame for from FROM_NODE to TO_NODE via TO_NEXT_INDEX.
   Returns frame index. */
static u32
vlib_frame_alloc (vlib_main_t * vm, vlib_node_runtime_t * from_node_runtime,
		  u32 to_next_index)
{
  vlib_node_t *from_node;

  from_node = vlib_get_node (vm, from_node_runtime->node_index);
  ASSERT (to_next_index < vec_len (from_node->next_nodes));

  return vlib_frame_alloc_to_node (vm, from_node->next_nodes[to_next_index],
				   /* frame_flags */ 0);
}

vlib_frame_t *
vlib_get_frame_to_node (vlib_main_t * vm, u32 to_node_index)
{
  u32 fi = vlib_frame_alloc_to_node (vm, to_node_index,
				     /* frame_flags */
				     VLIB_FRAME_FREE_AFTER_DISPATCH);
  return vlib_get_frame (vm, fi);
}

void
vlib_put_frame_to_node (vlib_main_t * vm, u32 to_node_index, vlib_frame_t * f)
{
  vlib_pending_frame_t *p;
  vlib_node_t *to_node;

  if (f->n_vectors == 0)
    return;

  to_node = vlib_get_node (vm, to_node_index);

  vec_add2 (vm->node_main.pending_frames, p, 1);

  f->frame_flags |= VLIB_FRAME_PENDING;
  p->frame_index = vlib_frame_index (vm, f);
  p->node_runtime_index = to_node->runtime_index;
  p->next_frame_index = VLIB_PENDING_FRAME_NO_NEXT_FRAME;
}

/* Free given frame. */
void
vlib_frame_free (vlib_main_t * vm, vlib_node_runtime_t * r, vlib_frame_t * f)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *node;
  vlib_frame_size_t *fs;
  u32 frame_index;

  ASSERT (f->frame_flags & VLIB_FRAME_IS_ALLOCATED);

  node = vlib_get_node (vm, r->node_index);
  fs = get_frame_size_info (nm, node->scalar_size, node->vector_size);

  frame_index = vlib_frame_index (vm, f);

  ASSERT (f->frame_flags & VLIB_FRAME_IS_ALLOCATED);

  /* No next frames may point to freed frame. */
  if (CLIB_DEBUG > 0)
    {
      vlib_next_frame_t *nf;
      vec_foreach (nf, vm->node_main.next_frames)
	ASSERT (nf->frame_index != frame_index);
    }

  f->frame_flags &= ~VLIB_FRAME_IS_ALLOCATED;

  vec_add1 (fs->free_frame_indices, frame_index);
  ASSERT (fs->n_alloc_frames > 0);
  fs->n_alloc_frames -= 1;
}

static clib_error_t *
show_frame_stats (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_frame_size_t *fs;

  vlib_cli_output (vm, "%=6s%=12s%=12s", "Size", "# Alloc", "# Free");
  vec_foreach (fs, nm->frame_sizes)
  {
    u32 n_alloc = fs->n_alloc_frames;
    u32 n_free = vec_len (fs->free_frame_indices);

    if (n_alloc + n_free > 0)
      vlib_cli_output (vm, "%=6d%=12d%=12d",
		       fs - nm->frame_sizes, n_alloc, n_free);
  }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_frame_stats_cli, static) = {
  .path = "show vlib frame-allocation",
  .short_help = "Show node dispatch frame statistics",
  .function = show_frame_stats,
};
/* *INDENT-ON* */

/* Change ownership of enqueue rights to given next node. */
static void
vlib_next_frame_change_ownership (vlib_main_t * vm,
				  vlib_node_runtime_t * node_runtime,
				  u32 next_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_next_frame_t *next_frame;
  vlib_node_t *node, *next_node;

  node = vec_elt (nm->nodes, node_runtime->node_index);

  /* Only internal & input nodes are allowed to call other nodes. */
  ASSERT (node->type == VLIB_NODE_TYPE_INTERNAL
	  || node->type == VLIB_NODE_TYPE_INPUT
	  || node->type == VLIB_NODE_TYPE_PROCESS);

  ASSERT (vec_len (node->next_nodes) == node_runtime->n_next_nodes);

  next_frame =
    vlib_node_runtime_get_next_frame (vm, node_runtime, next_index);
  next_node = vec_elt (nm->nodes, node->next_nodes[next_index]);

  if (next_node->owner_node_index != VLIB_INVALID_NODE_INDEX)
    {
      /* Get frame from previous owner. */
      vlib_next_frame_t *owner_next_frame;
      vlib_next_frame_t tmp;

      owner_next_frame =
	vlib_node_get_next_frame (vm,
				  next_node->owner_node_index,
				  next_node->owner_next_index);

      /* Swap target next frame with owner's. */
      tmp = owner_next_frame[0];
      owner_next_frame[0] = next_frame[0];
      next_frame[0] = tmp;

      /*
       * If next_frame is already pending, we have to track down
       * all pending frames and fix their next_frame_index fields.
       */
      if (next_frame->flags & VLIB_FRAME_PENDING)
	{
	  vlib_pending_frame_t *p;
	  if (next_frame->frame_index != ~0)
	    {
	      vec_foreach (p, nm->pending_frames)
	      {
		if (p->frame_index == next_frame->frame_index)
		  {
		    p->next_frame_index =
		      next_frame - vm->node_main.next_frames;
		  }
	      }
	    }
	}
    }
  else
    {
      /* No previous owner. Take ownership. */
      next_frame->flags |= VLIB_FRAME_OWNER;
    }

  /* Record new owner. */
  next_node->owner_node_index = node->index;
  next_node->owner_next_index = next_index;

  /* Now we should be owner. */
  ASSERT (next_frame->flags & VLIB_FRAME_OWNER);
}

/* Make sure that magic number is still there.
   Otherwise, it is likely that caller has overrun frame arguments. */
always_inline void
validate_frame_magic (vlib_main_t * vm,
		      vlib_frame_t * f, vlib_node_t * n, uword next_index)
{
  vlib_node_t *next_node = vlib_get_node (vm, n->next_nodes[next_index]);
  u32 *magic = vlib_frame_find_magic (f, next_node);
  ASSERT (VLIB_FRAME_MAGIC == magic[0]);
}

vlib_frame_t *
vlib_get_next_frame_internal (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      u32 next_index, u32 allocate_new_next_frame)
{
  vlib_frame_t *f;
  vlib_next_frame_t *nf;
  u32 n_used;

  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);

  /* Make sure this next frame owns right to enqueue to destination frame. */
  if (PREDICT_FALSE (!(nf->flags & VLIB_FRAME_OWNER)))
    vlib_next_frame_change_ownership (vm, node, next_index);

  /* ??? Don't need valid flag: can use frame_index == ~0 */
  if (PREDICT_FALSE (!(nf->flags & VLIB_FRAME_IS_ALLOCATED)))
    {
      nf->frame_index = vlib_frame_alloc (vm, node, next_index);
      nf->flags |= VLIB_FRAME_IS_ALLOCATED;
    }

  f = vlib_get_frame (vm, nf->frame_index);

  /* Has frame been removed from pending vector (e.g. finished dispatching)?
     If so we can reuse frame. */
  if ((nf->flags & VLIB_FRAME_PENDING)
      && !(f->frame_flags & VLIB_FRAME_PENDING))
    {
      nf->flags &= ~VLIB_FRAME_PENDING;
      f->n_vectors = 0;
      f->flags = 0;
    }

  /* Allocate new frame if current one is already full. */
  n_used = f->n_vectors;
  if (n_used >= VLIB_FRAME_SIZE || (allocate_new_next_frame && n_used > 0))
    {
      /* Old frame may need to be freed after dispatch, since we'll have
         two redundant frames from node -> next node. */
      if (!(nf->flags & VLIB_FRAME_NO_FREE_AFTER_DISPATCH))
	{
	  vlib_frame_t *f_old = vlib_get_frame (vm, nf->frame_index);
	  f_old->frame_flags |= VLIB_FRAME_FREE_AFTER_DISPATCH;
	}

      /* Allocate new frame to replace full one. */
      nf->frame_index = vlib_frame_alloc (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame_index);
      n_used = f->n_vectors;
    }

  /* Should have free vectors in frame now. */
  ASSERT (n_used < VLIB_FRAME_SIZE);

  if (CLIB_DEBUG > 0)
    {
      validate_frame_magic (vm, f,
			    vlib_get_node (vm, node->node_index), next_index);
    }

  return f;
}

static void
vlib_put_next_frame_validate (vlib_main_t * vm,
			      vlib_node_runtime_t * rt,
			      u32 next_index, u32 n_vectors_left)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  vlib_node_runtime_t *next_rt;
  vlib_node_t *next_node;
  u32 n_before, n_after;

  nf = vlib_node_runtime_get_next_frame (vm, rt, next_index);
  f = vlib_get_frame (vm, nf->frame_index);

  ASSERT (n_vectors_left <= VLIB_FRAME_SIZE);
  n_after = VLIB_FRAME_SIZE - n_vectors_left;
  n_before = f->n_vectors;

  ASSERT (n_after >= n_before);

  next_rt = vec_elt_at_index (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL],
			      nf->node_runtime_index);
  next_node = vlib_get_node (vm, next_rt->node_index);
  if (n_after > 0 && next_node->validate_frame)
    {
      u8 *msg = next_node->validate_frame (vm, rt, f);
      if (msg)
	{
	  clib_warning ("%v", msg);
	  ASSERT (0);
	}
      vec_free (msg);
    }
}

void
vlib_put_next_frame (vlib_main_t * vm,
		     vlib_node_runtime_t * r,
		     u32 next_index, u32 n_vectors_left)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  u32 n_vectors_in_frame;

  if (vm->buffer_main->callbacks_registered == 0 && CLIB_DEBUG > 0)
    vlib_put_next_frame_validate (vm, r, next_index, n_vectors_left);

  nf = vlib_node_runtime_get_next_frame (vm, r, next_index);
  f = vlib_get_frame (vm, nf->frame_index);

  /* Make sure that magic number is still there.  Otherwise, caller
     has overrun frame meta data. */
  if (CLIB_DEBUG > 0)
    {
      vlib_node_t *node = vlib_get_node (vm, r->node_index);
      validate_frame_magic (vm, f, node, next_index);
    }

  /* Convert # of vectors left -> number of vectors there. */
  ASSERT (n_vectors_left <= VLIB_FRAME_SIZE);
  n_vectors_in_frame = VLIB_FRAME_SIZE - n_vectors_left;

  f->n_vectors = n_vectors_in_frame;

  /* If vectors were added to frame, add to pending vector. */
  if (PREDICT_TRUE (n_vectors_in_frame > 0))
    {
      vlib_pending_frame_t *p;
      u32 v0, v1;

      r->cached_next_index = next_index;

      if (!(f->frame_flags & VLIB_FRAME_PENDING))
	{
	  __attribute__ ((unused)) vlib_node_t *node;
	  vlib_node_t *next_node;
	  vlib_node_runtime_t *next_runtime;

	  node = vlib_get_node (vm, r->node_index);
	  next_node = vlib_get_next_node (vm, r->node_index, next_index);
	  next_runtime = vlib_node_get_runtime (vm, next_node->index);

	  vec_add2 (nm->pending_frames, p, 1);

	  p->frame_index = nf->frame_index;
	  p->node_runtime_index = nf->node_runtime_index;
	  p->next_frame_index = nf - nm->next_frames;
	  nf->flags |= VLIB_FRAME_PENDING;
	  f->frame_flags |= VLIB_FRAME_PENDING;

	  /*
	   * If we're going to dispatch this frame on another thread,
	   * force allocation of a new frame. Otherwise, we create
	   * a dangling frame reference. Each thread has its own copy of
	   * the next_frames vector.
	   */
	  if (0 && r->thread_index != next_runtime->thread_index)
	    {
	      nf->frame_index = ~0;
	      nf->flags &= ~(VLIB_FRAME_PENDING | VLIB_FRAME_IS_ALLOCATED);
	    }
	}

      /* Copy trace flag from next_frame and from runtime. */
      nf->flags |=
	(nf->flags & VLIB_NODE_FLAG_TRACE) | (r->
					      flags & VLIB_NODE_FLAG_TRACE);

      v0 = nf->vectors_since_last_overflow;
      v1 = v0 + n_vectors_in_frame;
      nf->vectors_since_last_overflow = v1;
      if (PREDICT_FALSE (v1 < v0))
	{
	  vlib_node_t *node = vlib_get_node (vm, r->node_index);
	  vec_elt (node->n_vectors_by_next_node, next_index) += v0;
	}
    }
}

/* Sync up runtime (32 bit counters) and main node stats (64 bit counters). */
never_inline void
vlib_node_runtime_sync_stats (vlib_main_t * vm,
			      vlib_node_runtime_t * r,
			      uword n_calls, uword n_vectors, uword n_clocks,
			      uword n_ticks)
{
  vlib_node_t *n = vlib_get_node (vm, r->node_index);

  n->stats_total.calls += n_calls + r->calls_since_last_overflow;
  n->stats_total.vectors += n_vectors + r->vectors_since_last_overflow;
  n->stats_total.clocks += n_clocks + r->clocks_since_last_overflow;
  n->stats_total.perf_counter_ticks += n_ticks +
    r->perf_counter_ticks_since_last_overflow;
  n->stats_total.perf_counter_vectors += n_vectors +
    r->perf_counter_vectors_since_last_overflow;
  n->stats_total.max_clock = r->max_clock;
  n->stats_total.max_clock_n = r->max_clock_n;

  r->calls_since_last_overflow = 0;
  r->vectors_since_last_overflow = 0;
  r->clocks_since_last_overflow = 0;
  r->perf_counter_ticks_since_last_overflow = 0ULL;
  r->perf_counter_vectors_since_last_overflow = 0ULL;
}

always_inline void __attribute__ ((unused))
vlib_process_sync_stats (vlib_main_t * vm,
			 vlib_process_t * p,
			 uword n_calls, uword n_vectors, uword n_clocks,
			 uword n_ticks)
{
  vlib_node_runtime_t *rt = &p->node_runtime;
  vlib_node_t *n = vlib_get_node (vm, rt->node_index);
  vlib_node_runtime_sync_stats (vm, rt, n_calls, n_vectors, n_clocks,
				n_ticks);
  n->stats_total.suspends += p->n_suspends;
  p->n_suspends = 0;
}

void
vlib_node_sync_stats (vlib_main_t * vm, vlib_node_t * n)
{
  vlib_node_runtime_t *rt;

  if (n->type == VLIB_NODE_TYPE_PROCESS)
    {
      /* Nothing to do for PROCESS nodes except in main thread */
      if (vm != &vlib_global_main)
	return;

      vlib_process_t *p = vlib_get_process_from_node (vm, n);
      n->stats_total.suspends += p->n_suspends;
      p->n_suspends = 0;
      rt = &p->node_runtime;
    }
  else
    rt =
      vec_elt_at_index (vm->node_main.nodes_by_type[n->type],
			n->runtime_index);

  vlib_node_runtime_sync_stats (vm, rt, 0, 0, 0, 0);

  /* Sync up runtime next frame vector counters with main node structure. */
  {
    vlib_next_frame_t *nf;
    uword i;
    for (i = 0; i < rt->n_next_nodes; i++)
      {
	nf = vlib_node_runtime_get_next_frame (vm, rt, i);
	vec_elt (n->n_vectors_by_next_node, i) +=
	  nf->vectors_since_last_overflow;
	nf->vectors_since_last_overflow = 0;
      }
  }
}

always_inline u32
vlib_node_runtime_update_stats (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				uword n_calls,
				uword n_vectors, uword n_clocks,
				uword n_ticks)
{
  u32 ca0, ca1, v0, v1, cl0, cl1, r;
  u32 ptick0, ptick1, pvec0, pvec1;

  cl0 = cl1 = node->clocks_since_last_overflow;
  ca0 = ca1 = node->calls_since_last_overflow;
  v0 = v1 = node->vectors_since_last_overflow;
  ptick0 = ptick1 = node->perf_counter_ticks_since_last_overflow;
  pvec0 = pvec1 = node->perf_counter_vectors_since_last_overflow;

  ca1 = ca0 + n_calls;
  v1 = v0 + n_vectors;
  cl1 = cl0 + n_clocks;
  ptick1 = ptick0 + n_ticks;
  pvec1 = pvec0 + n_vectors;

  node->calls_since_last_overflow = ca1;
  node->clocks_since_last_overflow = cl1;
  node->vectors_since_last_overflow = v1;
  node->perf_counter_ticks_since_last_overflow = ptick1;
  node->perf_counter_vectors_since_last_overflow = pvec1;

  node->max_clock_n = node->max_clock > n_clocks ?
    node->max_clock_n : n_vectors;
  node->max_clock = node->max_clock > n_clocks ? node->max_clock : n_clocks;

  r = vlib_node_runtime_update_main_loop_vector_stats (vm, node, n_vectors);

  if (PREDICT_FALSE (ca1 < ca0 || v1 < v0 || cl1 < cl0) || (ptick1 < ptick0)
      || (pvec1 < pvec0))
    {
      node->calls_since_last_overflow = ca0;
      node->clocks_since_last_overflow = cl0;
      node->vectors_since_last_overflow = v0;
      node->perf_counter_ticks_since_last_overflow = ptick0;
      node->perf_counter_vectors_since_last_overflow = pvec0;

      vlib_node_runtime_sync_stats (vm, node, n_calls, n_vectors, n_clocks,
				    n_ticks);
    }

  return r;
}

static inline u64
vlib_node_runtime_perf_counter (vlib_main_t * vm)
{
  if (PREDICT_FALSE (vm->vlib_node_runtime_perf_counter_cb != 0))
    return ((*vm->vlib_node_runtime_perf_counter_cb) (vm));
  return 0ULL;
}

always_inline void
vlib_process_update_stats (vlib_main_t * vm,
			   vlib_process_t * p,
			   uword n_calls, uword n_vectors, uword n_clocks,
			   uword n_ticks)
{
  vlib_node_runtime_update_stats (vm, &p->node_runtime,
				  n_calls, n_vectors, n_clocks, n_ticks);
}

static clib_error_t *
vlib_cli_elog_clear (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  elog_reset_buffer (&vm->elog_main);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_clear_cli, static) = {
  .path = "event-logger clear",
  .short_help = "Clear the event log",
  .function = vlib_cli_elog_clear,
};
/* *INDENT-ON* */

#ifdef CLIB_UNIX
static clib_error_t *
elog_save_buffer (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  elog_main_t *em = &vm->elog_main;
  char *file, *chroot_file;
  clib_error_t *error = 0;

  if (!unformat (input, "%s", &file))
    {
      vlib_cli_output (vm, "expected file name, got `%U'",
		       format_unformat_error, input);
      return 0;
    }

  /* It's fairly hard to get "../oopsie" through unformat; just in case */
  if (strstr (file, "..") || index (file, '/'))
    {
      vlib_cli_output (vm, "illegal characters in filename '%s'", file);
      return 0;
    }

  chroot_file = (char *) format (0, "/tmp/%s%c", file, 0);

  vec_free (file);

  vlib_cli_output (vm, "Saving %wd of %wd events to %s",
		   elog_n_events_in_buffer (em),
		   elog_buffer_capacity (em), chroot_file);

  vlib_worker_thread_barrier_sync (vm);
  error = elog_write_file (em, chroot_file, 1 /* flush ring */ );
  vlib_worker_thread_barrier_release (vm);
  vec_free (chroot_file);
  return error;
}

void
elog_post_mortem_dump (void)
{
  vlib_main_t *vm = &vlib_global_main;
  elog_main_t *em = &vm->elog_main;
  u8 *filename;
  clib_error_t *error;

  if (!vm->elog_post_mortem_dump)
    return;

  filename = format (0, "/tmp/elog_post_mortem.%d%c", getpid (), 0);
  error = elog_write_file (em, (char *) filename, 1 /* flush ring */ );
  if (error)
    clib_error_report (error);
  vec_free (filename);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_save_cli, static) = {
  .path = "event-logger save",
  .short_help = "event-logger save <filename> (saves log in /tmp/<filename>)",
  .function = elog_save_buffer,
};
/* *INDENT-ON* */

static clib_error_t *
elog_stop (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  elog_main_t *em = &vm->elog_main;

  em->n_total_events_disable_limit = em->n_total_events;

  vlib_cli_output (vm, "Stopped the event logger...");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_stop_cli, static) = {
  .path = "event-logger stop",
  .short_help = "Stop the event-logger",
  .function = elog_stop,
};
/* *INDENT-ON* */

static clib_error_t *
elog_restart (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  elog_main_t *em = &vm->elog_main;

  em->n_total_events_disable_limit = ~0;

  vlib_cli_output (vm, "Restarted the event logger...");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_restart_cli, static) = {
  .path = "event-logger restart",
  .short_help = "Restart the event-logger",
  .function = elog_restart,
};
/* *INDENT-ON* */

static clib_error_t *
elog_resize (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  elog_main_t *em = &vm->elog_main;
  u32 tmp;

  /* Stop the parade */
  elog_reset_buffer (&vm->elog_main);

  if (unformat (input, "%d", &tmp))
    {
      elog_alloc (em, tmp);
      em->n_total_events_disable_limit = ~0;
    }
  else
    return clib_error_return (0, "Must specify how many events in the ring");

  vlib_cli_output (vm, "Resized ring and restarted the event logger...");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_resize_cli, static) = {
  .path = "event-logger resize",
  .short_help = "event-logger resize <nnn>",
  .function = elog_resize,
};
/* *INDENT-ON* */

#endif /* CLIB_UNIX */

static void
elog_show_buffer_internal (vlib_main_t * vm, u32 n_events_to_show)
{
  elog_main_t *em = &vm->elog_main;
  elog_event_t *e, *es;
  f64 dt;

  /* Show events in VLIB time since log clock starts after VLIB clock. */
  dt = (em->init_time.cpu - vm->clib_time.init_cpu_time)
    * vm->clib_time.seconds_per_clock;

  es = elog_peek_events (em);
  vlib_cli_output (vm, "%d of %d events in buffer, logger %s", vec_len (es),
		   em->event_ring_size,
		   em->n_total_events < em->n_total_events_disable_limit ?
		   "running" : "stopped");
  vec_foreach (e, es)
  {
    vlib_cli_output (vm, "%18.9f: %U",
		     e->time + dt, format_elog_event, em, e);
    n_events_to_show--;
    if (n_events_to_show == 0)
      break;
  }
  vec_free (es);

}

static clib_error_t *
elog_show_buffer (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 n_events_to_show;
  clib_error_t *error = 0;

  n_events_to_show = 250;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &n_events_to_show))
	;
      else if (unformat (input, "all"))
	n_events_to_show = ~0;
      else
	return unformat_parse_error (input);
    }
  elog_show_buffer_internal (vm, n_events_to_show);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_show_cli, static) = {
  .path = "show event-logger",
  .short_help = "Show event logger info",
  .function = elog_show_buffer,
};
/* *INDENT-ON* */

void
vlib_gdb_show_event_log (void)
{
  elog_show_buffer_internal (vlib_get_main (), (u32) ~ 0);
}

static inline void
vlib_elog_main_loop_event (vlib_main_t * vm,
			   u32 node_index,
			   u64 time, u32 n_vectors, u32 is_return)
{
  vlib_main_t *evm = &vlib_global_main;
  elog_main_t *em = &evm->elog_main;

  if (VLIB_ELOG_MAIN_LOOP && n_vectors)
    elog_track (em,
		/* event type */
		vec_elt_at_index (is_return
				  ? evm->node_return_elog_event_types
				  : evm->node_call_elog_event_types,
				  node_index),
		/* track */
		(vm->thread_index ? &vlib_worker_threads[vm->thread_index].
		 elog_track : &em->default_track),
		/* data to log */ n_vectors);
}

#if VLIB_BUFFER_TRACE_TRAJECTORY > 0
void (*vlib_buffer_trace_trajectory_cb) (vlib_buffer_t * b, u32 node_index);
void (*vlib_buffer_trace_trajectory_init_cb) (vlib_buffer_t * b);

void
vlib_buffer_trace_trajectory_init (vlib_buffer_t * b)
{
  if (PREDICT_TRUE (vlib_buffer_trace_trajectory_init_cb != 0))
    {
      (*vlib_buffer_trace_trajectory_init_cb) (b);
    }
}

#endif

static inline void
add_trajectory_trace (vlib_buffer_t * b, u32 node_index)
{
#if VLIB_BUFFER_TRACE_TRAJECTORY > 0
  if (PREDICT_TRUE (vlib_buffer_trace_trajectory_cb != 0))
    {
      (*vlib_buffer_trace_trajectory_cb) (b, node_index);
    }
#endif
}

u8 *format_vnet_buffer_flags (u8 * s, va_list * args) __attribute__ ((weak));
u8 *
format_vnet_buffer_flags (u8 * s, va_list * args)
{
  s = format (s, "BUG STUB %s", __FUNCTION__);
  return s;
}

u8 *format_vnet_buffer_opaque (u8 * s, va_list * args) __attribute__ ((weak));
u8 *
format_vnet_buffer_opaque (u8 * s, va_list * args)
{
  s = format (s, "BUG STUB %s", __FUNCTION__);
  return s;
}

u8 *format_vnet_buffer_opaque2 (u8 * s, va_list * args)
  __attribute__ ((weak));
u8 *
format_vnet_buffer_opaque2 (u8 * s, va_list * args)
{
  s = format (s, "BUG STUB %s", __FUNCTION__);
  return s;
}

static u8 *
format_buffer_metadata (u8 * s, va_list * args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);

  s = format (s, "flags: %U\n", format_vnet_buffer_flags, b);
  s = format (s, "current_data: %d, current_length: %d\n",
	      (i32) (b->current_data), (i32) (b->current_length));
  s = format (s, "current_config_index: %d, flow_id: %x, next_buffer: %x\n",
	      b->current_config_index, b->flow_id, b->next_buffer);
  s = format (s, "error: %d, n_add_refs: %d, buffer_pool_index: %d\n",
	      (u32) (b->error), (u32) (b->n_add_refs),
	      (u32) (b->buffer_pool_index));
  s = format (s,
	      "trace_index: %d, recycle_count: %d, len_not_first_buf: %d\n",
	      b->trace_index, b->recycle_count,
	      b->total_length_not_including_first_buffer);
  return s;
}

#define A(x) vec_add1(vm->pcap_buffer, (x))

static void
dispatch_pcap_trace (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  int i;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **bufp, *b;
  pcap_main_t *pm = &vm->dispatch_pcap_main;
  vlib_trace_main_t *tm = &vm->trace_main;
  u32 capture_size;
  vlib_node_t *n;
  i32 n_left;
  f64 time_now = vlib_time_now (vm);
  u32 *from;
  u8 *d;
  u8 string_count;

  /* Input nodes don't have frames yet */
  if (frame == 0 || frame->n_vectors == 0)
    return;

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  bufp = bufs;

  n = vlib_get_node (vm, node->node_index);

  for (i = 0; i < frame->n_vectors; i++)
    {
      if (PREDICT_TRUE (pm->n_packets_captured < pm->n_packets_to_capture))
	{
	  b = bufp[i];

	  vec_reset_length (vm->pcap_buffer);
	  string_count = 0;

	  /* Version, flags */
	  A ((u8) VLIB_PCAP_MAJOR_VERSION);
	  A ((u8) VLIB_PCAP_MINOR_VERSION);
	  A (0 /* string_count */ );
	  A (n->protocol_hint);

	  /* Buffer index (big endian) */
	  A ((from[i] >> 24) & 0xff);
	  A ((from[i] >> 16) & 0xff);
	  A ((from[i] >> 8) & 0xff);
	  A ((from[i] >> 0) & 0xff);

	  /* Node name, NULL-terminated ASCII */
	  vm->pcap_buffer = format (vm->pcap_buffer, "%v%c", n->name, 0);
	  string_count++;

	  vm->pcap_buffer = format (vm->pcap_buffer, "%U%c",
				    format_buffer_metadata, b, 0);
	  string_count++;
	  vm->pcap_buffer = format (vm->pcap_buffer, "%U%c",
				    format_vnet_buffer_opaque, b, 0);
	  string_count++;
	  vm->pcap_buffer = format (vm->pcap_buffer, "%U%c",
				    format_vnet_buffer_opaque2, b, 0);
	  string_count++;

	  /* Is this packet traced? */
	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vlib_trace_header_t **h
		= pool_elt_at_index (tm->trace_buffer_pool, b->trace_index);

	      vm->pcap_buffer = format (vm->pcap_buffer, "%U%c",
					format_vlib_trace, vm, h[0], 0);
	      string_count++;
	    }

	  /* Save the string count */
	  vm->pcap_buffer[2] = string_count;

	  /* Figure out how many bytes in the pcap trace */
	  capture_size = vec_len (vm->pcap_buffer) +
	    +vlib_buffer_length_in_chain (vm, b);

	  clib_spinlock_lock_if_init (&pm->lock);
	  n_left = clib_min (capture_size, 16384);
	  d = pcap_add_packet (pm, time_now, n_left, capture_size);

	  /* Copy the header */
	  clib_memcpy_fast (d, vm->pcap_buffer, vec_len (vm->pcap_buffer));
	  d += vec_len (vm->pcap_buffer);

	  n_left = clib_min
	    (vlib_buffer_length_in_chain (vm, b),
	     (16384 - vec_len (vm->pcap_buffer)));
	  /* Copy the packet data */
	  while (1)
	    {
	      u32 copy_length = clib_min ((u32) n_left, b->current_length);
	      clib_memcpy_fast (d, b->data + b->current_data, copy_length);
	      n_left -= b->current_length;
	      if (n_left <= 0)
		break;
	      d += b->current_length;
	      ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	      b = vlib_get_buffer (vm, b->next_buffer);
	    }
	  clib_spinlock_unlock_if_init (&pm->lock);
	}
    }
}

static_always_inline u64
dispatch_node (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       vlib_node_type_t type,
	       vlib_node_state_t dispatch_state,
	       vlib_frame_t * frame, u64 last_time_stamp)
{
  uword n, v;
  u64 t;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_next_frame_t *nf;

  if (CLIB_DEBUG > 0)
    {
      vlib_node_t *n = vlib_get_node (vm, node->node_index);
      ASSERT (n->type == type);
    }

  /* Only non-internal nodes may be disabled. */
  if (type != VLIB_NODE_TYPE_INTERNAL && node->state != dispatch_state)
    {
      ASSERT (type != VLIB_NODE_TYPE_INTERNAL);
      return last_time_stamp;
    }

  if ((type == VLIB_NODE_TYPE_PRE_INPUT || type == VLIB_NODE_TYPE_INPUT)
      && dispatch_state != VLIB_NODE_STATE_INTERRUPT)
    {
      u32 c = node->input_main_loops_per_call;
      /* Only call node when count reaches zero. */
      if (c)
	{
	  node->input_main_loops_per_call = c - 1;
	  return last_time_stamp;
	}
    }

  /* Speculatively prefetch next frames. */
  if (node->n_next_nodes > 0)
    {
      nf = vec_elt_at_index (nm->next_frames, node->next_frame_index);
      CLIB_PREFETCH (nf, 4 * sizeof (nf[0]), WRITE);
    }

  vm->cpu_time_last_node_dispatch = last_time_stamp;

  if (1 /* || vm->thread_index == node->thread_index */ )
    {
      u64 pmc_before, pmc_delta;

      vlib_elog_main_loop_event (vm, node->node_index,
				 last_time_stamp,
				 frame ? frame->n_vectors : 0,
				 /* is_after */ 0);

      /*
       * To validate accounting: pmc_before = last_time_stamp
       * perf ticks should equal clocks/pkt...
       */
      pmc_before = vlib_node_runtime_perf_counter (vm);

      /*
       * Turn this on if you run into
       * "bad monkey" contexts, and you want to know exactly
       * which nodes they've visited... See ixge.c...
       */
      if (VLIB_BUFFER_TRACE_TRAJECTORY && frame)
	{
	  int i;
	  u32 *from;
	  from = vlib_frame_vector_args (frame);
	  for (i = 0; i < frame->n_vectors; i++)
	    {
	      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	      add_trajectory_trace (b, node->node_index);
	    }
	  if (PREDICT_FALSE (vm->dispatch_pcap_enable))
	    dispatch_pcap_trace (vm, node, frame);
	  n = node->function (vm, node, frame);
	}
      else
	{
	  if (PREDICT_FALSE (vm->dispatch_pcap_enable))
	    dispatch_pcap_trace (vm, node, frame);
	  n = node->function (vm, node, frame);
	}

      t = clib_cpu_time_now ();

      /*
       * To validate accounting: pmc_delta = t - pmc_before;
       * perf ticks should equal clocks/pkt...
       */
      pmc_delta = vlib_node_runtime_perf_counter (vm) - pmc_before;

      vlib_elog_main_loop_event (vm, node->node_index, t, n,	/* is_after */
				 1);

      vm->main_loop_vectors_processed += n;
      vm->main_loop_nodes_processed += n > 0;

      v = vlib_node_runtime_update_stats (vm, node,
					  /* n_calls */ 1,
					  /* n_vectors */ n,
					  /* n_clocks */ t - last_time_stamp,
					  pmc_delta /* PMC ticks */ );

      /* When in interrupt mode and vector rate crosses threshold switch to
         polling mode. */
      if ((dispatch_state == VLIB_NODE_STATE_INTERRUPT)
	  || (dispatch_state == VLIB_NODE_STATE_POLLING
	      && (node->flags
		  & VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE)))
	{
#ifdef DISPATCH_NODE_ELOG_REQUIRED
	  ELOG_TYPE_DECLARE (e) =
	  {
	    .function = (char *) __FUNCTION__,.format =
	      "%s vector length %d, switching to %s",.format_args =
	      "T4i4t4",.n_enum_strings = 2,.enum_strings =
	    {
	  "interrupt", "polling",},};
	  struct
	  {
	    u32 node_name, vector_length, is_polling;
	  } *ed;
	  vlib_worker_thread_t *w = vlib_worker_threads + vm->thread_index;
#endif

	  if ((dispatch_state == VLIB_NODE_STATE_INTERRUPT
	       && v >= nm->polling_threshold_vector_length) &&
	      !(node->flags &
		VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE))
	    {
	      vlib_node_t *n = vlib_get_node (vm, node->node_index);
	      n->state = VLIB_NODE_STATE_POLLING;
	      node->state = VLIB_NODE_STATE_POLLING;
	      node->flags &=
		~VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE;
	      node->flags |=
		VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE;
	      nm->input_node_counts_by_state[VLIB_NODE_STATE_INTERRUPT] -= 1;
	      nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] += 1;

#ifdef DISPATCH_NODE_ELOG_REQUIRED
	      ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e,
				    w->elog_track);
	      ed->node_name = n->name_elog_string;
	      ed->vector_length = v;
	      ed->is_polling = 1;
#endif
	    }
	  else if (dispatch_state == VLIB_NODE_STATE_POLLING
		   && v <= nm->interrupt_threshold_vector_length)
	    {
	      vlib_node_t *n = vlib_get_node (vm, node->node_index);
	      if (node->flags &
		  VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE)
		{
		  /* Switch to interrupt mode after dispatch in polling one more time.
		     This allows driver to re-enable interrupts. */
		  n->state = VLIB_NODE_STATE_INTERRUPT;
		  node->state = VLIB_NODE_STATE_INTERRUPT;
		  node->flags &=
		    ~VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE;
		  nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] -=
		    1;
		  nm->input_node_counts_by_state[VLIB_NODE_STATE_INTERRUPT] +=
		    1;

		}
	      else
		{
		  node->flags |=
		    VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE;
#ifdef DISPATCH_NODE_ELOG_REQUIRED
		  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e,
					w->elog_track);
		  ed->node_name = n->name_elog_string;
		  ed->vector_length = v;
		  ed->is_polling = 0;
#endif
		}
	    }
	}
    }

  return t;
}

static u64
dispatch_pending_node (vlib_main_t * vm, uword pending_frame_index,
		       u64 last_time_stamp)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_frame_t *f;
  vlib_next_frame_t *nf, nf_dummy;
  vlib_node_runtime_t *n;
  u32 restore_frame_index;
  vlib_pending_frame_t *p;

  /* See comment below about dangling references to nm->pending_frames */
  p = nm->pending_frames + pending_frame_index;

  n = vec_elt_at_index (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL],
			p->node_runtime_index);

  f = vlib_get_frame (vm, p->frame_index);
  if (p->next_frame_index == VLIB_PENDING_FRAME_NO_NEXT_FRAME)
    {
      /* No next frame: so use dummy on stack. */
      nf = &nf_dummy;
      nf->flags = f->frame_flags & VLIB_NODE_FLAG_TRACE;
      nf->frame_index = ~p->frame_index;
    }
  else
    nf = vec_elt_at_index (nm->next_frames, p->next_frame_index);

  ASSERT (f->frame_flags & VLIB_FRAME_IS_ALLOCATED);

  /* Force allocation of new frame while current frame is being
     dispatched. */
  restore_frame_index = ~0;
  if (nf->frame_index == p->frame_index)
    {
      nf->frame_index = ~0;
      nf->flags &= ~VLIB_FRAME_IS_ALLOCATED;
      if (!(n->flags & VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH))
	restore_frame_index = p->frame_index;
    }

  /* Frame must be pending. */
  ASSERT (f->frame_flags & VLIB_FRAME_PENDING);
  ASSERT (f->n_vectors > 0);

  /* Copy trace flag from next frame to node.
     Trace flag indicates that at least one vector in the dispatched
     frame is traced. */
  n->flags &= ~VLIB_NODE_FLAG_TRACE;
  n->flags |= (nf->flags & VLIB_FRAME_TRACE) ? VLIB_NODE_FLAG_TRACE : 0;
  nf->flags &= ~VLIB_FRAME_TRACE;

  last_time_stamp = dispatch_node (vm, n,
				   VLIB_NODE_TYPE_INTERNAL,
				   VLIB_NODE_STATE_POLLING,
				   f, last_time_stamp);

  f->frame_flags &= ~VLIB_FRAME_PENDING;

  /* Frame is ready to be used again, so restore it. */
  if (restore_frame_index != ~0)
    {
      /*
       * We musn't restore a frame that is flagged to be freed. This
       * shouldn't happen since frames to be freed post dispatch are
       * those used when the to-node frame becomes full i.e. they form a
       * sort of queue of frames to a single node. If we get here then
       * the to-node frame and the pending frame *were* the same, and so
       * we removed the to-node frame.  Therefore this frame is no
       * longer part of the queue for that node and hence it cannot be
       * it's overspill.
       */
      ASSERT (!(f->frame_flags & VLIB_FRAME_FREE_AFTER_DISPATCH));

      /*
       * NB: dispatching node n can result in the creation and scheduling
       * of new frames, and hence in the reallocation of nm->pending_frames.
       * Recompute p, or no supper. This was broken for more than 10 years.
       */
      p = nm->pending_frames + pending_frame_index;

      /*
       * p->next_frame_index can change during node dispatch if node
       * function decides to change graph hook up.
       */
      nf = vec_elt_at_index (nm->next_frames, p->next_frame_index);
      nf->flags |= VLIB_FRAME_IS_ALLOCATED;

      if (~0 == nf->frame_index)
	{
	  /* no new frame has been assigned to this node, use the saved one */
	  nf->frame_index = restore_frame_index;
	  f->n_vectors = 0;
	}
      else
	{
	  /* The node has gained a frame, implying packets from the current frame
	     were re-queued to this same node. we don't need the saved one
	     anymore */
	  vlib_frame_free (vm, n, f);
	}
    }
  else
    {
      if (f->frame_flags & VLIB_FRAME_FREE_AFTER_DISPATCH)
	{
	  ASSERT (!(n->flags & VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH));
	  vlib_frame_free (vm, n, f);
	}
    }

  return last_time_stamp;
}

always_inline uword
vlib_process_stack_is_valid (vlib_process_t * p)
{
  return p->stack[0] == VLIB_PROCESS_STACK_MAGIC;
}

typedef struct
{
  vlib_main_t *vm;
  vlib_process_t *process;
  vlib_frame_t *frame;
} vlib_process_bootstrap_args_t;

/* Called in process stack. */
static uword
vlib_process_bootstrap (uword _a)
{
  vlib_process_bootstrap_args_t *a;
  vlib_main_t *vm;
  vlib_node_runtime_t *node;
  vlib_frame_t *f;
  vlib_process_t *p;
  uword n;

  a = uword_to_pointer (_a, vlib_process_bootstrap_args_t *);

  vm = a->vm;
  p = a->process;
  f = a->frame;
  node = &p->node_runtime;

  n = node->function (vm, node, f);

  ASSERT (vlib_process_stack_is_valid (p));

  clib_longjmp (&p->return_longjmp, n);

  return n;
}

/* Called in main stack. */
static_always_inline uword
vlib_process_startup (vlib_main_t * vm, vlib_process_t * p, vlib_frame_t * f)
{
  vlib_process_bootstrap_args_t a;
  uword r;

  a.vm = vm;
  a.process = p;
  a.frame = f;

  r = clib_setjmp (&p->return_longjmp, VLIB_PROCESS_RETURN_LONGJMP_RETURN);
  if (r == VLIB_PROCESS_RETURN_LONGJMP_RETURN)
    r = clib_calljmp (vlib_process_bootstrap, pointer_to_uword (&a),
		      (void *) p->stack + (1 << p->log2_n_stack_bytes));

  return r;
}

static_always_inline uword
vlib_process_resume (vlib_process_t * p)
{
  uword r;
  p->flags &= ~(VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK
		| VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT
		| VLIB_PROCESS_RESUME_PENDING);
  r = clib_setjmp (&p->return_longjmp, VLIB_PROCESS_RETURN_LONGJMP_RETURN);
  if (r == VLIB_PROCESS_RETURN_LONGJMP_RETURN)
    clib_longjmp (&p->resume_longjmp, VLIB_PROCESS_RESUME_LONGJMP_RESUME);
  return r;
}

static u64
dispatch_process (vlib_main_t * vm,
		  vlib_process_t * p, vlib_frame_t * f, u64 last_time_stamp)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_runtime_t *node_runtime = &p->node_runtime;
  vlib_node_t *node = vlib_get_node (vm, node_runtime->node_index);
  u32 old_process_index;
  u64 t;
  uword n_vectors, is_suspend;

  if (node->state != VLIB_NODE_STATE_POLLING
      || (p->flags & (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK
		      | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT)))
    return last_time_stamp;

  p->flags |= VLIB_PROCESS_IS_RUNNING;

  t = last_time_stamp;
  vlib_elog_main_loop_event (vm, node_runtime->node_index, t,
			     f ? f->n_vectors : 0, /* is_after */ 0);

  /* Save away current process for suspend. */
  old_process_index = nm->current_process_index;
  nm->current_process_index = node->runtime_index;

  n_vectors = vlib_process_startup (vm, p, f);

  nm->current_process_index = old_process_index;

  ASSERT (n_vectors != VLIB_PROCESS_RETURN_LONGJMP_RETURN);
  is_suspend = n_vectors == VLIB_PROCESS_RETURN_LONGJMP_SUSPEND;
  if (is_suspend)
    {
      vlib_pending_frame_t *pf;

      n_vectors = 0;
      pool_get (nm->suspended_process_frames, pf);
      pf->node_runtime_index = node->runtime_index;
      pf->frame_index = f ? vlib_frame_index (vm, f) : ~0;
      pf->next_frame_index = ~0;

      p->n_suspends += 1;
      p->suspended_process_frame_index = pf - nm->suspended_process_frames;

      if (p->flags & VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK)
	{
	  TWT (tw_timer_wheel) * tw =
	    (TWT (tw_timer_wheel) *) nm->timing_wheel;
	  p->stop_timer_handle =
	    TW (tw_timer_start) (tw,
				 vlib_timing_wheel_data_set_suspended_process
				 (node->runtime_index) /* [sic] pool idex */ ,
				 0 /* timer_id */ ,
				 p->resume_clock_interval);
	}
    }
  else
    p->flags &= ~VLIB_PROCESS_IS_RUNNING;

  t = clib_cpu_time_now ();

  vlib_elog_main_loop_event (vm, node_runtime->node_index, t, is_suspend,
			     /* is_after */ 1);

  vlib_process_update_stats (vm, p,
			     /* n_calls */ !is_suspend,
			     /* n_vectors */ n_vectors,
			     /* n_clocks */ t - last_time_stamp,
			     /* pmc_ticks */ 0ULL);

  return t;
}

void
vlib_start_process (vlib_main_t * vm, uword process_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p = vec_elt (nm->processes, process_index);
  dispatch_process (vm, p, /* frame */ 0, /* cpu_time_now */ 0);
}

static u64
dispatch_suspended_process (vlib_main_t * vm,
			    uword process_index, u64 last_time_stamp)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_runtime_t *node_runtime;
  vlib_node_t *node;
  vlib_frame_t *f;
  vlib_process_t *p;
  vlib_pending_frame_t *pf;
  u64 t, n_vectors, is_suspend;

  t = last_time_stamp;

  p = vec_elt (nm->processes, process_index);
  if (PREDICT_FALSE (!(p->flags & VLIB_PROCESS_IS_RUNNING)))
    return last_time_stamp;

  ASSERT (p->flags & (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK
		      | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT));

  pf = pool_elt_at_index (nm->suspended_process_frames,
			  p->suspended_process_frame_index);

  node_runtime = &p->node_runtime;
  node = vlib_get_node (vm, node_runtime->node_index);
  f = pf->frame_index != ~0 ? vlib_get_frame (vm, pf->frame_index) : 0;

  vlib_elog_main_loop_event (vm, node_runtime->node_index, t,
			     f ? f->n_vectors : 0, /* is_after */ 0);

  /* Save away current process for suspend. */
  nm->current_process_index = node->runtime_index;

  n_vectors = vlib_process_resume (p);
  t = clib_cpu_time_now ();

  nm->current_process_index = ~0;

  is_suspend = n_vectors == VLIB_PROCESS_RETURN_LONGJMP_SUSPEND;
  if (is_suspend)
    {
      /* Suspend it again. */
      n_vectors = 0;
      p->n_suspends += 1;
      if (p->flags & VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK)
	{
	  p->stop_timer_handle =
	    TW (tw_timer_start) ((TWT (tw_timer_wheel) *) nm->timing_wheel,
				 vlib_timing_wheel_data_set_suspended_process
				 (node->runtime_index) /* [sic] pool idex */ ,
				 0 /* timer_id */ ,
				 p->resume_clock_interval);
	}
    }
  else
    {
      p->flags &= ~VLIB_PROCESS_IS_RUNNING;
      pool_put_index (nm->suspended_process_frames,
		      p->suspended_process_frame_index);
      p->suspended_process_frame_index = ~0;
    }

  t = clib_cpu_time_now ();
  vlib_elog_main_loop_event (vm, node_runtime->node_index, t, !is_suspend,
			     /* is_after */ 1);

  vlib_process_update_stats (vm, p,
			     /* n_calls */ !is_suspend,
			     /* n_vectors */ n_vectors,
			     /* n_clocks */ t - last_time_stamp,
			     /* pmc_ticks */ 0ULL);

  return t;
}

void vl_api_send_pending_rpc_requests (vlib_main_t *) __attribute__ ((weak));
void
vl_api_send_pending_rpc_requests (vlib_main_t * vm)
{
}


static_always_inline void
vlib_main_or_worker_loop (vlib_main_t * vm, int is_main)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword i;
  u64 cpu_time_now;
  vlib_frame_queue_main_t *fqm;
  u32 *last_node_runtime_indices = 0;

  /* Initialize pending node vector. */
  if (is_main)
    {
      vec_resize (nm->pending_frames, 32);
      _vec_len (nm->pending_frames) = 0;
    }

  /* Mark time of main loop start. */
  if (is_main)
    {
      cpu_time_now = vm->clib_time.last_cpu_time;
      vm->cpu_time_main_loop_start = cpu_time_now;
    }
  else
    cpu_time_now = clib_cpu_time_now ();

  /* Pre-allocate interupt runtime indices and lock. */
  vec_alloc (nm->pending_interrupt_node_runtime_indices, 32);
  vec_alloc (last_node_runtime_indices, 32);
  if (!is_main)
    clib_spinlock_init (&nm->pending_interrupt_lock);

  /* Pre-allocate expired nodes. */
  if (!nm->polling_threshold_vector_length)
    nm->polling_threshold_vector_length = 10;
  if (!nm->interrupt_threshold_vector_length)
    nm->interrupt_threshold_vector_length = 5;

  /* Make sure the performance monitor counter is disabled */
  vm->perf_counter_id = ~0;

  /* Start all processes. */
  if (is_main)
    {
      uword i;
      nm->current_process_index = ~0;
      for (i = 0; i < vec_len (nm->processes); i++)
	cpu_time_now = dispatch_process (vm, nm->processes[i], /* frame */ 0,
					 cpu_time_now);
    }

  while (1)
    {
      vlib_node_runtime_t *n;

      if (PREDICT_FALSE (_vec_len (vm->pending_rpc_requests) > 0))
	{
	  if (!is_main)
	    vl_api_send_pending_rpc_requests (vm);
	}

      if (!is_main)
	{
	  vlib_worker_thread_barrier_check ();
	  vec_foreach (fqm, tm->frame_queue_mains)
	    vlib_frame_queue_dequeue (vm, fqm);
	  if (PREDICT_FALSE (vm->worker_thread_main_loop_callback != 0))
	    ((void (*)(vlib_main_t *)) vm->worker_thread_main_loop_callback)
	      (vm);
	}

      /* Process pre-input nodes. */
      vec_foreach (n, nm->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT])
	cpu_time_now = dispatch_node (vm, n,
				      VLIB_NODE_TYPE_PRE_INPUT,
				      VLIB_NODE_STATE_POLLING,
				      /* frame */ 0,
				      cpu_time_now);

      /* Next process input nodes. */
      vec_foreach (n, nm->nodes_by_type[VLIB_NODE_TYPE_INPUT])
	cpu_time_now = dispatch_node (vm, n,
				      VLIB_NODE_TYPE_INPUT,
				      VLIB_NODE_STATE_POLLING,
				      /* frame */ 0,
				      cpu_time_now);

      if (PREDICT_TRUE (is_main && vm->queue_signal_pending == 0))
	vm->queue_signal_callback (vm);

      /* Next handle interrupts. */
      {
	/* unlocked read, for performance */
	uword l = _vec_len (nm->pending_interrupt_node_runtime_indices);
	uword i;
	if (PREDICT_FALSE (l > 0))
	  {
	    u32 *tmp;
	    if (!is_main)
	      {
		clib_spinlock_lock (&nm->pending_interrupt_lock);
		/* Re-read w/ lock held, in case another thread added an item */
		l = _vec_len (nm->pending_interrupt_node_runtime_indices);
	      }

	    tmp = nm->pending_interrupt_node_runtime_indices;
	    nm->pending_interrupt_node_runtime_indices =
	      last_node_runtime_indices;
	    last_node_runtime_indices = tmp;
	    _vec_len (last_node_runtime_indices) = 0;
	    if (!is_main)
	      clib_spinlock_unlock (&nm->pending_interrupt_lock);
	    for (i = 0; i < l; i++)
	      {
		n = vec_elt_at_index (nm->nodes_by_type[VLIB_NODE_TYPE_INPUT],
				      last_node_runtime_indices[i]);
		cpu_time_now =
		  dispatch_node (vm, n, VLIB_NODE_TYPE_INPUT,
				 VLIB_NODE_STATE_INTERRUPT,
				 /* frame */ 0,
				 cpu_time_now);
	      }
	  }
      }
      /* Input nodes may have added work to the pending vector.
         Process pending vector until there is nothing left.
         All pending vectors will be processed from input -> output. */
      for (i = 0; i < _vec_len (nm->pending_frames); i++)
	cpu_time_now = dispatch_pending_node (vm, i, cpu_time_now);
      /* Reset pending vector for next iteration. */
      _vec_len (nm->pending_frames) = 0;

      if (is_main)
	{
	  /* Check if process nodes have expired from timing wheel. */
	  ASSERT (nm->data_from_advancing_timing_wheel != 0);

	  nm->data_from_advancing_timing_wheel =
	    TW (tw_timer_expire_timers_vec)
	    ((TWT (tw_timer_wheel) *) nm->timing_wheel, vlib_time_now (vm),
	     nm->data_from_advancing_timing_wheel);

	  ASSERT (nm->data_from_advancing_timing_wheel != 0);

	  if (PREDICT_FALSE
	      (_vec_len (nm->data_from_advancing_timing_wheel) > 0))
	    {
	      uword i;

	      for (i = 0; i < _vec_len (nm->data_from_advancing_timing_wheel);
		   i++)
		{
		  u32 d = nm->data_from_advancing_timing_wheel[i];
		  u32 di = vlib_timing_wheel_data_get_index (d);

		  if (vlib_timing_wheel_data_is_timed_event (d))
		    {
		      vlib_signal_timed_event_data_t *te =
			pool_elt_at_index (nm->signal_timed_event_data_pool,
					   di);
		      vlib_node_t *n =
			vlib_get_node (vm, te->process_node_index);
		      vlib_process_t *p =
			vec_elt (nm->processes, n->runtime_index);
		      void *data;
		      data =
			vlib_process_signal_event_helper (nm, n, p,
							  te->event_type_index,
							  te->n_data_elts,
							  te->n_data_elt_bytes);
		      if (te->n_data_bytes < sizeof (te->inline_event_data))
			clib_memcpy_fast (data, te->inline_event_data,
					  te->n_data_bytes);
		      else
			{
			  clib_memcpy_fast (data, te->event_data_as_vector,
					    te->n_data_bytes);
			  vec_free (te->event_data_as_vector);
			}
		      pool_put (nm->signal_timed_event_data_pool, te);
		    }
		  else
		    {
		      cpu_time_now = clib_cpu_time_now ();
		      cpu_time_now =
			dispatch_suspended_process (vm, di, cpu_time_now);
		    }
		}
	      _vec_len (nm->data_from_advancing_timing_wheel) = 0;
	    }
	}
      vlib_increment_main_loop_counter (vm);

      /* Record time stamp in case there are no enabled nodes and above
         calls do not update time stamp. */
      cpu_time_now = clib_cpu_time_now ();
    }
}

static void
vlib_main_loop (vlib_main_t * vm)
{
  vlib_main_or_worker_loop (vm, /* is_main */ 1);
}

void
vlib_worker_loop (vlib_main_t * vm)
{
  vlib_main_or_worker_loop (vm, /* is_main */ 0);
}

vlib_main_t vlib_global_main;

static clib_error_t *
vlib_main_configure (vlib_main_t * vm, unformat_input_t * input)
{
  int turn_on_mem_trace = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "memory-trace"))
	turn_on_mem_trace = 1;

      else if (unformat (input, "elog-events %d",
			 &vm->elog_main.event_ring_size))
	;
      else if (unformat (input, "elog-post-mortem-dump"))
	vm->elog_post_mortem_dump = 1;
      else
	return unformat_parse_error (input);
    }

  unformat_free (input);

  /* Enable memory trace as early as possible. */
  if (turn_on_mem_trace)
    clib_mem_trace (1);

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (vlib_main_configure, "vlib");

static void
dummy_queue_signal_callback (vlib_main_t * vm)
{
}

#define foreach_weak_reference_stub             \
_(vlib_map_stat_segment_init)                   \
_(vpe_api_init)                                 \
_(vlibmemory_init)                              \
_(map_api_segment_init)

#define _(name)                                                 \
clib_error_t *name (vlib_main_t *vm) __attribute__((weak));     \
clib_error_t *name (vlib_main_t *vm) { return 0; }
foreach_weak_reference_stub;
#undef _

/* Main function. */
int
vlib_main (vlib_main_t * volatile vm, unformat_input_t * input)
{
  clib_error_t *volatile error;
  vlib_node_main_t *nm = &vm->node_main;

  vm->queue_signal_callback = dummy_queue_signal_callback;

  clib_time_init (&vm->clib_time);

  /* Turn on event log. */
  if (!vm->elog_main.event_ring_size)
    vm->elog_main.event_ring_size = 128 << 10;
  elog_init (&vm->elog_main, vm->elog_main.event_ring_size);
  elog_enable_disable (&vm->elog_main, 1);

  /* Default name. */
  if (!vm->name)
    vm->name = "VLIB";

  if ((error = vlib_physmem_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  if ((error = vlib_buffer_main_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  if ((error = vlib_thread_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  if ((error = vlib_map_stat_segment_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  /* Register static nodes so that init functions may use them. */
  vlib_register_all_static_nodes (vm);

  /* Set seed for random number generator.
     Allow user to specify seed to make random sequence deterministic. */
  if (!unformat (input, "seed %wd", &vm->random_seed))
    vm->random_seed = clib_cpu_time_now ();
  clib_random_buffer_init (&vm->random_buffer, vm->random_seed);

  /* Initialize node graph. */
  if ((error = vlib_node_main_init (vm)))
    {
      /* Arrange for graph hook up error to not be fatal when debugging. */
      if (CLIB_DEBUG > 0)
	clib_error_report (error);
      else
	goto done;
    }

  /* Direct call / weak reference, for vlib standalone use-cases */
  if ((error = vpe_api_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  if ((error = vlibmemory_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  if ((error = map_api_segment_init (vm)))
    {
      clib_error_report (error);
      goto done;
    }

  /* See unix/main.c; most likely already set up */
  if (vm->init_functions_called == 0)
    vm->init_functions_called = hash_create (0, /* value bytes */ 0);
  if ((error = vlib_call_all_init_functions (vm)))
    goto done;

  nm->timing_wheel = clib_mem_alloc_aligned (sizeof (TWT (tw_timer_wheel)),
					     CLIB_CACHE_LINE_BYTES);

  vec_validate (nm->data_from_advancing_timing_wheel, 10);
  _vec_len (nm->data_from_advancing_timing_wheel) = 0;

  /* Create the process timing wheel */
  TW (tw_timer_wheel_init) ((TWT (tw_timer_wheel) *) nm->timing_wheel,
			    0 /* no callback */ ,
			    10e-6 /* timer period 10us */ ,
			    ~0 /* max expirations per call */ );

  vec_validate (vm->pending_rpc_requests, 0);
  _vec_len (vm->pending_rpc_requests) = 0;
  vec_validate (vm->processing_rpc_requests, 0);
  _vec_len (vm->processing_rpc_requests) = 0;

  switch (clib_setjmp (&vm->main_loop_exit, VLIB_MAIN_LOOP_EXIT_NONE))
    {
    case VLIB_MAIN_LOOP_EXIT_NONE:
      vm->main_loop_exit_set = 1;
      break;

    case VLIB_MAIN_LOOP_EXIT_CLI:
      goto done;

    default:
      error = vm->main_loop_error;
      goto done;
    }

  if ((error = vlib_call_all_config_functions (vm, input, 0 /* is_early */ )))
    goto done;

  /* Call all main loop enter functions. */
  {
    clib_error_t *sub_error;
    sub_error = vlib_call_all_main_loop_enter_functions (vm);
    if (sub_error)
      clib_error_report (sub_error);
  }

  vlib_main_loop (vm);

done:
  /* Call all exit functions. */
  {
    clib_error_t *sub_error;
    sub_error = vlib_call_all_main_loop_exit_functions (vm);
    if (sub_error)
      clib_error_report (sub_error);
  }

  if (error)
    clib_error_report (error);

  return 0;
}

static inline clib_error_t *
pcap_dispatch_trace_command_internal (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd, int rx_tx)
{
#define PCAP_DEF_PKT_TO_CAPTURE (100)

  unformat_input_t _line_input, *line_input = &_line_input;
  pcap_main_t *pm = &vm->dispatch_pcap_main;
  u8 *filename;
  u8 *chroot_filename = 0;
  u32 max = 0;
  int enabled = 0;
  int errorFlag = 0;
  clib_error_t *error = 0;
  u32 node_index, add;
  vlib_trace_main_t *tm;
  vlib_trace_node_t *tn;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	{
	  if (vm->dispatch_pcap_enable == 0)
	    {
	      enabled = 1;
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap dispatch capture already on...");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "off"))
	{
	  if (vm->dispatch_pcap_enable)
	    {
	      vlib_cli_output
		(vm, "captured %d pkts...", pm->n_packets_captured);
	      if (pm->n_packets_captured)
		{
		  pm->n_packets_to_capture = pm->n_packets_captured;
		  error = pcap_write (pm);
		  if (error)
		    clib_error_report (error);
		  else
		    vlib_cli_output (vm, "saved to %s...", pm->file_name);
		}
	      vm->dispatch_pcap_enable = 0;
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap tx capture already off...");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "max %d", &max))
	{
	  if (vm->dispatch_pcap_enable)
	    {
	      vlib_cli_output
		(vm,
		 "can't change max value while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }
	  pm->n_packets_to_capture = max;
	}
      else if (unformat (line_input, "file %s", &filename))
	{
	  if (vm->dispatch_pcap_enable)
	    {
	      vlib_cli_output
		(vm, "can't change file while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }

	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      vlib_cli_output (vm, "Hint: .. and / are not allowed.");
	      vec_free (filename);
	      errorFlag = 1;
	      break;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);
	}
      else if (unformat (line_input, "status"))
	{
	  if (vm->dispatch_pcap_enable)
	    {
	      vlib_cli_output
		(vm, "pcap dispatch capture is on: %d of %d pkts...",
		 pm->n_packets_captured, pm->n_packets_to_capture);
	      vlib_cli_output (vm, "Capture to file %s", pm->file_name);
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap dispatch capture is off...");
	    }
	  break;
	}
      else if (unformat (line_input, "buffer-trace %U %d",
			 unformat_vlib_node, vm, &node_index, &add))
	{
	  if (vnet_trace_dummy == 0)
	    vec_validate_aligned (vnet_trace_dummy, 2048,
				  CLIB_CACHE_LINE_BYTES);
	  vlib_cli_output (vm, "Buffer tracing of %d pkts from %U enabled...",
			   add, format_vlib_node_name, vm, node_index);

          /* *INDENT-OFF* */
          foreach_vlib_main ((
            {
              tm = &this_vlib_main->trace_main;
              tm->verbose = 0;  /* not sure this ever did anything... */
              vec_validate (tm->nodes, node_index);
              tn = tm->nodes + node_index;
              tn->limit += add;
              tm->trace_enable = 1;
            }));
          /* *INDENT-ON* */
	}

      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  errorFlag = 1;
	  break;
	}
    }
  unformat_free (line_input);


  if (errorFlag == 0)
    {
      /* Since no error, save configured values. */
      if (chroot_filename)
	{
	  if (pm->file_name)
	    vec_free (pm->file_name);
	  vec_add1 (chroot_filename, 0);
	  pm->file_name = (char *) chroot_filename;
	}

      if (max)
	pm->n_packets_to_capture = max;

      if (enabled)
	{
	  if (pm->file_name == 0)
	    pm->file_name = (char *) format (0, "/tmp/dispatch.pcap%c", 0);

	  pm->n_packets_captured = 0;
	  pm->packet_type = PCAP_PACKET_TYPE_user13;
	  if (pm->lock == 0)
	    clib_spinlock_init (&(pm->lock));
	  vm->dispatch_pcap_enable = 1;
	  vlib_cli_output (vm, "pcap dispatch capture on...");
	}
    }
  else if (chroot_filename)
    vec_free (chroot_filename);

  return error;
}

static clib_error_t *
pcap_dispatch_trace_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  return pcap_dispatch_trace_command_internal (vm, input, cmd, VLIB_RX);
}

/*?
 * This command is used to start or stop pcap dispatch trace capture, or show
 * the capture status.
 *
 * This command has the following optional parameters:
 *
 * - <b>on|off</b> - Used to start or stop capture.
 *
 * - <b>max <nn></b> - Depth of local buffer. Once '<em>nn</em>' number
 *   of packets have been received, buffer is flushed to file. Once another
 *   '<em>nn</em>' number of packets have been received, buffer is flushed
 *   to file, overwriting previous write. If not entered, value defaults
 *   to 100. Can only be updated if packet capture is off.
 *
 * - <b>file <name></b> - Used to specify the output filename. The file will
 *   be placed in the '<em>/tmp</em>' directory, so only the filename is
 *   supported. Directory should not be entered. If file already exists, file
 *   will be overwritten. If no filename is provided, '<em>/tmp/vpe.pcap</em>'
 *   will be used. Can only be updated if packet capture is off.
 *
 * - <b>status</b> - Displays the current status and configured attributes
 *   associated with a packet capture. If packet capture is in progress,
 *   '<em>status</em>' also will return the number of packets currently in
 *   the local buffer. All additional attributes entered on command line
 *   with '<em>status</em>' will be ignored and not applied.
 *
 * @cliexpar
 * Example of how to display the status of capture when off:
 * @cliexstart{pcap dispatch trace status}
 * max is 100, for any interface to file /tmp/vpe.pcap
 * pcap dispatch capture is off...
 * @cliexend
 * Example of how to start a dispatch trace capture:
 * @cliexstart{pcap dispatch trace on max 35 file dispatchTrace.pcap}
 * pcap dispatch capture on...
 * @cliexend
 * Example of how to start a dispatch trace capture with buffer tracing
 * @cliexstart{pcap dispatch trace on max 10000 file dispatchTrace.pcap buffer-trace dpdk-input 1000}
 * pcap dispatch capture on...
 * @cliexend
 * Example of how to display the status of a tx packet capture in progress:
 * @cliexstart{pcap tx trace status}
 * max is 35, dispatch trace to file /tmp/vppTest.pcap
 * pcap tx capture is on: 20 of 35 pkts...
 * @cliexend
 * Example of how to stop a tx packet capture:
 * @cliexstart{vppctl pcap dispatch trace off}
 * captured 21 pkts...
 * saved to /tmp/dispatchTrace.pcap...
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pcap_dispatch_trace_command, static) = {
    .path = "pcap dispatch trace",
    .short_help =
    "pcap dispatch trace [on|off] [max <nn>] [file <name>] [status]\n"
    "              [buffer-trace <input-node-name> <nn>]",
    .function = pcap_dispatch_trace_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

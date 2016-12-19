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
      f->cpu_index = vm->cpu_index;
      fi = vlib_frame_index_no_check (vm, f);
    }

  /* Poison frame when debugging. */
  if (CLIB_DEBUG > 0)
    {
      u32 save_cpu_index = f->cpu_index;

      memset (f, 0xfe, n);

      f->cpu_index = save_cpu_index;
    }

  /* Insert magic number. */
  {
    u32 *magic;

    magic = vlib_frame_find_magic (f, to_node);
    *magic = VLIB_FRAME_MAGIC;
  }

  f->flags = VLIB_FRAME_IS_ALLOCATED | frame_flags;
  f->n_vectors = 0;
  f->scalar_size = scalar_size;
  f->vector_size = vector_size;

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

  f->flags |= VLIB_FRAME_PENDING;
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

  ASSERT (f->flags & VLIB_FRAME_IS_ALLOCATED);

  node = vlib_get_node (vm, r->node_index);
  fs = get_frame_size_info (nm, node->scalar_size, node->vector_size);

  frame_index = vlib_frame_index (vm, f);

  ASSERT (f->flags & VLIB_FRAME_IS_ALLOCATED);

  /* No next frames may point to freed frame. */
  if (CLIB_DEBUG > 0)
    {
      vlib_next_frame_t *nf;
      vec_foreach (nf, vm->node_main.next_frames)
	ASSERT (nf->frame_index != frame_index);
    }

  f->flags &= ~VLIB_FRAME_IS_ALLOCATED;

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
  if ((nf->flags & VLIB_FRAME_PENDING) && !(f->flags & VLIB_FRAME_PENDING))
    {
      nf->flags &= ~VLIB_FRAME_PENDING;
      f->n_vectors = 0;
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
	  f_old->flags |= VLIB_FRAME_FREE_AFTER_DISPATCH;
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

  if (DPDK == 0 && CLIB_DEBUG > 0)
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

      if (!(f->flags & VLIB_FRAME_PENDING))
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
	  f->flags |= VLIB_FRAME_PENDING;

	  /*
	   * If we're going to dispatch this frame on another thread,
	   * force allocation of a new frame. Otherwise, we create
	   * a dangling frame reference. Each thread has its own copy of
	   * the next_frames vector.
	   */
	  if (0 && r->cpu_index != next_runtime->cpu_index)
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
			      uword n_calls, uword n_vectors, uword n_clocks)
{
  vlib_node_t *n = vlib_get_node (vm, r->node_index);

  n->stats_total.calls += n_calls + r->calls_since_last_overflow;
  n->stats_total.vectors += n_vectors + r->vectors_since_last_overflow;
  n->stats_total.clocks += n_clocks + r->clocks_since_last_overflow;
  n->stats_total.max_clock = r->max_clock;
  n->stats_total.max_clock_n = r->max_clock_n;

  r->calls_since_last_overflow = 0;
  r->vectors_since_last_overflow = 0;
  r->clocks_since_last_overflow = 0;
}

always_inline void __attribute__ ((unused))
vlib_process_sync_stats (vlib_main_t * vm,
			 vlib_process_t * p,
			 uword n_calls, uword n_vectors, uword n_clocks)
{
  vlib_node_runtime_t *rt = &p->node_runtime;
  vlib_node_t *n = vlib_get_node (vm, rt->node_index);
  vlib_node_runtime_sync_stats (vm, rt, n_calls, n_vectors, n_clocks);
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

  vlib_node_runtime_sync_stats (vm, rt, 0, 0, 0);

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
				uword n_vectors, uword n_clocks)
{
  u32 ca0, ca1, v0, v1, cl0, cl1, r;

  cl0 = cl1 = node->clocks_since_last_overflow;
  ca0 = ca1 = node->calls_since_last_overflow;
  v0 = v1 = node->vectors_since_last_overflow;

  ca1 = ca0 + n_calls;
  v1 = v0 + n_vectors;
  cl1 = cl0 + n_clocks;

  node->calls_since_last_overflow = ca1;
  node->clocks_since_last_overflow = cl1;
  node->vectors_since_last_overflow = v1;
  node->max_clock_n = node->max_clock > n_clocks ?
    node->max_clock_n : n_vectors;
  node->max_clock = node->max_clock > n_clocks ? node->max_clock : n_clocks;

  r = vlib_node_runtime_update_main_loop_vector_stats (vm, node, n_vectors);

  if (PREDICT_FALSE (ca1 < ca0 || v1 < v0 || cl1 < cl0))
    {
      node->calls_since_last_overflow = ca0;
      node->clocks_since_last_overflow = cl0;
      node->vectors_since_last_overflow = v0;
      vlib_node_runtime_sync_stats (vm, node, n_calls, n_vectors, n_clocks);
    }

  return r;
}

always_inline void
vlib_process_update_stats (vlib_main_t * vm,
			   vlib_process_t * p,
			   uword n_calls, uword n_vectors, uword n_clocks)
{
  vlib_node_runtime_update_stats (vm, &p->node_runtime,
				  n_calls, n_vectors, n_clocks);
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
  error = elog_write_file (em, chroot_file);
  vlib_worker_thread_barrier_release (vm);
  vec_free (chroot_file);
  return error;
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
		(vm->cpu_index ? &vlib_worker_threads[vm->cpu_index].
		 elog_track : &em->default_track),
		/* data to log */ n_vectors);
}

void
vlib_dump_context_trace (vlib_main_t * vm, u32 bi)
{
  vlib_node_main_t *vnm = &vm->node_main;
  vlib_buffer_t *b;
  u8 i, n;

  if (VLIB_BUFFER_TRACE_TRAJECTORY)
    {
      b = vlib_get_buffer (vm, bi);
      n = b->pre_data[0];

      fformat (stderr, "Context trace for bi %d b 0x%llx, visited %d\n",
	       bi, b, n);

      if (n == 0 || n > 20)
	{
	  fformat (stderr, "n is unreasonable\n");
	  return;
	}


      for (i = 0; i < n; i++)
	{
	  u32 node_index;

	  node_index = b->pre_data[i + 1];

	  if (node_index > vec_len (vnm->nodes))
	    {
	      fformat (stderr, "Skip bogus node index %d\n", node_index);
	      continue;
	    }

	  fformat (stderr, "%v (%d)\n", vnm->nodes[node_index]->name,
		   node_index);
	}
    }
  else
    {
      fformat (stderr,
	       "in vlib/buffers.h, #define VLIB_BUFFER_TRACE_TRAJECTORY 1\n");
    }
}


/* static_always_inline */ u64
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

  if (1 /* || vm->cpu_index == node->cpu_index */ )
    {
      vlib_main_t *stat_vm;

      stat_vm = /* vlib_mains ? vlib_mains[0] : */ vm;

      vlib_elog_main_loop_event (vm, node->node_index,
				 last_time_stamp,
				 frame ? frame->n_vectors : 0,
				 /* is_after */ 0);

      /*
       * Turn this on if you run into
       * "bad monkey" contexts, and you want to know exactly
       * which nodes they've visited... See ixge.c...
       */
      if (VLIB_BUFFER_TRACE_TRAJECTORY && frame)
	{
	  int i;
	  int log_index;
	  u32 *from;
	  from = vlib_frame_vector_args (frame);
	  for (i = 0; i < frame->n_vectors; i++)
	    {
	      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	      ASSERT (b->pre_data[0] < 32);
	      log_index = b->pre_data[0]++ + 1;
	      b->pre_data[log_index] = node->node_index;
	    }
	  n = node->function (vm, node, frame);
	}
      else
	n = node->function (vm, node, frame);

      t = clib_cpu_time_now ();

      vlib_elog_main_loop_event (vm, node->node_index, t, n,	/* is_after */
				 1);

      vm->main_loop_vectors_processed += n;
      vm->main_loop_nodes_processed += n > 0;

      v = vlib_node_runtime_update_stats (stat_vm, node,
					  /* n_calls */ 1,
					  /* n_vectors */ n,
					  /* n_clocks */ t - last_time_stamp);

      /* When in interrupt mode and vector rate crosses threshold switch to
         polling mode. */
      if ((DPDK == 0 && dispatch_state == VLIB_NODE_STATE_INTERRUPT)
	  || (DPDK == 0 && dispatch_state == VLIB_NODE_STATE_POLLING
	      && (node->flags
		  & VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE)))
	{
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

	  if (dispatch_state == VLIB_NODE_STATE_INTERRUPT
	      && v >= nm->polling_threshold_vector_length)
	    {
	      vlib_node_t *n = vlib_get_node (vm, node->node_index);
	      n->state = VLIB_NODE_STATE_POLLING;
	      node->state = VLIB_NODE_STATE_POLLING;
	      ASSERT (!
		      (node->flags &
		       VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE));
	      node->flags &=
		~VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE;
	      node->flags |=
		VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE;
	      nm->input_node_counts_by_state[VLIB_NODE_STATE_INTERRUPT] -= 1;
	      nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] += 1;

	      ed = ELOG_DATA (&vm->elog_main, e);
	      ed->node_name = n->name_elog_string;
	      ed->vector_length = v;
	      ed->is_polling = 1;
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
		  ed = ELOG_DATA (&vm->elog_main, e);
		  ed->node_name = n->name_elog_string;
		  ed->vector_length = v;
		  ed->is_polling = 0;
		}
	    }
	}
    }

  return t;
}

/* static */ u64
dispatch_pending_node (vlib_main_t * vm,
		       vlib_pending_frame_t * p, u64 last_time_stamp)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_frame_t *f;
  vlib_next_frame_t *nf, nf_dummy;
  vlib_node_runtime_t *n;
  u32 restore_frame_index;

  n = vec_elt_at_index (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL],
			p->node_runtime_index);

  f = vlib_get_frame (vm, p->frame_index);
  if (p->next_frame_index == VLIB_PENDING_FRAME_NO_NEXT_FRAME)
    {
      /* No next frame: so use dummy on stack. */
      nf = &nf_dummy;
      nf->flags = f->flags & VLIB_NODE_FLAG_TRACE;
      nf->frame_index = ~p->frame_index;
    }
  else
    nf = vec_elt_at_index (nm->next_frames, p->next_frame_index);

  ASSERT (f->flags & VLIB_FRAME_IS_ALLOCATED);

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
  ASSERT (f->flags & VLIB_FRAME_PENDING);
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

  f->flags &= ~VLIB_FRAME_PENDING;

  /* Frame is ready to be used again, so restore it. */
  if (restore_frame_index != ~0)
    {
      /* we musn't restore a frame that is flagged to be freed. This shouldn't
         happen since frames to be freed post dispatch are those used
         when the to-node frame becomes full i.e. they form a sort of queue of
         frames to a single node. If we get here then the to-node frame and the
         pending frame *were* the same, and so we removed the to-node frame.
         Therefore this frame is no longer part of the queue for that node
         and hence it cannot be it's overspill.
       */
      ASSERT (!(f->flags & VLIB_FRAME_FREE_AFTER_DISPATCH));

      /* p->next_frame_index can change during node dispatch if node
         function decides to change graph hook up. */
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
      if (f->flags & VLIB_FRAME_FREE_AFTER_DISPATCH)
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
  nm->current_process_index = node->runtime_index;

  n_vectors = vlib_process_startup (vm, p, f);

  nm->current_process_index = ~0;

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
	timing_wheel_insert (&nm->timing_wheel, p->resume_cpu_time,
			     vlib_timing_wheel_data_set_suspended_process
			     (node->runtime_index));
    }
  else
    p->flags &= ~VLIB_PROCESS_IS_RUNNING;

  t = clib_cpu_time_now ();

  vlib_elog_main_loop_event (vm, node_runtime->node_index, t, is_suspend,
			     /* is_after */ 1);

  vlib_process_update_stats (vm, p,
			     /* n_calls */ !is_suspend,
			     /* n_vectors */ n_vectors,
			     /* n_clocks */ t - last_time_stamp);

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

  pf =
    pool_elt_at_index (nm->suspended_process_frames,
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
	timing_wheel_insert (&nm->timing_wheel, p->resume_cpu_time,
			     vlib_timing_wheel_data_set_suspended_process
			     (node->runtime_index));
    }
  else
    {
      p->flags &= ~VLIB_PROCESS_IS_RUNNING;
      p->suspended_process_frame_index = ~0;
      pool_put (nm->suspended_process_frames, pf);
    }

  t = clib_cpu_time_now ();
  vlib_elog_main_loop_event (vm, node_runtime->node_index, t, !is_suspend,
			     /* is_after */ 1);

  vlib_process_update_stats (vm, p,
			     /* n_calls */ !is_suspend,
			     /* n_vectors */ n_vectors,
			     /* n_clocks */ t - last_time_stamp);

  return t;
}

static void
vlib_main_loop (vlib_main_t * vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  uword i;
  u64 cpu_time_now;

  /* Initialize pending node vector. */
  vec_resize (nm->pending_frames, 32);
  _vec_len (nm->pending_frames) = 0;

  /* Mark time of main loop start. */
  cpu_time_now = vm->clib_time.last_cpu_time;
  vm->cpu_time_main_loop_start = cpu_time_now;

  /* Arrange for first level of timing wheel to cover times we care
     most about. */
  nm->timing_wheel.min_sched_time = 10e-6;
  nm->timing_wheel.max_sched_time = 10e-3;
  timing_wheel_init (&nm->timing_wheel,
		     cpu_time_now, vm->clib_time.clocks_per_second);

  /* Pre-allocate expired nodes. */
  vec_alloc (nm->data_from_advancing_timing_wheel, 32);
  vec_alloc (nm->pending_interrupt_node_runtime_indices, 32);

  if (!nm->polling_threshold_vector_length)
    nm->polling_threshold_vector_length = 10;
  if (!nm->interrupt_threshold_vector_length)
    nm->interrupt_threshold_vector_length = 5;

  nm->current_process_index = ~0;

  /* Start all processes. */
  {
    uword i;
    for (i = 0; i < vec_len (nm->processes); i++)
      cpu_time_now =
	dispatch_process (vm, nm->processes[i], /* frame */ 0, cpu_time_now);
  }

  while (1)
    {
      vlib_node_runtime_t *n;

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

      if (PREDICT_TRUE (vm->queue_signal_pending == 0))
	vm->queue_signal_callback (vm);

      /* Next handle interrupts. */
      {
	uword l = _vec_len (nm->pending_interrupt_node_runtime_indices);
	uword i;
	if (l > 0)
	  {
	    _vec_len (nm->pending_interrupt_node_runtime_indices) = 0;
	    for (i = 0; i < l; i++)
	      {
		n = vec_elt_at_index (nm->nodes_by_type[VLIB_NODE_TYPE_INPUT],
				      nm->
				      pending_interrupt_node_runtime_indices
				      [i]);
		cpu_time_now =
		  dispatch_node (vm, n, VLIB_NODE_TYPE_INPUT,
				 VLIB_NODE_STATE_INTERRUPT,
				 /* frame */ 0,
				 cpu_time_now);
	      }
	  }
      }

      /* Check if process nodes have expired from timing wheel. */
      nm->data_from_advancing_timing_wheel
	= timing_wheel_advance (&nm->timing_wheel, cpu_time_now,
				nm->data_from_advancing_timing_wheel,
				&nm->cpu_time_next_process_ready);

      ASSERT (nm->data_from_advancing_timing_wheel != 0);
      if (PREDICT_FALSE (_vec_len (nm->data_from_advancing_timing_wheel) > 0))
	{
	  uword i;

	processes_timing_wheel_data:
	  for (i = 0; i < _vec_len (nm->data_from_advancing_timing_wheel);
	       i++)
	    {
	      u32 d = nm->data_from_advancing_timing_wheel[i];
	      u32 di = vlib_timing_wheel_data_get_index (d);

	      if (vlib_timing_wheel_data_is_timed_event (d))
		{
		  vlib_signal_timed_event_data_t *te =
		    pool_elt_at_index (nm->signal_timed_event_data_pool, di);
		  vlib_node_t *n = vlib_get_node (vm, te->process_node_index);
		  vlib_process_t *p =
		    vec_elt (nm->processes, n->runtime_index);
		  void *data;
		  data =
		    vlib_process_signal_event_helper (nm, n, p,
						      te->event_type_index,
						      te->n_data_elts,
						      te->n_data_elt_bytes);
		  if (te->n_data_bytes < sizeof (te->inline_event_data))
		    clib_memcpy (data, te->inline_event_data,
				 te->n_data_bytes);
		  else
		    {
		      clib_memcpy (data, te->event_data_as_vector,
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

	  /* Reset vector. */
	  _vec_len (nm->data_from_advancing_timing_wheel) = 0;
	}

      /* Input nodes may have added work to the pending vector.
         Process pending vector until there is nothing left.
         All pending vectors will be processed from input -> output. */
      for (i = 0; i < _vec_len (nm->pending_frames); i++)
	cpu_time_now = dispatch_pending_node (vm, nm->pending_frames + i,
					      cpu_time_now);
      /* Reset pending vector for next iteration. */
      _vec_len (nm->pending_frames) = 0;

      /* Pending internal nodes may resume processes. */
      if (_vec_len (nm->data_from_advancing_timing_wheel) > 0)
	goto processes_timing_wheel_data;

      vlib_increment_main_loop_counter (vm);

      /* Record time stamp in case there are no enabled nodes and above
         calls do not update time stamp. */
      cpu_time_now = clib_cpu_time_now ();
    }
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

/* Main function. */
int
vlib_main (vlib_main_t * volatile vm, unformat_input_t * input)
{
  clib_error_t *volatile error;

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

  vec_validate (vm->buffer_main, 0);

  if ((error = vlib_thread_init (vm)))
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

  /* See unix/main.c; most likely already set up */
  if (vm->init_functions_called == 0)
    vm->init_functions_called = hash_create (0, /* value bytes */ 0);
  if ((error = vlib_call_all_init_functions (vm)))
    goto done;

  /* Create default buffer free list. */
  vlib_buffer_get_or_create_free_list (vm,
				       VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES,
				       "default");

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

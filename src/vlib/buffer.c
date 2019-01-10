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
 * buffer.c: allocate/free network buffers.
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

/**
 * @file
 *
 * Allocate/free network buffers.
 */

#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#ifdef CLIB_HAVE_VEC128
/* Assumptions by vlib_buffer_free_inline: */
STATIC_ASSERT_FITS_IN (vlib_buffer_t, flags, 16);
STATIC_ASSERT_FITS_IN (vlib_buffer_t, n_add_refs, 16);
STATIC_ASSERT_FITS_IN (vlib_buffer_t, buffer_pool_index, 16);
#endif

/* Make sure that buffer template size is not accidentally changed */
STATIC_ASSERT_OFFSET_OF (vlib_buffer_t, template_end, 64);

vlib_buffer_callbacks_t *vlib_buffer_callbacks = 0;

/* when running unpriviledged we are limited by RLIMIT_MEMLOCK which is
   typically set to 16MB so setting default size for buffer memory to 14MB
   */
static u32 vlib_buffer_physmem_sz = 14 << 20;

/* logging */
static vlib_log_class_t buffer_log_default;

uword
vlib_buffer_length_in_chain_slow_path (vlib_main_t * vm,
				       vlib_buffer_t * b_first)
{
  vlib_buffer_t *b = b_first;
  uword l_first = b_first->current_length;
  uword l = 0;
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      l += b->current_length;
    }
  b_first->total_length_not_including_first_buffer = l;
  b_first->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  return l + l_first;
}

u8 *
format_vlib_buffer (u8 * s, va_list * args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);
  u32 indent = format_get_indent (s);
  u8 *a = 0;

#define _(bit, name, v) \
  if (v && (b->flags & VLIB_BUFFER_##name)) \
    a = format (a, "%s ", v);
  foreach_vlib_buffer_flag
#undef _
    s =
    format (s, "current data %d, length %d, buffer-pool %d, clone-count %u",
	    b->current_data, b->current_length, b->buffer_pool_index,
	    b->n_add_refs);

  if (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID)
    s = format (s, ", totlen-nifb %d",
		b->total_length_not_including_first_buffer);

  if (b->flags & VLIB_BUFFER_IS_TRACED)
    s = format (s, ", trace 0x%x", b->trace_index);

  if (a)
    s = format (s, "\n%U%v", format_white_space, indent, a);
  vec_free (a);

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      vlib_main_t *vm = vlib_get_main ();
      u32 next_buffer = b->next_buffer;
      b = vlib_get_buffer (vm, next_buffer);

      s =
	format (s, "\n%Unext-buffer 0x%x, segment length %d, clone-count %u",
		format_white_space, indent, next_buffer, b->current_length,
		b->n_add_refs);
    }

  return s;
}

u8 *
format_vlib_buffer_and_data (u8 * s, va_list * args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);

  s = format (s, "%U, %U",
	      format_vlib_buffer, b,
	      format_hex_bytes, vlib_buffer_get_current (b), 64);

  return s;
}

static u8 *
format_vlib_buffer_known_state (u8 * s, va_list * args)
{
  vlib_buffer_known_state_t state = va_arg (*args, vlib_buffer_known_state_t);
  char *t;

  switch (state)
    {
    case VLIB_BUFFER_UNKNOWN:
      t = "unknown";
      break;

    case VLIB_BUFFER_KNOWN_ALLOCATED:
      t = "known-allocated";
      break;

    case VLIB_BUFFER_KNOWN_FREE:
      t = "known-free";
      break;

    default:
      t = "invalid";
      break;
    }

  return format (s, "%s", t);
}

u8 *
format_vlib_buffer_contents (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_buffer_t *b = va_arg (*va, vlib_buffer_t *);

  while (1)
    {
      vec_add (s, vlib_buffer_get_current (b), b->current_length);
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      b = vlib_get_buffer (vm, b->next_buffer);
    }

  return s;
}

static u8 *
vlib_validate_buffer_helper (vlib_main_t * vm,
			     u32 bi,
			     uword follow_buffer_next, uword ** unique_hash)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);

  if (vec_len (bm->buffer_pools) <= b->buffer_pool_index)
    return format (0, "unknown buffer pool 0x%x", b->buffer_pool_index);

  if ((signed) b->current_data < (signed) -VLIB_BUFFER_PRE_DATA_SIZE)
    return format (0, "current data %d before pre-data", b->current_data);

  if (b->current_data + b->current_length > VLIB_BUFFER_DATA_SIZE)
    return format (0, "%d-%d beyond end of buffer %d", b->current_data,
		   b->current_length, VLIB_BUFFER_DATA_SIZE);

  if (follow_buffer_next && (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      vlib_buffer_known_state_t k;
      u8 *msg, *result;

      k = vlib_buffer_is_known (vm, b->next_buffer);
      if (k != VLIB_BUFFER_KNOWN_ALLOCATED)
	return format (0, "next 0x%x: %U",
		       b->next_buffer, format_vlib_buffer_known_state, k);

      if (unique_hash)
	{
	  if (hash_get (*unique_hash, b->next_buffer))
	    return format (0, "duplicate buffer 0x%x", b->next_buffer);

	  hash_set1 (*unique_hash, b->next_buffer);
	}

      msg = vlib_validate_buffer (vm, b->next_buffer, follow_buffer_next);
      if (msg)
	{
	  result = format (0, "next 0x%x: %v", b->next_buffer, msg);
	  vec_free (msg);
	  return result;
	}
    }

  return 0;
}

u8 *
vlib_validate_buffer (vlib_main_t * vm, u32 bi, uword follow_buffer_next)
{
  return vlib_validate_buffer_helper (vm, bi, follow_buffer_next,
				      /* unique_hash */ 0);
}

u8 *
vlib_validate_buffers (vlib_main_t * vm,
		       u32 * buffers,
		       uword next_buffer_stride,
		       uword n_buffers,
		       vlib_buffer_known_state_t known_state,
		       uword follow_buffer_next)
{
  uword i, *hash;
  u32 bi, *b = buffers;
  vlib_buffer_known_state_t k;
  u8 *msg = 0, *result = 0;

  hash = hash_create (0, 0);
  for (i = 0; i < n_buffers; i++)
    {
      bi = b[0];
      b += next_buffer_stride;

      /* Buffer is not unique. */
      if (hash_get (hash, bi))
	{
	  msg = format (0, "not unique");
	  goto done;
	}

      k = vlib_buffer_is_known (vm, bi);
      if (k != known_state)
	{
	  msg = format (0, "is %U; expected %U",
			format_vlib_buffer_known_state, k,
			format_vlib_buffer_known_state, known_state);
	  goto done;
	}

      msg = vlib_validate_buffer_helper (vm, bi, follow_buffer_next, &hash);
      if (msg)
	goto done;

      hash_set1 (hash, bi);
    }

done:
  if (msg)
    {
      result = format (0, "0x%x: %v", bi, msg);
      vec_free (msg);
    }
  hash_free (hash);
  return result;
}

/*
 * Hand-craft a static vector w/ length 1, so vec_len(vlib_mains) =1
 * and vlib_mains[0] = &vlib_global_main from the beginning of time.
 *
 * The only place which should ever expand vlib_mains is start_workers()
 * in threads.c. It knows about the bootstrap vector.
 */
/* *INDENT-OFF* */
static struct
{
  vec_header_t h;
  vlib_main_t *vm;
} __attribute__ ((packed)) __bootstrap_vlib_main_vector
  __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES))) =
{
  .h.len = 1,
  .vm = &vlib_global_main,
};
/* *INDENT-ON* */

vlib_main_t **vlib_mains = &__bootstrap_vlib_main_vector.vm;


/* When dubugging validate that given buffers are either known allocated
   or known free. */
void
vlib_buffer_validate_alloc_free (vlib_main_t * vm,
				 u32 * buffers,
				 uword n_buffers,
				 vlib_buffer_known_state_t expected_state)
{
  u32 *b;
  uword i, bi, is_free;

  if (CLIB_DEBUG == 0)
    return;

  if (vlib_buffer_callbacks)
    return;

  is_free = expected_state == VLIB_BUFFER_KNOWN_ALLOCATED;
  b = buffers;
  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_known_state_t known;

      bi = b[0];
      b += 1;
      known = vlib_buffer_is_known (vm, bi);
      if (known != expected_state)
	{
	  ASSERT (0);
	  vlib_panic_with_msg
	    (vm, "%s %U buffer 0x%x",
	     is_free ? "freeing" : "allocating",
	     format_vlib_buffer_known_state, known, bi);
	}

      vlib_buffer_set_known_state (vm, bi, is_free ? VLIB_BUFFER_KNOWN_FREE :
				   VLIB_BUFFER_KNOWN_ALLOCATED);
    }
}

static uword
vlib_buffer_pool_get_internal (vlib_main_t * vm, u8 buffer_pool_index,
			       u32 * buffers, u32 n_buffers)
{
  vlib_buffer_pool_t *bp = vlib_buffer_pool_get (vm, buffer_pool_index);
  u32 len;

  ASSERT (bp->buffers);

  clib_spinlock_lock (&bp->lock);
  len = vec_len (bp->buffers);
  if (PREDICT_TRUE (n_buffers < len))
    {
      len -= n_buffers;
      vlib_buffer_copy_indices (buffers, bp->buffers + len, n_buffers);
      _vec_len (bp->buffers) = len;
      clib_spinlock_unlock (&bp->lock);
      return n_buffers;
    }
  else
    {
      vlib_buffer_copy_indices (buffers, bp->buffers, len);
      _vec_len (bp->buffers) = 0;
      clib_spinlock_unlock (&bp->lock);
      return len;
    }
}

static void
vlib_buffer_pool_put_internal (vlib_main_t * vm, u8 buffer_pool_index,
			       u32 * buffers, u32 n_buffers)
{
  vlib_buffer_pool_t *bp = vlib_buffer_pool_get (vm, buffer_pool_index);
  vlib_buffer_pool_thread_t *bpt =
    vec_elt_at_index (bp->threads, vm->thread_index);

  vec_add_aligned (bpt->cached_buffers, buffers, n_buffers,
		   CLIB_CACHE_LINE_BYTES);

  if (vec_len (bpt->cached_buffers) > 4 * VLIB_FRAME_SIZE)
    {
      clib_spinlock_lock (&bp->lock);
      /* keep last stored buffers, as they are more likely hot in the cache */
      vec_add_aligned (bp->buffers, bpt->cached_buffers, VLIB_FRAME_SIZE,
		       CLIB_CACHE_LINE_BYTES);
      vec_delete (bpt->cached_buffers, VLIB_FRAME_SIZE, 0);
      bpt->n_alloc -= VLIB_FRAME_SIZE;
      clib_spinlock_unlock (&bp->lock);
    }
}

void
vlib_packet_template_init (vlib_main_t * vm,
			   vlib_packet_template_t * t,
			   void *packet_data,
			   uword n_packet_data_bytes,
			   uword min_n_buffers_each_alloc, char *fmt, ...)
{
  va_list va;

  va_start (va, fmt);
  t->name = va_format (0, fmt, &va);
  va_end (va);

  vlib_worker_thread_barrier_sync (vm);

  clib_memset (t, 0, sizeof (t[0]));

  vec_add (t->packet_data, packet_data, n_packet_data_bytes);
  t->min_n_buffers_each_alloc = min_n_buffers_each_alloc;
  vlib_worker_thread_barrier_release (vm);
}

void *
vlib_packet_template_get_packet (vlib_main_t * vm,
				 vlib_packet_template_t * t, u32 * bi_result)
{
  u32 bi;
  vlib_buffer_t *b;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 0;

  *bi_result = bi;

  b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (vlib_buffer_get_current (b),
		    t->packet_data, vec_len (t->packet_data));
  b->current_length = vec_len (t->packet_data);

  return b->data;
}

/* Append given data to end of buffer, possibly allocating new buffers. */
int
vlib_buffer_add_data (vlib_main_t * vm, u32 * buffer_index, void *data,
		      u32 n_data_bytes)
{
  u32 n_buffer_bytes, n_left, n_left_this_buffer, bi;
  vlib_buffer_t *b;
  void *d;

  bi = *buffer_index;
  if (bi == ~0 && 1 != vlib_buffer_alloc (vm, &bi, 1))
    goto out_of_buffers;

  d = data;
  n_left = n_data_bytes;
  n_buffer_bytes = VLIB_BUFFER_DATA_SIZE;

  b = vlib_get_buffer (vm, bi);
  b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

  /* Get to the end of the chain before we try to append data... */
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    b = vlib_get_buffer (vm, b->next_buffer);

  while (1)
    {
      u32 n;

      ASSERT (n_buffer_bytes >= b->current_length);
      n_left_this_buffer =
	n_buffer_bytes - (b->current_data + b->current_length);
      n = clib_min (n_left_this_buffer, n_left);
      clib_memcpy_fast (vlib_buffer_get_current (b) + b->current_length, d,
			n);
      b->current_length += n;
      n_left -= n;
      if (n_left == 0)
	break;

      d += n;
      if (1 != vlib_buffer_alloc (vm, &b->next_buffer, 1))
	goto out_of_buffers;

      b->flags |= VLIB_BUFFER_NEXT_PRESENT;

      b = vlib_get_buffer (vm, b->next_buffer);
    }

  *buffer_index = bi;
  return 0;

out_of_buffers:
  clib_warning ("out of buffers");
  return 1;
}

u16
vlib_buffer_chain_append_data_with_alloc (vlib_main_t * vm,
					  vlib_buffer_t * first,
					  vlib_buffer_t ** last, void *data,
					  u16 data_len)
{
  vlib_buffer_t *l = *last;
  u32 n_buffer_bytes = VLIB_BUFFER_DATA_SIZE;
  u16 copied = 0;
  ASSERT (n_buffer_bytes >= l->current_length + l->current_data);
  while (data_len)
    {
      u16 max = n_buffer_bytes - l->current_length - l->current_data;
      if (max == 0)
	{
	  if (1 != vlib_buffer_alloc_from_pool (vm, &l->next_buffer, 1,
						first->buffer_pool_index))
	    return copied;
	  *last = l = vlib_buffer_chain_buffer (vm, l, l->next_buffer);
	  max = n_buffer_bytes - l->current_length - l->current_data;
	}

      u16 len = (data_len > max) ? max : data_len;
      clib_memcpy_fast (vlib_buffer_get_current (l) + l->current_length,
			data + copied, len);
      vlib_buffer_chain_increase_length (first, l, len);
      data_len -= len;
      copied += len;
    }
  return copied;
}

u8
vlib_buffer_pool_create (vlib_main_t * vm, char *name, u32 buffer_size,
			 u32 physmem_map_index, int is_external)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;
  vlib_physmem_map_t *m = vlib_physmem_get_map (vm, physmem_map_index);
  uword start = pointer_to_uword (m->base);
  uword size = (uword) m->n_pages << m->log2_page_size;

  if (bm->buffer_mem_size == 0)
    {
      bm->buffer_mem_start = start;
      bm->buffer_mem_size = size;
    }
  else if (start < bm->buffer_mem_start)
    {
      bm->buffer_mem_size += bm->buffer_mem_start - start;
      bm->buffer_mem_start = start;
      if (size > bm->buffer_mem_size)
	bm->buffer_mem_size = size;
    }
  else if (start > bm->buffer_mem_start)
    {
      uword new_size = start - bm->buffer_mem_start + size;
      if (new_size > bm->buffer_mem_size)
	bm->buffer_mem_size = new_size;
    }

  if ((u64) bm->buffer_mem_size >
      ((u64) 1 << (32 + CLIB_LOG2_CACHE_LINE_BYTES)))
    {
      clib_panic ("buffer memory size out of range!");
    }

  vec_add2 (bm->buffer_pools, bp, 1);
  bp->start = start;
  bp->size = size;
  bp->index = bp - bm->buffer_pools;
  bp->buffer_template.buffer_pool_index = bp->index;
  bp->physmem_map_index = physmem_map_index;
  bp->name = format (0, "%s%c", name, 0);
  bp->buffer_size = buffer_size;
  bp->numa_node = m->numa_node;
  bp->ext_hdr_size = bm->cb.external_header_size;

  vec_validate_aligned (bp->threads, vec_len (vlib_mains) - 1,
			CLIB_CACHE_LINE_BYTES);

  clib_spinlock_init (&bp->lock);

  if (is_external)
    goto done;

  while (1)
    {
      u8 *p;
      u32 bi;

      p = vlib_physmem_alloc_from_map (vm, bp->physmem_map_index,
				       bp->buffer_size,
				       CLIB_CACHE_LINE_BYTES);

      if (p == 0)
	break;

      p += bp->ext_hdr_size;

      clib_memcpy_fast (p, &bp->buffer_template, sizeof (vlib_buffer_t));

      bi = vlib_get_buffer_index (vm, (vlib_buffer_t *) p);

      vec_add1_aligned (bp->buffers, bi, CLIB_CACHE_LINE_BYTES);

      if (CLIB_DEBUG > 0)
	vlib_buffer_set_known_state (vm, bi, VLIB_BUFFER_KNOWN_FREE);

      bp->n_buffers += 1;
    }

done:
  ASSERT (bp - bm->buffer_pools < 255);	/* 0xff should not be used */
  return bp->index;
}

static u8 *
format_vlib_buffer_pool (u8 * s, va_list * va)
{
  vlib_buffer_pool_t *bp = va_arg (*va, vlib_buffer_pool_t *);
  vlib_buffer_pool_thread_t *bpt;
  u32 cached = 0;

  if (!bp)
    return format (s, "%-20s%=6s%=6s%=6s%=6s%=8s%=8s%=8s",
		   "Pool Name", "Index", "NUMA", "Size", "Total", "Avail",
		   "Cached", "Used");

  /* *INDENT-OFF* */
  vec_foreach (bpt, bp->threads)
    cached += vec_len (bpt->cached_buffers);
  /* *INDENT-ON* */

  s = format (s, "%-20s%=6d%=6d%=6u%=6u%=8u%=8u%=8u",
	      bp->name, bp->index, bp->numa_node, bp->buffer_size,
	      bp->n_buffers, vec_len (bp->buffers), cached,
	      bp->n_buffers - vec_len (bp->buffers) - cached);

  return s;
}

static clib_error_t *
show_buffers (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  vlib_cli_output (vm, "%U", format_vlib_buffer_pool, 0);

  /* *INDENT-OFF* */
  vec_foreach (bp, bm->buffer_pools)
    vlib_cli_output (vm, "%U", format_vlib_buffer_pool, bp);
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_buffers_command, static) = {
  .path = "show buffers",
  .short_help = "Show packet buffer allocation",
  .function = show_buffers,
};
/* *INDENT-ON* */

clib_error_t *
vlib_buffer_worker_init (vlib_main_t * vm)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  /* *INDENT-OFF* */
  vec_foreach (bp, bm->buffer_pools)
    {
      clib_spinlock_lock (&bp->lock);
      vec_validate_aligned (bp->threads, vec_len (vlib_mains) - 1,
			    CLIB_CACHE_LINE_BYTES);
      clib_spinlock_unlock (&bp->lock);
    }
  /* *INDENT-ON* */

  return 0;
}

VLIB_WORKER_INIT_FUNCTION (vlib_buffer_worker_init);

static clib_error_t *
vlib_buffer_main_init_numa_node (struct vlib_main_t *vm, u32 numa_node)
{
  clib_error_t *error;
  vlib_buffer_main_t *bm = vm->buffer_main;
  int log2_page_size = 0;
  u32 physmem_map_index;
  u32 buffer_size;
  u8 *name;

  name = format (0, "buffers-numa-%d%c", numa_node, 0);

retry:
  error = vlib_physmem_shared_map_create (vm, (char *) name,
					  vlib_buffer_physmem_sz,
					  log2_page_size, numa_node,
					  &physmem_map_index);

  if (error && log2_page_size == 0)
    {
      vlib_log_warn (buffer_log_default, "%U", format_clib_error, error);
      clib_error_free (error);
      vlib_log_warn (buffer_log_default, "falling back to non-hugepage "
		     "backed buffer pool");
      log2_page_size = min_log2 (clib_mem_get_page_size ());
      goto retry;
    }

  if (error)
    return error;

  vec_reset_length (name);
  name = format (name, "default-numa-%d%c", numa_node, 0);

  buffer_size =
    VLIB_BUFFER_DATA_SIZE + sizeof (vlib_buffer_t) +
    bm->cb.external_header_size;

  vlib_buffer_pool_create (vm, (char *) name, buffer_size, physmem_map_index,
			   /* is_external */ 0);
  return 0;
}

clib_error_t *
vlib_buffer_main_init (struct vlib_main_t * vm)
{
  vlib_buffer_main_t *bm;
  clib_error_t *err;
  clib_bitmap_t *bmp = 0;
  u32 numa_node;

  buffer_log_default = vlib_log_register_class ("buffer", 0);

  bm = vm->buffer_main = clib_mem_alloc (sizeof (bm[0]));
  clib_memset (bm, 0, sizeof (bm[0]));

  if (vlib_buffer_callbacks)
    {
      /* external plugin has registered own buffer callbacks
         so we just copy them and quit */
      clib_memcpy_fast (&bm->cb, vlib_buffer_callbacks,
			sizeof (vlib_buffer_callbacks_t));
      if (vlib_buffer_callbacks->vlib_buffer_pool_get_cb)
	{
	  bm->callbacks_registered = 1;
	  return 0;
	}
    }

  bm->cb.vlib_buffer_pool_get_cb = &vlib_buffer_pool_get_internal;
  bm->cb.vlib_buffer_pool_put_cb = &vlib_buffer_pool_put_internal;
  clib_spinlock_init (&bm->buffer_known_hash_lockp);

  err = clib_sysfs_read ("/sys/devices/system/node/possible", "%U",
			 unformat_bitmap_list, &bmp);
  if (err)
    {
      /* no info from sysfs, assuming that only numa 0 exists */
      clib_error_free (err);
      bmp = clib_bitmap_set (bmp, 0, 1);
    }

  /* *INDENT-OFF* */
  clib_bitmap_foreach (numa_node, bmp, {
      if ((err = vlib_buffer_main_init_numa_node(vm, numa_node)))
	  goto done;
    });
  /* *INDENT-ON* */

  bm->n_numa_nodes = clib_bitmap_last_set (bmp) + 1;

done:
  vec_free (bmp);
  return err;
}

static clib_error_t *
vlib_buffers_configure (vlib_main_t * vm, unformat_input_t * input)
{
  u32 size_in_mb;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "memory-size-in-mb %d", &size_in_mb))
	vlib_buffer_physmem_sz = size_in_mb << 20;
      else
	return unformat_parse_error (input);
    }

  unformat_free (input);
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (vlib_buffers_configure, "buffers");


/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

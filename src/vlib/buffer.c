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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

vlib_buffer_callbacks_t *vlib_buffer_callbacks = 0;
static u32 vlib_buffer_physmem_sz = 32 << 20;

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
  uword indent = format_get_indent (s);

  s = format (s, "current data %d, length %d, free-list %d, clone-count %u",
	      b->current_data, b->current_length,
	      vlib_buffer_get_free_list_index (b), b->n_add_refs);

  if (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID)
    s = format (s, ", totlen-nifb %d",
		b->total_length_not_including_first_buffer);

  if (b->flags & VLIB_BUFFER_IS_TRACED)
    s = format (s, ", trace 0x%x", b->trace_index);

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
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *fl;

  if (pool_is_free_index
      (bm->buffer_free_list_pool, vlib_buffer_get_free_list_index (b)))
    return format (0, "unknown free list 0x%x",
		   vlib_buffer_get_free_list_index (b));

  fl =
    pool_elt_at_index (bm->buffer_free_list_pool,
		       vlib_buffer_get_free_list_index (b));

  if ((signed) b->current_data < (signed) -VLIB_BUFFER_PRE_DATA_SIZE)
    return format (0, "current data %d before pre-data", b->current_data);

  if (b->current_data + b->current_length > fl->n_data_bytes)
    return format (0, "%d-%d beyond end of buffer %d",
		   b->current_data, b->current_length, fl->n_data_bytes);

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
static void
vlib_buffer_validate_alloc_free (vlib_main_t * vm,
				 u32 * buffers,
				 uword n_buffers,
				 vlib_buffer_known_state_t expected_state)
{
  u32 *b;
  uword i, bi, is_free;

  if (CLIB_DEBUG == 0)
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

      vlib_buffer_set_known_state
	(vm, bi,
	 is_free ? VLIB_BUFFER_KNOWN_FREE : VLIB_BUFFER_KNOWN_ALLOCATED);
    }
}

void
vlib_buffer_merge_free_lists (vlib_buffer_free_list_t * dst,
			      vlib_buffer_free_list_t * src)
{
  uword l;
  u32 *d;

  l = vec_len (src->buffers);
  if (l > 0)
    {
      vec_add2_aligned (dst->buffers, d, l, CLIB_CACHE_LINE_BYTES);
      clib_memcpy (d, src->buffers, l * sizeof (d[0]));
      vec_free (src->buffers);
    }
}

/* Add buffer free list. */
static u32
vlib_buffer_create_free_list_helper (vlib_main_t * vm,
				     u32 n_data_bytes,
				     u32 is_public, u32 is_default, u8 * name)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  int i;

  ASSERT (vlib_get_thread_index () == 0);

  if (!is_default && pool_elts (bm->buffer_free_list_pool) == 0)
    {
      u32 default_free_free_list_index;

      /* *INDENT-OFF* */
      default_free_free_list_index =
        vlib_buffer_create_free_list_helper
        (vm,
         /* default buffer size */ VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES,
         /* is_public */ 1,
         /* is_default */ 1,
         (u8 *) "default");
      /* *INDENT-ON* */
      ASSERT (default_free_free_list_index ==
	      VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

      if (n_data_bytes == VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES && is_public)
	return default_free_free_list_index;
    }

  pool_get_aligned (bm->buffer_free_list_pool, f, CLIB_CACHE_LINE_BYTES);

  memset (f, 0, sizeof (f[0]));
  f->index = f - bm->buffer_free_list_pool;
  f->n_data_bytes = vlib_buffer_round_size (n_data_bytes);
  f->min_n_buffers_each_physmem_alloc = VLIB_FRAME_SIZE;
  f->name = clib_mem_is_vec (name) ? name : format (0, "%s", name);

  /* Setup free buffer template. */
  vlib_buffer_set_free_list_index (&f->buffer_init_template, f->index);
  f->buffer_init_template.n_add_refs = 0;

  if (is_public)
    {
      uword *p = hash_get (bm->free_list_by_size, f->n_data_bytes);
      if (!p)
	hash_set (bm->free_list_by_size, f->n_data_bytes, f->index);
    }

  clib_spinlock_init (&f->global_buffers_lock);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      vlib_buffer_main_t *wbm = vlib_mains[i]->buffer_main;
      vlib_buffer_free_list_t *wf;
      pool_get_aligned (wbm->buffer_free_list_pool,
			wf, CLIB_CACHE_LINE_BYTES);
      ASSERT (f - bm->buffer_free_list_pool ==
	      wf - wbm->buffer_free_list_pool);
      wf[0] = f[0];
      wf->buffers = 0;
      wf->n_alloc = 0;
    }

  return f->index;
}

u32
vlib_buffer_create_free_list (vlib_main_t * vm, u32 n_data_bytes,
			      char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  return vlib_buffer_create_free_list_helper (vm, n_data_bytes,
					      /* is_public */ 0,
					      /* is_default */ 0,
					      name);
}

u32
vlib_buffer_get_or_create_free_list (vlib_main_t * vm, u32 n_data_bytes,
				     char *fmt, ...)
{
  u32 i = vlib_buffer_get_free_list_with_size (vm, n_data_bytes);

  if (i == ~0)
    {
      va_list va;
      u8 *name;

      va_start (va, fmt);
      name = va_format (0, fmt, &va);
      va_end (va);

      i = vlib_buffer_create_free_list_helper (vm, n_data_bytes,
					       /* is_public */ 1,
					       /* is_default */ 0,
					       name);
    }

  return i;
}

static void
del_free_list (vlib_main_t * vm, vlib_buffer_free_list_t * f)
{
  u32 i;

  for (i = 0; i < vec_len (f->buffer_memory_allocated); i++)
    vm->os_physmem_free (vm, vm->buffer_main->physmem_region,
			 f->buffer_memory_allocated[i]);
  vec_free (f->name);
  vec_free (f->buffer_memory_allocated);
  vec_free (f->buffers);
}

/* Add buffer free list. */
void
vlib_buffer_delete_free_list_internal (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  u32 merge_index;
  int i;

  ASSERT (vlib_get_thread_index () == 0);

  f = vlib_buffer_get_free_list (vm, free_list_index);

  ASSERT (vec_len (f->buffers) == f->n_alloc);
  merge_index = vlib_buffer_get_free_list_with_size (vm, f->n_data_bytes);
  if (merge_index != ~0 && merge_index != free_list_index)
    {
      vlib_buffer_merge_free_lists (pool_elt_at_index
				    (bm->buffer_free_list_pool, merge_index),
				    f);
    }

  del_free_list (vm, f);

  /* Poison it. */
  memset (f, 0xab, sizeof (f[0]));

  pool_put (bm->buffer_free_list_pool, f);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      bm = vlib_mains[i]->buffer_main;
      f = vlib_buffer_get_free_list (vlib_mains[i], free_list_index);;
      memset (f, 0xab, sizeof (f[0]));
      pool_put (bm->buffer_free_list_pool, f);
    }
}

/* Make sure free list has at least given number of free buffers. */
static uword
fill_free_list (vlib_main_t * vm,
		vlib_buffer_free_list_t * fl, uword min_free_buffers)
{
  vlib_buffer_t *buffers, *b;
  vlib_buffer_free_list_t *mfl;
  int n, n_bytes, i;
  u32 *bi;
  u32 n_remaining, n_alloc, n_this_chunk;

  /* Already have enough free buffers on free list? */
  n = min_free_buffers - vec_len (fl->buffers);
  if (n <= 0)
    return min_free_buffers;

  mfl = vlib_buffer_get_free_list (vlib_mains[0], fl->index);
  if (vec_len (mfl->global_buffers) > 0)
    {
      int n_copy, n_left;
      clib_spinlock_lock (&mfl->global_buffers_lock);
      n_copy = clib_min (vec_len (mfl->global_buffers), n);
      n_left = vec_len (mfl->global_buffers) - n_copy;
      vec_add_aligned (fl->buffers, mfl->global_buffers + n_left, n_copy,
		       CLIB_CACHE_LINE_BYTES);
      _vec_len (mfl->global_buffers) = n_left;
      clib_spinlock_unlock (&mfl->global_buffers_lock);
      n = min_free_buffers - vec_len (fl->buffers);
      if (n <= 0)
	return min_free_buffers;
    }

  /* Always allocate round number of buffers. */
  n = round_pow2 (n, CLIB_CACHE_LINE_BYTES / sizeof (u32));

  /* Always allocate new buffers in reasonably large sized chunks. */
  n = clib_max (n, fl->min_n_buffers_each_physmem_alloc);

  n_remaining = n;
  n_alloc = 0;
  while (n_remaining > 0)
    {
      n_this_chunk = clib_min (n_remaining, 16);

      n_bytes = n_this_chunk * (sizeof (b[0]) + fl->n_data_bytes);

      /* drb: removed power-of-2 ASSERT */
      buffers =
	vm->os_physmem_alloc_aligned (vm, vm->buffer_main->physmem_region,
				      n_bytes, sizeof (vlib_buffer_t));
      if (!buffers)
	return n_alloc;

      /* Record chunk as being allocated so we can free it later. */
      vec_add1 (fl->buffer_memory_allocated, buffers);

      fl->n_alloc += n_this_chunk;
      n_alloc += n_this_chunk;
      n_remaining -= n_this_chunk;

      b = buffers;
      vec_add2_aligned (fl->buffers, bi, n_this_chunk, CLIB_CACHE_LINE_BYTES);
      for (i = 0; i < n_this_chunk; i++)
	{
	  bi[i] = vlib_get_buffer_index (vm, b);

	  if (CLIB_DEBUG > 0)
	    vlib_buffer_set_known_state (vm, bi[i], VLIB_BUFFER_KNOWN_FREE);
	  b = vlib_buffer_next_contiguous (b, fl->n_data_bytes);
	}

      memset (buffers, 0, n_bytes);

      /* Initialize all new buffers. */
      b = buffers;
      for (i = 0; i < n_this_chunk; i++)
	{
	  vlib_buffer_init_for_free_list (b, fl);
	  b = vlib_buffer_next_contiguous (b, fl->n_data_bytes);
	}

      if (fl->buffer_init_function)
	fl->buffer_init_function (vm, fl, bi, n_this_chunk);
    }
  return n_alloc;
}

static u32
alloc_from_free_list (vlib_main_t * vm,
		      vlib_buffer_free_list_t * free_list,
		      u32 * alloc_buffers, u32 n_alloc_buffers)
{
  u32 *dst, *src;
  uword len;
  uword n_filled;

  dst = alloc_buffers;

  n_filled = fill_free_list (vm, free_list, n_alloc_buffers);
  if (n_filled == 0)
    return 0;

  len = vec_len (free_list->buffers);
  ASSERT (len >= n_alloc_buffers);

  src = free_list->buffers + len - n_alloc_buffers;
  clib_memcpy (dst, src, n_alloc_buffers * sizeof (u32));

  _vec_len (free_list->buffers) -= n_alloc_buffers;

  /* Verify that buffers are known free. */
  vlib_buffer_validate_alloc_free (vm, alloc_buffers,
				   n_alloc_buffers, VLIB_BUFFER_KNOWN_FREE);

  return n_alloc_buffers;
}


/* Allocate a given number of buffers into given array.
   Returns number actually allocated which will be either zero or
   number requested. */
static u32
vlib_buffer_alloc_internal (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  return alloc_from_free_list
    (vm,
     pool_elt_at_index (bm->buffer_free_list_pool,
			VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX),
     buffers, n_buffers);
}

static u32
vlib_buffer_alloc_from_free_list_internal (vlib_main_t * vm,
					   u32 * buffers,
					   u32 n_buffers, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  f = pool_elt_at_index (bm->buffer_free_list_pool, free_list_index);
  return alloc_from_free_list (vm, f, buffers, n_buffers);
}

void *
vlib_set_buffer_free_callback (vlib_main_t * vm, void *fp)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  void *rv = bm->buffer_free_callback;

  bm->buffer_free_callback = fp;
  return rv;
}

static_always_inline void
vlib_buffer_free_inline (vlib_main_t * vm,
			 u32 * buffers, u32 n_buffers, u32 follow_buffer_next)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *fl;
  u32 fi;
  int i;
  u32 (*cb) (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
	     u32 follow_buffer_next);

  cb = bm->buffer_free_callback;

  if (PREDICT_FALSE (cb != 0))
    n_buffers = (*cb) (vm, buffers, n_buffers, follow_buffer_next);

  if (!n_buffers)
    return;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b;
      u32 bi = buffers[i];

      b = vlib_get_buffer (vm, bi);

      fl = vlib_buffer_get_buffer_free_list (vm, b, &fi);

      /* The only current use of this callback: multicast recycle */
      if (PREDICT_FALSE (fl->buffers_added_to_freelist_function != 0))
	{
	  int j;

	  vlib_buffer_add_to_free_list
	    (vm, fl, buffers[i], (b->flags & VLIB_BUFFER_RECYCLE) == 0);

	  for (j = 0; j < vec_len (bm->announce_list); j++)
	    {
	      if (fl == bm->announce_list[j])
		goto already_announced;
	    }
	  vec_add1 (bm->announce_list, fl);
	already_announced:
	  ;
	}
      else
	{
	  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_RECYCLE) == 0))
	    {
	      u32 flags, next;

	      do
		{
		  vlib_buffer_t *nb = vlib_get_buffer (vm, bi);
		  flags = nb->flags;
		  next = nb->next_buffer;
		  if (nb->n_add_refs)
		    nb->n_add_refs--;
		  else
		    {
		      vlib_buffer_validate_alloc_free (vm, &bi, 1,
						       VLIB_BUFFER_KNOWN_ALLOCATED);
		      vlib_buffer_add_to_free_list (vm, fl, bi, 1);
		    }
		  bi = next;
		}
	      while (follow_buffer_next
		     && (flags & VLIB_BUFFER_NEXT_PRESENT));

	    }
	}
    }
  if (vec_len (bm->announce_list))
    {
      vlib_buffer_free_list_t *fl;
      for (i = 0; i < vec_len (bm->announce_list); i++)
	{
	  fl = bm->announce_list[i];
	  fl->buffers_added_to_freelist_function (vm, fl);
	}
      _vec_len (bm->announce_list) = 0;
    }
}

static void
vlib_buffer_free_internal (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   1);
}

static void
vlib_buffer_free_no_next_internal (vlib_main_t * vm, u32 * buffers,
				   u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   0);
}

/* Copy template packet data into buffers as they are allocated. */
static void __attribute__ ((unused))
vlib_packet_template_buffer_init (vlib_main_t * vm,
				  vlib_buffer_free_list_t * fl,
				  u32 * buffers, u32 n_buffers)
{
  vlib_packet_template_t *t =
    uword_to_pointer (fl->buffer_init_function_opaque,
		      vlib_packet_template_t *);
  uword i;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
      ASSERT (b->current_length == vec_len (t->packet_data));
      clib_memcpy (vlib_buffer_get_current (b), t->packet_data,
		   b->current_length);
    }
}

void
vlib_packet_template_init (vlib_main_t * vm,
			   vlib_packet_template_t * t,
			   void *packet_data,
			   uword n_packet_data_bytes,
			   uword min_n_buffers_each_physmem_alloc,
			   char *fmt, ...)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  va_list va;
  u8 *name;
  vlib_buffer_free_list_t *fl;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  if (bm->cb.vlib_packet_template_init_cb)
    bm->cb.vlib_packet_template_init_cb (vm, (void *) t, packet_data,
					 n_packet_data_bytes,
					 min_n_buffers_each_physmem_alloc,
					 name);

  vlib_worker_thread_barrier_sync (vm);

  memset (t, 0, sizeof (t[0]));

  vec_add (t->packet_data, packet_data, n_packet_data_bytes);
  t->min_n_buffers_each_physmem_alloc = min_n_buffers_each_physmem_alloc;

  t->free_list_index = vlib_buffer_create_free_list_helper
    (vm, n_packet_data_bytes,
     /* is_public */ 1,
     /* is_default */ 0,
     name);

  ASSERT (t->free_list_index != 0);
  fl = vlib_buffer_get_free_list (vm, t->free_list_index);
  fl->min_n_buffers_each_physmem_alloc = t->min_n_buffers_each_physmem_alloc;

  fl->buffer_init_function = vlib_packet_template_buffer_init;
  fl->buffer_init_function_opaque = pointer_to_uword (t);

  fl->buffer_init_template.current_data = 0;
  fl->buffer_init_template.current_length = n_packet_data_bytes;
  fl->buffer_init_template.flags = 0;
  fl->buffer_init_template.n_add_refs = 0;
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
  clib_memcpy (vlib_buffer_get_current (b),
	       t->packet_data, vec_len (t->packet_data));
  b->current_length = vec_len (t->packet_data);

  return b->data;
}

void
vlib_packet_template_get_packet_helper (vlib_main_t * vm,
					vlib_packet_template_t * t)
{
  word n = t->min_n_buffers_each_physmem_alloc;
  word l = vec_len (t->packet_data);
  word n_alloc;

  ASSERT (l > 0);
  ASSERT (vec_len (t->free_buffers) == 0);

  vec_validate (t->free_buffers, n - 1);
  n_alloc = vlib_buffer_alloc_from_free_list (vm, t->free_buffers,
					      n, t->free_list_index);
  _vec_len (t->free_buffers) = n_alloc;
}

/* Append given data to end of buffer, possibly allocating new buffers. */
u32
vlib_buffer_add_data (vlib_main_t * vm,
		      u32 free_list_index,
		      u32 buffer_index, void *data, u32 n_data_bytes)
{
  u32 n_buffer_bytes, n_left, n_left_this_buffer, bi;
  vlib_buffer_t *b;
  void *d;

  bi = buffer_index;
  if (bi == 0
      && 1 != vlib_buffer_alloc_from_free_list (vm, &bi, 1, free_list_index))
    goto out_of_buffers;

  d = data;
  n_left = n_data_bytes;
  n_buffer_bytes = vlib_buffer_free_list_buffer_size (vm, free_list_index);

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
      clib_memcpy (vlib_buffer_get_current (b) + b->current_length, d, n);
      b->current_length += n;
      n_left -= n;
      if (n_left == 0)
	break;

      d += n;
      if (1 !=
	  vlib_buffer_alloc_from_free_list (vm, &b->next_buffer, 1,
					    free_list_index))
	goto out_of_buffers;

      b->flags |= VLIB_BUFFER_NEXT_PRESENT;

      b = vlib_get_buffer (vm, b->next_buffer);
    }

  return bi;

out_of_buffers:
  clib_error ("out of buffers");
  return bi;
}

u16
vlib_buffer_chain_append_data_with_alloc (vlib_main_t * vm,
					  u32 free_list_index,
					  vlib_buffer_t * first,
					  vlib_buffer_t ** last,
					  void *data, u16 data_len)
{
  vlib_buffer_t *l = *last;
  u32 n_buffer_bytes =
    vlib_buffer_free_list_buffer_size (vm, free_list_index);
  u16 copied = 0;
  ASSERT (n_buffer_bytes >= l->current_length + l->current_data);
  while (data_len)
    {
      u16 max = n_buffer_bytes - l->current_length - l->current_data;
      if (max == 0)
	{
	  if (1 !=
	      vlib_buffer_alloc_from_free_list (vm, &l->next_buffer, 1,
						free_list_index))
	    return copied;
	  *last = l = vlib_buffer_chain_buffer (vm, first, l, l->next_buffer);
	  max = n_buffer_bytes - l->current_length - l->current_data;
	}

      u16 len = (data_len > max) ? max : data_len;
      clib_memcpy (vlib_buffer_get_current (l) + l->current_length,
		   data + copied, len);
      vlib_buffer_chain_increase_length (first, l, len);
      data_len -= len;
      copied += len;
    }
  return copied;
}

void
vlib_buffer_add_mem_range (vlib_main_t * vm, uword start, uword size)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

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
}

static u8 *
format_vlib_buffer_free_list (u8 * s, va_list * va)
{
  vlib_buffer_free_list_t *f = va_arg (*va, vlib_buffer_free_list_t *);
  u32 threadnum = va_arg (*va, u32);
  uword bytes_alloc, bytes_free, n_free, size;

  if (!f)
    return format (s, "%=7s%=30s%=12s%=12s%=12s%=12s%=12s%=12s",
		   "Thread", "Name", "Index", "Size", "Alloc", "Free",
		   "#Alloc", "#Free");

  size = sizeof (vlib_buffer_t) + f->n_data_bytes;
  n_free = vec_len (f->buffers);
  bytes_alloc = size * f->n_alloc;
  bytes_free = size * n_free;

  s = format (s, "%7d%30v%12d%12d%=12U%=12U%=12d%=12d", threadnum,
	      f->name, f->index, f->n_data_bytes,
	      format_memory_size, bytes_alloc,
	      format_memory_size, bytes_free, f->n_alloc, n_free);

  return s;
}

static clib_error_t *
show_buffers (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_buffer_main_t *bm;
  vlib_buffer_free_list_t *f;
  vlib_main_t *curr_vm;
  u32 vm_index = 0;

  vlib_cli_output (vm, "%U", format_vlib_buffer_free_list, 0, 0);

  do
    {
      curr_vm = vlib_mains[vm_index];
      bm = curr_vm->buffer_main;

    /* *INDENT-OFF* */
    pool_foreach (f, bm->buffer_free_list_pool, ({
      vlib_cli_output (vm, "%U", format_vlib_buffer_free_list, f, vm_index);
    }));
    /* *INDENT-ON* */

      vm_index++;
    }
  while (vm_index < vec_len (vlib_mains));

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
vlib_buffer_main_init (struct vlib_main_t * vm)
{
  vlib_buffer_main_t *bm;
  clib_error_t *error;

  vec_validate (vm->buffer_main, 0);
  bm = vm->buffer_main;

  if (vlib_buffer_callbacks)
    {
      /* external plugin has registered own buffer callbacks
         so we just copy them  and quit */
      vlib_buffer_main_t *bm = vm->buffer_main;
      clib_memcpy (&bm->cb, vlib_buffer_callbacks,
		   sizeof (vlib_buffer_callbacks_t));
      bm->callbacks_registered = 1;
      return 0;
    }

  bm->cb.vlib_buffer_alloc_cb = &vlib_buffer_alloc_internal;
  bm->cb.vlib_buffer_alloc_from_free_list_cb =
    &vlib_buffer_alloc_from_free_list_internal;
  bm->cb.vlib_buffer_free_cb = &vlib_buffer_free_internal;
  bm->cb.vlib_buffer_free_no_next_cb = &vlib_buffer_free_no_next_internal;
  bm->cb.vlib_buffer_delete_free_list_cb =
    &vlib_buffer_delete_free_list_internal;
  clib_spinlock_init (&bm->buffer_known_hash_lockp);

  /* allocate default region */
  error = vlib_physmem_region_alloc (vm, "buffers",
				     vlib_buffer_physmem_sz, 0,
				     VLIB_PHYSMEM_F_INIT_MHEAP |
				     VLIB_PHYSMEM_F_HAVE_BUFFERS,
				     &bm->physmem_region);

  if (error == 0)
    return 0;

  clib_error_free (error);

  /* we my be running unpriviledged, so try to allocate fake physmem */
  error = vlib_physmem_region_alloc (vm, "buffers (fake)",
				     vlib_buffer_physmem_sz, 0,
				     VLIB_PHYSMEM_F_FAKE |
				     VLIB_PHYSMEM_F_INIT_MHEAP |
				     VLIB_PHYSMEM_F_HAVE_BUFFERS,
				     &bm->physmem_region);
  return error;
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

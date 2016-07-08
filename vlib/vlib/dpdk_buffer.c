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

#include <rte_config.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <vlib/vlib.h>

#pragma weak rte_mem_virt2phy
#pragma weak rte_eal_has_hugepages
#pragma weak rte_socket_id
#pragma weak rte_pktmbuf_pool_create

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

  s = format (s, "current data %d, length %d, free-list %d",
	      b->current_data, b->current_length, b->free_list_index);

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

      s = format (s, "\n%Unext-buffer 0x%x, segment length %d",
		  format_white_space, indent, next_buffer, b->current_length);
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

vlib_main_t **vlib_mains;

/* Aligned copy routine. */
void
vlib_aligned_memcpy (void *_dst, void *_src, int n_bytes)
{
  vlib_copy_unit_t *dst = _dst;
  vlib_copy_unit_t *src = _src;

  /* Arguments must be naturally aligned. */
  ASSERT (pointer_to_uword (dst) % sizeof (dst[0]) == 0);
  ASSERT (pointer_to_uword (src) % sizeof (src[0]) == 0);
  ASSERT (n_bytes % sizeof (dst[0]) == 0);

  if (4 * sizeof (dst[0]) == CLIB_CACHE_LINE_BYTES)
    {
      CLIB_PREFETCH (dst + 0, 4 * sizeof (dst[0]), WRITE);
      CLIB_PREFETCH (src + 0, 4 * sizeof (src[0]), READ);

      while (n_bytes >= 4 * sizeof (dst[0]))
	{
	  dst += 4;
	  src += 4;
	  n_bytes -= 4 * sizeof (dst[0]);
	  CLIB_PREFETCH (dst, 4 * sizeof (dst[0]), WRITE);
	  CLIB_PREFETCH (src, 4 * sizeof (src[0]), READ);
	  dst[-4] = src[-4];
	  dst[-3] = src[-3];
	  dst[-2] = src[-2];
	  dst[-1] = src[-1];
	}
    }
  else if (8 * sizeof (dst[0]) == CLIB_CACHE_LINE_BYTES)
    {
      CLIB_PREFETCH (dst + 0, 8 * sizeof (dst[0]), WRITE);
      CLIB_PREFETCH (src + 0, 8 * sizeof (src[0]), READ);

      while (n_bytes >= 8 * sizeof (dst[0]))
	{
	  dst += 8;
	  src += 8;
	  n_bytes -= 8 * sizeof (dst[0]);
	  CLIB_PREFETCH (dst, 8 * sizeof (dst[0]), WRITE);
	  CLIB_PREFETCH (src, 8 * sizeof (src[0]), READ);
	  dst[-8] = src[-8];
	  dst[-7] = src[-7];
	  dst[-6] = src[-6];
	  dst[-5] = src[-5];
	  dst[-4] = src[-4];
	  dst[-3] = src[-3];
	  dst[-2] = src[-2];
	  dst[-1] = src[-1];
	}
    }
  else
    /* Cache line size unknown: fall back to slow version. */ ;

  while (n_bytes > 0)
    {
      *dst++ = *src++;
      n_bytes -= 1 * sizeof (dst[0]);
    }
}

#define BUFFERS_PER_COPY (sizeof (vlib_copy_unit_t) / sizeof (u32))

/* Make sure we have at least given number of unaligned buffers. */
static void
fill_unaligned (vlib_main_t * vm,
		vlib_buffer_free_list_t * free_list,
		uword n_unaligned_buffers)
{
  word la = vec_len (free_list->aligned_buffers);
  word lu = vec_len (free_list->unaligned_buffers);

  /* Aligned come in aligned copy-sized chunks. */
  ASSERT (la % BUFFERS_PER_COPY == 0);

  ASSERT (la >= n_unaligned_buffers);

  while (lu < n_unaligned_buffers)
    {
      /* Copy 4 buffers from end of aligned vector to unaligned vector. */
      vec_add (free_list->unaligned_buffers,
	       free_list->aligned_buffers + la - BUFFERS_PER_COPY,
	       BUFFERS_PER_COPY);
      la -= BUFFERS_PER_COPY;
      lu += BUFFERS_PER_COPY;
    }
  _vec_len (free_list->aligned_buffers) = la;
}

/* After free aligned buffers may not contain even sized chunks. */
static void
trim_aligned (vlib_buffer_free_list_t * f)
{
  uword l, n_trim;

  /* Add unaligned to aligned before trim. */
  l = vec_len (f->unaligned_buffers);
  if (l > 0)
    {
      vec_add_aligned (f->aligned_buffers, f->unaligned_buffers, l,
		       /* align */ sizeof (vlib_copy_unit_t));

      _vec_len (f->unaligned_buffers) = 0;
    }

  /* Remove unaligned buffers from end of aligned vector and save for next trim. */
  l = vec_len (f->aligned_buffers);
  n_trim = l % BUFFERS_PER_COPY;
  if (n_trim)
    {
      /* Trim aligned -> unaligned. */
      vec_add (f->unaligned_buffers, f->aligned_buffers + l - n_trim, n_trim);

      /* Remove from aligned. */
      _vec_len (f->aligned_buffers) = l - n_trim;
    }
}

static void
merge_free_lists (vlib_buffer_free_list_t * dst,
		  vlib_buffer_free_list_t * src)
{
  uword l;
  u32 *d;

  trim_aligned (src);
  trim_aligned (dst);

  l = vec_len (src->aligned_buffers);
  if (l > 0)
    {
      vec_add2_aligned (dst->aligned_buffers, d, l,
			/* align */ sizeof (vlib_copy_unit_t));
      vlib_aligned_memcpy (d, src->aligned_buffers, l * sizeof (d[0]));
      vec_free (src->aligned_buffers);
    }

  l = vec_len (src->unaligned_buffers);
  if (l > 0)
    {
      vec_add (dst->unaligned_buffers, src->unaligned_buffers, l);
      vec_free (src->unaligned_buffers);
    }
}

always_inline u32
vlib_buffer_get_free_list_with_size (vlib_main_t * vm, u32 size)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  size = vlib_buffer_round_size (size);
  uword *p = hash_get (bm->free_list_by_size, size);
  return p ? p[0] : ~0;
}

/* Add buffer free list. */
static u32
vlib_buffer_create_free_list_helper (vlib_main_t * vm,
				     u32 n_data_bytes,
				     u32 is_public, u32 is_default, u8 * name)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;

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
  f->min_n_buffers_each_physmem_alloc = 16;
  f->name = clib_mem_is_heap_object (name) ? name : format (0, "%s", name);

  /* Setup free buffer template. */
  f->buffer_init_template.free_list_index = f->index;

  if (is_public)
    {
      uword *p = hash_get (bm->free_list_by_size, f->n_data_bytes);
      if (!p)
	hash_set (bm->free_list_by_size, f->n_data_bytes, f->index);
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
  struct rte_mbuf *mb;
  vlib_buffer_t *b;

  for (i = 0; i < vec_len (f->unaligned_buffers); i++)
    {
      b = vlib_get_buffer (vm, f->unaligned_buffers[i]);
      mb = rte_mbuf_from_vlib_buffer (b);
      ASSERT (rte_mbuf_refcnt_read (mb) == 1);
      rte_pktmbuf_free (mb);
    }
  for (i = 0; i < vec_len (f->aligned_buffers); i++)
    {
      b = vlib_get_buffer (vm, f->aligned_buffers[i]);
      mb = rte_mbuf_from_vlib_buffer (b);
      ASSERT (rte_mbuf_refcnt_read (mb) == 1);
      rte_pktmbuf_free (mb);
    }
  vec_free (f->name);
  vec_free (f->unaligned_buffers);
  vec_free (f->aligned_buffers);
}

/* Add buffer free list. */
void
vlib_buffer_delete_free_list (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  u32 merge_index;

  f = vlib_buffer_get_free_list (vm, free_list_index);

  merge_index = vlib_buffer_get_free_list_with_size (vm, f->n_data_bytes);
  if (merge_index != ~0 && merge_index != free_list_index)
    {
      merge_free_lists (pool_elt_at_index (bm->buffer_free_list_pool,
					   merge_index), f);
    }

  del_free_list (vm, f);

  /* Poison it. */
  memset (f, 0xab, sizeof (f[0]));

  pool_put (bm->buffer_free_list_pool, f);
}

/* Make sure free list has at least given number of free buffers. */
static uword
fill_free_list (vlib_main_t * vm,
		vlib_buffer_free_list_t * fl, uword min_free_buffers)
{
  vlib_buffer_t *b;
  int n, i;
  u32 bi;
  u32 n_remaining = 0, n_alloc = 0;
  unsigned socket_id = rte_socket_id ? rte_socket_id () : 0;
  struct rte_mempool *rmp = vm->buffer_main->pktmbuf_pools[socket_id];
  struct rte_mbuf *mb;

  /* Too early? */
  if (PREDICT_FALSE (rmp == 0))
    return 0;

  trim_aligned (fl);

  /* Already have enough free buffers on free list? */
  n = min_free_buffers - vec_len (fl->aligned_buffers);
  if (n <= 0)
    return min_free_buffers;

  /* Always allocate round number of buffers. */
  n = round_pow2 (n, BUFFERS_PER_COPY);

  /* Always allocate new buffers in reasonably large sized chunks. */
  n = clib_max (n, fl->min_n_buffers_each_physmem_alloc);

  vec_validate (vm->mbuf_alloc_list, n - 1);

  if (rte_mempool_get_bulk (rmp, vm->mbuf_alloc_list, n) < 0)
    return 0;

  _vec_len (vm->mbuf_alloc_list) = n;

  for (i = 0; i < n; i++)
    {
      mb = vm->mbuf_alloc_list[i];

      ASSERT (rte_mbuf_refcnt_read (mb) == 0);
      rte_mbuf_refcnt_set (mb, 1);
      mb->next = NULL;
      mb->data_off = RTE_PKTMBUF_HEADROOM;
      mb->nb_segs = 1;

      b = vlib_buffer_from_rte_mbuf (mb);
      bi = vlib_get_buffer_index (vm, b);

      vec_add1_aligned (fl->aligned_buffers, bi, sizeof (vlib_copy_unit_t));
      n_alloc++;
      n_remaining--;

      vlib_buffer_init_for_free_list (b, fl);

      if (fl->buffer_init_function)
	fl->buffer_init_function (vm, fl, &bi, 1);
    }

  fl->n_alloc += n;

  return n;
}

always_inline uword
copy_alignment (u32 * x)
{
  return (pointer_to_uword (x) / sizeof (x[0])) % BUFFERS_PER_COPY;
}

static u32
alloc_from_free_list (vlib_main_t * vm,
		      vlib_buffer_free_list_t * free_list,
		      u32 * alloc_buffers, u32 n_alloc_buffers)
{
  u32 *dst, *u_src;
  uword u_len, n_left;
  uword n_unaligned_start, n_unaligned_end, n_filled;

  n_left = n_alloc_buffers;
  dst = alloc_buffers;
  n_unaligned_start = ((BUFFERS_PER_COPY - copy_alignment (dst))
		       & (BUFFERS_PER_COPY - 1));

  n_filled = fill_free_list (vm, free_list, n_alloc_buffers);
  if (n_filled == 0)
    return 0;

  n_left = n_filled < n_left ? n_filled : n_left;
  n_alloc_buffers = n_left;

  if (n_unaligned_start >= n_left)
    {
      n_unaligned_start = n_left;
      n_unaligned_end = 0;
    }
  else
    n_unaligned_end = copy_alignment (dst + n_alloc_buffers);

  fill_unaligned (vm, free_list, n_unaligned_start + n_unaligned_end);

  u_len = vec_len (free_list->unaligned_buffers);
  u_src = free_list->unaligned_buffers + u_len - 1;

  if (n_unaligned_start)
    {
      uword n_copy = n_unaligned_start;
      if (n_copy > n_left)
	n_copy = n_left;
      n_left -= n_copy;

      while (n_copy > 0)
	{
	  *dst++ = *u_src--;
	  n_copy--;
	  u_len--;
	}

      /* Now dst should be aligned. */
      if (n_left > 0)
	ASSERT (pointer_to_uword (dst) % sizeof (vlib_copy_unit_t) == 0);
    }

  /* Aligned copy. */
  {
    vlib_copy_unit_t *d, *s;
    uword n_copy;

    if (vec_len (free_list->aligned_buffers) <
	((n_left / BUFFERS_PER_COPY) * BUFFERS_PER_COPY))
      abort ();

    n_copy = n_left / BUFFERS_PER_COPY;
    n_left = n_left % BUFFERS_PER_COPY;

    /* Remove buffers from aligned free list. */
    _vec_len (free_list->aligned_buffers) -= n_copy * BUFFERS_PER_COPY;

    s = (vlib_copy_unit_t *) vec_end (free_list->aligned_buffers);
    d = (vlib_copy_unit_t *) dst;

    /* Fast path loop. */
    while (n_copy >= 4)
      {
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	d[3] = s[3];
	n_copy -= 4;
	s += 4;
	d += 4;
      }

    while (n_copy >= 1)
      {
	d[0] = s[0];
	n_copy -= 1;
	s += 1;
	d += 1;
      }

    dst = (void *) d;
  }

  /* Unaligned copy. */
  ASSERT (n_unaligned_end == n_left);
  while (n_left > 0)
    {
      *dst++ = *u_src--;
      n_left--;
      u_len--;
    }

  if (!free_list->unaligned_buffers)
    ASSERT (u_len == 0);
  else
    _vec_len (free_list->unaligned_buffers) = u_len;

  return n_alloc_buffers;
}

/* Allocate a given number of buffers into given array.
   Returns number actually allocated which will be either zero or
   number requested. */
u32
vlib_buffer_alloc (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  return alloc_from_free_list
    (vm,
     pool_elt_at_index (bm->buffer_free_list_pool,
			VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX),
     buffers, n_buffers);
}

u32
vlib_buffer_alloc_from_free_list (vlib_main_t * vm,
				  u32 * buffers,
				  u32 n_buffers, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  f = pool_elt_at_index (bm->buffer_free_list_pool, free_list_index);
  return alloc_from_free_list (vm, f, buffers, n_buffers);
}

always_inline void
add_buffer_to_free_list (vlib_main_t * vm,
			 vlib_buffer_free_list_t * f,
			 u32 buffer_index, u8 do_init)
{
  vlib_buffer_t *b;
  b = vlib_get_buffer (vm, buffer_index);
  if (PREDICT_TRUE (do_init))
    vlib_buffer_init_for_free_list (b, f);
  vec_add1_aligned (f->aligned_buffers, buffer_index,
		    sizeof (vlib_copy_unit_t));
}

always_inline vlib_buffer_free_list_t *
buffer_get_free_list (vlib_main_t * vm, vlib_buffer_t * b, u32 * index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  u32 i;

  *index = i = b->free_list_index;
  return pool_elt_at_index (bm->buffer_free_list_pool, i);
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
      struct rte_mbuf *mb;

      b = vlib_get_buffer (vm, buffers[i]);

      fl = buffer_get_free_list (vm, b, &fi);

      /* The only current use of this callback: multicast recycle */
      if (PREDICT_FALSE (fl->buffers_added_to_freelist_function != 0))
	{
	  int j;

	  add_buffer_to_free_list
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
	      mb = rte_mbuf_from_vlib_buffer (b);
	      ASSERT (rte_mbuf_refcnt_read (mb) == 1);
	      rte_pktmbuf_free (mb);
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

void
vlib_buffer_free (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   1);
}

void
vlib_buffer_free_no_next (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   0);
}

/* Copy template packet data into buffers as they are allocated. */
__attribute__ ((unused))
     static void
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
  va_list va;
  __attribute__ ((unused)) u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  vlib_worker_thread_barrier_sync (vm);
  memset (t, 0, sizeof (t[0]));

  vec_add (t->packet_data, packet_data, n_packet_data_bytes);

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

  /* Fix up mbuf header length fields */
  struct rte_mbuf *mb;
  mb = rte_mbuf_from_vlib_buffer (b);
  mb->data_len = b->current_length;
  mb->pkt_len = b->current_length;

  return b->data;
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

/*
 * Fills in the required rte_mbuf fields for chained buffers given a VLIB chain.
 */
void
vlib_buffer_chain_validate (vlib_main_t * vm, vlib_buffer_t * b_first)
{
  vlib_buffer_t *b = b_first, *prev = b_first;
  struct rte_mbuf *mb_prev, *mb, *mb_first;

  mb_first = rte_mbuf_from_vlib_buffer (b_first);

  mb_first->pkt_len = mb_first->data_len = b_first->current_length;
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      mb = rte_mbuf_from_vlib_buffer (b);
      mb_prev = rte_mbuf_from_vlib_buffer (prev);
      mb_first->nb_segs++;
      mb_first->pkt_len += b->current_length;
      mb_prev->next = mb;
      mb->data_len = b->current_length;
      prev = b;
    }
}

clib_error_t *
vlib_buffer_pool_create (vlib_main_t * vm, unsigned num_mbufs,
			 unsigned socket_id)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  struct rte_mempool *rmp;
  uword new_start, new_size;
  int i;

  if (!rte_pktmbuf_pool_create)
    return clib_error_return (0, "not linked with DPDK");

  vec_validate_aligned (bm->pktmbuf_pools, socket_id, CLIB_CACHE_LINE_BYTES);

  /* pool already exists, nothing to do */
  if (bm->pktmbuf_pools[socket_id])
    return 0;

  u8 *pool_name = format (0, "mbuf_pool_socket%u%c", socket_id, 0);

  rmp = rte_pktmbuf_pool_create ((char *) pool_name,	/* pool name */
				 num_mbufs,	/* number of mbufs */
				 512,	/* cache size */
				 VLIB_BUFFER_HDR_SIZE,	/* priv size */
				 VLIB_BUFFER_PRE_DATA_SIZE + VLIB_BUFFER_DATA_SIZE,	/* dataroom size */
				 socket_id);	/* cpu socket */

  vec_free (pool_name);

  if (rmp)
    {
      new_start = pointer_to_uword (rmp);
      new_size = rmp->elt_va_end - new_start;

      if (vpm->virtual.size > 0)
	{
	  ASSERT (new_start != vpm->virtual.start);
	  if (new_start < vpm->virtual.start)
	    {
	      new_size = vpm->virtual.size + vpm->virtual.start - new_start;
	    }
	  else
	    {
	      new_size += new_start - vpm->virtual.start;
	      new_start = vpm->virtual.start;
	    }

	  /* check if fits into buffer index range */
	  if ((u64) new_size > ((u64) 1 << (32 + CLIB_LOG2_CACHE_LINE_BYTES)))
	    rmp = 0;
	}
    }

  if (rmp)
    {
      bm->pktmbuf_pools[socket_id] = rmp;
      vpm->virtual.start = new_start;
      vpm->virtual.size = new_size;
      vpm->virtual.end = new_start + new_size;
      return 0;
    }

  /* no usable pool for this socket, try to use pool from another one */
  for (i = 0; i < vec_len (bm->pktmbuf_pools); i++)
    {
      if (bm->pktmbuf_pools[i])
	{
	  clib_warning
	    ("WARNING: Failed to allocate mempool for CPU socket %u. "
	     "Threads running on socket %u will use socket %u mempool.",
	     socket_id, socket_id, i);
	  bm->pktmbuf_pools[socket_id] = bm->pktmbuf_pools[i];
	  return 0;
	}
    }

  return clib_error_return (0, "failed to allocate mempool on socket %u",
			    socket_id);
}


static void
vlib_serialize_tx (serialize_main_header_t * m, serialize_stream_t * s)
{
  vlib_main_t *vm;
  vlib_serialize_buffer_main_t *sm;
  uword n, n_bytes_to_write;
  vlib_buffer_t *last;

  n_bytes_to_write = s->current_buffer_index;
  sm =
    uword_to_pointer (s->data_function_opaque,
		      vlib_serialize_buffer_main_t *);
  vm = sm->vlib_main;

  ASSERT (sm->tx.max_n_data_bytes_per_chain > 0);
  if (serialize_stream_is_end_of_stream (s)
      || sm->tx.n_total_data_bytes + n_bytes_to_write >
      sm->tx.max_n_data_bytes_per_chain)
    {
      vlib_process_t *p = vlib_get_current_process (vm);

      last = vlib_get_buffer (vm, sm->last_buffer);
      last->current_length = n_bytes_to_write;

      vlib_set_next_frame_buffer (vm, &p->node_runtime, sm->tx.next_index,
				  sm->first_buffer);

      sm->first_buffer = sm->last_buffer = ~0;
      sm->tx.n_total_data_bytes = 0;
    }

  else if (n_bytes_to_write == 0 && s->n_buffer_bytes == 0)
    {
      ASSERT (sm->first_buffer == ~0);
      ASSERT (sm->last_buffer == ~0);
      n =
	vlib_buffer_alloc_from_free_list (vm, &sm->first_buffer, 1,
					  sm->tx.free_list_index);
      if (n != 1)
	serialize_error (m,
			 clib_error_create
			 ("vlib_buffer_alloc_from_free_list fails"));
      sm->last_buffer = sm->first_buffer;
      s->n_buffer_bytes =
	vlib_buffer_free_list_buffer_size (vm, sm->tx.free_list_index);
    }

  if (n_bytes_to_write > 0)
    {
      vlib_buffer_t *prev = vlib_get_buffer (vm, sm->last_buffer);
      n =
	vlib_buffer_alloc_from_free_list (vm, &sm->last_buffer, 1,
					  sm->tx.free_list_index);
      if (n != 1)
	serialize_error (m,
			 clib_error_create
			 ("vlib_buffer_alloc_from_free_list fails"));
      sm->tx.n_total_data_bytes += n_bytes_to_write;
      prev->current_length = n_bytes_to_write;
      prev->next_buffer = sm->last_buffer;
      prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
    }

  if (sm->last_buffer != ~0)
    {
      last = vlib_get_buffer (vm, sm->last_buffer);
      s->buffer = vlib_buffer_get_current (last);
      s->current_buffer_index = 0;
      ASSERT (last->current_data == s->current_buffer_index);
    }
}

static void
vlib_serialize_rx (serialize_main_header_t * m, serialize_stream_t * s)
{
  vlib_main_t *vm;
  vlib_serialize_buffer_main_t *sm;
  vlib_buffer_t *last;

  sm =
    uword_to_pointer (s->data_function_opaque,
		      vlib_serialize_buffer_main_t *);
  vm = sm->vlib_main;

  if (serialize_stream_is_end_of_stream (s))
    return;

  if (sm->last_buffer != ~0)
    {
      last = vlib_get_buffer (vm, sm->last_buffer);

      if (last->flags & VLIB_BUFFER_NEXT_PRESENT)
	sm->last_buffer = last->next_buffer;
      else
	{
	  vlib_buffer_free (vm, &sm->first_buffer, /* count */ 1);
	  sm->first_buffer = sm->last_buffer = ~0;
	}
    }

  if (sm->last_buffer == ~0)
    {
      while (clib_fifo_elts (sm->rx.buffer_fifo) == 0)
	{
	  sm->rx.ready_one_time_event =
	    vlib_process_create_one_time_event (vm, vlib_current_process (vm),
						~0);
	  vlib_process_wait_for_one_time_event (vm, /* no event data */ 0,
						sm->rx.ready_one_time_event);
	}

      clib_fifo_sub1 (sm->rx.buffer_fifo, sm->first_buffer);
      sm->last_buffer = sm->first_buffer;
    }

  ASSERT (sm->last_buffer != ~0);

  last = vlib_get_buffer (vm, sm->last_buffer);
  s->current_buffer_index = 0;
  s->buffer = vlib_buffer_get_current (last);
  s->n_buffer_bytes = last->current_length;
}

static void
serialize_open_vlib_helper (serialize_main_t * m,
			    vlib_main_t * vm,
			    vlib_serialize_buffer_main_t * sm, uword is_read)
{
  /* Initialize serialize main but save overflow buffer for re-use between calls. */
  {
    u8 *save = m->stream.overflow_buffer;
    memset (m, 0, sizeof (m[0]));
    m->stream.overflow_buffer = save;
    if (save)
      _vec_len (save) = 0;
  }

  sm->first_buffer = sm->last_buffer = ~0;
  if (is_read)
    clib_fifo_reset (sm->rx.buffer_fifo);
  else
    sm->tx.n_total_data_bytes = 0;
  sm->vlib_main = vm;
  m->header.data_function = is_read ? vlib_serialize_rx : vlib_serialize_tx;
  m->stream.data_function_opaque = pointer_to_uword (sm);
}

void
serialize_open_vlib_buffer (serialize_main_t * m, vlib_main_t * vm,
			    vlib_serialize_buffer_main_t * sm)
{
  serialize_open_vlib_helper (m, vm, sm, /* is_read */ 0);
}

void
unserialize_open_vlib_buffer (serialize_main_t * m, vlib_main_t * vm,
			      vlib_serialize_buffer_main_t * sm)
{
  serialize_open_vlib_helper (m, vm, sm, /* is_read */ 1);
}

u32
serialize_close_vlib_buffer (serialize_main_t * m)
{
  vlib_serialize_buffer_main_t *sm
    = uword_to_pointer (m->stream.data_function_opaque,
			vlib_serialize_buffer_main_t *);
  vlib_buffer_t *last;
  serialize_stream_t *s = &m->stream;

  last = vlib_get_buffer (sm->vlib_main, sm->last_buffer);
  last->current_length = s->current_buffer_index;

  if (vec_len (s->overflow_buffer) > 0)
    {
      sm->last_buffer
	= vlib_buffer_add_data (sm->vlib_main, sm->tx.free_list_index,
				sm->last_buffer == ~0 ? 0 : sm->last_buffer,
				s->overflow_buffer,
				vec_len (s->overflow_buffer));
      _vec_len (s->overflow_buffer) = 0;
    }

  return sm->first_buffer;
}

void
unserialize_close_vlib_buffer (serialize_main_t * m)
{
  vlib_serialize_buffer_main_t *sm
    = uword_to_pointer (m->stream.data_function_opaque,
			vlib_serialize_buffer_main_t *);
  if (sm->first_buffer != ~0)
    vlib_buffer_free_one (sm->vlib_main, sm->first_buffer);
  clib_fifo_reset (sm->rx.buffer_fifo);
  if (m->stream.overflow_buffer)
    _vec_len (m->stream.overflow_buffer) = 0;
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
  n_free = vec_len (f->aligned_buffers) + vec_len (f->unaligned_buffers);
  bytes_alloc = size * f->n_alloc;
  bytes_free = size * n_free;

  s = format (s, "%7d%30s%12d%12d%=12U%=12U%=12d%=12d",
	      threadnum,
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
      curr_vm = vec_len (vlib_mains) ? vlib_mains[vm_index] : vm;
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

#if CLIB_DEBUG > 0

u32 *vlib_buffer_state_validation_lock;
uword *vlib_buffer_state_validation_hash;
void *vlib_buffer_state_heap;

static clib_error_t *
buffer_state_validation_init (vlib_main_t * vm)
{
  void *oldheap;

  vlib_buffer_state_heap = mheap_alloc (0, 10 << 20);

  oldheap = clib_mem_set_heap (vlib_buffer_state_heap);

  vlib_buffer_state_validation_hash = hash_create (0, sizeof (uword));
  vec_validate_aligned (vlib_buffer_state_validation_lock, 0,
			CLIB_CACHE_LINE_BYTES);
  clib_mem_set_heap (oldheap);
  return 0;
}

VLIB_INIT_FUNCTION (buffer_state_validation_init);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

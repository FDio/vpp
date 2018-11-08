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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/bitops.h>
#include <vppinfra/hash.h>
#include <vppinfra/format.h>
#include <vppinfra/mheap.h>
#include <vppinfra/os.h>
#include <vppinfra/time.h>

#ifdef CLIB_UNIX
#include <vppinfra/elf_clib.h>
#endif

static void mheap_get_trace (void *v, uword offset, uword size);
static void mheap_put_trace (void *v, uword offset, uword size);
static int mheap_trace_sort (const void *t1, const void *t2);

always_inline void
mheap_maybe_lock (void *v)
{
  mheap_t *h = mheap_header (v);
  if (v && (h->flags & MHEAP_FLAG_THREAD_SAFE))
    {
      u32 my_cpu = os_get_thread_index ();
      if (h->owner_cpu == my_cpu)
	{
	  h->recursion_count++;
	  return;
	}

      while (clib_atomic_test_and_set (&h->lock))
	;

      h->owner_cpu = my_cpu;
      h->recursion_count = 1;
    }
}

always_inline void
mheap_maybe_unlock (void *v)
{
  mheap_t *h = mheap_header (v);
  if (v && h->flags & MHEAP_FLAG_THREAD_SAFE)
    {
      ASSERT (os_get_thread_index () == h->owner_cpu);
      if (--h->recursion_count == 0)
	{
	  h->owner_cpu = ~0;
	  CLIB_MEMORY_BARRIER ();
	  h->lock = 0;
	}
    }
}

/* Find bin for objects with size at least n_user_data_bytes. */
always_inline uword
user_data_size_to_bin_index (uword n_user_data_bytes)
{
  uword n_user_data_words;
  word small_bin, large_bin;

  /* User size must be at least big enough to hold free elt. */
  n_user_data_bytes = clib_max (n_user_data_bytes, MHEAP_MIN_USER_DATA_BYTES);

  /* Round to words. */
  n_user_data_words =
    (round_pow2 (n_user_data_bytes, MHEAP_USER_DATA_WORD_BYTES) /
     MHEAP_USER_DATA_WORD_BYTES);

  ASSERT (n_user_data_words > 0);
  small_bin =
    n_user_data_words -
    (MHEAP_MIN_USER_DATA_BYTES / MHEAP_USER_DATA_WORD_BYTES);
  ASSERT (small_bin >= 0);

  large_bin =
    MHEAP_N_SMALL_OBJECT_BINS + max_log2 (n_user_data_bytes) -
    MHEAP_LOG2_N_SMALL_OBJECT_BINS;

  return small_bin < MHEAP_N_SMALL_OBJECT_BINS ? small_bin : large_bin;
}

always_inline uword
mheap_elt_size_to_user_n_bytes (uword n_bytes)
{
  ASSERT (n_bytes >= sizeof (mheap_elt_t));
  return (n_bytes - STRUCT_OFFSET_OF (mheap_elt_t, user_data));
}

always_inline uword __attribute__ ((unused))
mheap_elt_size_to_user_n_words (uword n_bytes)
{
  ASSERT (n_bytes % MHEAP_USER_DATA_WORD_BYTES == 0);
  return mheap_elt_size_to_user_n_bytes (n_bytes) /
    MHEAP_USER_DATA_WORD_BYTES;
}

always_inline void
mheap_elt_set_size (void *v,
		    uword uoffset, uword n_user_data_bytes, uword is_free)
{
  mheap_elt_t *e, *n;

  e = mheap_elt_at_uoffset (v, uoffset);

  ASSERT (n_user_data_bytes % MHEAP_USER_DATA_WORD_BYTES == 0);

  e->n_user_data = n_user_data_bytes / MHEAP_USER_DATA_WORD_BYTES;
  e->is_free = is_free;
  ASSERT (e->prev_n_user_data * sizeof (e->user_data[0]) >=
	  MHEAP_MIN_USER_DATA_BYTES);

  n = mheap_next_elt (e);
  n->prev_n_user_data = e->n_user_data;
  n->prev_is_free = is_free;
}

always_inline void
set_first_free_elt_offset (mheap_t * h, uword bin, uword uoffset)
{
  uword i0, i1;

  h->first_free_elt_uoffset_by_bin[bin] = uoffset;

  i0 = bin / BITS (h->non_empty_free_elt_heads[0]);
  i1 = (uword) 1 << (uword) (bin % BITS (h->non_empty_free_elt_heads[0]));

  ASSERT (i0 < ARRAY_LEN (h->non_empty_free_elt_heads));
  if (h->first_free_elt_uoffset_by_bin[bin] == MHEAP_GROUNDED)
    h->non_empty_free_elt_heads[i0] &= ~i1;
  else
    h->non_empty_free_elt_heads[i0] |= i1;
}

always_inline void
set_free_elt (void *v, uword uoffset, uword n_user_data_bytes)
{
  mheap_t *h = mheap_header (v);
  mheap_elt_t *e = mheap_elt_at_uoffset (v, uoffset);
  mheap_elt_t *n = mheap_next_elt (e);
  uword bin = user_data_size_to_bin_index (n_user_data_bytes);

  ASSERT (n->prev_is_free);
  ASSERT (e->is_free);

  e->free_elt.prev_uoffset = MHEAP_GROUNDED;
  e->free_elt.next_uoffset = h->first_free_elt_uoffset_by_bin[bin];

  /* Fill in next free elt's previous pointer. */
  if (e->free_elt.next_uoffset != MHEAP_GROUNDED)
    {
      mheap_elt_t *nf = mheap_elt_at_uoffset (v, e->free_elt.next_uoffset);
      ASSERT (nf->is_free);
      nf->free_elt.prev_uoffset = uoffset;
    }

  set_first_free_elt_offset (h, bin, uoffset);
}

always_inline void
new_free_elt (void *v, uword uoffset, uword n_user_data_bytes)
{
  mheap_elt_set_size (v, uoffset, n_user_data_bytes, /* is_free */ 1);
  set_free_elt (v, uoffset, n_user_data_bytes);
}

always_inline void
remove_free_elt (void *v, mheap_elt_t * e, uword bin)
{
  mheap_t *h = mheap_header (v);
  mheap_elt_t *p, *n;
#if CLIB_VEC64 > 0
  u64 no, po;
#else
  u32 no, po;
#endif

  no = e->free_elt.next_uoffset;

  n = no != MHEAP_GROUNDED ? mheap_elt_at_uoffset (v, no) : 0;
  po = e->free_elt.prev_uoffset;
  p = po != MHEAP_GROUNDED ? mheap_elt_at_uoffset (v, po) : 0;

  if (!p)
    set_first_free_elt_offset (h, bin, no);
  else
    p->free_elt.next_uoffset = no;

  if (n)
    n->free_elt.prev_uoffset = po;
}

always_inline void
remove_free_elt2 (void *v, mheap_elt_t * e)
{
  uword bin;
  bin = user_data_size_to_bin_index (mheap_elt_data_bytes (e));
  remove_free_elt (v, e, bin);
}

#define MHEAP_VM_MAP		(1 << 0)
#define MHEAP_VM_UNMAP		(1 << 1)
#define MHEAP_VM_NOMAP		(0 << 1)
#define MHEAP_VM_ROUND		(1 << 2)
#define MHEAP_VM_ROUND_UP	MHEAP_VM_ROUND
#define MHEAP_VM_ROUND_DOWN	(0 << 2)

static uword mheap_page_size;

static_always_inline uword
mheap_page_round (uword addr)
{
  return (addr + mheap_page_size - 1) & ~(mheap_page_size - 1);
}

static_always_inline uword
mheap_page_truncate (uword addr)
{
  return addr & ~(mheap_page_size - 1);
}

static_always_inline uword
mheap_vm (void *v, uword flags, clib_address_t start_addr, uword size)
{
  mheap_t *h = mheap_header (v);
  clib_address_t start_page, end_page, end_addr;
  uword mapped_bytes;

  ASSERT (!(h->flags & MHEAP_FLAG_DISABLE_VM));

  end_addr = start_addr + size;

  /* Round start/end address up to page boundary. */
  start_page = mheap_page_round (start_addr);

  if ((flags & MHEAP_VM_ROUND) == MHEAP_VM_ROUND_UP)
    end_page = mheap_page_round (end_addr);
  else
    end_page = mheap_page_truncate (end_addr);

  mapped_bytes = 0;
  if (end_page > start_page)
    {
      mapped_bytes = end_page - start_page;
      if (flags & MHEAP_VM_MAP)
	clib_mem_vm_map ((void *) start_page, end_page - start_page);
      else if (flags & MHEAP_VM_UNMAP)
	clib_mem_vm_unmap ((void *) start_page, end_page - start_page);
    }

  return mapped_bytes;
}

static_always_inline uword
mheap_vm_elt (void *v, uword flags, uword offset)
{
  mheap_elt_t *e;
  clib_address_t start_addr, end_addr;

  e = mheap_elt_at_uoffset (v, offset);
  start_addr = (clib_address_t) ((void *) e->user_data);
  end_addr = (clib_address_t) mheap_next_elt (e);
  return mheap_vm (v, flags, start_addr, end_addr - start_addr);
}

always_inline uword
mheap_small_object_cache_mask (mheap_small_object_cache_t * c, uword bin)
{
  uword mask;

/* $$$$ ELIOT FIXME: add Altivec version of this routine */
#if !defined (CLIB_HAVE_VEC128) || defined (__ALTIVEC__) || defined (__i386__)
  mask = 0;
#else
  u8x16 b = u8x16_splat (bin);

  ASSERT (bin < 256);

#define _(i) ((uword) u8x16_compare_byte_mask ((b == c->bins.as_u8x16[i])) << (uword) ((i)*16))
  mask = _(0) | _(1);
  if (BITS (uword) > 32)
    mask |= _(2) | _(3);
#undef _

#endif
  return mask;
}

always_inline uword
mheap_get_small_object (mheap_t * h, uword bin)
{
  mheap_small_object_cache_t *c = &h->small_object_cache;
  uword mask = mheap_small_object_cache_mask (c, bin + 1);
  uword offset = MHEAP_GROUNDED;

  if (mask)
    {
      uword i = min_log2 (mask);
      uword o = c->offsets[i];
      ASSERT (o != MHEAP_GROUNDED);
      c->bins.as_u8[i] = 0;
      offset = o;
    }

  return offset;
}

always_inline uword
mheap_put_small_object (mheap_t * h, uword bin, uword offset)
{
  mheap_small_object_cache_t *c = &h->small_object_cache;
  uword free_mask = mheap_small_object_cache_mask (c, 0);
  uword b = bin + 1;
  uword i;

  if (free_mask != 0)
    {
      i = min_log2 (free_mask);
      c->bins.as_u8[i] = b;
      c->offsets[i] = offset;
      return 0;
    }
  else
    /* Nothing free with right size: cyclic replacement. */
    {
      uword old_offset;

      i = c->replacement_index++;
      i %= BITS (uword);
      c->bins.as_u8[i] = b;
      old_offset = c->offsets[i];
      c->offsets[i] = offset;

      /* Return old offset so it can be freed. */
      return old_offset;
    }
}

static uword
mheap_get_search_free_bin (void *v,
			   uword bin,
			   uword * n_user_data_bytes_arg,
			   uword align, uword align_offset)
{
  mheap_t *h = mheap_header (v);
  mheap_elt_t *e;

  /* Free object is at offset f0 ... f1;
     Allocatted object is at offset o0 ... o1. */
  word o0, o1, f0, f1, search_n_user_data_bytes;
  word lo_free_usize, hi_free_usize;

  ASSERT (h->first_free_elt_uoffset_by_bin[bin] != MHEAP_GROUNDED);
  e = mheap_elt_at_uoffset (v, h->first_free_elt_uoffset_by_bin[bin]);

  search_n_user_data_bytes = *n_user_data_bytes_arg;

  /* Silence compiler warning. */
  o0 = o1 = f0 = f1 = 0;

  h->stats.free_list.n_search_attempts += 1;

  /* Find an object that is large enough with correct alignment at given alignment offset. */
  while (1)
    {
      uword this_object_n_user_data_bytes = mheap_elt_data_bytes (e);

      ASSERT (e->is_free);
      if (bin < MHEAP_N_SMALL_OBJECT_BINS)
	ASSERT (this_object_n_user_data_bytes >= search_n_user_data_bytes);

      h->stats.free_list.n_objects_searched += 1;

      if (this_object_n_user_data_bytes < search_n_user_data_bytes)
	goto next;

      /* Bounds of free object: from f0 to f1. */
      f0 = ((void *) e->user_data - v);
      f1 = f0 + this_object_n_user_data_bytes;

      /* Place candidate object at end of free block and align as requested. */
      o0 = ((f1 - search_n_user_data_bytes) & ~(align - 1)) - align_offset;
      while (o0 < f0)
	o0 += align;

      /* Make sure that first free fragment is either empty or
         large enough to be valid. */
      while (1)
	{
	  lo_free_usize = o0 != f0 ? o0 - f0 - MHEAP_ELT_OVERHEAD_BYTES : 0;
	  if (o0 <= f0 || lo_free_usize >= (word) MHEAP_MIN_USER_DATA_BYTES)
	    break;
	  o0 -= align;
	}

      o1 = o0 + search_n_user_data_bytes;

      /* Does it fit? */
      if (o0 >= f0 && o1 <= f1)
	goto found;

    next:
      /* Reached end of free list without finding large enough object. */
      if (e->free_elt.next_uoffset == MHEAP_GROUNDED)
	return MHEAP_GROUNDED;

      /* Otherwise keep searching for large enough object. */
      e = mheap_elt_at_uoffset (v, e->free_elt.next_uoffset);
    }

found:
  /* Free fragment at end. */
  hi_free_usize = f1 != o1 ? f1 - o1 - MHEAP_ELT_OVERHEAD_BYTES : 0;

  /* If fragment at end is too small to be a new object,
     give user's object a bit more space than requested. */
  if (hi_free_usize < (word) MHEAP_MIN_USER_DATA_BYTES)
    {
      search_n_user_data_bytes += f1 - o1;
      o1 = f1;
      hi_free_usize = 0;
    }

  /* Need to make sure that relevant memory areas are mapped. */
  if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
    {
      mheap_elt_t *f0_elt = mheap_elt_at_uoffset (v, f0);
      mheap_elt_t *f1_elt = mheap_elt_at_uoffset (v, f1);
      mheap_elt_t *o0_elt = mheap_elt_at_uoffset (v, o0);
      mheap_elt_t *o1_elt = mheap_elt_at_uoffset (v, o1);

      uword f0_page_start, f0_page_end;
      uword o0_page_start, o0_page_end;

      /* Free elt is mapped.  Addresses after that may not be mapped. */
      f0_page_start = mheap_page_round (pointer_to_uword (f0_elt->user_data));
      f0_page_end = mheap_page_truncate (pointer_to_uword (f1_elt));

      o0_page_start = mheap_page_truncate (pointer_to_uword (o0_elt));
      o0_page_end = mheap_page_round (pointer_to_uword (o1_elt->user_data));

      if (o0_page_start < f0_page_start)
	o0_page_start = f0_page_start;
      if (o0_page_end > f0_page_end)
	o0_page_end = f0_page_end;

      if (o0_page_end > o0_page_start)
	clib_mem_vm_map (uword_to_pointer (o0_page_start, void *),
			 o0_page_end - o0_page_start);
    }

  /* Remove free object from free list. */
  remove_free_elt (v, e, bin);

  /* Free fragment at begining. */
  if (lo_free_usize > 0)
    {
      ASSERT (lo_free_usize >= (word) MHEAP_MIN_USER_DATA_BYTES);
      mheap_elt_set_size (v, f0, lo_free_usize, /* is_free */ 1);
      new_free_elt (v, f0, lo_free_usize);
    }

  mheap_elt_set_size (v, o0, search_n_user_data_bytes, /* is_free */ 0);

  if (hi_free_usize > 0)
    {
      uword uo = o1 + MHEAP_ELT_OVERHEAD_BYTES;
      mheap_elt_set_size (v, uo, hi_free_usize, /* is_free */ 1);
      new_free_elt (v, uo, hi_free_usize);
    }

  /* Return actual size of block. */
  *n_user_data_bytes_arg = search_n_user_data_bytes;

  h->stats.free_list.n_objects_found += 1;

  return o0;
}

/* Search free lists for object with given size and alignment. */
static uword
mheap_get_search_free_list (void *v,
			    uword * n_user_bytes_arg,
			    uword align, uword align_offset)
{
  mheap_t *h = mheap_header (v);
  uword bin, n_user_bytes, i, bi;

  n_user_bytes = *n_user_bytes_arg;
  bin = user_data_size_to_bin_index (n_user_bytes);

  if (MHEAP_HAVE_SMALL_OBJECT_CACHE
      && (h->flags & MHEAP_FLAG_SMALL_OBJECT_CACHE)
      && bin < 255
      && align == STRUCT_SIZE_OF (mheap_elt_t, user_data[0])
      && align_offset == 0)
    {
      uword r = mheap_get_small_object (h, bin);
      h->stats.n_small_object_cache_attempts += 1;
      if (r != MHEAP_GROUNDED)
	{
	  h->stats.n_small_object_cache_hits += 1;
	  return r;
	}
    }

  for (i = bin / BITS (uword); i < ARRAY_LEN (h->non_empty_free_elt_heads);
       i++)
    {
      uword non_empty_bin_mask = h->non_empty_free_elt_heads[i];

      /* No need to search smaller bins. */
      if (i == bin / BITS (uword))
	non_empty_bin_mask &= ~pow2_mask (bin % BITS (uword));

      /* Search each occupied free bin which is large enough. */
      /* *INDENT-OFF* */
      foreach_set_bit (bi, non_empty_bin_mask,
      ({
        uword r =
          mheap_get_search_free_bin (v, bi + i * BITS (uword),
                                     n_user_bytes_arg,
                                     align,
                                     align_offset);
        if (r != MHEAP_GROUNDED) return r;
      }));
      /* *INDENT-ON* */
    }

  return MHEAP_GROUNDED;
}

static never_inline void *
mheap_get_extend_vector (void *v,
			 uword n_user_data_bytes,
			 uword align,
			 uword align_offset, uword * offset_return)
{
  /* Bounds of free and allocated objects (as above). */
  uword f0, f1, o0, o1;
  word free_size;
  mheap_t *h = mheap_header (v);
  mheap_elt_t *e;

  if (_vec_len (v) == 0)
    {
      _vec_len (v) = MHEAP_ELT_OVERHEAD_BYTES;

      /* Create first element of heap. */
      e = mheap_elt_at_uoffset (v, _vec_len (v));
      e->prev_n_user_data = MHEAP_N_USER_DATA_INVALID;
    }

  f0 = _vec_len (v);

  o0 = round_pow2 (f0, align) - align_offset;
  while (1)
    {
      free_size = o0 - f0 - MHEAP_ELT_OVERHEAD_BYTES;
      if (o0 == f0 || free_size >= (word) sizeof (mheap_elt_t))
	break;

      o0 += align;
    }

  o1 = o0 + n_user_data_bytes;
  f1 = o1 + MHEAP_ELT_OVERHEAD_BYTES;

  ASSERT (v != 0);
  h = mheap_header (v);

  /* Make sure we have space for object plus overhead. */
  if (f1 > h->max_size)
    {
      *offset_return = MHEAP_GROUNDED;
      return v;
    }

  _vec_len (v) = f1;

  if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
    {
      mheap_elt_t *f0_elt = mheap_elt_at_uoffset (v, f0);
      mheap_elt_t *f1_elt = mheap_elt_at_uoffset (v, f1);

      uword f0_page = mheap_page_round (pointer_to_uword (f0_elt->user_data));
      uword f1_page = mheap_page_round (pointer_to_uword (f1_elt->user_data));

      if (f1_page > f0_page)
	mheap_vm (v, MHEAP_VM_MAP, f0_page, f1_page - f0_page);
    }

  if (free_size > 0)
    new_free_elt (v, f0, free_size);

  mheap_elt_set_size (v, o0, n_user_data_bytes, /* is_free */ 0);

  /* Mark last element. */
  e = mheap_elt_at_uoffset (v, f1);
  e->n_user_data = MHEAP_N_USER_DATA_INVALID;

  *offset_return = o0;

  return v;
}

void *
mheap_get_aligned (void *v,
		   uword n_user_data_bytes,
		   uword align, uword align_offset, uword * offset_return)
{
  mheap_t *h;
  uword offset;
  u64 cpu_times[2];

  cpu_times[0] = clib_cpu_time_now ();

  align = clib_max (align, STRUCT_SIZE_OF (mheap_elt_t, user_data[0]));
  align = max_pow2 (align);

  /* Correct align offset to be smaller than alignment. */
  align_offset &= (align - 1);

  /* Align offset must be multiple of minimum object size. */
  if (align_offset % STRUCT_SIZE_OF (mheap_elt_t, user_data[0]) != 0)
    {
      *offset_return = MHEAP_GROUNDED;
      return v;
    }

  /*
   * Round requested size.
   *
   * Step 1: round up to the minimum object size.
   * Step 2: round up to a multiple of the user data size (e.g. 4)
   * Step 3: if non-trivial alignment requested, round up
   *         so that the object precisely fills a chunk
   *         as big as the alignment request.
   *
   * Step 3 prevents the code from going into "bin search hyperspace":
   * looking at a huge number of fractional remainder chunks, none of which
   * will satisfy the alignment constraint. This fixes an allocator
   * performance issue when one requests a large number of 16 byte objects
   * aligned to 64 bytes, to name one variation on the theme.
   */
  n_user_data_bytes = clib_max (n_user_data_bytes, MHEAP_MIN_USER_DATA_BYTES);
  n_user_data_bytes =
    round_pow2 (n_user_data_bytes,
		STRUCT_SIZE_OF (mheap_elt_t, user_data[0]));
  if (align > MHEAP_ELT_OVERHEAD_BYTES)
    n_user_data_bytes = clib_max (n_user_data_bytes,
				  align - MHEAP_ELT_OVERHEAD_BYTES);
  if (!v)
    v = mheap_alloc (0, 64 << 20);

  mheap_maybe_lock (v);

  h = mheap_header (v);

  if (h->flags & MHEAP_FLAG_VALIDATE)
    mheap_validate (v);

  /* First search free lists for object. */
  offset =
    mheap_get_search_free_list (v, &n_user_data_bytes, align, align_offset);

  h = mheap_header (v);

  /* If that fails allocate object at end of heap by extending vector. */
  if (offset == MHEAP_GROUNDED && _vec_len (v) < h->max_size)
    {
      v =
	mheap_get_extend_vector (v, n_user_data_bytes, align, align_offset,
				 &offset);
      h = mheap_header (v);
      h->stats.n_vector_expands += offset != MHEAP_GROUNDED;
    }

  *offset_return = offset;
  if (offset != MHEAP_GROUNDED)
    {
      h->n_elts += 1;

      if (h->flags & MHEAP_FLAG_TRACE)
	{
	  /* Recursion block for case when we are traceing main clib heap. */
	  h->flags &= ~MHEAP_FLAG_TRACE;

	  mheap_get_trace (v, offset, n_user_data_bytes);

	  h->flags |= MHEAP_FLAG_TRACE;
	}
    }

  if (h->flags & MHEAP_FLAG_VALIDATE)
    mheap_validate (v);

  mheap_maybe_unlock (v);

  cpu_times[1] = clib_cpu_time_now ();
  h->stats.n_clocks_get += cpu_times[1] - cpu_times[0];
  h->stats.n_gets += 1;

  return v;
}

static void
free_last_elt (void *v, mheap_elt_t * e)
{
  mheap_t *h = mheap_header (v);

  /* Possibly delete preceeding free element also. */
  if (e->prev_is_free)
    {
      e = mheap_prev_elt (e);
      remove_free_elt2 (v, e);
    }

  if (e->prev_n_user_data == MHEAP_N_USER_DATA_INVALID)
    {
      if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
	mheap_vm_elt (v, MHEAP_VM_UNMAP, mheap_elt_uoffset (v, e));
      _vec_len (v) = 0;
    }
  else
    {
      uword uo = mheap_elt_uoffset (v, e);
      if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
	mheap_vm_elt (v, MHEAP_VM_UNMAP, uo);
      e->n_user_data = MHEAP_N_USER_DATA_INVALID;
      _vec_len (v) = uo;
    }
}

void
mheap_put (void *v, uword uoffset)
{
  mheap_t *h;
  uword n_user_data_bytes, bin;
  mheap_elt_t *e, *n;
  uword trace_uoffset, trace_n_user_data_bytes;
  u64 cpu_times[2];

  cpu_times[0] = clib_cpu_time_now ();

  h = mheap_header (v);

  mheap_maybe_lock (v);

  if (h->flags & MHEAP_FLAG_VALIDATE)
    mheap_validate (v);

  ASSERT (h->n_elts > 0);
  h->n_elts--;
  h->stats.n_puts += 1;

  e = mheap_elt_at_uoffset (v, uoffset);
  n = mheap_next_elt (e);
  n_user_data_bytes = mheap_elt_data_bytes (e);

  trace_uoffset = uoffset;
  trace_n_user_data_bytes = n_user_data_bytes;

  bin = user_data_size_to_bin_index (n_user_data_bytes);
  if (MHEAP_HAVE_SMALL_OBJECT_CACHE
      && bin < 255 && (h->flags & MHEAP_FLAG_SMALL_OBJECT_CACHE))
    {
      uoffset = mheap_put_small_object (h, bin, uoffset);
      if (uoffset == 0)
	goto done;

      e = mheap_elt_at_uoffset (v, uoffset);
      n = mheap_next_elt (e);
      n_user_data_bytes = mheap_elt_data_bytes (e);
    }

  /* Assert that forward and back pointers are equal. */
  if (e->n_user_data != n->prev_n_user_data)
    os_panic ();

  /* Forward and backwards is_free must agree. */
  if (e->is_free != n->prev_is_free)
    os_panic ();

  /* Object was already freed. */
  if (e->is_free)
    os_panic ();

  /* Special case: delete last element in heap. */
  if (n->n_user_data == MHEAP_N_USER_DATA_INVALID)
    free_last_elt (v, e);

  else
    {
      uword f0, f1, n_combine;

      f0 = uoffset;
      f1 = f0 + n_user_data_bytes;
      n_combine = 0;

      if (e->prev_is_free)
	{
	  mheap_elt_t *p = mheap_prev_elt (e);
	  f0 = mheap_elt_uoffset (v, p);
	  remove_free_elt2 (v, p);
	  n_combine++;
	}

      if (n->is_free)
	{
	  mheap_elt_t *m = mheap_next_elt (n);
	  f1 = (void *) m - v;
	  remove_free_elt2 (v, n);
	  n_combine++;
	}

      if (n_combine)
	mheap_elt_set_size (v, f0, f1 - f0, /* is_free */ 1);
      else
	e->is_free = n->prev_is_free = 1;
      set_free_elt (v, f0, f1 - f0);

      if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
	mheap_vm_elt (v, MHEAP_VM_UNMAP, f0);
    }

done:
  h = mheap_header (v);

  if (h->flags & MHEAP_FLAG_TRACE)
    {
      /* Recursion block for case when we are traceing main clib heap. */
      h->flags &= ~MHEAP_FLAG_TRACE;

      mheap_put_trace (v, trace_uoffset, trace_n_user_data_bytes);

      h->flags |= MHEAP_FLAG_TRACE;
    }

  if (h->flags & MHEAP_FLAG_VALIDATE)
    mheap_validate (v);

  mheap_maybe_unlock (v);

  cpu_times[1] = clib_cpu_time_now ();
  h->stats.n_clocks_put += cpu_times[1] - cpu_times[0];
}

void *
mheap_alloc_with_flags (void *memory, uword memory_size, uword flags)
{
  mheap_t *h;
  void *v;
  uword size;

  if (!mheap_page_size)
    mheap_page_size = clib_mem_get_page_size ();

  if (!memory)
    {
      /* No memory given, try to VM allocate some. */
      memory = clib_mem_vm_alloc (memory_size);
      if (!memory)
	return 0;

      /* No memory region implies we have virtual memory. */
      flags &= ~MHEAP_FLAG_DISABLE_VM;
    }

  /* Make sure that given memory is page aligned. */
  {
    uword am, av, ah;

    am = pointer_to_uword (memory);
    av = mheap_page_round (am);
    v = uword_to_pointer (av, void *);
    h = mheap_header (v);
    ah = pointer_to_uword (h);
    while (ah < am)
      ah += mheap_page_size;

    h = uword_to_pointer (ah, void *);
    v = mheap_vector (h);

    if (PREDICT_FALSE (memory + memory_size < v))
      {
	/*
	 * This will happen when the requested memory_size is too
	 * small to cope with the heap header and/or memory alignment.
	 */
	clib_mem_vm_free (memory, memory_size);
	return 0;
      }

    size = memory + memory_size - v;
  }

  /* VM map header so we can use memory. */
  if (!(flags & MHEAP_FLAG_DISABLE_VM))
    clib_mem_vm_map (h, sizeof (h[0]));

  /* Zero vector header: both heap header and vector length. */
  clib_memset (h, 0, sizeof (h[0]));
  _vec_len (v) = 0;

  h->vm_alloc_offset_from_header = (void *) h - memory;
  h->vm_alloc_size = memory_size;

  h->max_size = size;
  h->owner_cpu = ~0;

  /* Set flags based on those given less builtin-flags. */
  h->flags |= (flags & ~MHEAP_FLAG_TRACE);

  /* Unmap remainder of heap until we will be ready to use it. */
  if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
    mheap_vm (v, MHEAP_VM_UNMAP | MHEAP_VM_ROUND_UP,
	      (clib_address_t) v, h->max_size);

  /* Initialize free list heads to empty. */
  clib_memset (h->first_free_elt_uoffset_by_bin, 0xFF,
	       sizeof (h->first_free_elt_uoffset_by_bin));

  return v;
}

void *
mheap_alloc (void *memory, uword size)
{
  uword flags = 0;

  if (memory != 0)
    flags |= MHEAP_FLAG_DISABLE_VM;

#ifdef CLIB_HAVE_VEC128
  flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
#endif

  return mheap_alloc_with_flags (memory, size, flags);
}

void *
mheap_alloc_with_lock (void *memory, uword size, int locked)
{
  uword flags = 0;
  void *rv;

  if (memory != 0)
    flags |= MHEAP_FLAG_DISABLE_VM;

#ifdef CLIB_HAVE_VEC128
  flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
#endif

  rv = mheap_alloc_with_flags (memory, size, flags);

  if (rv && locked)
    {
      mheap_t *h = mheap_header (rv);
      h->flags |= MHEAP_FLAG_THREAD_SAFE;
    }
  return rv;
}

void *
_mheap_free (void *v)
{
  mheap_t *h = mheap_header (v);

  if (v)
    clib_mem_vm_free ((void *) h - h->vm_alloc_offset_from_header,
		      h->vm_alloc_size);

  return 0;
}

/* Call user's function with each object in heap. */
void
mheap_foreach (void *v,
	       uword (*func) (void *arg, void *v, void *elt_data,
			      uword elt_size), void *arg)
{
  mheap_elt_t *e;
  u8 *stack_heap, *clib_mem_mheap_save;
  u8 tmp_heap_memory[16 * 1024];

  mheap_maybe_lock (v);

  if (vec_len (v) == 0)
    goto done;

  clib_mem_mheap_save = 0;
  stack_heap = 0;

  /* Allocate a new temporary heap on the stack.
     This is so that our hash table & user's callback function can
     themselves allocate memory somewhere without getting in the way
     of the heap we are looking at. */
  if (v == clib_mem_get_heap ())
    {
      stack_heap = mheap_alloc (tmp_heap_memory, sizeof (tmp_heap_memory));
      clib_mem_mheap_save = v;
      clib_mem_set_heap (stack_heap);
    }

  for (e = v;
       e->n_user_data != MHEAP_N_USER_DATA_INVALID; e = mheap_next_elt (e))
    {
      void *p = mheap_elt_data (v, e);
      if (e->is_free)
	continue;
      if ((*func) (arg, v, p, mheap_elt_data_bytes (e)))
	break;
    }

  /* Restore main CLIB heap. */
  if (clib_mem_mheap_save)
    clib_mem_set_heap (clib_mem_mheap_save);

done:
  mheap_maybe_unlock (v);
}

/* Bytes in mheap header overhead not including data bytes. */
always_inline uword
mheap_bytes_overhead (void *v)
{
  mheap_t *h = mheap_header (v);
  return v ? sizeof (h[0]) + h->n_elts * sizeof (mheap_elt_t) : 0;
}

/* Total number of bytes including both data and overhead. */
uword
mheap_bytes (void *v)
{
  return mheap_bytes_overhead (v) + vec_bytes (v);
}

static void
mheap_usage_no_lock (void *v, clib_mem_usage_t * usage)
{
  mheap_t *h = mheap_header (v);
  uword used = 0, free = 0, free_vm_unmapped = 0;

  if (vec_len (v) > 0)
    {
      mheap_elt_t *e;

      for (e = v;
	   e->n_user_data != MHEAP_N_USER_DATA_INVALID;
	   e = mheap_next_elt (e))
	{
	  uword size = mheap_elt_data_bytes (e);
	  if (e->is_free)
	    {
	      free += size;
	      if (!(h->flags & MHEAP_FLAG_DISABLE_VM))
		free_vm_unmapped +=
		  mheap_vm_elt (v, MHEAP_VM_NOMAP, mheap_elt_uoffset (v, e));
	    }
	  else
	    used += size;
	}
    }

  usage->object_count = mheap_elts (v);
  usage->bytes_total = mheap_bytes (v);
  usage->bytes_overhead = mheap_bytes_overhead (v);
  usage->bytes_max = mheap_max_size (v);
  usage->bytes_used = used;
  usage->bytes_free = free;
  usage->bytes_free_reclaimed = free_vm_unmapped;
}

void
mheap_usage (void *v, clib_mem_usage_t * usage)
{
  mheap_maybe_lock (v);
  mheap_usage_no_lock (v, usage);
  mheap_maybe_unlock (v);
}

static u8 *
format_mheap_byte_count (u8 * s, va_list * va)
{
  uword n_bytes = va_arg (*va, uword);
  if (n_bytes < 1024)
    return format (s, "%wd", n_bytes);
  else
    return format (s, "%wdk", n_bytes / 1024);
}

/* Returns first corrupt heap element. */
static mheap_elt_t *
mheap_first_corrupt (void *v)
{
  mheap_elt_t *e, *n;

  if (vec_len (v) == 0)
    return 0;

  e = v;
  while (1)
    {
      if (e->n_user_data == MHEAP_N_USER_DATA_INVALID)
	break;

      n = mheap_next_elt (e);

      if (e->n_user_data != n->prev_n_user_data)
	return e;

      if (e->is_free != n->prev_is_free)
	return e;

      e = n;
    }

  return 0;
}

static u8 *
format_mheap_stats (u8 * s, va_list * va)
{
  mheap_t *h = va_arg (*va, mheap_t *);
  mheap_stats_t *st = &h->stats;
  u32 indent = format_get_indent (s);

  s =
    format (s,
	    "alloc. from small object cache: %Ld hits %Ld attempts (%.2f%%) replacements %d",
	    st->n_small_object_cache_hits, st->n_small_object_cache_attempts,
	    (st->n_small_object_cache_attempts !=
	     0 ? 100. * (f64) st->n_small_object_cache_hits /
	     (f64) st->n_small_object_cache_attempts : 0.),
	    h->small_object_cache.replacement_index);

  s =
    format (s,
	    "\n%Ualloc. from free-list: %Ld attempts, %Ld hits (%.2f%%), %Ld considered (per-attempt %.2f)",
	    format_white_space, indent, st->free_list.n_search_attempts,
	    st->free_list.n_objects_found,
	    (st->free_list.n_search_attempts !=
	     0 ? 100. * (f64) st->free_list.n_objects_found /
	     (f64) st->free_list.n_search_attempts : 0.),
	    st->free_list.n_objects_searched,
	    (st->free_list.n_search_attempts !=
	     0 ? (f64) st->free_list.n_objects_searched /
	     (f64) st->free_list.n_search_attempts : 0.));

  s = format (s, "\n%Ualloc. from vector-expand: %Ld",
	      format_white_space, indent, st->n_vector_expands);

  s = format (s, "\n%Uallocs: %Ld %.2f clocks/call",
	      format_white_space, indent,
	      st->n_gets, (f64) st->n_clocks_get / (f64) st->n_gets);

  s = format (s, "\n%Ufrees: %Ld %.2f clocks/call",
	      format_white_space, indent,
	      st->n_puts, (f64) st->n_clocks_put / (f64) st->n_puts);

  return s;
}

u8 *
format_mheap (u8 * s, va_list * va)
{
  void *v = va_arg (*va, u8 *);
  int verbose = va_arg (*va, int);

  mheap_t *h;
  uword i, size;
  u32 indent;
  clib_mem_usage_t usage;
  mheap_elt_t *first_corrupt;

  mheap_maybe_lock (v);

  h = mheap_header (v);

  mheap_usage_no_lock (v, &usage);

  indent = format_get_indent (s);

  s =
    format (s,
	    "%d objects, %U of %U used, %U free, %U reclaimed, %U overhead",
	    usage.object_count, format_mheap_byte_count, usage.bytes_used,
	    format_mheap_byte_count, usage.bytes_total,
	    format_mheap_byte_count, usage.bytes_free,
	    format_mheap_byte_count, usage.bytes_free_reclaimed,
	    format_mheap_byte_count, usage.bytes_overhead);

  if (usage.bytes_max != ~0)
    s = format (s, ", %U capacity", format_mheap_byte_count, usage.bytes_max);

  /* Show histogram of sizes. */
  if (verbose > 1)
    {
      uword hist[MHEAP_N_BINS];
      mheap_elt_t *e;
      uword i, n_hist;

      clib_memset (hist, 0, sizeof (hist));

      n_hist = 0;
      for (e = v;
	   e->n_user_data != MHEAP_N_USER_DATA_INVALID;
	   e = mheap_next_elt (e))
	{
	  uword n_user_data_bytes = mheap_elt_data_bytes (e);
	  uword bin = user_data_size_to_bin_index (n_user_data_bytes);
	  if (!e->is_free)
	    {
	      hist[bin] += 1;
	      n_hist += 1;
	    }
	}

      s = format (s, "\n%U%=12s%=12s%=16s",
		  format_white_space, indent + 2,
		  "Size", "Count", "Fraction");

      for (i = 0; i < ARRAY_LEN (hist); i++)
	{
	  if (hist[i] == 0)
	    continue;
	  s = format (s, "\n%U%12d%12wd%16.4f",
		      format_white_space, indent + 2,
		      MHEAP_MIN_USER_DATA_BYTES +
		      i * MHEAP_USER_DATA_WORD_BYTES, hist[i],
		      (f64) hist[i] / (f64) n_hist);
	}
    }

  if (verbose)
    s = format (s, "\n%U%U",
		format_white_space, indent + 2, format_mheap_stats, h);

  if ((h->flags & MHEAP_FLAG_TRACE) && vec_len (h->trace_main.traces) > 0)
    {
      /* Make a copy of traces since we'll be sorting them. */
      mheap_trace_t *t, *traces_copy;
      u32 indent, total_objects_traced;

      traces_copy = vec_dup (h->trace_main.traces);
      qsort (traces_copy, vec_len (traces_copy), sizeof (traces_copy[0]),
	     mheap_trace_sort);

      total_objects_traced = 0;
      s = format (s, "\n");
      vec_foreach (t, traces_copy)
      {
	/* Skip over free elements. */
	if (t->n_allocations == 0)
	  continue;

	total_objects_traced += t->n_allocations;

	/* When not verbose only report allocations of more than 1k. */
	if (!verbose && t->n_bytes < 1024)
	  continue;

	if (t == traces_copy)
	  s = format (s, "%=9s%=9s %=10s Traceback\n", "Bytes", "Count",
		      "Sample");
	s = format (s, "%9d%9d %p", t->n_bytes, t->n_allocations,
		    t->offset + v);
	indent = format_get_indent (s);
	for (i = 0; i < ARRAY_LEN (t->callers) && t->callers[i]; i++)
	  {
	    if (i > 0)
	      s = format (s, "%U", format_white_space, indent);
#ifdef CLIB_UNIX
	    s =
	      format (s, " %U\n", format_clib_elf_symbol_with_address,
		      t->callers[i]);
#else
	    s = format (s, " %p\n", t->callers[i]);
#endif
	  }
      }

      s = format (s, "%d total traced objects\n", total_objects_traced);

      vec_free (traces_copy);
    }

  first_corrupt = mheap_first_corrupt (v);
  if (first_corrupt)
    {
      size = mheap_elt_data_bytes (first_corrupt);
      s = format (s, "\n  first corrupt object: %p, size %wd\n  %U",
		  first_corrupt, size, format_hex_bytes, first_corrupt, size);
    }

  /* FIXME.  This output could be wrong in the unlikely case that format
     uses the same mheap as we are currently inspecting. */
  if (verbose > 1)
    {
      mheap_elt_t *e;
      uword i, o;

      s = format (s, "\n");

      e = mheap_elt_at_uoffset (v, 0);
      i = 0;
      while (1)
	{
	  if ((i % 8) == 0)
	    s = format (s, "%8d: ", i);

	  o = mheap_elt_uoffset (v, e);

	  if (e->is_free)
	    s = format (s, "(%8d) ", o);
	  else
	    s = format (s, " %8d  ", o);

	  if ((i % 8) == 7 || (i + 1) >= h->n_elts)
	    s = format (s, "\n");
	}
    }

  mheap_maybe_unlock (v);

  return s;
}

void
dmh (void *v)
{
  fformat (stderr, "%U", format_mheap, v, 1);
}

static void
mheap_validate_breakpoint ()
{
  os_panic ();
}

void
mheap_validate (void *v)
{
  mheap_t *h = mheap_header (v);
  uword i, s;

  uword elt_count, elt_size;
  uword free_count_from_free_lists, free_size_from_free_lists;
  uword small_elt_free_count, small_elt_free_size;

#define CHECK(x) if (! (x)) { mheap_validate_breakpoint (); os_panic (); }

  if (vec_len (v) == 0)
    return;

  mheap_maybe_lock (v);

  /* Validate number of elements and size. */
  free_size_from_free_lists = free_count_from_free_lists = 0;
  for (i = 0; i < ARRAY_LEN (h->first_free_elt_uoffset_by_bin); i++)
    {
      mheap_elt_t *e, *n;
      uword is_first;

      CHECK ((h->first_free_elt_uoffset_by_bin[i] != MHEAP_GROUNDED)
	     ==
	     ((h->non_empty_free_elt_heads[i /
					   BITS (uword)] & ((uword) 1 <<
							    (uword) (i %
								     BITS
								     (uword))))
	      != 0));

      if (h->first_free_elt_uoffset_by_bin[i] == MHEAP_GROUNDED)
	continue;

      e = mheap_elt_at_uoffset (v, h->first_free_elt_uoffset_by_bin[i]);
      is_first = 1;
      while (1)
	{
	  uword s;

	  n = mheap_next_elt (e);

	  /* Object must be marked free. */
	  CHECK (e->is_free);

	  /* Next object's previous free bit must also be set. */
	  CHECK (n->prev_is_free);

	  if (is_first)
	    CHECK (e->free_elt.prev_uoffset == MHEAP_GROUNDED);
	  is_first = 0;

	  s = mheap_elt_data_bytes (e);
	  CHECK (user_data_size_to_bin_index (s) == i);

	  free_count_from_free_lists += 1;
	  free_size_from_free_lists += s;

	  if (e->free_elt.next_uoffset == MHEAP_GROUNDED)
	    break;

	  n = mheap_elt_at_uoffset (v, e->free_elt.next_uoffset);

	  /* Check free element linkages. */
	  CHECK (n->free_elt.prev_uoffset == mheap_elt_uoffset (v, e));

	  e = n;
	}
    }

  /* Go through small object cache. */
  small_elt_free_count = small_elt_free_size = 0;
  for (i = 0; i < ARRAY_LEN (h->small_object_cache.bins.as_u8); i++)
    {
      if (h->small_object_cache.bins.as_u8[i] != 0)
	{
	  mheap_elt_t *e;
	  uword b = h->small_object_cache.bins.as_u8[i] - 1;
	  uword o = h->small_object_cache.offsets[i];
	  uword s;

	  e = mheap_elt_at_uoffset (v, o);

	  /* Object must be allocated. */
	  CHECK (!e->is_free);

	  s = mheap_elt_data_bytes (e);
	  CHECK (user_data_size_to_bin_index (s) == b);

	  small_elt_free_count += 1;
	  small_elt_free_size += s;
	}
    }

  {
    mheap_elt_t *e, *n;
    uword elt_free_size, elt_free_count;

    elt_count = elt_size = elt_free_size = elt_free_count = 0;
    for (e = v; e->n_user_data != MHEAP_N_USER_DATA_INVALID; e = n)
      {
	if (e->prev_n_user_data != MHEAP_N_USER_DATA_INVALID)
	  CHECK (e->prev_n_user_data * sizeof (e->user_data[0]) >=
		 MHEAP_MIN_USER_DATA_BYTES);

	CHECK (e->n_user_data * sizeof (e->user_data[0]) >=
	       MHEAP_MIN_USER_DATA_BYTES);

	n = mheap_next_elt (e);

	CHECK (e->is_free == n->prev_is_free);

	elt_count++;
	s = mheap_elt_data_bytes (e);
	elt_size += s;

	if (e->is_free)
	  {
	    elt_free_count++;
	    elt_free_size += s;
	  }

	/* Consecutive free objects should have been combined. */
	CHECK (!(e->prev_is_free && n->prev_is_free));
      }

    CHECK (free_count_from_free_lists == elt_free_count);
    CHECK (free_size_from_free_lists == elt_free_size);
    CHECK (elt_count == h->n_elts + elt_free_count + small_elt_free_count);
    CHECK (elt_size + (elt_count + 1) * MHEAP_ELT_OVERHEAD_BYTES ==
	   vec_len (v));
  }

  {
    mheap_elt_t *e, *n;

    for (e = v; e->n_user_data == MHEAP_N_USER_DATA_INVALID; e = n)
      {
	n = mheap_next_elt (e);
	CHECK (e->n_user_data == n->prev_n_user_data);
      }
  }

#undef CHECK

  mheap_maybe_unlock (v);

  h->validate_serial += 1;
}

static void
mheap_get_trace (void *v, uword offset, uword size)
{
  mheap_t *h;
  mheap_trace_main_t *tm;
  mheap_trace_t *t;
  uword i, n_callers, trace_index, *p;
  mheap_trace_t trace;

  /* Spurious Coverity warnings be gone. */
  clib_memset (&trace, 0, sizeof (trace));

  n_callers = clib_backtrace (trace.callers, ARRAY_LEN (trace.callers),
			      /* Skip mheap_get_aligned's frame */ 1);
  if (n_callers == 0)
    return;

  for (i = n_callers; i < ARRAY_LEN (trace.callers); i++)
    trace.callers[i] = 0;

  h = mheap_header (v);
  tm = &h->trace_main;

  if (!tm->trace_by_callers)
    tm->trace_by_callers =
      hash_create_shmem (0, sizeof (trace.callers), sizeof (uword));

  p = hash_get_mem (tm->trace_by_callers, &trace.callers);
  if (p)
    {
      trace_index = p[0];
      t = tm->traces + trace_index;
    }
  else
    {
      i = vec_len (tm->trace_free_list);
      if (i > 0)
	{
	  trace_index = tm->trace_free_list[i - 1];
	  _vec_len (tm->trace_free_list) = i - 1;
	}
      else
	{
	  mheap_trace_t *old_start = tm->traces;
	  mheap_trace_t *old_end = vec_end (tm->traces);

	  vec_add2 (tm->traces, t, 1);

	  if (tm->traces != old_start)
	    {
	      hash_pair_t *p;
	      mheap_trace_t *q;
            /* *INDENT-OFF* */
	    hash_foreach_pair (p, tm->trace_by_callers,
            ({
              q = uword_to_pointer (p->key, mheap_trace_t *);
              ASSERT (q >= old_start && q < old_end);
	      p->key = pointer_to_uword (tm->traces + (q - old_start));
	    }));
            /* *INDENT-ON* */
	    }
	  trace_index = t - tm->traces;
	}

      t = tm->traces + trace_index;
      t[0] = trace;
      t->n_allocations = 0;
      t->n_bytes = 0;
      hash_set_mem (tm->trace_by_callers, t->callers, trace_index);
    }

  t->n_allocations += 1;
  t->n_bytes += size;
  t->offset = offset;		/* keep a sample to autopsy */
  hash_set (tm->trace_index_by_offset, offset, t - tm->traces);
}

static void
mheap_put_trace (void *v, uword offset, uword size)
{
  mheap_t *h;
  mheap_trace_main_t *tm;
  mheap_trace_t *t;
  uword trace_index, *p;

  h = mheap_header (v);
  tm = &h->trace_main;
  p = hash_get (tm->trace_index_by_offset, offset);
  if (!p)
    return;

  trace_index = p[0];
  hash_unset (tm->trace_index_by_offset, offset);
  ASSERT (trace_index < vec_len (tm->traces));

  t = tm->traces + trace_index;
  ASSERT (t->n_allocations > 0);
  ASSERT (t->n_bytes >= size);
  t->n_allocations -= 1;
  t->n_bytes -= size;
  if (t->n_allocations == 0)
    {
      hash_unset_mem (tm->trace_by_callers, t->callers);
      vec_add1 (tm->trace_free_list, trace_index);
      clib_memset (t, 0, sizeof (t[0]));
    }
}

static int
mheap_trace_sort (const void *_t1, const void *_t2)
{
  const mheap_trace_t *t1 = _t1;
  const mheap_trace_t *t2 = _t2;
  word cmp;

  cmp = (word) t2->n_bytes - (word) t1->n_bytes;
  if (!cmp)
    cmp = (word) t2->n_allocations - (word) t1->n_allocations;
  return cmp;
}

always_inline void
mheap_trace_main_free (mheap_trace_main_t * tm)
{
  vec_free (tm->traces);
  vec_free (tm->trace_free_list);
  hash_free (tm->trace_by_callers);
  hash_free (tm->trace_index_by_offset);
}

void
mheap_trace (void *v, int enable)
{
  mheap_t *h;

  h = mheap_header (v);

  if (enable)
    {
      h->flags |= MHEAP_FLAG_TRACE;
    }
  else
    {
      mheap_trace_main_free (&h->trace_main);
      h->flags &= ~MHEAP_FLAG_TRACE;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

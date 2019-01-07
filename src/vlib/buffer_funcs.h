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
 * buffer_funcs.h: VLIB buffer related functions/inlines
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

#ifndef included_vlib_buffer_funcs_h
#define included_vlib_buffer_funcs_h

#include <vppinfra/hash.h>
#include <vppinfra/fifo.h>

/** \file
    vlib buffer access methods.
*/


/** \brief Translate buffer index into buffer pointer

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffer_index - (u32) buffer index
    @return - (vlib_buffer_t *) buffer pointer
*/
always_inline vlib_buffer_t *
vlib_get_buffer (vlib_main_t * vm, u32 buffer_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  uword offset = ((uword) buffer_index) << CLIB_LOG2_CACHE_LINE_BYTES;
  ASSERT (offset < bm->buffer_mem_size);

  return uword_to_pointer (bm->buffer_mem_start + offset, void *);
}

static_always_inline void
vlib_buffer_copy_indices (u32 * dst, u32 * src, u32 n_indices)
{
  clib_memcpy_fast (dst, src, n_indices * sizeof (u32));
}

always_inline u8
vlib_buffer_pool_get_default_for_numa (vlib_main_t * vm, u32 numa_node)
{
  ASSERT (numa_node < vm->buffer_main->n_numa_nodes);
  return numa_node;
}

/** \brief Translate array of buffer indices into buffer pointers with offset

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param bi - (u32 *) array of buffer indices
    @param b - (void **) array to store buffer pointers
    @param count - (uword) number of elements
    @param offset - (i32) offset applied to each pointer
*/
static_always_inline void
vlib_get_buffers_with_offset (vlib_main_t * vm, u32 * bi, void **b, int count,
			      i32 offset)
{
  uword buffer_mem_start = vm->buffer_main->buffer_mem_start;
#ifdef CLIB_HAVE_VEC256
  u64x4 off = u64x4_splat (buffer_mem_start + offset);
  /* if count is not const, compiler will not unroll while loop
     se we maintain two-in-parallel variant */
  while (count >= 8)
    {
      u64x4 b0 = u32x4_extend_to_u64x4 (u32x4_load_unaligned (bi));
      u64x4 b1 = u32x4_extend_to_u64x4 (u32x4_load_unaligned (bi + 4));
      /* shift and add to get vlib_buffer_t pointer */
      u64x4_store_unaligned ((b0 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b);
      u64x4_store_unaligned ((b1 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b + 4);
      b += 8;
      bi += 8;
      count -= 8;
    }
#endif
  while (count >= 4)
    {
#ifdef CLIB_HAVE_VEC256
      u64x4 b0 = u32x4_extend_to_u64x4 (u32x4_load_unaligned (bi));
      /* shift and add to get vlib_buffer_t pointer */
      u64x4_store_unaligned ((b0 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b);
#elif defined (CLIB_HAVE_VEC128)
      u64x2 off = u64x2_splat (buffer_mem_start + offset);
      u32x4 bi4 = u32x4_load_unaligned (bi);
      u64x2 b0 = u32x4_extend_to_u64x2 ((u32x4) bi4);
#if defined (__aarch64__)
      u64x2 b1 = u32x4_extend_to_u64x2_high ((u32x4) bi4);
#else
      bi4 = u32x4_shuffle (bi4, 2, 3, 0, 1);
      u64x2 b1 = u32x4_extend_to_u64x2 ((u32x4) bi4);
#endif
      u64x2_store_unaligned ((b0 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b);
      u64x2_store_unaligned ((b1 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b + 2);
#else
      b[0] = ((u8 *) vlib_get_buffer (vm, bi[0])) + offset;
      b[1] = ((u8 *) vlib_get_buffer (vm, bi[1])) + offset;
      b[2] = ((u8 *) vlib_get_buffer (vm, bi[2])) + offset;
      b[3] = ((u8 *) vlib_get_buffer (vm, bi[3])) + offset;
#endif
      b += 4;
      bi += 4;
      count -= 4;
    }
  while (count)
    {
      b[0] = ((u8 *) vlib_get_buffer (vm, bi[0])) + offset;
      b += 1;
      bi += 1;
      count -= 1;
    }
}

/** \brief Translate array of buffer indices into buffer pointers

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param bi - (u32 *) array of buffer indices
    @param b - (vlib_buffer_t **) array to store buffer pointers
    @param count - (uword) number of elements
*/

static_always_inline void
vlib_get_buffers (vlib_main_t * vm, u32 * bi, vlib_buffer_t ** b, int count)
{
  vlib_get_buffers_with_offset (vm, bi, (void **) b, count, 0);
}

/** \brief Translate buffer pointer into buffer index

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param p - (void *) buffer pointer
    @return - (u32) buffer index
*/

always_inline u32
vlib_get_buffer_index (vlib_main_t * vm, void *p)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  uword offset = pointer_to_uword (p) - bm->buffer_mem_start;
  ASSERT (pointer_to_uword (p) >= bm->buffer_mem_start);
  ASSERT (offset < bm->buffer_mem_size);
  ASSERT ((offset % (1 << CLIB_LOG2_CACHE_LINE_BYTES)) == 0);
  return offset >> CLIB_LOG2_CACHE_LINE_BYTES;
}

/** \brief Translate array of buffer pointers into buffer indices with offset

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param b - (void **) array of buffer pointers
    @param bi - (u32 *) array to store buffer indices
    @param count - (uword) number of elements
    @param offset - (i32) offset applied to each pointer
*/
static_always_inline void
vlib_get_buffer_indices_with_offset (vlib_main_t * vm, void **b, u32 * bi,
				     uword count, i32 offset)
{
#ifdef CLIB_HAVE_VEC256
  u32x8 mask = { 0, 2, 4, 6, 1, 3, 5, 7 };
  u64x4 off4 = u64x4_splat (vm->buffer_main->buffer_mem_start - offset);

  while (count >= 8)
    {
      /* load 4 pointers into 256-bit register */
      u64x4 v0 = u64x4_load_unaligned (b);
      u64x4 v1 = u64x4_load_unaligned (b + 4);
      u32x8 v2, v3;

      v0 -= off4;
      v1 -= off4;

      v0 >>= CLIB_LOG2_CACHE_LINE_BYTES;
      v1 >>= CLIB_LOG2_CACHE_LINE_BYTES;

      /* permute 256-bit register so lower u32s of each buffer index are
       * placed into lower 128-bits */
      v2 = u32x8_permute ((u32x8) v0, mask);
      v3 = u32x8_permute ((u32x8) v1, mask);

      /* extract lower 128-bits and save them to the array of buffer indices */
      u32x4_store_unaligned (u32x8_extract_lo (v2), bi);
      u32x4_store_unaligned (u32x8_extract_lo (v3), bi + 4);
      bi += 8;
      b += 8;
      count -= 8;
    }
#endif
  while (count >= 4)
    {
      /* equivalent non-nector implementation */
      bi[0] = vlib_get_buffer_index (vm, ((u8 *) b[0]) + offset);
      bi[1] = vlib_get_buffer_index (vm, ((u8 *) b[1]) + offset);
      bi[2] = vlib_get_buffer_index (vm, ((u8 *) b[2]) + offset);
      bi[3] = vlib_get_buffer_index (vm, ((u8 *) b[3]) + offset);
      bi += 4;
      b += 4;
      count -= 4;
    }
  while (count)
    {
      bi[0] = vlib_get_buffer_index (vm, ((u8 *) b[0]) + offset);
      bi += 1;
      b += 1;
      count -= 1;
    }
}

/** \brief Translate array of buffer pointers into buffer indices

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param b - (vlib_buffer_t **) array of buffer pointers
    @param bi - (u32 *) array to store buffer indices
    @param count - (uword) number of elements
*/
static_always_inline void
vlib_get_buffer_indices (vlib_main_t * vm, vlib_buffer_t ** b, u32 * bi,
			 uword count)
{
  vlib_get_buffer_indices_with_offset (vm, (void **) b, bi, count, 0);
}

/** \brief Get next buffer in buffer linklist, or zero for end of list.

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param b - (void *) buffer pointer
    @return - (vlib_buffer_t *) next buffer, or NULL
*/
always_inline vlib_buffer_t *
vlib_get_next_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  return (b->flags & VLIB_BUFFER_NEXT_PRESENT
	  ? vlib_get_buffer (vm, b->next_buffer) : 0);
}

uword vlib_buffer_length_in_chain_slow_path (vlib_main_t * vm,
					     vlib_buffer_t * b_first);

/** \brief Get length in bytes of the buffer chain

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param b - (void *) buffer pointer
    @return - (uword) length of buffer chain
*/
always_inline uword
vlib_buffer_length_in_chain (vlib_main_t * vm, vlib_buffer_t * b)
{
  uword len = b->current_length;

  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    return len;

  if (PREDICT_TRUE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    return len + b->total_length_not_including_first_buffer;

  return vlib_buffer_length_in_chain_slow_path (vm, b);
}

/** \brief Get length in bytes of the buffer index buffer chain

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param bi - (u32) buffer index
    @return - (uword) length of buffer chain
*/
always_inline uword
vlib_buffer_index_length_in_chain (vlib_main_t * vm, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  return vlib_buffer_length_in_chain (vm, b);
}

/** \brief Copy buffer contents to memory

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffer_index - (u32) buffer index
    @param contents - (u8 *) memory, <strong>must be large enough</strong>
    @return - (uword) length of buffer chain
*/
always_inline uword
vlib_buffer_contents (vlib_main_t * vm, u32 buffer_index, u8 * contents)
{
  uword content_len = 0;
  uword l;
  vlib_buffer_t *b;

  while (1)
    {
      b = vlib_get_buffer (vm, buffer_index);
      l = b->current_length;
      clib_memcpy_fast (contents + content_len, b->data + b->current_data, l);
      content_len += l;
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      buffer_index = b->next_buffer;
    }

  return content_len;
}

always_inline uword
vlib_buffer_get_pa (vlib_main_t * vm, vlib_buffer_t * b)
{
  return vlib_physmem_get_pa (vm, b->data);
}

always_inline uword
vlib_buffer_get_current_pa (vlib_main_t * vm, vlib_buffer_t * b)
{
  return vlib_buffer_get_pa (vm, b) + b->current_data;
}

/** \brief Prefetch buffer metadata by buffer index
    The first 64 bytes of buffer contains most header information

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param bi - (u32) buffer index
    @param type - LOAD, STORE. In most cases, STORE is the right answer
*/
/* Prefetch buffer header given index. */
#define vlib_prefetch_buffer_with_index(vm,bi,type)	\
  do {							\
    vlib_buffer_t * _b = vlib_get_buffer (vm, bi);	\
    vlib_prefetch_buffer_header (_b, type);		\
  } while (0)

typedef enum
{
  /* Index is unknown. */
  VLIB_BUFFER_UNKNOWN,

  /* Index is known and free/allocated. */
  VLIB_BUFFER_KNOWN_FREE,
  VLIB_BUFFER_KNOWN_ALLOCATED,
} vlib_buffer_known_state_t;

void vlib_buffer_validate_alloc_free (vlib_main_t * vm, u32 * buffers,
				      uword n_buffers,
				      vlib_buffer_known_state_t
				      expected_state);

always_inline vlib_buffer_known_state_t
vlib_buffer_is_known (vlib_main_t * vm, u32 buffer_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  clib_spinlock_lock (&bm->buffer_known_hash_lockp);
  uword *p = hash_get (bm->buffer_known_hash, buffer_index);
  clib_spinlock_unlock (&bm->buffer_known_hash_lockp);
  return p ? p[0] : VLIB_BUFFER_UNKNOWN;
}

always_inline void
vlib_buffer_set_known_state (vlib_main_t * vm, u32 buffer_index,
			     vlib_buffer_known_state_t state)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  clib_spinlock_lock (&bm->buffer_known_hash_lockp);
  hash_set (bm->buffer_known_hash, buffer_index, state);
  clib_spinlock_unlock (&bm->buffer_known_hash_lockp);
}

/* Validates sanity of a single buffer.
   Returns format'ed vector with error message if any. */
u8 *vlib_validate_buffer (vlib_main_t * vm, u32 buffer_index,
			  uword follow_chain);

always_inline u32
vlib_buffer_round_size (u32 size)
{
  return round_pow2 (size, sizeof (vlib_buffer_t));
}

static_always_inline void
vlib_buffer_init_metadata_from_template (vlib_main_t * vm, vlib_buffer_t * bt,
					 u32 * buffers, u32 n_buffers)
{
  u32 n_left = n_buffers;
  u16 prefetch_stride = 16;
  u16 batch_size = 128;
  vlib_buffer_t *buffer_ptrs[batch_size + prefetch_stride], **b;

#if defined (CLIB_HAVE_VEC256)
  u8x32 r0, r1;
  r0 = u8x32_load_unaligned (((u8 *) bt) + 0);
  r1 = u8x32_load_unaligned (((u8 *) bt) + 32);
#define _(b) \
  u8x32_store_unaligned (r0, ((u8 *) b) + 0); \
  u8x32_store_unaligned (r1, ((u8 *) b) + 32)
#elif defined (CLIB_HAVE_VEC128)
  u8x16 r0, r1, r2, r3;
  r0 = u8x16_load_unaligned (((u8 *) bt) + 0);
  r1 = u8x16_load_unaligned (((u8 *) bt) + 16);
  r2 = u8x16_load_unaligned (((u8 *) bt) + 32);
  r3 = u8x16_load_unaligned (((u8 *) bt) + 48);
#define _(b) \
  u8x16_store_unaligned (r0, ((u8 *) b) + 0); \
  u8x16_store_unaligned (r1, ((u8 *) b) + 16); \
  u8x16_store_unaligned (r2, ((u8 *) b) + 32); \
  u8x16_store_unaligned (r3, ((u8 *) b) + 48)
#else
#define _(b) \
  clib_memcpy (b, bt, 64)
#endif

  while (n_buffers >= batch_size + prefetch_stride)
    {
      b = buffer_ptrs;
      vlib_get_buffers (vm, buffers, b, batch_size + prefetch_stride);
      n_left = batch_size;
      while (n_left)
	{
	  vlib_buffer_t **pb = b + prefetch_stride;
	  vlib_prefetch_buffer_header (pb[0], STORE);
	  vlib_prefetch_buffer_header (pb[1], STORE);
	  vlib_prefetch_buffer_header (pb[2], STORE);
	  vlib_prefetch_buffer_header (pb[3], STORE);
	  _(b[0]);
	  _(b[1]);
	  _(b[2]);
	  _(b[3]);
	  vlib_prefetch_buffer_header (pb[4], STORE);
	  vlib_prefetch_buffer_header (pb[5], STORE);
	  vlib_prefetch_buffer_header (pb[6], STORE);
	  vlib_prefetch_buffer_header (pb[7], STORE);
	  _(b[4]);
	  _(b[5]);
	  _(b[6]);
	  _(b[7]);

	  n_left -= 8;
	  b += 8;
	}
      n_buffers -= batch_size;
      buffers += batch_size;
    }

  b = buffer_ptrs;
  vlib_get_buffers (vm, buffers, b, n_buffers);

  while (n_left >= 8)
    {
      _(b[0]);
      _(b[1]);
      _(b[2]);
      _(b[3]);
      _(b[4]);
      _(b[5]);
      _(b[6]);
      _(b[7]);

      n_left -= 8;
      b += 8;
    }

  while (n_left)
    {
      _(b[0]);

      n_left -= 1;
      b += 1;
    }
#undef _
}

/** \brief Allocate buffers from specific freelist into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/

always_inline u32
vlib_buffer_alloc_from_pool (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			     u8 buffer_pool_index, int do_init)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;
  vlib_buffer_pool_thread_t *bpt;
  u32 *src, *dst, len, n_left;

  ASSERT (bm->cb.vlib_buffer_pool_get_cb);

  bp = vec_elt_at_index (bm->buffer_pools, buffer_pool_index);
  bpt = vec_elt_at_index (bp->threads, vm->thread_index);

  dst = buffers;
  n_left = n_buffers;
  len = vec_len (bpt->cached_buffers);

  /* per-thread cache contains enough buffers */
  if (len >= n_buffers)
    {
      src = bpt->cached_buffers + len - n_buffers;
      vlib_buffer_copy_indices (dst, src, n_buffers);
      _vec_len (bpt->cached_buffers) -= n_buffers;
      vlib_buffer_validate_alloc_free (vm, buffers, n_buffers,
				       VLIB_BUFFER_KNOWN_FREE);
      vlib_buffer_init_metadata_from_template (vm, &bp->buffer_template,
					       buffers, n_buffers);
      return n_buffers;
    }

  /* take everything available in the cache */
  if (len)
    {
      vlib_buffer_copy_indices (dst, bpt->cached_buffers, len);
      _vec_len (bpt->cached_buffers) = 0;
      dst += len;
      n_left -= len;
    }

  len = round_pow2 (n_left, 32);
  vec_validate_aligned (bpt->cached_buffers, len - 1, CLIB_CACHE_LINE_BYTES);
  len = bm->cb.vlib_buffer_pool_get_cb (vm, buffer_pool_index,
					bpt->cached_buffers, len);
  _vec_len (bpt->cached_buffers) = len;

  if (len)
    {
      u32 n_copy = clib_min (len, n_left);
      src = bpt->cached_buffers + len - n_copy;
      vlib_buffer_copy_indices (dst, src, n_copy);
      _vec_len (bpt->cached_buffers) -= n_copy;
      n_left -= n_copy;
    }

  n_buffers -= n_left;

  /* Verify that buffers are known free. */
  vlib_buffer_validate_alloc_free (vm, buffers, n_buffers,
				   VLIB_BUFFER_KNOWN_FREE);

  if (do_init)
    vlib_buffer_init_metadata_from_template (vm, &bp->buffer_template,
					     buffers, n_buffers);
  return n_buffers;
}

static_always_inline vlib_buffer_pool_t *
vlib_buffer_pool_get (vlib_main_t * vm, u8 buffer_pool_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  return vec_elt_at_index (bm->buffer_pools, buffer_pool_index);
}

/** \brief Initialize buffer metadata from pool template

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @param buffer_pool_index - (u8) buffer pool index
    less than the number requested or zero
*/
always_inline void
vlib_buffer_init_for_pool (vlib_main_t * vm, vlib_buffer_t * b,
			   u8 buffer_pool_index)
{
  vlib_buffer_pool_t *bp = vlib_buffer_pool_get (vm, buffer_pool_index);
  clib_memcpy_fast (b, &bp->buffer_template, CLIB_CACHE_LINE_BYTES);
}

/** \brief Allocate buffers from specific numa node into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @param numa_node - (u32) numa node
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/
always_inline u32
vlib_buffer_alloc_on_numa (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			   u32 numa_node)
{
  u8 index = vlib_buffer_pool_get_default_for_numa (vm, numa_node);
  return vlib_buffer_alloc_from_pool (vm, buffers, n_buffers, index, 1);
}

/** \brief Allocate buffers from specific numa node into supplied array
           without initializing buffer metadata

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @param numa_node - (u32) numa node
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/

always_inline u32
vlib_buffer_alloc_on_numa_no_init (vlib_main_t * vm, u32 * buffers,
				   u32 n_buffers, u32 numa_node)
{
  u8 index = vlib_buffer_pool_get_default_for_numa (vm, numa_node);
  return vlib_buffer_alloc_from_pool (vm, buffers, n_buffers, index, 0);
}

/** \brief Allocate buffers into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/

always_inline u32
vlib_buffer_alloc (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  return vlib_buffer_alloc_on_numa (vm, buffers, n_buffers, vm->numa_node);
}

/** \brief Allocate buffers into supplied array without initializing buffer
           metadata
    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/

always_inline u32
vlib_buffer_alloc_no_init (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  return vlib_buffer_alloc_on_numa_no_init (vm, buffers, n_buffers,
					    vm->numa_node);
}


/** \brief Allocate buffers into ring

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index ring
    @param start - (u32) first slot in the ring
    @param ring_size - (u32) ring size
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/
always_inline u32
vlib_buffer_alloc_to_ring (vlib_main_t * vm, u32 * ring, u32 start,
			   u32 ring_size, u32 n_buffers)
{
  u32 n_alloc;

  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    return vlib_buffer_alloc (vm, ring + start, n_buffers);

  n_alloc = vlib_buffer_alloc (vm, ring + start, ring_size - start);

  if (PREDICT_TRUE (n_alloc == ring_size - start))
    n_alloc += vlib_buffer_alloc (vm, ring, n_buffers - n_alloc);

  return n_alloc;
}

/** \brief Allocate buffers into ring from specific buffer pool and don't
           init buffer metadata

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index ring
    @param start - (u32) first slot in the ring
    @param ring_size - (u32) ring size
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/
always_inline u32
vlib_buffer_alloc_to_ring_from_pool_no_init (vlib_main_t * vm, u32 * ring,
					     u32 start, u32 ring_size,
					     u32 n_buffers,
					     u8 buffer_pool_index)
{
  u32 n_alloc;

  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    return vlib_buffer_alloc_from_pool (vm, ring + start, n_buffers,
					buffer_pool_index, 0);

  n_alloc = vlib_buffer_alloc_from_pool (vm, ring + start, ring_size - start,
					 buffer_pool_index, 0);

  if (PREDICT_TRUE (n_alloc == ring_size - start))
    n_alloc += vlib_buffer_alloc_from_pool (vm, ring, n_buffers - n_alloc,
					    buffer_pool_index, 0);

  return n_alloc;
}

void vlib_buffer_free2 (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			int maybe_next);

/** \brief Free buffers
    Frees the entire buffer chain for each buffer

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers to free

*/
always_inline void
vlib_buffer_free (vlib_main_t * vm,
		  /* pointer to first buffer */
		  u32 * buffers,
		  /* number of buffers to free */
		  u32 n_buffers)
{
  vlib_buffer_free2 (vm, buffers, n_buffers, 1);
}

/** \brief Free buffers, does not free the buffer chain for each buffer

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers to free

*/
always_inline void
vlib_buffer_free_no_next (vlib_main_t * vm,
			  /* pointer to first buffer */
			  u32 * buffers,
			  /* number of buffers to free */
			  u32 n_buffers)
{
  vlib_buffer_free2 (vm, buffers, n_buffers, 0);
}

/** \brief Free one buffer
    Shorthand to free a single buffer chain.

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffer_index - (u32) buffer index to free
*/
always_inline void
vlib_buffer_free_one (vlib_main_t * vm, u32 buffer_index)
{
  vlib_buffer_free (vm, &buffer_index, /* n_buffers */ 1);
}

/** \brief Free buffers from ring

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index ring
    @param start - (u32) first slot in the ring
    @param ring_size - (u32) ring size
    @param n_buffers - (u32) number of buffers
*/
always_inline void
vlib_buffer_free_from_ring (vlib_main_t * vm, u32 * ring, u32 start,
			    u32 ring_size, u32 n_buffers)
{
  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    {
      vlib_buffer_free (vm, ring + start, n_buffers);
    }
  else
    {
      vlib_buffer_free (vm, ring + start, ring_size - start);
      vlib_buffer_free (vm, ring, n_buffers - (ring_size - start));
    }
}

/** \brief Free buffers from ring without freeing tail buffers

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index ring
    @param start - (u32) first slot in the ring
    @param ring_size - (u32) ring size
    @param n_buffers - (u32) number of buffers
*/
always_inline void
vlib_buffer_free_from_ring_no_next (vlib_main_t * vm, u32 * ring, u32 start,
				    u32 ring_size, u32 n_buffers)
{
  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    {
      vlib_buffer_free_no_next (vm, ring + start, n_buffers);
    }
  else
    {
      vlib_buffer_free_no_next (vm, ring + start, ring_size - start);
      vlib_buffer_free_no_next (vm, ring, n_buffers - (ring_size - start));
    }
}

/* Append given data to end of buffer, possibly allocating new buffers. */
int vlib_buffer_add_data (vlib_main_t * vm, u32 * buffer_index, void *data,
			  u32 n_data_bytes);

/* duplicate all buffers in chain */
always_inline vlib_buffer_t *
vlib_buffer_copy (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_buffer_t *s, *d, *fd;
  uword n_alloc, n_buffers = 1;
  u32 flag_mask = VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID;
  int i;

  s = b;
  while (s->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      n_buffers++;
      s = vlib_get_buffer (vm, s->next_buffer);
    }
  u32 new_buffers[n_buffers];

  n_alloc = vlib_buffer_alloc (vm, new_buffers, n_buffers);

  /* No guarantee that we'll get all the buffers we asked for */
  if (PREDICT_FALSE (n_alloc < n_buffers))
    {
      if (n_alloc > 0)
	vlib_buffer_free (vm, new_buffers, n_alloc);
      return 0;
    }

  /* 1st segment */
  s = b;
  fd = d = vlib_get_buffer (vm, new_buffers[0]);
  d->current_data = s->current_data;
  d->current_length = s->current_length;
  d->flags = s->flags & flag_mask;
  d->total_length_not_including_first_buffer =
    s->total_length_not_including_first_buffer;
  clib_memcpy_fast (d->opaque, s->opaque, sizeof (s->opaque));
  clib_memcpy_fast (d->opaque2, s->opaque2, sizeof (s->opaque2));
  clib_memcpy_fast (vlib_buffer_get_current (d),
		    vlib_buffer_get_current (s), s->current_length);

  /* next segments */
  for (i = 1; i < n_buffers; i++)
    {
      /* previous */
      d->next_buffer = new_buffers[i];
      /* current */
      s = vlib_get_buffer (vm, s->next_buffer);
      d = vlib_get_buffer (vm, new_buffers[i]);
      d->current_data = s->current_data;
      d->current_length = s->current_length;
      clib_memcpy_fast (vlib_buffer_get_current (d),
			vlib_buffer_get_current (s), s->current_length);
      d->flags = s->flags & flag_mask;
    }

  return fd;
}

/** \brief Create a maximum of 256 clones of buffer and store them
    in the supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param src_buffer - (u32) source buffer index
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u16) number of buffer clones requested (<=256)
    @param head_end_offset - (u16) offset relative to current position
           where packet head ends
    @return - (u16) number of buffers actually cloned, may be
    less than the number requested or zero
*/
always_inline u16
vlib_buffer_clone_256 (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
		       u16 n_buffers, u16 head_end_offset)
{
  u16 i;
  vlib_buffer_t *s = vlib_get_buffer (vm, src_buffer);

  ASSERT (s->n_add_refs == 0);
  ASSERT (n_buffers);
  ASSERT (n_buffers <= 256);

  if (s->current_length <= head_end_offset + CLIB_CACHE_LINE_BYTES * 2)
    {
      buffers[0] = src_buffer;
      for (i = 1; i < n_buffers; i++)
	{
	  vlib_buffer_t *d;
	  d = vlib_buffer_copy (vm, s);
	  if (d == 0)
	    return i;
	  buffers[i] = vlib_get_buffer_index (vm, d);

	}
      return n_buffers;
    }

  if (PREDICT_FALSE (n_buffers == 1))
    {
      buffers[0] = src_buffer;
      return 1;
    }

  n_buffers = vlib_buffer_alloc_from_pool (vm, buffers, n_buffers,
					   s->buffer_pool_index, 1);

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *d = vlib_get_buffer (vm, buffers[i]);
      d->current_data = s->current_data;
      d->current_length = head_end_offset;
      ASSERT (d->buffer_pool_index == s->buffer_pool_index);

      d->total_length_not_including_first_buffer = s->current_length -
	head_end_offset;
      if (PREDICT_FALSE (s->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  d->total_length_not_including_first_buffer +=
	    s->total_length_not_including_first_buffer;
	}
      d->flags = s->flags | VLIB_BUFFER_NEXT_PRESENT;
      d->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
      clib_memcpy_fast (d->opaque, s->opaque, sizeof (s->opaque));
      clib_memcpy_fast (d->opaque2, s->opaque2, sizeof (s->opaque2));
      clib_memcpy_fast (vlib_buffer_get_current (d),
			vlib_buffer_get_current (s), head_end_offset);
      d->next_buffer = src_buffer;
    }
  vlib_buffer_advance (s, head_end_offset);
  s->n_add_refs = n_buffers - 1;
  while (s->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      s = vlib_get_buffer (vm, s->next_buffer);
      s->n_add_refs = n_buffers - 1;
    }

  return n_buffers;
}

/** \brief Create multiple clones of buffer and store them
    in the supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param src_buffer - (u32) source buffer index
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u16) number of buffer clones requested (<=256)
    @param head_end_offset - (u16) offset relative to current position
           where packet head ends
    @return - (u16) number of buffers actually cloned, may be
    less than the number requested or zero
*/
always_inline u16
vlib_buffer_clone (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
		   u16 n_buffers, u16 head_end_offset)
{
  vlib_buffer_t *s = vlib_get_buffer (vm, src_buffer);
  u16 n_cloned = 0;

  while (n_buffers > 256)
    {
      vlib_buffer_t *copy;
      copy = vlib_buffer_copy (vm, s);
      n_cloned += vlib_buffer_clone_256 (vm,
					 vlib_get_buffer_index (vm, copy),
					 (buffers + n_cloned),
					 256, head_end_offset);
      n_buffers -= 256;
    }
  n_cloned += vlib_buffer_clone_256 (vm, src_buffer,
				     buffers + n_cloned,
				     n_buffers, head_end_offset);

  return n_cloned;
}

/** \brief Attach cloned tail to the buffer

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param head - (vlib_buffer_t *) head buffer
    @param tail - (Vlib buffer_t *) tail buffer to clone and attach to head
*/

always_inline void
vlib_buffer_attach_clone (vlib_main_t * vm, vlib_buffer_t * head,
			  vlib_buffer_t * tail)
{
  ASSERT ((head->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  ASSERT (head->buffer_pool_index == tail->buffer_pool_index);

  head->flags |= VLIB_BUFFER_NEXT_PRESENT;
  head->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
  head->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
  head->flags |= (tail->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
  head->next_buffer = vlib_get_buffer_index (vm, tail);
  head->total_length_not_including_first_buffer = tail->current_length +
    tail->total_length_not_including_first_buffer;

next_segment:
  clib_atomic_add_fetch (&tail->n_add_refs, 1);

  if (tail->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      tail = vlib_get_buffer (vm, tail->next_buffer);
      goto next_segment;
    }
}

/* Initializes the buffer as an empty packet with no chained buffers. */
always_inline void
vlib_buffer_chain_init (vlib_buffer_t * first)
{
  first->total_length_not_including_first_buffer = 0;
  first->current_length = 0;
  first->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  first->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
}

/* The provided next_bi buffer index is appended to the end of the packet. */
always_inline vlib_buffer_t *
vlib_buffer_chain_buffer (vlib_main_t * vm, vlib_buffer_t * last, u32 next_bi)
{
  vlib_buffer_t *next_buffer = vlib_get_buffer (vm, next_bi);
  last->next_buffer = next_bi;
  last->flags |= VLIB_BUFFER_NEXT_PRESENT;
  next_buffer->current_length = 0;
  next_buffer->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  return next_buffer;
}

/* Increases or decreases the packet length.
 * It does not allocate or deallocate new buffers.
 * Therefore, the added length must be compatible
 * with the last buffer. */
always_inline void
vlib_buffer_chain_increase_length (vlib_buffer_t * first,
				   vlib_buffer_t * last, i32 len)
{
  last->current_length += len;
  if (first != last)
    first->total_length_not_including_first_buffer += len;
}

/* Copy data to the end of the packet and increases its length.
 * It does not allocate new buffers.
 * Returns the number of copied bytes. */
always_inline u16
vlib_buffer_chain_append_data (vlib_main_t * vm,
			       vlib_buffer_t * first,
			       vlib_buffer_t * last, void *data, u16 data_len)
{
  u32 n_buffer_bytes = VLIB_BUFFER_DATA_SIZE;
  ASSERT (n_buffer_bytes >= last->current_length + last->current_data);
  u16 len = clib_min (data_len,
		      n_buffer_bytes - last->current_length -
		      last->current_data);
  clib_memcpy_fast (vlib_buffer_get_current (last) + last->current_length,
		    data, len);
  vlib_buffer_chain_increase_length (first, last, len);
  return len;
}

/* Copy data to the end of the packet and increases its length.
 * Allocates additional buffers from the free list if necessary.
 * Returns the number of copied bytes.
 * 'last' value is modified whenever new buffers are allocated and
 * chained and points to the last buffer in the chain. */
u16
vlib_buffer_chain_append_data_with_alloc (vlib_main_t * vm,
					  vlib_buffer_t * first,
					  vlib_buffer_t ** last, void *data,
					  u16 data_len);
void vlib_buffer_chain_validate (vlib_main_t * vm, vlib_buffer_t * first);

format_function_t format_vlib_buffer, format_vlib_buffer_and_data,
  format_vlib_buffer_contents;

typedef struct
{
  /* Vector of packet data. */
  u8 *packet_data;

  /* Number of buffers to allocate in each call to allocator. */
  u32 min_n_buffers_each_alloc;

  u8 *name;
} vlib_packet_template_t;

void vlib_packet_template_init (vlib_main_t * vm,
				vlib_packet_template_t * t,
				void *packet_data,
				uword n_packet_data_bytes,
				uword min_n_buffers_each_alloc,
				char *fmt, ...);

void *vlib_packet_template_get_packet (vlib_main_t * vm,
				       vlib_packet_template_t * t,
				       u32 * bi_result);

always_inline void
vlib_packet_template_free (vlib_main_t * vm, vlib_packet_template_t * t)
{
  vec_free (t->packet_data);
}

always_inline void
vlib_buffer_add_to_free_list (vlib_main_t * vm, u32 buffer_index, u8 do_init)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  vlib_buffer_pool_t *bp = vlib_buffer_pool_get (vm, b->buffer_pool_index);
  vlib_buffer_pool_thread_t *bpt =
    vec_elt_at_index (bp->threads, vm->thread_index);
  vec_add1_aligned (bpt->cached_buffers, buffer_index, CLIB_CACHE_LINE_BYTES);

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

#if CLIB_DEBUG > 0
extern u32 *vlib_buffer_state_validation_lock;
extern uword *vlib_buffer_state_validation_hash;
extern void *vlib_buffer_state_heap;
#endif

static inline void
vlib_validate_buffer_in_use (vlib_buffer_t * b, u32 expected)
{
#if CLIB_DEBUG > 0
  uword *p;
  void *oldheap;

  oldheap = clib_mem_set_heap (vlib_buffer_state_heap);

  while (clib_atomic_test_and_set (vlib_buffer_state_validation_lock))
    ;

  p = hash_get (vlib_buffer_state_validation_hash, b);

  /* If we don't know about b, declare it to be in the expected state */
  if (!p)
    {
      hash_set (vlib_buffer_state_validation_hash, b, expected);
      goto out;
    }

  if (p[0] != expected)
    {
      void cj_stop (void);
      u32 bi;
      vlib_main_t *vm = &vlib_global_main;

      cj_stop ();

      bi = vlib_get_buffer_index (vm, b);

      clib_mem_set_heap (oldheap);
      clib_warning ("%.6f buffer %llx (%d): %s, not %s",
		    vlib_time_now (vm), bi,
		    p[0] ? "busy" : "free", expected ? "busy" : "free");
      os_panic ();
    }
out:
  CLIB_MEMORY_BARRIER ();
  *vlib_buffer_state_validation_lock = 0;
  clib_mem_set_heap (oldheap);
#endif
}

static inline void
vlib_validate_buffer_set_in_use (vlib_buffer_t * b, u32 expected)
{
#if CLIB_DEBUG > 0
  void *oldheap;

  oldheap = clib_mem_set_heap (vlib_buffer_state_heap);

  while (clib_atomic_test_and_set (vlib_buffer_state_validation_lock))
    ;

  hash_set (vlib_buffer_state_validation_hash, b, expected);

  CLIB_MEMORY_BARRIER ();
  *vlib_buffer_state_validation_lock = 0;
  clib_mem_set_heap (oldheap);
#endif
}

/** minimum data size of first buffer in a buffer chain */
#define VLIB_BUFFER_CHAIN_MIN_FIRST_DATA_SIZE (256)

/**
 * @brief compress buffer chain in a way where the first buffer is at least
 * VLIB_BUFFER_CHAIN_MIN_FIRST_DATA_SIZE long
 *
 * @param[in] vm - vlib_main
 * @param[in,out] first - first buffer in chain
 * @param[in,out] discard_vector - vector of buffer indexes which were removed
 * from the chain
 */
always_inline void
vlib_buffer_chain_compress (vlib_main_t * vm,
			    vlib_buffer_t * first, u32 ** discard_vector)
{
  if (first->current_length >= VLIB_BUFFER_CHAIN_MIN_FIRST_DATA_SIZE ||
      !(first->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      /* this is already big enough or not a chain */
      return;
    }
  /* probe free list to find allocated buffer size to avoid overfill */

  u32 want_first_size = clib_min (VLIB_BUFFER_CHAIN_MIN_FIRST_DATA_SIZE,
				  VLIB_BUFFER_DATA_SIZE -
				  first->current_data);
  do
    {
      vlib_buffer_t *second = vlib_get_buffer (vm, first->next_buffer);
      u32 need = want_first_size - first->current_length;
      u32 amount_to_copy = clib_min (need, second->current_length);
      clib_memcpy_fast (((u8 *) vlib_buffer_get_current (first)) +
			first->current_length,
			vlib_buffer_get_current (second), amount_to_copy);
      first->current_length += amount_to_copy;
      second->current_data += amount_to_copy;
      second->current_length -= amount_to_copy;
      if (first->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID)
	{
	  first->total_length_not_including_first_buffer -= amount_to_copy;
	}
      if (!second->current_length)
	{
	  vec_add1 (*discard_vector, first->next_buffer);
	  if (second->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      first->next_buffer = second->next_buffer;
	    }
	  else
	    {
	      first->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	    }
	  second->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	}
    }
  while ((first->current_length < want_first_size) &&
	 (first->flags & VLIB_BUFFER_NEXT_PRESENT));
}

/**
 * @brief linearize buffer chain - the first buffer is filled, if needed,
 * buffers are allocated and filled, returns free space in last buffer or
 * negative on failure
 *
 * @param[in] vm - vlib_main
 * @param[in,out] first - first buffer in chain
 */
always_inline int
vlib_buffer_chain_linearize (vlib_main_t * vm, vlib_buffer_t * first)
{
  vlib_buffer_t *b = first;
  u32 buf_len = VLIB_BUFFER_DATA_SIZE;
  // free buffer chain starting from the second buffer
  int free_count = (b->flags & VLIB_BUFFER_NEXT_PRESENT) != 0;
  u32 chain_to_free = b->next_buffer;

  u32 len = vlib_buffer_length_in_chain (vm, b);
  u32 free_len = buf_len - b->current_data - b->current_length;
  int alloc_len = clib_max (len - free_len, 0);	//use the free len in the first buffer
  int n_buffers = (alloc_len + buf_len - 1) / buf_len;
  u32 new_buffers[n_buffers];

  u32 n_alloc = vlib_buffer_alloc (vm, new_buffers, n_buffers);
  if (n_alloc != n_buffers)
    {
      vlib_buffer_free_no_next (vm, new_buffers, n_alloc);
      return -1;
    }

  vlib_buffer_t *s = b;
  while (s->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      s = vlib_get_buffer (vm, s->next_buffer);
      int d_free_len = buf_len - b->current_data - b->current_length;
      ASSERT (d_free_len >= 0);
      // chain buf and split write
      u32 copy_len = clib_min (d_free_len, s->current_length);
      u8 *d = vlib_buffer_put_uninit (b, copy_len);
      clib_memcpy (d, vlib_buffer_get_current (s), copy_len);
      int rest = s->current_length - copy_len;
      if (rest > 0)
	{
	  //prev buf is full
	  ASSERT (vlib_buffer_get_tail (b) == b->data + buf_len);
	  ASSERT (n_buffers > 0);
	  b = vlib_buffer_chain_buffer (vm, b, new_buffers[--n_buffers]);
	  //make full use of the new buffers
	  b->current_data = 0;
	  d = vlib_buffer_put_uninit (b, rest);
	  clib_memcpy (d, vlib_buffer_get_current (s) + copy_len, rest);
	}
    }
  vlib_buffer_free (vm, &chain_to_free, free_count);
  b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
  if (b == first)		/* no buffers addeed */
    b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  ASSERT (len == vlib_buffer_length_in_chain (vm, first));
  ASSERT (n_buffers == 0);
  return buf_len - b->current_data - b->current_length;
}

#endif /* included_vlib_buffer_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

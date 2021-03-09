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
#include <vlib/buffer.h>
#include <vlib/physmem_funcs.h>
#include <vlib/main.h>
#include <vlib/node.h>

/** \file
    vlib buffer access methods.
*/

always_inline void
vlib_buffer_validate (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  /* reference count in allocated buffer always must be 1 or higher */
  ASSERT (b->ref_count > 0);

  /* verify that buffer pool index is valid */
  bp = vec_elt_at_index (bm->buffer_pools, b->buffer_pool_index);
  ASSERT (pointer_to_uword (b) >= bp->start);
  ASSERT (pointer_to_uword (b) < bp->start + bp->size -
	  (bp->data_size + sizeof (vlib_buffer_t)));
}

always_inline void *
vlib_buffer_ptr_from_index (uword buffer_mem_start, u32 buffer_index,
			    uword offset)
{
  offset += ((uword) buffer_index) << CLIB_LOG2_CACHE_LINE_BYTES;
  return uword_to_pointer (buffer_mem_start + offset, vlib_buffer_t *);
}

/** \brief Translate buffer index into buffer pointer

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffer_index - (u32) buffer index
    @return - (vlib_buffer_t *) buffer pointer
*/
always_inline vlib_buffer_t *
vlib_get_buffer (vlib_main_t * vm, u32 buffer_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_t *b;

  b = vlib_buffer_ptr_from_index (bm->buffer_mem_start, buffer_index, 0);
  vlib_buffer_validate (vm, b);
  return b;
}

static_always_inline u32
vlib_buffer_get_default_data_size (vlib_main_t * vm)
{
  return vm->buffer_main->default_data_size;
}

static_always_inline void
vlib_buffer_copy_indices (u32 * dst, u32 * src, u32 n_indices)
{
#if defined(CLIB_HAVE_VEC512)
  while (n_indices >= 16)
    {
      u32x16_store_unaligned (u32x16_load_unaligned (src), dst);
      dst += 16;
      src += 16;
      n_indices -= 16;
    }
#endif

#if defined(CLIB_HAVE_VEC256)
  while (n_indices >= 8)
    {
      u32x8_store_unaligned (u32x8_load_unaligned (src), dst);
      dst += 8;
      src += 8;
      n_indices -= 8;
    }
#endif

#if defined(CLIB_HAVE_VEC128)
  while (n_indices >= 4)
    {
      u32x4_store_unaligned (u32x4_load_unaligned (src), dst);
      dst += 4;
      src += 4;
      n_indices -= 4;
    }
#endif

  while (n_indices)
    {
      dst[0] = src[0];
      dst += 1;
      src += 1;
      n_indices -= 1;
    }
}

always_inline void
vlib_buffer_copy_indices_from_ring (u32 * dst, u32 * ring, u32 start,
				    u32 ring_size, u32 n_buffers)
{
  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    {
      vlib_buffer_copy_indices (dst, ring + start, n_buffers);
    }
  else
    {
      u32 n = ring_size - start;
      vlib_buffer_copy_indices (dst, ring + start, n);
      vlib_buffer_copy_indices (dst + n, ring, n_buffers - n);
    }
}

always_inline void
vlib_buffer_copy_indices_to_ring (u32 * ring, u32 * src, u32 start,
				  u32 ring_size, u32 n_buffers)
{
  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    {
      vlib_buffer_copy_indices (ring + start, src, n_buffers);
    }
  else
    {
      u32 n = ring_size - start;
      vlib_buffer_copy_indices (ring + start, src, n);
      vlib_buffer_copy_indices (ring, src + n, n_buffers - n);
    }
}

STATIC_ASSERT_OFFSET_OF (vlib_buffer_t, template_end, 64);
static_always_inline void
vlib_buffer_copy_template (vlib_buffer_t * b, vlib_buffer_t * bt)
{
#if defined CLIB_HAVE_VEC512
  b->as_u8x64[0] = bt->as_u8x64[0];
#elif defined (CLIB_HAVE_VEC256)
  b->as_u8x32[0] = bt->as_u8x32[0];
  b->as_u8x32[1] = bt->as_u8x32[1];
#elif defined (CLIB_HAVE_VEC128)
  b->as_u8x16[0] = bt->as_u8x16[0];
  b->as_u8x16[1] = bt->as_u8x16[1];
  b->as_u8x16[2] = bt->as_u8x16[2];
  b->as_u8x16[3] = bt->as_u8x16[3];
#else
  clib_memcpy_fast (b, bt, 64);
#endif
}

always_inline u8
vlib_buffer_pool_get_default_for_numa (vlib_main_t * vm, u32 numa_node)
{
  ASSERT (numa_node < VLIB_BUFFER_MAX_NUMA_NODES);
  return vm->buffer_main->default_buffer_pool_index_for_numa[numa_node];
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
      u64x4 b0 = u64x4_from_u32x4 (u32x4_load_unaligned (bi));
      u64x4 b1 = u64x4_from_u32x4 (u32x4_load_unaligned (bi + 4));
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
      u64x4 b0 = u64x4_from_u32x4 (u32x4_load_unaligned (bi));
      /* shift and add to get vlib_buffer_t pointer */
      u64x4_store_unaligned ((b0 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b);
#elif defined (CLIB_HAVE_VEC128)
      u64x2 off = u64x2_splat (buffer_mem_start + offset);
      u32x4 bi4 = u32x4_load_unaligned (bi);
      u64x2 b0 = u64x2_from_u32x4 ((u32x4) bi4);
#if defined (__aarch64__)
      u64x2 b1 = u64x2_from_u32x4_high ((u32x4) bi4);
#else
      bi4 = u32x4_shuffle (bi4, 2, 3, 0, 1);
      u64x2 b1 = u64x2_from_u32x4 ((u32x4) bi4);
#endif
      u64x2_store_unaligned ((b0 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b);
      u64x2_store_unaligned ((b1 << CLIB_LOG2_CACHE_LINE_BYTES) + off, b + 2);
#else
      b[0] = vlib_buffer_ptr_from_index (buffer_mem_start, bi[0], offset);
      b[1] = vlib_buffer_ptr_from_index (buffer_mem_start, bi[1], offset);
      b[2] = vlib_buffer_ptr_from_index (buffer_mem_start, bi[2], offset);
      b[3] = vlib_buffer_ptr_from_index (buffer_mem_start, bi[3], offset);
#endif
      b += 4;
      bi += 4;
      count -= 4;
    }
  while (count)
    {
      b[0] = vlib_buffer_ptr_from_index (buffer_mem_start, bi[0], offset);
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

/* Validates sanity of a single buffer.
   Returns format'ed vector with error message if any. */
u8 *vlib_validate_buffer (vlib_main_t * vm, u32 buffer_index,
			  uword follow_chain);

u8 *vlib_validate_buffers (vlib_main_t * vm,
			   u32 * buffers,
			   uword next_buffer_stride,
			   uword n_buffers,
			   vlib_buffer_known_state_t known_state,
			   uword follow_buffer_next);

static_always_inline vlib_buffer_pool_t *
vlib_get_buffer_pool (vlib_main_t * vm, u8 buffer_pool_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  return vec_elt_at_index (bm->buffer_pools, buffer_pool_index);
}

static_always_inline __clib_warn_unused_result uword
vlib_buffer_pool_get (vlib_main_t * vm, u8 buffer_pool_index, u32 * buffers,
		      u32 n_buffers)
{
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  u32 len;

  ASSERT (bp->buffers);

  clib_spinlock_lock (&bp->lock);
  len = bp->n_avail;
  if (PREDICT_TRUE (n_buffers < len))
    {
      len -= n_buffers;
      vlib_buffer_copy_indices (buffers, bp->buffers + len, n_buffers);
      bp->n_avail = len;
      clib_spinlock_unlock (&bp->lock);
      return n_buffers;
    }
  else
    {
      vlib_buffer_copy_indices (buffers, bp->buffers, len);
      bp->n_avail = 0;
      clib_spinlock_unlock (&bp->lock);
      return len;
    }
}


/** \brief Allocate buffers from specific pool into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/

always_inline __clib_warn_unused_result u32
vlib_buffer_alloc_from_pool (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			     u8 buffer_pool_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;
  vlib_buffer_pool_thread_t *bpt;
  u32 *src, *dst, len, n_left;

  /* If buffer allocation fault injection is configured */
  if (VLIB_BUFFER_ALLOC_FAULT_INJECTOR > 0)
    {
      u32 vlib_buffer_alloc_may_fail (vlib_main_t *, u32);

      /* See how many buffers we're willing to allocate */
      n_buffers = vlib_buffer_alloc_may_fail (vm, n_buffers);
      if (n_buffers == 0)
	return (n_buffers);
    }

  bp = vec_elt_at_index (bm->buffer_pools, buffer_pool_index);
  bpt = vec_elt_at_index (bp->threads, vm->thread_index);

  dst = buffers;
  n_left = n_buffers;
  len = bpt->n_cached;

  /* per-thread cache contains enough buffers */
  if (len >= n_buffers)
    {
      src = bpt->cached_buffers + len - n_buffers;
      vlib_buffer_copy_indices (dst, src, n_buffers);
      bpt->n_cached -= n_buffers;
      goto done;
    }

  /* alloc bigger than cache - take buffers directly from main pool */
  if (n_buffers >= VLIB_BUFFER_POOL_PER_THREAD_CACHE_SZ)
    {
      n_buffers = vlib_buffer_pool_get (vm, buffer_pool_index, buffers,
					n_buffers);
      goto done;
    }

  /* take everything available in the cache */
  if (len)
    {
      vlib_buffer_copy_indices (dst, bpt->cached_buffers, len);
      bpt->n_cached = 0;
      dst += len;
      n_left -= len;
    }

  len = round_pow2 (n_left, 32);
  len = vlib_buffer_pool_get (vm, buffer_pool_index, bpt->cached_buffers,
			      len);
  bpt->n_cached = len;

  if (len)
    {
      u32 n_copy = clib_min (len, n_left);
      src = bpt->cached_buffers + len - n_copy;
      vlib_buffer_copy_indices (dst, src, n_copy);
      bpt->n_cached -= n_copy;
      n_left -= n_copy;
    }

  n_buffers -= n_left;

done:
  /* Verify that buffers are known free. */
  if (CLIB_DEBUG > 0)
    vlib_buffer_validate_alloc_free (vm, buffers, n_buffers,
				     VLIB_BUFFER_KNOWN_FREE);
  if (PREDICT_FALSE (bm->alloc_cbak_fn != 0))
    bm->alloc_cbak_fn (vm, VLIB_BUFFER_ALLOC, n_buffers);
  return n_buffers;
}

/** \brief Allocate buffers from specific numa node into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @param numa_node - (u32) numa node
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/
always_inline __clib_warn_unused_result u32
vlib_buffer_alloc_on_numa (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			   u32 numa_node)
{
  u8 index = vlib_buffer_pool_get_default_for_numa (vm, numa_node);
  return vlib_buffer_alloc_from_pool (vm, buffers, n_buffers, index);
}

/** \brief Allocate buffers into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/

always_inline __clib_warn_unused_result u32
vlib_buffer_alloc (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  return vlib_buffer_alloc_on_numa (vm, buffers, n_buffers, vm->numa_node);
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
always_inline __clib_warn_unused_result u32
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

/** \brief Allocate buffers into ring from specific buffer pool

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index ring
    @param start - (u32) first slot in the ring
    @param ring_size - (u32) ring size
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/
always_inline __clib_warn_unused_result u32
vlib_buffer_alloc_to_ring_from_pool (vlib_main_t * vm, u32 * ring, u32 start,
				     u32 ring_size, u32 n_buffers,
				     u8 buffer_pool_index)
{
  u32 n_alloc;

  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    return vlib_buffer_alloc_from_pool (vm, ring + start, n_buffers,
					buffer_pool_index);

  n_alloc = vlib_buffer_alloc_from_pool (vm, ring + start, ring_size - start,
					 buffer_pool_index);

  if (PREDICT_TRUE (n_alloc == ring_size - start))
    n_alloc += vlib_buffer_alloc_from_pool (vm, ring, n_buffers - n_alloc,
					    buffer_pool_index);

  return n_alloc;
}

static_always_inline void
vlib_buffer_pool_put (vlib_main_t * vm, u8 buffer_pool_index,
		      u32 * buffers, u32 n_buffers)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  vlib_buffer_pool_thread_t *bpt = vec_elt_at_index (bp->threads,
						     vm->thread_index);
  u32 n_cached, n_empty;

  if (CLIB_DEBUG > 0)
    vlib_buffer_validate_alloc_free (vm, buffers, n_buffers,
				     VLIB_BUFFER_KNOWN_ALLOCATED);
  if (PREDICT_FALSE (bm->alloc_cbak_fn != 0))
    bm->alloc_cbak_fn (vm, VLIB_BUFFER_FREE, n_buffers);

  n_cached = bpt->n_cached;
  n_empty = VLIB_BUFFER_POOL_PER_THREAD_CACHE_SZ - n_cached;
  if (n_buffers <= n_empty)
    {
      vlib_buffer_copy_indices (bpt->cached_buffers + n_cached,
				buffers, n_buffers);
      bpt->n_cached = n_cached + n_buffers;
      return;
    }

  vlib_buffer_copy_indices (bpt->cached_buffers + n_cached,
			    buffers + n_buffers - n_empty, n_empty);
  bpt->n_cached = VLIB_BUFFER_POOL_PER_THREAD_CACHE_SZ;

  clib_spinlock_lock (&bp->lock);
  vlib_buffer_copy_indices (bp->buffers + bp->n_avail, buffers,
			    n_buffers - n_empty);
  bp->n_avail += n_buffers - n_empty;
  clib_spinlock_unlock (&bp->lock);
}

static_always_inline void
vlib_buffer_free_inline (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			 int maybe_next)
{
  const int queue_size = 128;
  vlib_buffer_pool_t *bp = 0;
  u8 buffer_pool_index = ~0;
  u32 n_queue = 0, queue[queue_size + 4];
  vlib_buffer_t bt = { };
#if defined(CLIB_HAVE_VEC128)
  vlib_buffer_t bpi_mask = {.buffer_pool_index = ~0 };
  vlib_buffer_t bpi_vec = {.buffer_pool_index = ~0 };
  vlib_buffer_t flags_refs_mask = {
    .flags = VLIB_BUFFER_NEXT_PRESENT,
    .ref_count = ~1
  };
#endif

  while (n_buffers)
    {
      vlib_buffer_t *b[8];
      u32 bi, sum = 0, flags, next;

      if (n_buffers < 12)
	goto one_by_one;

      vlib_get_buffers (vm, buffers, b, 4);
      vlib_get_buffers (vm, buffers + 8, b + 4, 4);

      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

#if defined(CLIB_HAVE_VEC128)
      u8x16 p0, p1, p2, p3, r;
      p0 = u8x16_load_unaligned (b[0]);
      p1 = u8x16_load_unaligned (b[1]);
      p2 = u8x16_load_unaligned (b[2]);
      p3 = u8x16_load_unaligned (b[3]);

      r = p0 ^ bpi_vec.as_u8x16[0];
      r |= p1 ^ bpi_vec.as_u8x16[0];
      r |= p2 ^ bpi_vec.as_u8x16[0];
      r |= p3 ^ bpi_vec.as_u8x16[0];
      r &= bpi_mask.as_u8x16[0];
      r |= (p0 | p1 | p2 | p3) & flags_refs_mask.as_u8x16[0];

      sum = !u8x16_is_all_zero (r);
#else
      sum |= b[0]->flags;
      sum |= b[1]->flags;
      sum |= b[2]->flags;
      sum |= b[3]->flags;
      sum &= VLIB_BUFFER_NEXT_PRESENT;
      sum += b[0]->ref_count - 1;
      sum += b[1]->ref_count - 1;
      sum += b[2]->ref_count - 1;
      sum += b[3]->ref_count - 1;
      sum |= b[0]->buffer_pool_index ^ buffer_pool_index;
      sum |= b[1]->buffer_pool_index ^ buffer_pool_index;
      sum |= b[2]->buffer_pool_index ^ buffer_pool_index;
      sum |= b[3]->buffer_pool_index ^ buffer_pool_index;
#endif

      if (sum)
	goto one_by_one;

      vlib_buffer_copy_indices (queue + n_queue, buffers, 4);
      vlib_buffer_copy_template (b[0], &bt);
      vlib_buffer_copy_template (b[1], &bt);
      vlib_buffer_copy_template (b[2], &bt);
      vlib_buffer_copy_template (b[3], &bt);
      n_queue += 4;

      vlib_buffer_validate (vm, b[0]);
      vlib_buffer_validate (vm, b[1]);
      vlib_buffer_validate (vm, b[2]);
      vlib_buffer_validate (vm, b[3]);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      if (n_queue >= queue_size)
	{
	  vlib_buffer_pool_put (vm, buffer_pool_index, queue, n_queue);
	  n_queue = 0;
	}
      buffers += 4;
      n_buffers -= 4;
      continue;

    one_by_one:
      bi = buffers[0];

    next_in_chain:
      b[0] = vlib_get_buffer (vm, bi);
      flags = b[0]->flags;
      next = b[0]->next_buffer;

      if (PREDICT_FALSE (buffer_pool_index != b[0]->buffer_pool_index))
	{

	  if (n_queue)
	    {
	      vlib_buffer_pool_put (vm, buffer_pool_index, queue, n_queue);
	      n_queue = 0;
	    }

	  buffer_pool_index = b[0]->buffer_pool_index;
#if defined(CLIB_HAVE_VEC128)
	  bpi_vec.buffer_pool_index = buffer_pool_index;
#endif
	  bp = vlib_get_buffer_pool (vm, buffer_pool_index);
	  vlib_buffer_copy_template (&bt, &bp->buffer_template);
	}

      vlib_buffer_validate (vm, b[0]);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      if (clib_atomic_sub_fetch (&b[0]->ref_count, 1) == 0)
	{
	  vlib_buffer_copy_template (b[0], &bt);
	  queue[n_queue++] = bi;
	}

      if (n_queue == queue_size)
	{
	  vlib_buffer_pool_put (vm, buffer_pool_index, queue, queue_size);
	  n_queue = 0;
	}

      if (maybe_next && (flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  bi = next;
	  goto next_in_chain;
	}

      buffers++;
      n_buffers--;
    }

  if (n_queue)
    vlib_buffer_pool_put (vm, buffer_pool_index, queue, n_queue);
}


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
  vlib_buffer_free_inline (vm, buffers, n_buffers, /* maybe next */ 1);
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
  vlib_buffer_free_inline (vm, buffers, n_buffers, /* maybe next */ 0);
}

/** \brief Free one buffer
    Shorthand to free a single buffer chain.

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffer_index - (u32) buffer index to free
*/
always_inline void
vlib_buffer_free_one (vlib_main_t * vm, u32 buffer_index)
{
  vlib_buffer_free_inline (vm, &buffer_index, 1, /* maybe next */ 1);
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

/* Define vlib_buffer and vnet_buffer flags bits preserved for copy/clone */
#define VLIB_BUFFER_COPY_CLONE_FLAGS_MASK                     	\
  (VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID |	\
   VLIB_BUFFER_IS_TRACED | ~VLIB_BUFFER_FLAGS_ALL)

/* duplicate all buffers in chain */
always_inline vlib_buffer_t *
vlib_buffer_copy (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_buffer_t *s, *d, *fd;
  uword n_alloc, n_buffers = 1;
  u32 flag_mask = VLIB_BUFFER_COPY_CLONE_FLAGS_MASK;
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
  d->trace_handle = s->trace_handle;
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

/* duplicate first buffer in chain */
always_inline vlib_buffer_t *
vlib_buffer_copy_no_chain (vlib_main_t * vm, vlib_buffer_t * b, u32 * di)
{
  vlib_buffer_t *d;

  if ((vlib_buffer_alloc (vm, di, 1)) != 1)
    return 0;

  d = vlib_get_buffer (vm, *di);
  /* 1st segment */
  d->current_data = b->current_data;
  d->current_length = b->current_length;
  clib_memcpy_fast (d->opaque, b->opaque, sizeof (b->opaque));
  clib_memcpy_fast (d->opaque2, b->opaque2, sizeof (b->opaque2));
  clib_memcpy_fast (vlib_buffer_get_current (d),
		    vlib_buffer_get_current (b), b->current_length);

  return d;
}

/*  \brief Move packet from current position to offset position in buffer.
    Only work for small packet using one buffer with room to fit the move
    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param b -  (vlib_buffer_t *) pointer to buffer
    @param offset - (i16) position to move the packet in buffer
 */
always_inline void
vlib_buffer_move (vlib_main_t * vm, vlib_buffer_t * b, i16 offset)
{
  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  ASSERT (offset + VLIB_BUFFER_PRE_DATA_SIZE >= 0);
  ASSERT (offset + b->current_length <
	  vlib_buffer_get_default_data_size (vm));

  u8 *source = vlib_buffer_get_current (b);
  b->current_data = offset;
  u8 *destination = vlib_buffer_get_current (b);
  u16 length = b->current_length;

  if (source + length <= destination)	/* no overlap */
    clib_memcpy_fast (destination, source, length);
  else
    memmove (destination, source, length);
}

/** \brief Create a maximum of 256 clones of buffer and store them
    in the supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param src_buffer - (u32) source buffer index
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u16) number of buffer clones requested (<=256)
    @param head_end_offset - (u16) offset relative to current position
           where packet head ends
    @param offset - (i16) copy packet head at current position if 0,
           else at offset position to change headroom space as specified
    @return - (u16) number of buffers actually cloned, may be
    less than the number requested or zero
*/
always_inline u16
vlib_buffer_clone_256 (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
		       u16 n_buffers, u16 head_end_offset, i16 offset)
{
  u16 i;
  vlib_buffer_t *s = vlib_get_buffer (vm, src_buffer);

  ASSERT (s->ref_count == 1);
  ASSERT (n_buffers);
  ASSERT (n_buffers <= 256);
  ASSERT (offset + VLIB_BUFFER_PRE_DATA_SIZE >= 0);
  ASSERT ((offset + head_end_offset) <
	  vlib_buffer_get_default_data_size (vm));

  if (s->current_length <= head_end_offset + CLIB_CACHE_LINE_BYTES * 2)
    {
      buffers[0] = src_buffer;
      if (offset)
	vlib_buffer_move (vm, s, offset);

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

  if (PREDICT_FALSE ((n_buffers == 1) && (offset == 0)))
    {
      buffers[0] = src_buffer;
      return 1;
    }

  n_buffers = vlib_buffer_alloc_from_pool (vm, buffers, n_buffers,
					   s->buffer_pool_index);

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *d = vlib_get_buffer (vm, buffers[i]);
      if (offset)
	d->current_data = offset;
      else
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
      d->flags = (s->flags & VLIB_BUFFER_COPY_CLONE_FLAGS_MASK) |
	VLIB_BUFFER_NEXT_PRESENT;
      d->trace_handle = s->trace_handle;
      clib_memcpy_fast (d->opaque, s->opaque, sizeof (s->opaque));
      clib_memcpy_fast (d->opaque2, s->opaque2, sizeof (s->opaque2));
      clib_memcpy_fast (vlib_buffer_get_current (d),
			vlib_buffer_get_current (s), head_end_offset);
      d->next_buffer = src_buffer;
    }
  vlib_buffer_advance (s, head_end_offset);
  s->ref_count = n_buffers ? n_buffers : s->ref_count;
  while (s->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      s = vlib_get_buffer (vm, s->next_buffer);
      s->ref_count = n_buffers ? n_buffers : s->ref_count;
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
    @param offset - (i16) copy packet head at current position if 0,
           else at offset position to change headroom space as specified
    @return - (u16) number of buffers actually cloned, may be
    less than the number requested or zero
*/
always_inline u16
vlib_buffer_clone_at_offset (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
			     u16 n_buffers, u16 head_end_offset, i16 offset)
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
					 256, head_end_offset, offset);
      n_buffers -= 256;
    }
  n_cloned += vlib_buffer_clone_256 (vm, src_buffer,
				     buffers + n_cloned,
				     n_buffers, head_end_offset, offset);

  return n_cloned;
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
  return vlib_buffer_clone_at_offset (vm, src_buffer, buffers, n_buffers,
				      head_end_offset, 0);
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
  clib_atomic_add_fetch (&tail->ref_count, 1);

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
  u32 n_buffer_bytes = vlib_buffer_get_default_data_size (vm);
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
  format_vlib_buffer_contents, format_vlib_buffer_no_chain;

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

always_inline u32
vlib_buffer_space_left_at_end (vlib_main_t * vm, vlib_buffer_t * b)
{
  return b->data + vlib_buffer_get_default_data_size (vm) -
    ((u8 *) vlib_buffer_get_current (b) + b->current_length);
}

always_inline u32
vlib_buffer_chain_linearize (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_buffer_t *db = b, *sb, *first = b;
  int is_cloned = 0;
  u32 bytes_left = 0, data_size;
  u16 src_left, dst_left, n_buffers = 1;
  u8 *dp, *sp;
  u32 to_free = 0;

  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    return 1;

  data_size = vlib_buffer_get_default_data_size (vm);

  dst_left = vlib_buffer_space_left_at_end (vm, b);

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      if (b->ref_count > 1)
	is_cloned = 1;
      bytes_left += b->current_length;
      n_buffers++;
    }

  /* if buffer is cloned, create completely new chain - unless everything fits
   * into one buffer */
  if (is_cloned && bytes_left >= dst_left)
    {
      u32 len = 0;
      u32 space_needed = bytes_left - dst_left;
      u32 tail;

      if (vlib_buffer_alloc (vm, &tail, 1) == 0)
	return 0;

      ++n_buffers;
      len += data_size;
      b = vlib_get_buffer (vm, tail);

      while (len < space_needed)
	{
	  u32 bi;
	  if (vlib_buffer_alloc (vm, &bi, 1) == 0)
	    {
	      vlib_buffer_free_one (vm, tail);
	      return 0;
	    }
	  b->flags = VLIB_BUFFER_NEXT_PRESENT;
	  b->next_buffer = bi;
	  b = vlib_get_buffer (vm, bi);
	  len += data_size;
	  n_buffers++;
	}
      sb = vlib_get_buffer (vm, first->next_buffer);
      to_free = first->next_buffer;
      first->next_buffer = tail;
    }
  else
    sb = vlib_get_buffer (vm, first->next_buffer);

  src_left = sb->current_length;
  sp = vlib_buffer_get_current (sb);
  dp = vlib_buffer_get_tail (db);

  while (bytes_left)
    {
      u16 bytes_to_copy;

      if (dst_left == 0)
	{
	  db->current_length = dp - (u8 *) vlib_buffer_get_current (db);
	  ASSERT (db->flags & VLIB_BUFFER_NEXT_PRESENT);
	  db = vlib_get_buffer (vm, db->next_buffer);
	  dst_left = data_size;
	  if (db->current_data > 0)
	    {
	      db->current_data = 0;
	    }
	  else
	    {
	      dst_left += -db->current_data;
	    }
	  dp = vlib_buffer_get_current (db);
	}

      while (src_left == 0)
	{
	  ASSERT (sb->flags & VLIB_BUFFER_NEXT_PRESENT);
	  sb = vlib_get_buffer (vm, sb->next_buffer);
	  src_left = sb->current_length;
	  sp = vlib_buffer_get_current (sb);
	}

      bytes_to_copy = clib_min (dst_left, src_left);

      if (dp != sp)
	{
	  if (sb == db)
	    bytes_to_copy = clib_min (bytes_to_copy, sp - dp);

	  clib_memcpy_fast (dp, sp, bytes_to_copy);
	}

      src_left -= bytes_to_copy;
      dst_left -= bytes_to_copy;
      dp += bytes_to_copy;
      sp += bytes_to_copy;
      bytes_left -= bytes_to_copy;
    }
  if (db != first)
    db->current_data = 0;
  db->current_length = dp - (u8 *) vlib_buffer_get_current (db);

  if (is_cloned && to_free)
    vlib_buffer_free_one (vm, to_free);
  else
    {
      if (db->flags & VLIB_BUFFER_NEXT_PRESENT)
	vlib_buffer_free_one (vm, db->next_buffer);
      db->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
      b = first;
      n_buffers = 1;
      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  b = vlib_get_buffer (vm, b->next_buffer);
	  ++n_buffers;
	}
    }

  first->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

  return n_buffers;
}

#endif /* included_vlib_buffer_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

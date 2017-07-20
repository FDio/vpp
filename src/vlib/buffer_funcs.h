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
      clib_memcpy (contents + content_len, b->data + b->current_data, l);
      content_len += l;
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      buffer_index = b->next_buffer;
    }

  return content_len;
}

/* Return physical address of buffer->data start. */
always_inline u64
vlib_get_buffer_data_physical_address (vlib_main_t * vm, u32 buffer_index)
{
  return vlib_physmem_offset_to_physical (vm, vm->buffer_main->physmem_region,
					  (((uword) buffer_index) <<
					   CLIB_LOG2_CACHE_LINE_BYTES) +
					  STRUCT_OFFSET_OF (vlib_buffer_t,
							    data));
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

#if 0
/* Iterate over known allocated vlib bufs. You probably do not want
 * to do this!
 @param vm      the vlib_main_t
 @param bi      found allocated buffer index
 @param body    operation to perform on buffer index
 function executes body for each allocated buffer index
 */
#define vlib_buffer_foreach_allocated(vm,bi,body)                \
do {                                                             \
  vlib_main_t * _vmain = (vm);                                   \
  vlib_buffer_main_t * _bmain = &_vmain->buffer_main;            \
  hash_pair_t * _vbpair;                                         \
  hash_foreach_pair(_vbpair, _bmain->buffer_known_hash, ({       \
    if (VLIB_BUFFER_KNOWN_ALLOCATED == _vbpair->value[0]) {      \
      (bi) = _vbpair->key;                                       \
      body;                                                      \
    }                                                            \
  }));                                                           \
} while (0)
#endif

typedef enum
{
  /* Index is unknown. */
  VLIB_BUFFER_UNKNOWN,

  /* Index is known and free/allocated. */
  VLIB_BUFFER_KNOWN_FREE,
  VLIB_BUFFER_KNOWN_ALLOCATED,
} vlib_buffer_known_state_t;

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
vlib_buffer_set_known_state (vlib_main_t * vm,
			     u32 buffer_index,
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
  vlib_buffer_main_t *bm = vm->buffer_main;

  ASSERT (bm->cb.vlib_buffer_alloc_cb);

  return bm->cb.vlib_buffer_alloc_cb (vm, buffers, n_buffers);
}

always_inline u32
vlib_buffer_round_size (u32 size)
{
  return round_pow2 (size, sizeof (vlib_buffer_t));
}

always_inline u32
vlib_buffer_get_free_list_index (vlib_buffer_t * b)
{
  return b->flags & VLIB_BUFFER_FREE_LIST_INDEX_MASK;
}

always_inline void
vlib_buffer_set_free_list_index (vlib_buffer_t * b, u32 index)
{
  /* if there is an need for more free lists we should consider
     storig data in the 2nd cacheline */
  ASSERT (VLIB_BUFFER_FREE_LIST_INDEX_MASK & 1);
  ASSERT (index <= VLIB_BUFFER_FREE_LIST_INDEX_MASK);

  b->flags &= ~VLIB_BUFFER_FREE_LIST_INDEX_MASK;
  b->flags |= index & VLIB_BUFFER_FREE_LIST_INDEX_MASK;
}

/** \brief Allocate buffers from specific freelist into supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u32) number of buffers requested
    @return - (u32) number of buffers actually allocated, may be
    less than the number requested or zero
*/
always_inline u32
vlib_buffer_alloc_from_free_list (vlib_main_t * vm,
				  u32 * buffers,
				  u32 n_buffers, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  ASSERT (bm->cb.vlib_buffer_alloc_from_free_list_cb);

  return bm->cb.vlib_buffer_alloc_from_free_list_cb (vm, buffers, n_buffers,
						     free_list_index);
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
  vlib_buffer_main_t *bm = vm->buffer_main;

  ASSERT (bm->cb.vlib_buffer_free_cb);

  return bm->cb.vlib_buffer_free_cb (vm, buffers, n_buffers);
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
  vlib_buffer_main_t *bm = vm->buffer_main;

  ASSERT (bm->cb.vlib_buffer_free_no_next_cb);

  return bm->cb.vlib_buffer_free_no_next_cb (vm, buffers, n_buffers);
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

/* Add/delete buffer free lists. */
u32 vlib_buffer_create_free_list (vlib_main_t * vm, u32 n_data_bytes,
				  char *fmt, ...);
always_inline void
vlib_buffer_delete_free_list (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  ASSERT (bm->cb.vlib_buffer_delete_free_list_cb);

  bm->cb.vlib_buffer_delete_free_list_cb (vm, free_list_index);
}

/* Find already existing public free list with given size or create one. */
u32 vlib_buffer_get_or_create_free_list (vlib_main_t * vm, u32 n_data_bytes,
					 char *fmt, ...);

/* Merge two free lists */
void vlib_buffer_merge_free_lists (vlib_buffer_free_list_t * dst,
				   vlib_buffer_free_list_t * src);

/* Make sure we have at least given number of unaligned buffers. */
void vlib_buffer_free_list_fill_unaligned (vlib_main_t * vm,
					   vlib_buffer_free_list_t *
					   free_list,
					   uword n_unaligned_buffers);

always_inline u32
vlib_buffer_get_free_list_with_size (vlib_main_t * vm, u32 size)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  size = vlib_buffer_round_size (size);
  uword *p = hash_get (bm->free_list_by_size, size);
  return p ? p[0] : ~0;
}

always_inline vlib_buffer_free_list_t *
vlib_buffer_get_buffer_free_list (vlib_main_t * vm, vlib_buffer_t * b,
				  u32 * index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  u32 i;

  *index = i = vlib_buffer_get_free_list_index (b);
  return pool_elt_at_index (bm->buffer_free_list_pool, i);
}

always_inline vlib_buffer_free_list_t *
vlib_buffer_get_free_list (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;

  f = pool_elt_at_index (bm->buffer_free_list_pool, free_list_index);

  /* Sanity: indices must match. */
  ASSERT (f->index == free_list_index);

  return f;
}

always_inline u32
vlib_buffer_free_list_buffer_size (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_free_list_t *f =
    vlib_buffer_get_free_list (vm, free_list_index);
  return f->n_data_bytes;
}

void vlib_aligned_memcpy (void *_dst, void *_src, int n_bytes);

/* Reasonably fast buffer copy routine. */
always_inline void
vlib_copy_buffers (u32 * dst, u32 * src, u32 n)
{
  while (n >= 4)
    {
      dst[0] = src[0];
      dst[1] = src[1];
      dst[2] = src[2];
      dst[3] = src[3];
      dst += 4;
      src += 4;
      n -= 4;
    }
  while (n > 0)
    {
      dst[0] = src[0];
      dst += 1;
      src += 1;
      n -= 1;
    }
}

/* Append given data to end of buffer, possibly allocating new buffers. */
u32 vlib_buffer_add_data (vlib_main_t * vm,
			  u32 free_list_index,
			  u32 buffer_index, void *data, u32 n_data_bytes);

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
  clib_memcpy (d->opaque, s->opaque, sizeof (s->opaque));
  clib_memcpy (vlib_buffer_get_current (d),
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
      clib_memcpy (vlib_buffer_get_current (d),
		   vlib_buffer_get_current (s), s->current_length);
      d->flags = s->flags & flag_mask;
    }

  return fd;
}

/** \brief Create multiple clones of buffer and store them in the supplied array

    @param vm - (vlib_main_t *) vlib main data structure pointer
    @param src_buffer - (u32) source buffer index
    @param buffers - (u32 * ) buffer index array
    @param n_buffers - (u8) number of buffer clones requested
    @param head_end_offset - (u16) offset relative to current position
           where packet head ends
    @return - (u8) number of buffers actually cloned, may be
    less than the number requested or zero
*/

always_inline u8
vlib_buffer_clone (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
		   u8 n_buffers, u16 head_end_offset)
{
  u8 i;
  vlib_buffer_t *s = vlib_get_buffer (vm, src_buffer);

  ASSERT (s->n_add_refs == 0);
  ASSERT (n_buffers);

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

  n_buffers = vlib_buffer_alloc_from_free_list (vm, buffers, n_buffers,
						vlib_buffer_get_free_list_index
						(s));
  if (PREDICT_FALSE (n_buffers == 0))
    {
      buffers[0] = src_buffer;
      return 1;
    }

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *d = vlib_get_buffer (vm, buffers[i]);
      d->current_data = s->current_data;
      d->current_length = head_end_offset;
      vlib_buffer_set_free_list_index (d,
				       vlib_buffer_get_free_list_index (s));
      d->total_length_not_including_first_buffer =
	s->total_length_not_including_first_buffer + s->current_length -
	head_end_offset;
      d->flags = s->flags | VLIB_BUFFER_NEXT_PRESENT;
      d->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
      clib_memcpy (d->opaque, s->opaque, sizeof (s->opaque));
      clib_memcpy (vlib_buffer_get_current (d), vlib_buffer_get_current (s),
		   head_end_offset);
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
  ASSERT (vlib_buffer_get_free_list_index (head) ==
	  vlib_buffer_get_free_list_index (tail));

  head->flags |= VLIB_BUFFER_NEXT_PRESENT;
  head->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
  head->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
  head->flags |= (tail->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
  head->next_buffer = vlib_get_buffer_index (vm, tail);
  head->total_length_not_including_first_buffer = tail->current_length +
    tail->total_length_not_including_first_buffer;

next_segment:
  __sync_add_and_fetch (&tail->n_add_refs, 1);

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
vlib_buffer_chain_buffer (vlib_main_t * vm,
			  vlib_buffer_t * first,
			  vlib_buffer_t * last, u32 next_bi)
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
			       u32 free_list_index,
			       vlib_buffer_t * first,
			       vlib_buffer_t * last, void *data, u16 data_len)
{
  u32 n_buffer_bytes =
    vlib_buffer_free_list_buffer_size (vm, free_list_index);
  ASSERT (n_buffer_bytes >= last->current_length + last->current_data);
  u16 len = clib_min (data_len,
		      n_buffer_bytes - last->current_length -
		      last->current_data);
  clib_memcpy (vlib_buffer_get_current (last) + last->current_length, data,
	       len);
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
					  u32 free_list_index,
					  vlib_buffer_t * first,
					  vlib_buffer_t ** last,
					  void *data, u16 data_len);
void vlib_buffer_chain_validate (vlib_main_t * vm, vlib_buffer_t * first);

format_function_t format_vlib_buffer, format_vlib_buffer_and_data,
  format_vlib_buffer_contents;

typedef struct
{
  /* Vector of packet data. */
  u8 *packet_data;

  /* Number of buffers to allocate in each call to physmem
     allocator. */
  u32 min_n_buffers_each_physmem_alloc;

  /* Buffer free list for this template. */
  u32 free_list_index;

  u32 *free_buffers;
} vlib_packet_template_t;

void vlib_packet_template_get_packet_helper (vlib_main_t * vm,
					     vlib_packet_template_t * t);

void vlib_packet_template_init (vlib_main_t * vm,
				vlib_packet_template_t * t,
				void *packet_data,
				uword n_packet_data_bytes,
				uword min_n_buffers_each_physmem_alloc,
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
unserialize_vlib_buffer_n_bytes (serialize_main_t * m)
{
  serialize_stream_t *s = &m->stream;
  vlib_serialize_buffer_main_t *sm
    = uword_to_pointer (m->stream.data_function_opaque,
			vlib_serialize_buffer_main_t *);
  vlib_main_t *vm = sm->vlib_main;
  u32 n, *f;

  n = s->n_buffer_bytes - s->current_buffer_index;
  if (sm->last_buffer != ~0)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, sm->last_buffer);
      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  b = vlib_get_buffer (vm, b->next_buffer);
	  n += b->current_length;
	}
    }

  /* *INDENT-OFF* */
  clib_fifo_foreach (f, sm->rx.buffer_fifo, ({
    n += vlib_buffer_index_length_in_chain (vm, f[0]);
  }));
/* *INDENT-ON* */

  return n;
}

/* Set a buffer quickly into "uninitialized" state.  We want this to
   be extremely cheap and arrange for all fields that need to be
   initialized to be in the first 128 bits of the buffer. */
always_inline void
vlib_buffer_init_for_free_list (vlib_buffer_t * dst,
				vlib_buffer_free_list_t * fl)
{
  vlib_buffer_t *src = &fl->buffer_init_template;

  /* Make sure vlib_buffer_t is cacheline aligned and sized */
  ASSERT (STRUCT_OFFSET_OF (vlib_buffer_t, cacheline0) == 0);
  ASSERT (STRUCT_OFFSET_OF (vlib_buffer_t, cacheline1) ==
	  CLIB_CACHE_LINE_BYTES);
  ASSERT (STRUCT_OFFSET_OF (vlib_buffer_t, cacheline2) ==
	  CLIB_CACHE_LINE_BYTES * 2);

  /* Make sure buffer template is sane. */
  ASSERT (fl->index == vlib_buffer_get_free_list_index (src));

  clib_memcpy (STRUCT_MARK_PTR (dst, template_start),
	       STRUCT_MARK_PTR (src, template_start),
	       STRUCT_OFFSET_OF (vlib_buffer_t, template_end) -
	       STRUCT_OFFSET_OF (vlib_buffer_t, template_start));

  /* Not in the first 16 octets. */
  dst->n_add_refs = src->n_add_refs;

  /* Make sure it really worked. */
#define _(f) ASSERT (dst->f == src->f);
  _(current_data);
  _(current_length);
  _(flags);
#undef _
  /* ASSERT (dst->total_length_not_including_first_buffer == 0); */
  /* total_length_not_including_first_buffer is not in the template anymore
   * so it may actually not zeroed for some buffers. One option is to
   * uncomment the line lower (comes at a cost), the other, is to just  not
   * care */
  /* dst->total_length_not_including_first_buffer = 0; */
  ASSERT (dst->n_add_refs == 0);
}

always_inline void
vlib_buffer_add_to_free_list (vlib_main_t * vm,
			      vlib_buffer_free_list_t * f,
			      u32 buffer_index, u8 do_init)
{
  vlib_buffer_t *b;
  b = vlib_get_buffer (vm, buffer_index);
  if (PREDICT_TRUE (do_init))
    vlib_buffer_init_for_free_list (b, f);
  vec_add1_aligned (f->buffers, buffer_index, CLIB_CACHE_LINE_BYTES);

  if (vec_len (f->buffers) > 4 * VLIB_FRAME_SIZE)
    {
      vlib_buffer_free_list_t *mf;
      mf = vlib_buffer_get_free_list (vlib_mains[0], f->index);
      clib_spinlock_lock (&mf->global_buffers_lock);
      /* keep last stored buffers, as they are more likely hot in the cache */
      vec_add_aligned (mf->global_buffers, f->buffers, VLIB_FRAME_SIZE,
		       CLIB_CACHE_LINE_BYTES);
      vec_delete (f->buffers, VLIB_FRAME_SIZE, 0);
      clib_spinlock_unlock (&mf->global_buffers_lock);
    }
}

always_inline void
vlib_buffer_init_two_for_free_list (vlib_buffer_t * dst0,
				    vlib_buffer_t * dst1,
				    vlib_buffer_free_list_t * fl)
{
  vlib_buffer_t *src = &fl->buffer_init_template;

  /* Make sure buffer template is sane. */
  ASSERT (fl->index == vlib_buffer_get_free_list_index (src));

  clib_memcpy (STRUCT_MARK_PTR (dst0, template_start),
	       STRUCT_MARK_PTR (src, template_start),
	       STRUCT_OFFSET_OF (vlib_buffer_t, template_end) -
	       STRUCT_OFFSET_OF (vlib_buffer_t, template_start));

  clib_memcpy (STRUCT_MARK_PTR (dst1, template_start),
	       STRUCT_MARK_PTR (src, template_start),
	       STRUCT_OFFSET_OF (vlib_buffer_t, template_end) -
	       STRUCT_OFFSET_OF (vlib_buffer_t, template_start));

  /* Not in the first 16 octets. */
  dst0->n_add_refs = src->n_add_refs;
  dst1->n_add_refs = src->n_add_refs;

  /* Make sure it really worked. */
#define _(f) ASSERT (dst0->f == src->f);  ASSERT( dst1->f == src->f)
  _(current_data);
  _(current_length);
  _(flags);
#undef _

  ASSERT (dst0->total_length_not_including_first_buffer == 0);
  ASSERT (dst1->total_length_not_including_first_buffer == 0);
  ASSERT (dst0->n_add_refs == 0);
  ASSERT (dst1->n_add_refs == 0);
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

  while (__sync_lock_test_and_set (vlib_buffer_state_validation_lock, 1))
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

  while (__sync_lock_test_and_set (vlib_buffer_state_validation_lock, 1))
    ;

  hash_set (vlib_buffer_state_validation_hash, b, expected);

  CLIB_MEMORY_BARRIER ();
  *vlib_buffer_state_validation_lock = 0;
  clib_mem_set_heap (oldheap);
#endif
}

#endif /* included_vlib_buffer_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

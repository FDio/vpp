/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/time.h>
#include <vppinfra/format.h>
#include <vppinfra/clib_error.h>

#define CLIB_MEM_BULK_DEFAULT_MIN_ELTS_PER_CHUNK 32

typedef struct clib_mem_bulk_chunk_hdr
{
  u32 freelist;
  u32 n_free;
  struct clib_mem_bulk_chunk_hdr *prev, *next;
} clib_mem_bulk_chunk_hdr_t;

typedef struct
{
  u32 elt_sz;
  u32 chunk_hdr_sz;
  u32 elts_per_chunk;
  u32 align;
  u32 chunk_align;
  clib_mem_heap_t *heap;
  clib_mem_bulk_chunk_hdr_t *full_chunks, *avail_chunks;
} clib_mem_bulk_t;

static inline uword
bulk_chunk_size (clib_mem_bulk_t *b)
{
  return (uword) b->elts_per_chunk * b->elt_sz + b->chunk_hdr_sz;
}

__clib_export clib_mem_bulk_handle_t
clib_mem_bulk_init (u32 elt_sz, u32 align, u32 min_elts_per_chunk)
{
  clib_mem_heap_t *heap = clib_mem_get_heap ();
  clib_mem_bulk_t *b;
  uword sz;

  b = clib_mem_heap_alloc_aligned_or_null (heap, sizeof (clib_mem_bulk_t), 16);
  if (b == 0)
    return 0;

  if (align < 16)
    align = 16;

  if (min_elts_per_chunk == 0)
    min_elts_per_chunk = CLIB_MEM_BULK_DEFAULT_MIN_ELTS_PER_CHUNK;

  clib_mem_unpoison (b, sizeof (clib_mem_bulk_t));
  clib_memset (b, 0, sizeof (clib_mem_bulk_t));
  b->heap = heap;
  b->align = align;
  b->elt_sz = round_pow2 (elt_sz, align);
  b->chunk_hdr_sz = round_pow2 (sizeof (clib_mem_bulk_chunk_hdr_t), align);
  b->elts_per_chunk = min_elts_per_chunk;
  sz = bulk_chunk_size (b);
  b->chunk_align = max_pow2 (sz);
  b->elts_per_chunk += (b->chunk_align - sz) / b->elt_sz;
  return b;
}

__clib_export void
clib_mem_bulk_destroy (clib_mem_bulk_handle_t h)
{
  clib_mem_bulk_t *b = h;
  clib_mem_bulk_chunk_hdr_t *c, *next;
  clib_mem_heap_t *heap = b->heap;

  c = b->full_chunks;

again:
  while (c)
    {
      next = c->next;
      clib_mem_heap_free (heap, c);
      c = next;
    }

  if (b->avail_chunks)
    {
      c = b->avail_chunks;
      b->avail_chunks = 0;
      goto again;
    }

  clib_mem_poison (b, sizeof (clib_mem_bulk_t));
  clib_mem_heap_free (heap, b);
}

static inline void *
get_chunk_elt_ptr (clib_mem_bulk_t *b, clib_mem_bulk_chunk_hdr_t *c, u32 index)
{
  return (u8 *) c + b->chunk_hdr_sz + index * b->elt_sz;
}

static inline void
add_to_chunk_list (clib_mem_bulk_chunk_hdr_t **first,
		   clib_mem_bulk_chunk_hdr_t *c)
{
  c->next = *first;
  c->prev = 0;
  if (c->next)
    c->next->prev = c;
  *first = c;
}

static inline void
remove_from_chunk_list (clib_mem_bulk_chunk_hdr_t **first,
			clib_mem_bulk_chunk_hdr_t *c)
{
  if (c->next)
    c->next->prev = c->prev;
  if (c->prev)
    c->prev->next = c->next;
  else
    *first = c->next;
}

__clib_export void *
clib_mem_bulk_alloc (clib_mem_bulk_handle_t h)
{
  clib_mem_bulk_t *b = h;
  clib_mem_bulk_chunk_hdr_t *c = b->avail_chunks;
  u32 elt_idx;

  if (b->avail_chunks == 0)
    {
      u32 i, sz = bulk_chunk_size (b);
      c = clib_mem_heap_alloc_aligned_or_null (b->heap, sz, b->chunk_align);
      if (c == 0)
	return 0;
      clib_mem_unpoison (c, sz);
      clib_memset (c, 0, sizeof (clib_mem_bulk_chunk_hdr_t));
      b->avail_chunks = c;
      c->n_free = b->elts_per_chunk;

      /* populate freelist */
      for (i = 0; i < b->elts_per_chunk - 1; i++)
	*((u32 *) get_chunk_elt_ptr (b, c, i)) = i + 1;
      *((u32 *) get_chunk_elt_ptr (b, c, i)) = ~0;
    }

  ASSERT (c->freelist != ~0);
  elt_idx = c->freelist;
  c->freelist = *((u32 *) get_chunk_elt_ptr (b, c, elt_idx));
  c->n_free--;

  if (c->n_free == 0)
    {
      /* chunk is full */
      ASSERT (c->freelist == ~0);
      remove_from_chunk_list (&b->avail_chunks, c);
      add_to_chunk_list (&b->full_chunks, c);
    }

  return get_chunk_elt_ptr (b, c, elt_idx);
}

__clib_export void
clib_mem_bulk_free (clib_mem_bulk_handle_t h, void *p)
{
  clib_mem_bulk_t *b = h;
  uword offset = (uword) p & (b->chunk_align - 1);
  clib_mem_bulk_chunk_hdr_t *c = (void *) ((u8 *) p - offset);
  u32 elt_idx = (offset - b->chunk_hdr_sz) / b->elt_sz;

  ASSERT (elt_idx < b->elts_per_chunk);
  ASSERT (get_chunk_elt_ptr (b, c, elt_idx) == p);

  c->n_free++;

  if (c->n_free == b->elts_per_chunk)
    {
      /* chunk is empty - give it back */
      remove_from_chunk_list (&b->avail_chunks, c);
      clib_mem_heap_free (b->heap, c);
      return;
    }

  if (c->n_free == 1)
    {
      /* move chunk to avail chunks */
      remove_from_chunk_list (&b->full_chunks, c);
      add_to_chunk_list (&b->avail_chunks, c);
    }

  /* add elt to freelist */
  *(u32 *) p = c->freelist;
  c->freelist = elt_idx;
}

__clib_export u8 *
format_clib_mem_bulk (u8 *s, va_list *args)
{
  clib_mem_bulk_t *b = va_arg (*args, clib_mem_bulk_handle_t);
  clib_mem_bulk_chunk_hdr_t *c;
  uword n_chunks = 0, n_free_elts = 0, n_elts, chunk_sz;

  c = b->full_chunks;
  while (c)
    {
      n_chunks++;
      c = c->next;
    }

  c = b->avail_chunks;
  while (c)
    {
      n_chunks++;
      n_free_elts += c->n_free;
      c = c->next;
    }

  n_elts = n_chunks * b->elts_per_chunk;
  chunk_sz = b->chunk_hdr_sz + (uword) b->elts_per_chunk * b->elt_sz;

  s = format (s, "%u bytes/elt, align %u, chunk-align %u, ", b->elt_sz,
	      b->align, b->chunk_align);
  s = format (s, "%u elts-per-chunk, chunk size %lu bytes", b->elts_per_chunk,
	      chunk_sz);

  if (n_chunks == 0)
    return format (s, "\nempty");

  s = format (s, "\n%lu chunks allocated, ", n_chunks);
  s = format (s, "%lu / %lu free elts (%.1f%%), ", n_free_elts, n_elts,
	      (f64) n_free_elts * 100 / n_elts);
  s = format (s, "%lu bytes of memory consumed", n_chunks * chunk_sz);

  return s;
}

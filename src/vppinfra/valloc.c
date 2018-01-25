/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vppinfra/valloc.h>

/** @file
    @brief Simple first-fit virtual space allocator
*/

/** @brief initialize a virtual address allocation arena
 */

void
clib_valloc_init (clib_valloc_main_t * vam, clib_valloc_chunk_t * template,
		  int need_lock)
{
  clib_valloc_chunk_t *ch;

  ASSERT (template->baseva && template->size);
  memset (vam, 0, sizeof (*vam));
  if (need_lock)
    clib_spinlock_init (&vam->lock);

  vam->chunk_index_by_baseva = hash_create (0, sizeof (uword));

  pool_get (vam->chunks, ch);
  memset (ch, 0, sizeof (*ch));

  ch->next = ch->prev = ~0;
  ch->baseva = template->baseva;
  ch->size = template->size;
  vam->first_index = ch - vam->chunks;

  hash_set (vam->chunk_index_by_baseva, ch->baseva, vam->first_index);
}

uword
clib_valloc_alloc (clib_valloc_main_t * vam, uword size,
		   int os_out_of_memory_on_failure)
{
  clib_valloc_chunk_t *ch, *new_ch, *next_ch;
  u32 index;

  clib_spinlock_lock_if_init (&vam->lock);

  index = vam->first_index;

  while (index != ~0)
    {
      ch = pool_elt_at_index (vam->chunks, index);
      /* If the chunk is free... */
      if ((ch->flags & CLIB_VALLOC_BUSY) == 0)
	{
	  /* Too small? */
	  if (ch->size < size)
	    goto next_chunk;
	  /* Exact match? */
	  if (ch->size == size)
	    {
	      ch->flags |= CLIB_VALLOC_BUSY;
	      clib_spinlock_unlock_if_init (&vam->lock);
	      return ch->baseva;
	    }
	  /*
	   * The current free chunk is larger than necessary, split the block.
	   */
	  pool_get (vam->chunks, new_ch);
	  /* ch might have just moved */
	  ch = pool_elt_at_index (vam->chunks, index);
	  memset (new_ch, 0, sizeof (*new_ch));
	  new_ch->next = new_ch->prev = ~0;
	  new_ch->baseva = ch->baseva + size;
	  new_ch->size = ch->size - size;
	  ch->size = size;

	  /* Insert into doubly-linked list */
	  new_ch->next = ch->next;
	  new_ch->prev = ch - vam->chunks;

	  if (ch->next != ~0)
	    {
	      next_ch = pool_elt_at_index (vam->chunks, ch->next);
	      next_ch->prev = new_ch - vam->chunks;
	    }
	  ch->next = new_ch - vam->chunks;

	  hash_set (vam->chunk_index_by_baseva, new_ch->baseva,
		    new_ch - vam->chunks);

	  ch->flags |= CLIB_VALLOC_BUSY;
	  clib_spinlock_unlock_if_init (&vam->lock);
	  return ch->baseva;
	}

    next_chunk:
      index = ch->next;
    }
  clib_spinlock_unlock_if_init (&vam->lock);

  if (os_out_of_memory_on_failure)
    os_out_of_memory ();

  return 0;
}


void
clib_valloc_free (clib_valloc_main_t * vam, uword baseva)
{
  clib_valloc_chunk_t *ch, *prev_ch, *next_ch, *n2_ch;
  u32 index;
  uword *p;

  clib_spinlock_lock_if_init (&vam->lock);

  p = hash_get (vam->chunk_index_by_baseva, baseva);

  /* Check even in production images */
  if (p == 0)
    os_panic ();

  index = p[0];

  ch = pool_elt_at_index (vam->chunks, index);

  ASSERT (ch->baseva == baseva);
  ASSERT ((ch->flags & CLIB_VALLOC_BUSY) != 0);

  ch->flags &= ~CLIB_VALLOC_BUSY;

  /* combine with previous entry? */
  if (ch->prev != ~0)
    {
      prev_ch = pool_elt_at_index (vam->chunks, ch->prev);
      /*
       * Previous item must be free as well, and
       * tangent to this block.
       */
      if ((prev_ch->flags & CLIB_VALLOC_BUSY) == 0
	  && ((prev_ch->baseva + prev_ch->size) == ch->baseva))
	{
	  hash_unset (vam->chunk_index_by_baseva, baseva);
	  prev_ch->size += ch->size;
	  prev_ch->next = ch->next;
	  if (ch->next != ~0)
	    {
	      next_ch = pool_elt_at_index (vam->chunks, ch->next);
	      next_ch->prev = ch->prev;
	    }
	  ASSERT (ch - vam->chunks != vam->first_index);
	  memset (ch, 0xfe, sizeof (*ch));
	  pool_put (vam->chunks, ch);
	  /* See about combining with next elt */
	  ch = prev_ch;
	}
    }

  /* Combine with next entry? */
  if (ch->next != ~0)
    {
      next_ch = pool_elt_at_index (vam->chunks, ch->next);

      if ((next_ch->flags & CLIB_VALLOC_BUSY) == 0
	  && ((ch->baseva + ch->size) == next_ch->baseva))
	{
	  hash_unset (vam->chunk_index_by_baseva, next_ch->baseva);
	  ch->size += next_ch->size;
	  ch->next = next_ch->next;
	  if (ch->next != ~0)
	    {
	      n2_ch = pool_elt_at_index (vam->chunks, next_ch->next);
	      n2_ch->prev = ch - vam->chunks;
	    }
	  ASSERT (next_ch - vam->chunks != vam->first_index);
	  memset (next_ch, 0xfe, sizeof (*ch));
	  pool_put (vam->chunks, next_ch);
	}
    }

  clib_spinlock_unlock_if_init (&vam->lock);
}

u8 *
format_valloc (u8 * s, va_list * va)
{
  clib_valloc_main_t *vam = va_arg (*va, clib_valloc_main_t *);
  int verbose = va_arg (*va, int);
  clib_valloc_chunk_t *ch;
  u32 index;
  uword *p;

  clib_spinlock_lock_if_init (&vam->lock);

  s = format (s, "%d chunks, first index %d\n",
	      pool_elts (vam->chunks), vam->first_index);

  if (verbose)
    {
      index = vam->first_index;
      while (index != ~0)
	{
	  ch = pool_elt_at_index (vam->chunks, index);

	  s = format (s, "[%d] base %llx size %llx (%lld) prev %d %s\n",
		      index, ch->baseva, ch->size, ch->size, ch->prev,
		      (ch->flags & CLIB_VALLOC_BUSY) ? "busy" : "free");

	  p = hash_get (vam->chunk_index_by_baseva, ch->baseva);
	  if (p == 0)
	    {
	      s = format (s, "   BUG: baseva not in hash table!\n");
	    }
	  else if (p[0] != index)
	    {
	      s = format (s, "   BUG: baseva in hash table %d not %d!\n",
			  p[0], index);
	    }
	  index = ch->next;
	}
    }

  clib_spinlock_unlock_if_init (&vam->lock);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

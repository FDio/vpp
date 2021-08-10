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

#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/in_out_acl.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>	/* for API error numbers */
#include <vnet/l2/l2_classify.h>	/* for L2_INPUT_CLASSIFY_NEXT_xxx */
#include <vnet/fib/fib_table.h>
#include <vppinfra/lock.h>
#include <vnet/classify/trace_classify.h>



/**
 * @file
 * @brief N-tuple classifier
 */

vnet_classify_main_t vnet_classify_main;

#if VALIDATION_SCAFFOLDING
/* Validation scaffolding */
void
mv (vnet_classify_table_t * t)
{
  void *oldheap;

  oldheap = clib_mem_set_heap (t->mheap);
  clib_mem_validate ();
  clib_mem_set_heap (oldheap);
}

void
rogue (vnet_classify_table_t * t)
{
  int i, j, k;
  vnet_classify_entry_t *v, *save_v;
  u32 active_elements = 0;
  vnet_classify_bucket_t *b;

  for (i = 0; i < t->nbuckets; i++)
    {
      b = &t->buckets[i];
      if (b->offset == 0)
	continue;
      save_v = vnet_classify_get_entry (t, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < t->entries_per_page; k++)
	    {
	      v = vnet_classify_entry_at_index
		(t, save_v, j * t->entries_per_page + k);

	      if (vnet_classify_entry_is_busy (v))
		active_elements++;
	    }
	}
    }

  if (active_elements != t->active_elements)
    clib_warning ("found %u expected %u elts", active_elements,
		  t->active_elements);
}
#else
void
mv (vnet_classify_table_t * t)
{
}

void
rogue (vnet_classify_table_t * t)
{
}
#endif

void
vnet_classify_register_unformat_l2_next_index_fn (unformat_function_t * fn)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  vec_add1 (cm->unformat_l2_next_index_fns, fn);
}

void
vnet_classify_register_unformat_ip_next_index_fn (unformat_function_t * fn)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  vec_add1 (cm->unformat_ip_next_index_fns, fn);
}

void
vnet_classify_register_unformat_acl_next_index_fn (unformat_function_t * fn)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  vec_add1 (cm->unformat_acl_next_index_fns, fn);
}

void
vnet_classify_register_unformat_policer_next_index_fn (unformat_function_t *
						       fn)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  vec_add1 (cm->unformat_policer_next_index_fns, fn);
}

void
vnet_classify_register_unformat_opaque_index_fn (unformat_function_t * fn)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  vec_add1 (cm->unformat_opaque_index_fns, fn);
}

vnet_classify_table_t *
vnet_classify_new_table (vnet_classify_main_t *cm, const u8 *mask,
			 u32 nbuckets, u32 memory_size, u32 skip_n_vectors,
			 u32 match_n_vectors)
{
  vnet_classify_table_t *t;
  void *oldheap;

  nbuckets = 1 << (max_log2 (nbuckets));

  pool_get_aligned_zero (cm->tables, t, CLIB_CACHE_LINE_BYTES);

  clib_memset_u32 (t->mask, 0, 4 * ARRAY_LEN (t->mask));
  clib_memcpy_fast (t->mask, mask, match_n_vectors * sizeof (u32x4));

  t->next_table_index = ~0;
  t->nbuckets = nbuckets;
  t->log2_nbuckets = max_log2 (nbuckets);
  t->match_n_vectors = match_n_vectors;
  t->skip_n_vectors = skip_n_vectors;
  t->entries_per_page = 2;
  t->load_mask = pow2_mask (match_n_vectors * 2);

  t->mheap = clib_mem_create_heap (0, memory_size, 1 /* locked */ ,
				   "classify");

  vec_validate_aligned (t->buckets, nbuckets - 1, CLIB_CACHE_LINE_BYTES);
  oldheap = clib_mem_set_heap (t->mheap);

  clib_spinlock_init (&t->writer_lock);
  clib_mem_set_heap (oldheap);
  return (t);
}

void
vnet_classify_delete_table_index (vnet_classify_main_t * cm,
				  u32 table_index, int del_chain)
{
  vnet_classify_table_t *t;

  /* Tolerate multiple frees, up to a point */
  if (pool_is_free_index (cm->tables, table_index))
    return;

  t = pool_elt_at_index (cm->tables, table_index);
  if (del_chain && t->next_table_index != ~0)
    /* Recursively delete the entire chain */
    vnet_classify_delete_table_index (cm, t->next_table_index, del_chain);

  vec_free (t->buckets);
  clib_mem_destroy_heap (t->mheap);
  pool_put (cm->tables, t);
}

static vnet_classify_entry_t *
vnet_classify_entry_alloc (vnet_classify_table_t * t, u32 log2_pages)
{
  vnet_classify_entry_t *rv = 0;
  u32 required_length;
  void *oldheap;

  CLIB_SPINLOCK_ASSERT_LOCKED (&t->writer_lock);
  required_length =
    (sizeof (vnet_classify_entry_t) + (t->match_n_vectors * sizeof (u32x4)))
    * t->entries_per_page * (1 << log2_pages);

  if (log2_pages >= vec_len (t->freelists) || t->freelists[log2_pages] == 0)
    {
      oldheap = clib_mem_set_heap (t->mheap);

      vec_validate (t->freelists, log2_pages);

      rv = clib_mem_alloc_aligned (required_length, CLIB_CACHE_LINE_BYTES);
      clib_mem_set_heap (oldheap);
      goto initialize;
    }
  rv = t->freelists[log2_pages];
  t->freelists[log2_pages] = rv->next_free;

initialize:
  ASSERT (rv);

  clib_memset (rv, 0xff, required_length);
  return rv;
}

static void
vnet_classify_entry_free (vnet_classify_table_t * t,
			  vnet_classify_entry_t * v, u32 log2_pages)
{
  CLIB_SPINLOCK_ASSERT_LOCKED (&t->writer_lock);

  ASSERT (vec_len (t->freelists) > log2_pages);

  v->next_free = t->freelists[log2_pages];
  t->freelists[log2_pages] = v;
}

static inline void make_working_copy
  (vnet_classify_table_t * t, vnet_classify_bucket_t * b)
{
  vnet_classify_entry_t *v;
  vnet_classify_bucket_t working_bucket __attribute__ ((aligned (8)));
  void *oldheap;
  vnet_classify_entry_t *working_copy;
  u32 thread_index = vlib_get_thread_index ();
  int working_copy_length, required_length;

  if (thread_index >= vec_len (t->working_copies))
    {
      oldheap = clib_mem_set_heap (t->mheap);
      vec_validate (t->working_copies, thread_index);
      vec_validate (t->working_copy_lengths, thread_index);
      t->working_copy_lengths[thread_index] = -1;
      clib_mem_set_heap (oldheap);
    }

  /*
   * working_copies are per-cpu so that near-simultaneous
   * updates from multiple threads will not result in sporadic, spurious
   * lookup failures.
   */
  working_copy = t->working_copies[thread_index];
  working_copy_length = t->working_copy_lengths[thread_index];
  required_length =
    (sizeof (vnet_classify_entry_t) + (t->match_n_vectors * sizeof (u32x4)))
    * t->entries_per_page * (1 << b->log2_pages);

  t->saved_bucket.as_u64 = b->as_u64;
  oldheap = clib_mem_set_heap (t->mheap);

  if (required_length > working_copy_length)
    {
      if (working_copy)
	clib_mem_free (working_copy);
      working_copy =
	clib_mem_alloc_aligned (required_length, CLIB_CACHE_LINE_BYTES);
      t->working_copies[thread_index] = working_copy;
    }

  clib_mem_set_heap (oldheap);

  v = vnet_classify_get_entry (t, b->offset);

  clib_memcpy_fast (working_copy, v, required_length);

  working_bucket.as_u64 = b->as_u64;
  working_bucket.offset = vnet_classify_get_offset (t, working_copy);
  CLIB_MEMORY_BARRIER ();
  b->as_u64 = working_bucket.as_u64;
  t->working_copies[thread_index] = working_copy;
}

static vnet_classify_entry_t *
split_and_rehash (vnet_classify_table_t * t,
		  vnet_classify_entry_t * old_values, u32 old_log2_pages,
		  u32 new_log2_pages)
{
  vnet_classify_entry_t *new_values, *v, *new_v;
  int i, j, length_in_entries;

  new_values = vnet_classify_entry_alloc (t, new_log2_pages);
  length_in_entries = (1 << old_log2_pages) * t->entries_per_page;

  for (i = 0; i < length_in_entries; i++)
    {
      u64 new_hash;

      v = vnet_classify_entry_at_index (t, old_values, i);

      if (vnet_classify_entry_is_busy (v))
	{
	  /* Hack so we can use the packet hash routine */
	  u8 *key_minus_skip;
	  key_minus_skip = (u8 *) v->key;
	  key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

	  new_hash = vnet_classify_hash_packet (t, key_minus_skip);
	  new_hash >>= t->log2_nbuckets;
	  new_hash &= (1 << new_log2_pages) - 1;

	  for (j = 0; j < t->entries_per_page; j++)
	    {
	      new_v = vnet_classify_entry_at_index (t, new_values,
						    new_hash + j);

	      if (vnet_classify_entry_is_free (new_v))
		{
		  clib_memcpy_fast (new_v, v, sizeof (vnet_classify_entry_t)
				    + (t->match_n_vectors * sizeof (u32x4)));
		  new_v->flags &= ~(VNET_CLASSIFY_ENTRY_FREE);
		  goto doublebreak;
		}
	    }
	  /* Crap. Tell caller to try again */
	  vnet_classify_entry_free (t, new_values, new_log2_pages);
	  return 0;
	doublebreak:
	  ;
	}
    }
  return new_values;
}

static vnet_classify_entry_t *
split_and_rehash_linear (vnet_classify_table_t * t,
			 vnet_classify_entry_t * old_values,
			 u32 old_log2_pages, u32 new_log2_pages)
{
  vnet_classify_entry_t *new_values, *v, *new_v;
  int i, j, new_length_in_entries, old_length_in_entries;

  new_values = vnet_classify_entry_alloc (t, new_log2_pages);
  new_length_in_entries = (1 << new_log2_pages) * t->entries_per_page;
  old_length_in_entries = (1 << old_log2_pages) * t->entries_per_page;

  j = 0;
  for (i = 0; i < old_length_in_entries; i++)
    {
      v = vnet_classify_entry_at_index (t, old_values, i);

      if (vnet_classify_entry_is_busy (v))
	{
	  for (; j < new_length_in_entries; j++)
	    {
	      new_v = vnet_classify_entry_at_index (t, new_values, j);

	      if (vnet_classify_entry_is_busy (new_v))
		{
		  clib_warning ("BUG: linear rehash new entry not free!");
		  continue;
		}
	      clib_memcpy_fast (new_v, v, sizeof (vnet_classify_entry_t)
				+ (t->match_n_vectors * sizeof (u32x4)));
	      new_v->flags &= ~(VNET_CLASSIFY_ENTRY_FREE);
	      j++;
	      goto doublebreak;
	    }
	  /*
	   * Crap. Tell caller to try again.
	   * This should never happen...
	   */
	  clib_warning ("BUG: linear rehash failed!");
	  vnet_classify_entry_free (t, new_values, new_log2_pages);
	  return 0;
	}
    doublebreak:
      ;
    }

  return new_values;
}

static void
vnet_classify_entry_claim_resource (vnet_classify_entry_t * e)
{
  switch (e->action)
    {
    case CLASSIFY_ACTION_SET_IP4_FIB_INDEX:
      fib_table_lock (e->metadata, FIB_PROTOCOL_IP4, FIB_SOURCE_CLASSIFY);
      break;
    case CLASSIFY_ACTION_SET_IP6_FIB_INDEX:
      fib_table_lock (e->metadata, FIB_PROTOCOL_IP6, FIB_SOURCE_CLASSIFY);
      break;
    case CLASSIFY_ACTION_SET_METADATA:
    case CLASSIFY_ACTION_NONE:
      break;
    }
}

static void
vnet_classify_entry_release_resource (vnet_classify_entry_t * e)
{
  switch (e->action)
    {
    case CLASSIFY_ACTION_SET_IP4_FIB_INDEX:
      fib_table_unlock (e->metadata, FIB_PROTOCOL_IP4, FIB_SOURCE_CLASSIFY);
      break;
    case CLASSIFY_ACTION_SET_IP6_FIB_INDEX:
      fib_table_unlock (e->metadata, FIB_PROTOCOL_IP6, FIB_SOURCE_CLASSIFY);
      break;
    case CLASSIFY_ACTION_SET_METADATA:
    case CLASSIFY_ACTION_NONE:
      break;
    }
}

static int
vnet_classify_add_del (vnet_classify_table_t *t, vnet_classify_entry_t *add_v,
		       int is_add)
{
  u32 bucket_index;
  vnet_classify_bucket_t *b, tmp_b;
  vnet_classify_entry_t *v, *new_v, *save_new_v, *working_copy, *save_v;
  u32 value_index;
  int rv = 0;
  int i;
  u64 hash, new_hash;
  u32 limit;
  u32 old_log2_pages, new_log2_pages;
  u32 thread_index = vlib_get_thread_index ();
  u8 *key_minus_skip;
  int resplit_once = 0;
  int mark_bucket_linear;

  ASSERT ((add_v->flags & VNET_CLASSIFY_ENTRY_FREE) == 0);

  key_minus_skip = (u8 *) add_v->key;
  key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

  hash = vnet_classify_hash_packet (t, key_minus_skip);

  bucket_index = hash & (t->nbuckets - 1);
  b = &t->buckets[bucket_index];

  hash >>= t->log2_nbuckets;

  clib_spinlock_lock (&t->writer_lock);

  /* First elt in the bucket? */
  if (b->offset == 0)
    {
      if (is_add == 0)
	{
	  rv = -1;
	  goto unlock;
	}

      v = vnet_classify_entry_alloc (t, 0 /* new_log2_pages */ );
      clib_memcpy_fast (v, add_v, sizeof (vnet_classify_entry_t) +
			t->match_n_vectors * sizeof (u32x4));
      v->flags &= ~(VNET_CLASSIFY_ENTRY_FREE);
      vnet_classify_entry_claim_resource (v);

      tmp_b.as_u64 = 0;
      tmp_b.offset = vnet_classify_get_offset (t, v);

      b->as_u64 = tmp_b.as_u64;
      t->active_elements++;

      goto unlock;
    }

  make_working_copy (t, b);

  save_v = vnet_classify_get_entry (t, t->saved_bucket.offset);
  value_index = hash & ((1 << t->saved_bucket.log2_pages) - 1);
  limit = t->entries_per_page;
  if (PREDICT_FALSE (b->linear_search))
    {
      value_index = 0;
      limit *= (1 << b->log2_pages);
    }

  if (is_add)
    {
      /*
       * For obvious (in hindsight) reasons, see if we're supposed to
       * replace an existing key, then look for an empty slot.
       */

      for (i = 0; i < limit; i++)
	{
	  v = vnet_classify_entry_at_index (t, save_v, value_index + i);

	  if (!memcmp
	      (v->key, add_v->key, t->match_n_vectors * sizeof (u32x4)))
	    {
	      clib_memcpy_fast (v, add_v, sizeof (vnet_classify_entry_t) +
				t->match_n_vectors * sizeof (u32x4));
	      v->flags &= ~(VNET_CLASSIFY_ENTRY_FREE);
	      vnet_classify_entry_claim_resource (v);

	      CLIB_MEMORY_BARRIER ();
	      /* Restore the previous (k,v) pairs */
	      b->as_u64 = t->saved_bucket.as_u64;
	      goto unlock;
	    }
	}
      for (i = 0; i < limit; i++)
	{
	  v = vnet_classify_entry_at_index (t, save_v, value_index + i);

	  if (vnet_classify_entry_is_free (v))
	    {
	      clib_memcpy_fast (v, add_v, sizeof (vnet_classify_entry_t) +
				t->match_n_vectors * sizeof (u32x4));
	      v->flags &= ~(VNET_CLASSIFY_ENTRY_FREE);
	      vnet_classify_entry_claim_resource (v);

	      CLIB_MEMORY_BARRIER ();
	      b->as_u64 = t->saved_bucket.as_u64;
	      t->active_elements++;
	      goto unlock;
	    }
	}
      /* no room at the inn... split case... */
    }
  else
    {
      for (i = 0; i < limit; i++)
	{
	  v = vnet_classify_entry_at_index (t, save_v, value_index + i);

	  if (!memcmp
	      (v->key, add_v->key, t->match_n_vectors * sizeof (u32x4)))
	    {
	      vnet_classify_entry_release_resource (v);
	      clib_memset (v, 0xff, sizeof (vnet_classify_entry_t) +
			   t->match_n_vectors * sizeof (u32x4));
	      v->flags |= VNET_CLASSIFY_ENTRY_FREE;

	      CLIB_MEMORY_BARRIER ();
	      b->as_u64 = t->saved_bucket.as_u64;
	      t->active_elements--;
	      goto unlock;
	    }
	}
      rv = -3;
      b->as_u64 = t->saved_bucket.as_u64;
      goto unlock;
    }

  old_log2_pages = t->saved_bucket.log2_pages;
  new_log2_pages = old_log2_pages + 1;
  working_copy = t->working_copies[thread_index];

  if (t->saved_bucket.linear_search)
    goto linear_resplit;

  mark_bucket_linear = 0;

  new_v = split_and_rehash (t, working_copy, old_log2_pages, new_log2_pages);

  if (new_v == 0)
    {
    try_resplit:
      resplit_once = 1;
      new_log2_pages++;

      new_v = split_and_rehash (t, working_copy, old_log2_pages,
				new_log2_pages);
      if (new_v == 0)
	{
	mark_linear:
	  new_log2_pages--;

	linear_resplit:
	  /* pinned collisions, use linear search */
	  new_v = split_and_rehash_linear (t, working_copy, old_log2_pages,
					   new_log2_pages);
	  /* A new linear-search bucket? */
	  if (!t->saved_bucket.linear_search)
	    t->linear_buckets++;
	  mark_bucket_linear = 1;
	}
    }

  /* Try to add the new entry */
  save_new_v = new_v;

  key_minus_skip = (u8 *) add_v->key;
  key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

  new_hash = vnet_classify_hash_packet_inline (t, key_minus_skip);
  new_hash >>= t->log2_nbuckets;
  new_hash &= (1 << new_log2_pages) - 1;

  limit = t->entries_per_page;
  if (mark_bucket_linear)
    {
      limit *= (1 << new_log2_pages);
      new_hash = 0;
    }

  for (i = 0; i < limit; i++)
    {
      new_v = vnet_classify_entry_at_index (t, save_new_v, new_hash + i);

      if (vnet_classify_entry_is_free (new_v))
	{
	  clib_memcpy_fast (new_v, add_v, sizeof (vnet_classify_entry_t) +
			    t->match_n_vectors * sizeof (u32x4));
	  new_v->flags &= ~(VNET_CLASSIFY_ENTRY_FREE);
	  vnet_classify_entry_claim_resource (new_v);

	  goto expand_ok;
	}
    }
  /* Crap. Try again */
  vnet_classify_entry_free (t, save_new_v, new_log2_pages);

  if (resplit_once)
    goto mark_linear;
  else
    goto try_resplit;

expand_ok:
  tmp_b.log2_pages = new_log2_pages;
  tmp_b.offset = vnet_classify_get_offset (t, save_new_v);
  tmp_b.linear_search = mark_bucket_linear;

  CLIB_MEMORY_BARRIER ();
  b->as_u64 = tmp_b.as_u64;
  t->active_elements++;
  v = vnet_classify_get_entry (t, t->saved_bucket.offset);
  vnet_classify_entry_free (t, v, old_log2_pages);

unlock:
  clib_spinlock_unlock (&t->writer_lock);
  return rv;
}

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  ethernet_header_t eh;
  ip4_header_t ip;
}) classify_data_or_mask_t;
/* *INDENT-ON* */

u64
vnet_classify_hash_packet (const vnet_classify_table_t *t, const u8 *h)
{
  return vnet_classify_hash_packet_inline (t, h);
}

vnet_classify_entry_t *
vnet_classify_find_entry (vnet_classify_table_t *t, const u8 *h, u64 hash,
			  f64 now)
{
  return vnet_classify_find_entry_inline (t, h, hash, now);
}

static u8 *
format_classify_entry (u8 * s, va_list * args)
{
  vnet_classify_table_t *t = va_arg (*args, vnet_classify_table_t *);
  vnet_classify_entry_t *e = va_arg (*args, vnet_classify_entry_t *);

  s = format
    (s, "[%u]: next_index %d advance %d opaque %d action %d metadata %d\n",
     vnet_classify_get_offset (t, e), e->next_index, e->advance,
     e->opaque_index, e->action, e->metadata);


  s = format (s, "        k: %U\n", format_hex_bytes, e->key,
	      t->match_n_vectors * sizeof (u32x4));

  if (vnet_classify_entry_is_busy (e))
    s = format (s, "        hits %lld, last_heard %.2f\n",
		e->hits, e->last_heard);
  else
    s = format (s, "  entry is free\n");
  return s;
}

u8 *
format_classify_table (u8 * s, va_list * args)
{
  vnet_classify_table_t *t = va_arg (*args, vnet_classify_table_t *);
  int verbose = va_arg (*args, int);
  vnet_classify_bucket_t *b;
  vnet_classify_entry_t *v, *save_v;
  int i, j, k;
  u64 active_elements = 0;

  for (i = 0; i < t->nbuckets; i++)
    {
      b = &t->buckets[i];
      if (b->offset == 0)
	{
	  if (verbose > 1)
	    s = format (s, "[%d]: empty\n", i);
	  continue;
	}

      if (verbose)
	{
	  s = format (s, "[%d]: heap offset %d, elts %d, %s\n", i,
		      b->offset, (1 << b->log2_pages) * t->entries_per_page,
		      b->linear_search ? "LINEAR" : "normal");
	}

      save_v = vnet_classify_get_entry (t, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < t->entries_per_page; k++)
	    {

	      v = vnet_classify_entry_at_index (t, save_v,
						j * t->entries_per_page + k);

	      if (vnet_classify_entry_is_free (v))
		{
		  if (verbose > 1)
		    s = format (s, "    %d: empty\n",
				j * t->entries_per_page + k);
		  continue;
		}
	      if (verbose)
		{
		  s = format (s, "    %d: %U\n",
			      j * t->entries_per_page + k,
			      format_classify_entry, t, v);
		}
	      active_elements++;
	    }
	}
    }

  s = format (s, "    %lld active elements\n", active_elements);
  s = format (s, "    %d free lists\n", vec_len (t->freelists));
  s = format (s, "    %d linear-search buckets\n", t->linear_buckets);
  return s;
}

int
vnet_classify_add_del_table (vnet_classify_main_t *cm, const u8 *mask,
			     u32 nbuckets, u32 memory_size, u32 skip,
			     u32 match, u32 next_table_index,
			     u32 miss_next_index, u32 *table_index,
			     u8 current_data_flag, i16 current_data_offset,
			     int is_add, int del_chain)
{
  vnet_classify_table_t *t;

  if (is_add)
    {
      if (*table_index == ~0)	/* add */
	{
	  if (memory_size == 0)
	    return VNET_API_ERROR_INVALID_MEMORY_SIZE;

	  if (nbuckets == 0)
	    return VNET_API_ERROR_INVALID_VALUE;

	  if (match < 1 || match > 5)
	    return VNET_API_ERROR_INVALID_VALUE;

	  t = vnet_classify_new_table (cm, mask, nbuckets, memory_size,
				       skip, match);
	  t->next_table_index = next_table_index;
	  t->miss_next_index = miss_next_index;
	  t->current_data_flag = current_data_flag;
	  t->current_data_offset = current_data_offset;
	  *table_index = t - cm->tables;
	}
      else			/* update */
	{
	  vnet_classify_main_t *cm = &vnet_classify_main;
	  t = pool_elt_at_index (cm->tables, *table_index);

	  t->next_table_index = next_table_index;
	}
      return 0;
    }

  vnet_classify_delete_table_index (cm, *table_index, del_chain);
  return 0;
}

#define foreach_tcp_proto_field                 \
_(src)                                          \
_(dst)

#define foreach_udp_proto_field                 \
_(src_port)                                     \
_(dst_port)

#define foreach_ip4_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(tos)                                          \
_(length)					\
_(fragment_id)                                  \
_(ttl)                                          \
_(protocol)                                     \
_(checksum)

uword
unformat_tcp_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  tcp_header_t *tcp;

#define _(a) u8 a=0;
  foreach_tcp_proto_field;
#undef _

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0);
#define _(a) else if (unformat (input, #a)) a=1;
      foreach_tcp_proto_field
#undef _
	else
	break;
    }

#define _(a) found_something += a;
  foreach_tcp_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*tcp) - 1);

  tcp = (tcp_header_t *) mask;

#define _(a) if (a) clib_memset (&tcp->a, 0xff, sizeof (tcp->a));
  foreach_tcp_proto_field;
#undef _

  *maskp = mask;
  return 1;
}

uword
unformat_udp_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  udp_header_t *udp;

#define _(a) u8 a=0;
  foreach_udp_proto_field;
#undef _

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0);
#define _(a) else if (unformat (input, #a)) a=1;
      foreach_udp_proto_field
#undef _
	else
	break;
    }

#define _(a) found_something += a;
  foreach_udp_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*udp) - 1);

  udp = (udp_header_t *) mask;

#define _(a) if (a) clib_memset (&udp->a, 0xff, sizeof (udp->a));
  foreach_udp_proto_field;
#undef _

  *maskp = mask;
  return 1;
}

typedef struct
{
  u16 src_port, dst_port;
} tcpudp_header_t;

uword
unformat_l4_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u16 src_port = 0, dst_port = 0;
  tcpudp_header_t *tcpudp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tcp %U", unformat_tcp_mask, maskp))
	return 1;
      else if (unformat (input, "udp %U", unformat_udp_mask, maskp))
	return 1;
      else if (unformat (input, "src_port"))
	src_port = 0xFFFF;
      else if (unformat (input, "dst_port"))
	dst_port = 0xFFFF;
      else
	break;
    }

  if (!src_port && !dst_port)
    return 0;

  u8 *mask = 0;
  vec_validate (mask, sizeof (tcpudp_header_t) - 1);

  tcpudp = (tcpudp_header_t *) mask;
  tcpudp->src_port = src_port;
  tcpudp->dst_port = dst_port;

  *maskp = mask;

  return 1;
}

uword
unformat_ip4_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  ip4_header_t *ip;
  u32 src_prefix_len = 32;
  u32 src_prefix_mask = ~0;
  u32 dst_prefix_len = 32;
  u32 dst_prefix_mask = ~0;

#define _(a) u8 a=0;
  foreach_ip4_proto_field;
#undef _
  u8 version = 0;
  u8 hdr_length = 0;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version"))
	version = 1;
      else if (unformat (input, "hdr_length"))
	hdr_length = 1;
      else if (unformat (input, "src/%d", &src_prefix_len))
	{
	  src_address = 1;
	  src_prefix_mask &= ~((1 << (32 - src_prefix_len)) - 1);
	  src_prefix_mask = clib_host_to_net_u32 (src_prefix_mask);
	}
      else if (unformat (input, "dst/%d", &dst_prefix_len))
	{
	  dst_address = 1;
	  dst_prefix_mask &= ~((1 << (32 - dst_prefix_len)) - 1);
	  dst_prefix_mask = clib_host_to_net_u32 (dst_prefix_mask);
	}
      else if (unformat (input, "src"))
	src_address = 1;
      else if (unformat (input, "dst"))
	dst_address = 1;
      else if (unformat (input, "proto"))
	protocol = 1;

#define _(a) else if (unformat (input, #a)) a=1;
      foreach_ip4_proto_field
#undef _
	else
	break;
    }

  found_something = version + hdr_length;
#define _(a) found_something += a;
  foreach_ip4_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*ip) - 1);

  ip = (ip4_header_t *) mask;

#define _(a) if (a) clib_memset (&ip->a, 0xff, sizeof (ip->a));
  foreach_ip4_proto_field;
#undef _

  if (src_address)
    ip->src_address.as_u32 = src_prefix_mask;

  if (dst_address)
    ip->dst_address.as_u32 = dst_prefix_mask;

  ip->ip_version_and_header_length = 0;

  if (version)
    ip->ip_version_and_header_length |= 0xF0;

  if (hdr_length)
    ip->ip_version_and_header_length |= 0x0F;

  *maskp = mask;
  return 1;
}

#define foreach_ip6_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(payload_length)				\
_(hop_limit)                                    \
_(protocol)

uword
unformat_ip6_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something;
  ip6_header_t *ip;
  u32 ip_version_traffic_class_and_flow_label;

#define _(a) u8 a=0;
  foreach_ip6_proto_field;
#undef _
  u8 version = 0;
  u8 traffic_class = 0;
  u8 flow_label = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version"))
	version = 1;
      else if (unformat (input, "traffic-class"))
	traffic_class = 1;
      else if (unformat (input, "flow-label"))
	flow_label = 1;
      else if (unformat (input, "src"))
	src_address = 1;
      else if (unformat (input, "dst"))
	dst_address = 1;
      else if (unformat (input, "proto"))
	protocol = 1;

#define _(a) else if (unformat (input, #a)) a=1;
      foreach_ip6_proto_field
#undef _
	else
	break;
    }

  /* Account for "special" field names */
  found_something = version + traffic_class + flow_label
    + src_address + dst_address + protocol;

#define _(a) found_something += a;
  foreach_ip6_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*ip) - 1);

  ip = (ip6_header_t *) mask;

#define _(a) if (a) clib_memset (&ip->a, 0xff, sizeof (ip->a));
  foreach_ip6_proto_field;
#undef _

  ip_version_traffic_class_and_flow_label = 0;

  if (version)
    ip_version_traffic_class_and_flow_label |= 0xF0000000;

  if (traffic_class)
    ip_version_traffic_class_and_flow_label |= 0x0FF00000;

  if (flow_label)
    ip_version_traffic_class_and_flow_label |= 0x000FFFFF;

  ip->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (ip_version_traffic_class_and_flow_label);

  *maskp = mask;
  return 1;
}

uword
unformat_l3_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4 %U", unformat_ip4_mask, maskp))
	return 1;
      else if (unformat (input, "ip6 %U", unformat_ip6_mask, maskp))
	return 1;
      else
	break;
    }
  return 0;
}

uword
unformat_l2_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 src = 0;
  u8 dst = 0;
  u8 proto = 0;
  u8 tag1 = 0;
  u8 tag2 = 0;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u8 dot1q = 0;
  u8 dot1ad = 0;
  int len = 14;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src"))
	src = 1;
      else if (unformat (input, "dst"))
	dst = 1;
      else if (unformat (input, "proto"))
	proto = 1;
      else if (unformat (input, "tag1"))
	tag1 = 1;
      else if (unformat (input, "tag2"))
	tag2 = 1;
      else if (unformat (input, "ignore-tag1"))
	ignore_tag1 = 1;
      else if (unformat (input, "ignore-tag2"))
	ignore_tag2 = 1;
      else if (unformat (input, "cos1"))
	cos1 = 1;
      else if (unformat (input, "cos2"))
	cos2 = 1;
      else if (unformat (input, "dot1q"))
	dot1q = 1;
      else if (unformat (input, "dot1ad"))
	dot1ad = 1;
      else
	break;
    }
  if ((src + dst + proto + tag1 + tag2 + dot1q + dot1ad +
       ignore_tag1 + ignore_tag2 + cos1 + cos2) == 0)
    return 0;

  if (tag1 || ignore_tag1 || cos1 || dot1q)
    len = 18;
  if (tag2 || ignore_tag2 || cos2 || dot1ad)
    len = 22;

  vec_validate (mask, len - 1);

  if (dst)
    clib_memset (mask, 0xff, 6);

  if (src)
    clib_memset (mask + 6, 0xff, 6);

  if (tag2 || dot1ad)
    {
      /* inner vlan tag */
      if (tag2)
	{
	  mask[19] = 0xff;
	  mask[18] = 0x0f;
	}
      if (cos2)
	mask[18] |= 0xe0;
      if (proto)
	mask[21] = mask[20] = 0xff;
      if (tag1)
	{
	  mask[15] = 0xff;
	  mask[14] = 0x0f;
	}
      if (cos1)
	mask[14] |= 0xe0;
      *maskp = mask;
      return 1;
    }
  if (tag1 | dot1q)
    {
      if (tag1)
	{
	  mask[15] = 0xff;
	  mask[14] = 0x0f;
	}
      if (cos1)
	mask[14] |= 0xe0;
      if (proto)
	mask[16] = mask[17] = 0xff;
      *maskp = mask;
      return 1;
    }
  if (cos2)
    mask[18] |= 0xe0;
  if (cos1)
    mask[14] |= 0xe0;
  if (proto)
    mask[12] = mask[13] = 0xff;

  *maskp = mask;
  return 1;
}

uword
unformat_classify_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u32 *skipp = va_arg (*args, u32 *);
  u32 *matchp = va_arg (*args, u32 *);
  u32 match;
  u8 *mask = 0;
  u8 *l2 = 0;
  u8 *l3 = 0;
  u8 *l4 = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hex %U", unformat_hex_string, &mask))
	;
      else if (unformat (input, "l2 %U", unformat_l2_mask, &l2))
	;
      else if (unformat (input, "l3 %U", unformat_l3_mask, &l3))
	;
      else if (unformat (input, "l4 %U", unformat_l4_mask, &l4))
	;
      else
	break;
    }

  if (l4 && !l3)
    {
      vec_free (mask);
      vec_free (l2);
      vec_free (l4);
      return 0;
    }

  if (mask || l2 || l3 || l4)
    {
      if (l2 || l3 || l4)
	{
	  /* "With a free Ethernet header in every package" */
	  if (l2 == 0)
	    vec_validate (l2, 13);
	  mask = l2;
	  if (l3)
	    {
	      vec_append (mask, l3);
	      vec_free (l3);
	    }
	  if (l4)
	    {
	      vec_append (mask, l4);
	      vec_free (l4);
	    }
	}

      /* Scan forward looking for the first significant mask octet */
      for (i = 0; i < vec_len (mask); i++)
	if (mask[i])
	  break;

      /* compute (skip, match) params */
      *skipp = i / sizeof (u32x4);
      vec_delete (mask, *skipp * sizeof (u32x4), 0);

      /* Pad mask to an even multiple of the vector size */
      while (vec_len (mask) % sizeof (u32x4))
	vec_add1 (mask, 0);

      match = vec_len (mask) / sizeof (u32x4);

      for (i = match * sizeof (u32x4); i > 0; i -= sizeof (u32x4))
	{
	  u64 *tmp = (u64 *) (mask + (i - sizeof (u32x4)));
	  if (*tmp || *(tmp + 1))
	    break;
	  match--;
	}
      if (match == 0)
	clib_warning ("BUG: match 0");

      _vec_len (mask) = match * sizeof (u32x4);

      *matchp = match;
      *maskp = mask;

      return 1;
    }

  return 0;
}

#define foreach_l2_input_next                   \
_(drop, DROP)                                   \
_(ethernet, ETHERNET_INPUT)                     \
_(ip4, IP4_INPUT)                               \
_(ip6, IP6_INPUT)				\
_(li, LI)

uword
unformat_l2_input_next_index (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_l2_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_l2_next_index_fns[i], &tmp))
	{
	  next_index = tmp;
	  goto out;
	}
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = L2_INPUT_CLASSIFY_NEXT_##N; goto out;}
  foreach_l2_input_next;
#undef _

  if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_l2_output_next                   \
_(drop, DROP)

uword
unformat_l2_output_next_index (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_l2_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_l2_next_index_fns[i], &tmp))
	{
	  next_index = tmp;
	  goto out;
	}
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = L2_OUTPUT_CLASSIFY_NEXT_##N; goto out;}
  foreach_l2_output_next;
#undef _

  if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_ip_next                         \
_(drop, DROP)                                   \
_(rewrite, REWRITE)

uword
unformat_ip_next_index (unformat_input_t * input, va_list * args)
{
  u32 *miss_next_indexp = va_arg (*args, u32 *);
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_ip_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_ip_next_index_fns[i], &tmp))
	{
	  next_index = tmp;
	  goto out;
	}
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = IP_LOOKUP_NEXT_##N; goto out;}
  foreach_ip_next;
#undef _

  if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_acl_next                        \
_(deny, DENY)

uword
unformat_acl_next_index (unformat_input_t * input, va_list * args)
{
  u32 *next_indexp = va_arg (*args, u32 *);
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_acl_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_acl_next_index_fns[i], &tmp))
	{
	  next_index = tmp;
	  goto out;
	}
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = ACL_NEXT_INDEX_##N; goto out;}
  foreach_acl_next;
#undef _

  if (unformat (input, "permit"))
    {
      next_index = ~0;
      goto out;
    }
  else if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

out:
  *next_indexp = next_index;
  return 1;
}

uword
unformat_policer_next_index (unformat_input_t * input, va_list * args)
{
  u32 *next_indexp = va_arg (*args, u32 *);
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_policer_next_index_fns); i++)
    {
      if (unformat
	  (input, "%U", cm->unformat_policer_next_index_fns[i], &tmp))
	{
	  next_index = tmp;
	  goto out;
	}
    }

  if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

out:
  *next_indexp = next_index;
  return 1;
}

static clib_error_t *
classify_table_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 nbuckets = 2;
  u32 skip = ~0;
  u32 match = ~0;
  int is_add = 1;
  int del_chain = 0;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 memory_size = 2 << 20;
  u32 tmp;
  u32 current_data_flag = 0;
  int current_data_offset = 0;

  u8 *mask = 0;
  vnet_classify_main_t *cm = &vnet_classify_main;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "del-chain"))
	{
	  is_add = 0;
	  del_chain = 1;
	}
      else if (unformat (input, "buckets %d", &nbuckets))
	;
      else if (unformat (input, "skip %d", &skip))
	;
      else if (unformat (input, "match %d", &match))
	;
      else if (unformat (input, "table %d", &table_index))
	;
      else if (unformat (input, "mask %U", unformat_classify_mask,
			 &mask, &skip, &match))
	;
      else if (unformat (input, "memory-size %uM", &tmp))
	memory_size = tmp << 20;
      else if (unformat (input, "memory-size %uG", &tmp))
	memory_size = tmp << 30;
      else if (unformat (input, "next-table %d", &next_table_index))
	;
      else if (unformat (input, "miss-next %U", unformat_ip_next_index,
			 &miss_next_index))
	;
      else
	if (unformat
	    (input, "l2-input-miss-next %U", unformat_l2_input_next_index,
	     &miss_next_index))
	;
      else
	if (unformat
	    (input, "l2-output-miss-next %U", unformat_l2_output_next_index,
	     &miss_next_index))
	;
      else if (unformat (input, "acl-miss-next %U", unformat_acl_next_index,
			 &miss_next_index))
	;
      else if (unformat (input, "current-data-flag %d", &current_data_flag))
	;
      else
	if (unformat (input, "current-data-offset %d", &current_data_offset))
	;

      else
	break;
    }

  if (is_add && mask == 0 && table_index == ~0)
    return clib_error_return (0, "Mask required");

  if (is_add && skip == ~0 && table_index == ~0)
    return clib_error_return (0, "skip count required");

  if (is_add && match == ~0 && table_index == ~0)
    return clib_error_return (0, "match count required");

  if (!is_add && table_index == ~0)
    return clib_error_return (0, "table index required for delete");

  rv = vnet_classify_add_del_table (cm, mask, nbuckets, (u32) memory_size,
				    skip, match, next_table_index,
				    miss_next_index, &table_index,
				    current_data_flag, current_data_offset,
				    is_add, del_chain);
  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "vnet_classify_add_del_table returned %d",
				rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (classify_table, static) =
{
  .path = "classify table",
  .short_help =
  "classify table [miss-next|l2-miss_next|acl-miss-next <next_index>]"
  "\n mask <mask-value> buckets <nn> [skip <n>] [match <n>]"
  "\n [current-data-flag <n>] [current-data-offset <n>] [table <n>]"
  "\n [memory-size <nn>[M][G]] [next-table <n>]"
  "\n [del] [del-chain]",
  .function = classify_table_command_fn,
};
/* *INDENT-ON* */

static int
filter_table_mask_compare (void *a1, void *a2)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *ti1 = a1;
  u32 *ti2 = a2;
  u32 n1 = 0, n2 = 0;
  vnet_classify_table_t *t1, *t2;
  u8 *m1, *m2;
  int i;

  t1 = pool_elt_at_index (cm->tables, *ti1);
  t2 = pool_elt_at_index (cm->tables, *ti2);

  m1 = (u8 *) (t1->mask);
  m2 = (u8 *) (t2->mask);

  for (i = 0; i < t1->match_n_vectors * sizeof (u32x4); i++)
    {
      n1 += count_set_bits (m1[0]);
      m1++;
    }

  for (i = 0; i < t2->match_n_vectors * sizeof (u32x4); i++)
    {
      n2 += count_set_bits (m2[0]);
      m2++;
    }

  /* Reverse sort: descending number of set bits */
  if (n1 < n2)
    return 1;
  else if (n1 > n2)
    return -1;
  else
    return 0;
}


/*
 * Reorder the chain of tables starting with table_index such
 * that more more-specific masks come before less-specific masks.
 * Return the new head of the table chain.
 */
u32
classify_sort_table_chain (vnet_classify_main_t * cm, u32 table_index)
{
  /*
   * Form a vector of all classifier tables in this chain.
   */
  u32 *tables = 0;
  vnet_classify_table_t *t;
  u32 cti;
  for (cti = table_index; cti != ~0; cti = t->next_table_index)
    {
      vec_add1 (tables, cti);
      t = pool_elt_at_index (cm->tables, cti);
    }

  /*
   * Sort filter tables from most-specific mask to least-specific mask.
   */
  vec_sort_with_function (tables, filter_table_mask_compare);

  /*
   * Relink tables via next_table_index fields.
   */
  int i;
  for (i = 0; i < vec_len (tables); i++)
    {
      t = pool_elt_at_index (cm->tables, tables[i]);

      if ((i + 1) < vec_len (tables))
	t->next_table_index = tables[i + 1];
      else
	t->next_table_index = ~0;
    }

  table_index = tables[0];
  vec_free (tables);

  return table_index;
}


u32
classify_get_trace_chain (void)
{
  u32 table_index;

  table_index = vlib_global_main.trace_filter.classify_table_index;

  return table_index;
}

/*
 * Seting the Trace chain to ~0 is a request to delete and clear it.
 */
void
classify_set_trace_chain (vnet_classify_main_t * cm, u32 table_index)
{
  if (table_index == ~0)
    {
      u32 old_table_index;

      old_table_index = vlib_global_main.trace_filter.classify_table_index;
      vnet_classify_delete_table_index (cm, old_table_index, 1);
    }

  vlib_global_main.trace_filter.classify_table_index = table_index;
}


u32
classify_get_pcap_chain (vnet_classify_main_t * cm, u32 sw_if_index)
{
  u32 table_index = ~0;

  if (sw_if_index != ~0
      && (sw_if_index < vec_len (cm->classify_table_index_by_sw_if_index)))
    table_index = cm->classify_table_index_by_sw_if_index[sw_if_index];

  return table_index;
}

void
classify_set_pcap_chain (vnet_classify_main_t * cm,
			 u32 sw_if_index, u32 table_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (sw_if_index != ~0 && table_index != ~0)
    vec_validate_init_empty (cm->classify_table_index_by_sw_if_index,
			     sw_if_index, ~0);

  if (table_index == ~0)
    {
      u32 old_table_index = ~0;

      if (sw_if_index < vec_len (cm->classify_table_index_by_sw_if_index))
	old_table_index =
	  cm->classify_table_index_by_sw_if_index[sw_if_index];

      vnet_classify_delete_table_index (cm, old_table_index, 1);
    }

  /*
   * Put the table index where device drivers can find them.
   * This table index will be either a valid table or a ~0 to clear it.
   */
  if (vec_len (cm->classify_table_index_by_sw_if_index) > sw_if_index)
    cm->classify_table_index_by_sw_if_index[sw_if_index] = table_index;
  if (sw_if_index > 0)
    {
      vnet_hw_interface_t *hi;
      hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
      hi->trace_classify_table_index = table_index;
    }
}


/*
 * Search for a mask-compatible Classify table within the given table chain.
 */
u32
classify_lookup_chain (u32 table_index, u8 * mask, u32 n_skip, u32 n_match)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *t;
  u32 cti;

  if (table_index == ~0)
    return ~0;

  for (cti = table_index; cti != ~0; cti = t->next_table_index)
    {
      t = pool_elt_at_index (cm->tables, cti);

      /* Classifier geometry mismatch, can't use this table. */
      if (t->match_n_vectors != n_match || t->skip_n_vectors != n_skip)
	continue;

      /* Masks aren't congruent, can't use this table. */
      if (t->match_n_vectors * sizeof (u32x4) != vec_len (mask))
	continue;

      /* Masks aren't bit-for-bit identical, can't use this table. */
      if (memcmp (t->mask, mask, t->match_n_vectors * sizeof (u32x4)))
	continue;

      /* Winner... */
      return cti;
    }

  return ~0;
}


static clib_error_t *
classify_filter_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  u32 nbuckets = 8;
  vnet_main_t *vnm = vnet_get_main ();
  uword memory_size = (uword) (128 << 10);
  u32 skip = ~0;
  u32 match = ~0;
  u8 *match_vector;
  int is_add = 1;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 current_data_flag = 0;
  int current_data_offset = 0;
  u32 sw_if_index = ~0;
  int pkt_trace = 0;
  int pcap = 0;
  u8 *mask = 0;
  vnet_classify_main_t *cm = &vnet_classify_main;
  int rv = 0;
  clib_error_t *err = 0;

  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "pcap %=", &pcap, 1))
	sw_if_index = 0;
      else if (unformat (line_input, "trace"))
	pkt_trace = 1;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  if (sw_if_index == 0)
	    return clib_error_return (0, "Local interface not supported...");
	}
      else if (unformat (line_input, "buckets %d", &nbuckets))
	;
      else if (unformat (line_input, "mask %U", unformat_classify_mask,
			 &mask, &skip, &match))
	;
      else if (unformat (line_input, "memory-size %U", unformat_memory_size,
			 &memory_size))
	;
      else
	break;
    }

  if (is_add && mask == 0)
    err = clib_error_return (0, "Mask required");

  else if (is_add && skip == ~0)
    err = clib_error_return (0, "skip count required");

  else if (is_add && match == ~0)
    err = clib_error_return (0, "match count required");

  else if (sw_if_index == ~0 && pkt_trace == 0 && pcap == 0)
    err = clib_error_return (0, "Must specify trace, pcap or interface...");

  else if (pkt_trace && pcap)
    err = clib_error_return
      (0, "Packet trace and pcap are mutually exclusive...");

  else if (pkt_trace && sw_if_index != ~0)
    err = clib_error_return (0, "Packet trace filter is per-system");

  if (err)
    {
      unformat_free (line_input);
      return err;
    }

  if (!is_add)
    {
      /*
       * Delete an existing PCAP or trace classify table.
       */
      if (pkt_trace)
	classify_set_trace_chain (cm, ~0);
      else
	classify_set_pcap_chain (cm, sw_if_index, ~0);

      vec_free (mask);
      unformat_free (line_input);

      return 0;
    }

  /*
   * Find an existing compatible table or else make a new one.
   */
  if (pkt_trace)
    table_index = classify_get_trace_chain ();
  else
    table_index = classify_get_pcap_chain (cm, sw_if_index);

  if (table_index != ~0)
    {
      /*
       * look for a compatible table in the existing chain
       *  - if a compatible table is found, table_index is updated with it
       *  - if not, table_index is updated to ~0 (aka nil) and because of that
       *    we are going to create one (see below). We save the original head
       *    in next_table_index so we can chain it with the newly created
       *    table
       */
      next_table_index = table_index;
      table_index = classify_lookup_chain (table_index, mask, skip, match);
    }

  /*
   * When no table is found, make one.
   */
  if (table_index == ~0)
    {
      u32 new_head_index;

      /*
       * Matching table wasn't found, so create a new one at the
       * head of the next_table_index chain.
       */
      rv = vnet_classify_add_del_table (cm, mask, nbuckets, memory_size,
					skip, match, next_table_index,
					miss_next_index, &table_index,
					current_data_flag,
					current_data_offset, 1, 0);

      if (rv != 0)
	{
	  vec_free (mask);
	  unformat_free (line_input);
	  return clib_error_return (0,
				    "vnet_classify_add_del_table returned %d",
				    rv);
	}

      /*
       * Reorder tables such that masks are most-specify to least-specific.
       */
      new_head_index = classify_sort_table_chain (cm, table_index);

      /*
       * Put first classifier table in chain in a place where
       * other data structures expect to find and use it.
       */
      if (pkt_trace)
	classify_set_trace_chain (cm, new_head_index);
      else
	classify_set_pcap_chain (cm, sw_if_index, new_head_index);
    }

  vec_free (mask);

  /*
   * Now try to parse a and add a filter-match session.
   */
  if (unformat (line_input, "match %U", unformat_classify_match,
		cm, &match_vector, table_index) == 0)
    return 0;

  /*
   * We use hit or miss to determine whether to trace or pcap pkts
   * so the session setup is very limited
   */
  rv = vnet_classify_add_del_session (cm, table_index,
				      match_vector, 0 /* hit_next_index */ ,
				      0 /* opaque_index */ ,
				      0 /* advance */ ,
				      0 /* action */ ,
				      0 /* metadata */ ,
				      1 /* is_add */ );

  vec_free (match_vector);

  return 0;
}

/** Enable / disable packet trace filter */
int
vlib_enable_disable_pkt_trace_filter (int enable)
{
  if (enable)
    {
      vlib_global_main.trace_filter.trace_filter_enable = 1;
    }
  else
    {
      vlib_global_main.trace_filter.trace_filter_enable = 0;
    }
  return 0;
}

/*?
 * Construct an arbitrary set of packet classifier tables for use with
 * "pcap rx | tx trace," and with the vpp packet tracer
 *
 * Packets which match a rule in the classifier table chain
 * will be traced. The tables are automatically ordered so that
 * matches in the most specific table are tried first.
 *
 * It's reasonably likely that folks will configure a single
 * table with one or two matches. As a result, we configure
 * 8 hash buckets and 128K of match rule space. One can override
 * the defaults by specifying "buckets <nnn>" and "memory-size <xxx>"
 * as desired.
 *
 * To build up complex filter chains, repeatedly issue the
 * classify filter debug CLI command. Each command must specify the desired
 * mask and match values. If a classifier table with a suitable mask
 * already exists, the CLI command adds a match rule to the existing table.
 * If not, the CLI command add a new table and the indicated mask rule
 *
 * Here is a terse description of the "mask <xxx>" syntax:
 *
 * l2 src dst proto tag1 tag2 ignore-tag1 ignore-tag2 cos1 cos2 dot1q dot1ad
 *
 * l3 ip4 <ip4-mask> ip6 <ip6-mask>
 *
 * <ip4-mask> version hdr_length src[/width] dst[/width]
 *            tos length fragment_id ttl protocol checksum
 *
 * <ip6-mask> version traffic-class flow-label src dst proto
 *            payload_length hop_limit protocol
 *
 * l4 tcp <tcp-mask> udp <udp_mask> src_port dst_port
 *
 * <tcp-mask> src dst  # ports
 *
 * <udp-mask> src_port dst_port
 *
 * To construct matches, add the values to match after the indicated keywords:
 * in the match syntax. For example:
 * mask l3 ip4 src -> match l3 ip4 src 192.168.1.11
 *
 * @cliexpar
 * Configuring the classify filter
 *
 * Configure a simple classify filter, and configure pcap rx trace to use it:
 *
 * @cliexcmd{classify filter rx mask l3 ip4 src match l3 ip4 src 192.168.1.11}
 * <b><em>pcap rx trace on max 100 filter</em></b>
 *
 * Configure another fairly simple filter
 *
 * @cliexcmd{classify filter mask l3 ip4 src dst match l3 ip4 src 192.168.1.10
 * dst 192.168.2.10}
 *
 *
 * Configure a filter for use with the vpp packet tracer:
 * @cliexcmd{classify filter trace mask l3 ip4 src dst match l3 ip4 src
 * 192.168.1.10 dst 192.168.2.10}
 * <b><em>trace add dpdk-input 100 filter</em></b>
 *
 * Clear classifier filters
 *
 * <b><em>classify filter [trace | rx | tx  | <intfc>] del</em></b>
 *
 * To display the top-level classifier tables for each use case:
 * <b><em>show classify filter</em></b>
 *
 * To inspect the classifier tables, use
 *
 * <b><em>show classify table [verbose]</em></b>
 * The verbose form displays all of the match rules, with hit-counters
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (classify_filter, static) =
{
  .path = "classify filter",
  .short_help =
  "classify filter <intfc> | pcap mask <mask-value> match <match-value>\n"
  "  | trace mask <mask-value> match <match-value> [del]\n"
  "    [buckets <nn>] [memory-size <n>]",
  .function = classify_filter_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_classify_filter_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_main_t *vnm = vnet_get_main ();
  u8 *name = 0;
  u8 *s = 0;
  u32 table_index;
  int verbose = 0;
  int i, j, limit;

  (void) unformat (input, "verbose %=", &verbose, 1);

  vlib_cli_output (vm, "%-30s%s", "Filter Used By", " Table(s)");
  vlib_cli_output (vm, "%-30s%s", "--------------", " --------");

  limit = vec_len (cm->classify_table_index_by_sw_if_index);

  for (i = -1; i < limit; i++)
    {
      switch (i)
	{
	case -1:
	  table_index = vlib_global_main.trace_filter.classify_table_index;
	  name = format (0, "packet tracer:");
	  break;

	case 0:
	  table_index = cm->classify_table_index_by_sw_if_index[i];
	  name = format (0, "pcap rx/tx/drop:");
	  break;

	default:
	  table_index = cm->classify_table_index_by_sw_if_index[i];
	  name = format (0, "%U:", format_vnet_sw_if_index_name, vnm, i);
	  break;
	}

      if (verbose)
	{
	  vnet_classify_table_t *t;
	  j = table_index;
	  do
	    {
	      if (j == ~0)
		s = format (s, " none");
	      else
		{
		  s = format (s, " %u", j);
		  t = pool_elt_at_index (cm->tables, j);
		  j = t->next_table_index;
		}
	    }
	  while (j != ~0);

	  vlib_cli_output (vm, "%-30v table(s)%v", name, s);
	  vec_reset_length (s);
	}
      else
	{
	  if (table_index != ~0)
	    s = format (s, " %u", table_index);
	  else
	    s = format (s, " none");

	  vlib_cli_output (vm, "%-30v first table%v", name, s);
	  vec_reset_length (s);
	}
      vec_reset_length (name);
    }
  vec_free (s);
  vec_free (name);
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_classify_filter, static) =
{
  .path = "show classify filter",
  .short_help = "show classify filter [verbose [nn]]",
  .function = show_classify_filter_command_fn,
};
/* *INDENT-ON* */

u8 *
format_vnet_classify_table (u8 *s, va_list *args)
{
  vnet_classify_main_t *cm = va_arg (*args, vnet_classify_main_t *);
  int verbose = va_arg (*args, int);
  u32 index = va_arg (*args, u32);
  vnet_classify_table_t *t;

  if (index == ~0)
    {
      s = format (s, "\n%10s%10s%10s%10s", "TableIdx", "Sessions", "NextTbl",
		  "NextNode", verbose ? "Details" : "");
      return s;
    }

  t = pool_elt_at_index (cm->tables, index);
  s = format (s, "%10u%10d%10d%10d", index, t->active_elements,
	      t->next_table_index, t->miss_next_index);

  s = format (s, "\n  Heap: %U", format_clib_mem_heap, t->mheap,
	      0 /*verbose */ );

  s = format (s, "\n  nbuckets %d, skip %d match %d flag %d offset %d",
	      t->nbuckets, t->skip_n_vectors, t->match_n_vectors,
	      t->current_data_flag, t->current_data_offset);
  s = format (s, "\n  mask %U", format_hex_bytes, t->mask,
	      t->match_n_vectors * sizeof (u32x4));
  s = format (s, "\n  linear-search buckets %d\n", t->linear_buckets);

  if (verbose == 0)
    return s;

  s = format (s, "\n%U", format_classify_table, t, verbose);

  return s;
}

static clib_error_t *
show_classify_tables_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *t;
  u32 match_index = ~0;
  u32 *indices = 0;
  int verbose = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %d", &match_index))
	;
      else if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
    }

  /* *INDENT-OFF* */
  pool_foreach (t, cm->tables)
   {
    if (match_index == ~0 || (match_index == t - cm->tables))
      vec_add1 (indices, t - cm->tables);
  }
  /* *INDENT-ON* */

  if (vec_len (indices))
    {
      for (i = 0; i < vec_len (indices); i++)
	{
	  vlib_cli_output (vm, "%U", format_vnet_classify_table, cm, verbose,
			   ~0 /* hdr */);
	  vlib_cli_output (vm, "%U", format_vnet_classify_table, cm, verbose,
			   indices[i]);
	}
    }
  else
    vlib_cli_output (vm, "No classifier tables configured");

  vec_free (indices);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_classify_table_command, static) = {
  .path = "show classify tables",
  .short_help = "show classify tables [index <nn>]",
  .function = show_classify_tables_command_fn,
};
/* *INDENT-ON* */

uword
unformat_l4_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);

  u8 *proto_header = 0;
  int src_port = 0;
  int dst_port = 0;

  tcpudp_header_t h;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src_port %d", &src_port))
	;
      else if (unformat (input, "dst_port %d", &dst_port))
	;
      else
	break;
    }

  h.src_port = clib_host_to_net_u16 (src_port);
  h.dst_port = clib_host_to_net_u16 (dst_port);
  vec_validate (proto_header, sizeof (h) - 1);
  memcpy (proto_header, &h, sizeof (h));

  *matchp = proto_header;

  return 1;
}

uword
unformat_ip4_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u8 *match = 0;
  ip4_header_t *ip;
  int version = 0;
  u32 version_val;
  int hdr_length = 0;
  u32 hdr_length_val;
  int src = 0, dst = 0;
  ip4_address_t src_val, dst_val;
  int proto = 0;
  u32 proto_val;
  int tos = 0;
  u32 tos_val;
  int length = 0;
  u32 length_val;
  int fragment_id = 0;
  u32 fragment_id_val;
  int ttl = 0;
  int ttl_val;
  int checksum = 0;
  u32 checksum_val;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version %d", &version_val))
	version = 1;
      else if (unformat (input, "hdr_length %d", &hdr_length_val))
	hdr_length = 1;
      else if (unformat (input, "src %U", unformat_ip4_address, &src_val))
	src = 1;
      else if (unformat (input, "dst %U", unformat_ip4_address, &dst_val))
	dst = 1;
      else if (unformat (input, "proto %d", &proto_val))
	proto = 1;
      else if (unformat (input, "tos %d", &tos_val))
	tos = 1;
      else if (unformat (input, "length %d", &length_val))
	length = 1;
      else if (unformat (input, "fragment_id %d", &fragment_id_val))
	fragment_id = 1;
      else if (unformat (input, "ttl %d", &ttl_val))
	ttl = 1;
      else if (unformat (input, "checksum %d", &checksum_val))
	checksum = 1;
      else
	break;
    }

  if (version + hdr_length + src + dst + proto + tos + length + fragment_id
      + ttl + checksum == 0)
    return 0;

  /*
   * Aligned because we use the real comparison functions
   */
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof (u32x4));

  ip = (ip4_header_t *) match;

  /* These are realistically matched in practice */
  if (src)
    ip->src_address.as_u32 = src_val.as_u32;

  if (dst)
    ip->dst_address.as_u32 = dst_val.as_u32;

  if (proto)
    ip->protocol = proto_val;


  /* These are not, but they're included for completeness */
  if (version)
    ip->ip_version_and_header_length |= (version_val & 0xF) << 4;

  if (hdr_length)
    ip->ip_version_and_header_length |= (hdr_length_val & 0xF);

  if (tos)
    ip->tos = tos_val;

  if (length)
    ip->length = clib_host_to_net_u16 (length_val);

  if (ttl)
    ip->ttl = ttl_val;

  if (checksum)
    ip->checksum = clib_host_to_net_u16 (checksum_val);

  *matchp = match;
  return 1;
}

uword
unformat_ip6_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u8 *match = 0;
  ip6_header_t *ip;
  int version = 0;
  u32 version_val;
  u8 traffic_class = 0;
  u32 traffic_class_val;
  u8 flow_label = 0;
  u8 flow_label_val;
  int src = 0, dst = 0;
  ip6_address_t src_val, dst_val;
  int proto = 0;
  u32 proto_val;
  int payload_length = 0;
  u32 payload_length_val;
  int hop_limit = 0;
  int hop_limit_val;
  u32 ip_version_traffic_class_and_flow_label;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version %d", &version_val))
	version = 1;
      else if (unformat (input, "traffic_class %d", &traffic_class_val))
	traffic_class = 1;
      else if (unformat (input, "flow_label %d", &flow_label_val))
	flow_label = 1;
      else if (unformat (input, "src %U", unformat_ip6_address, &src_val))
	src = 1;
      else if (unformat (input, "dst %U", unformat_ip6_address, &dst_val))
	dst = 1;
      else if (unformat (input, "proto %d", &proto_val))
	proto = 1;
      else if (unformat (input, "payload_length %d", &payload_length_val))
	payload_length = 1;
      else if (unformat (input, "hop_limit %d", &hop_limit_val))
	hop_limit = 1;
      else
	break;
    }

  if (version + traffic_class + flow_label + src + dst + proto +
      payload_length + hop_limit == 0)
    return 0;

  /*
   * Aligned because we use the real comparison functions
   */
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof (u32x4));

  ip = (ip6_header_t *) match;

  if (src)
    clib_memcpy_fast (&ip->src_address, &src_val, sizeof (ip->src_address));

  if (dst)
    clib_memcpy_fast (&ip->dst_address, &dst_val, sizeof (ip->dst_address));

  if (proto)
    ip->protocol = proto_val;

  ip_version_traffic_class_and_flow_label = 0;

  if (version)
    ip_version_traffic_class_and_flow_label |= (version_val & 0xF) << 28;

  if (traffic_class)
    ip_version_traffic_class_and_flow_label |=
      (traffic_class_val & 0xFF) << 20;

  if (flow_label)
    ip_version_traffic_class_and_flow_label |= (flow_label_val & 0xFFFFF);

  ip->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (ip_version_traffic_class_and_flow_label);

  if (payload_length)
    ip->payload_length = clib_host_to_net_u16 (payload_length_val);

  if (hop_limit)
    ip->hop_limit = hop_limit_val;

  *matchp = match;
  return 1;
}

uword
unformat_l3_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4 %U", unformat_ip4_match, matchp))
	return 1;
      else if (unformat (input, "ip6 %U", unformat_ip6_match, matchp))
	return 1;
      /* $$$$ add mpls */
      else
	break;
    }
  return 0;
}

uword
unformat_vlan_tag (unformat_input_t * input, va_list * args)
{
  u8 *tagp = va_arg (*args, u8 *);
  u32 tag;

  if (unformat (input, "%d", &tag))
    {
      tagp[0] = (tag >> 8) & 0x0F;
      tagp[1] = tag & 0xFF;
      return 1;
    }

  return 0;
}

uword
unformat_l2_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u8 *match = 0;
  u8 src = 0;
  u8 src_val[6];
  u8 dst = 0;
  u8 dst_val[6];
  u8 proto = 0;
  u16 proto_val;
  u8 tag1 = 0;
  u8 tag1_val[2];
  u8 tag2 = 0;
  u8 tag2_val[2];
  int len = 14;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u32 cos1_val = 0;
  u32 cos2_val = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_ethernet_address, &src_val))
	src = 1;
      else
	if (unformat (input, "dst %U", unformat_ethernet_address, &dst_val))
	dst = 1;
      else if (unformat (input, "proto %U",
			 unformat_ethernet_type_host_byte_order, &proto_val))
	proto = 1;
      else if (unformat (input, "tag1 %U", unformat_vlan_tag, tag1_val))
	tag1 = 1;
      else if (unformat (input, "tag2 %U", unformat_vlan_tag, tag2_val))
	tag2 = 1;
      else if (unformat (input, "ignore-tag1"))
	ignore_tag1 = 1;
      else if (unformat (input, "ignore-tag2"))
	ignore_tag2 = 1;
      else if (unformat (input, "cos1 %d", &cos1_val))
	cos1 = 1;
      else if (unformat (input, "cos2 %d", &cos2_val))
	cos2 = 1;
      else
	break;
    }
  if ((src + dst + proto + tag1 + tag2 +
       ignore_tag1 + ignore_tag2 + cos1 + cos2) == 0)
    return 0;

  if (tag1 || ignore_tag1 || cos1)
    len = 18;
  if (tag2 || ignore_tag2 || cos2)
    len = 22;

  vec_validate_aligned (match, len - 1, sizeof (u32x4));

  if (dst)
    clib_memcpy_fast (match, dst_val, 6);

  if (src)
    clib_memcpy_fast (match + 6, src_val, 6);

  if (tag2)
    {
      /* inner vlan tag */
      match[19] = tag2_val[1];
      match[18] = tag2_val[0];
      if (cos2)
	match[18] |= (cos2_val & 0x7) << 5;
      if (proto)
	{
	  match[21] = proto_val & 0xff;
	  match[20] = proto_val >> 8;
	}
      if (tag1)
	{
	  match[15] = tag1_val[1];
	  match[14] = tag1_val[0];
	}
      if (cos1)
	match[14] |= (cos1_val & 0x7) << 5;
      *matchp = match;
      return 1;
    }
  if (tag1)
    {
      match[15] = tag1_val[1];
      match[14] = tag1_val[0];
      if (proto)
	{
	  match[17] = proto_val & 0xff;
	  match[16] = proto_val >> 8;
	}
      if (cos1)
	match[14] |= (cos1_val & 0x7) << 5;

      *matchp = match;
      return 1;
    }
  if (cos2)
    match[18] |= (cos2_val & 0x7) << 5;
  if (cos1)
    match[14] |= (cos1_val & 0x7) << 5;
  if (proto)
    {
      match[13] = proto_val & 0xff;
      match[12] = proto_val >> 8;
    }

  *matchp = match;
  return 1;
}


uword
unformat_classify_match (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = va_arg (*args, vnet_classify_main_t *);
  u8 **matchp = va_arg (*args, u8 **);
  u32 table_index = va_arg (*args, u32);
  vnet_classify_table_t *t;

  u8 *match = 0;
  u8 *l2 = 0;
  u8 *l3 = 0;
  u8 *l4 = 0;

  if (pool_is_free_index (cm->tables, table_index))
    return 0;

  t = pool_elt_at_index (cm->tables, table_index);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hex %U", unformat_hex_string, &match))
	;
      else if (unformat (input, "l2 %U", unformat_l2_match, &l2))
	;
      else if (unformat (input, "l3 %U", unformat_l3_match, &l3))
	;
      else if (unformat (input, "l4 %U", unformat_l4_match, &l4))
	;
      else
	break;
    }

  if (l4 && !l3)
    {
      vec_free (match);
      vec_free (l2);
      vec_free (l4);
      return 0;
    }

  if (match || l2 || l3 || l4)
    {
      if (l2 || l3 || l4)
	{
	  /* "Win a free Ethernet header in every packet" */
	  if (l2 == 0)
	    vec_validate_aligned (l2, 13, sizeof (u32x4));
	  match = l2;
	  if (l3)
	    {
	      vec_append_aligned (match, l3, sizeof (u32x4));
	      vec_free (l3);
	    }
	  if (l4)
	    {
	      vec_append_aligned (match, l4, sizeof (u32x4));
	      vec_free (l4);
	    }
	}

      /* Make sure the vector is big enough even if key is all 0's */
      vec_validate_aligned
	(match,
	 ((t->match_n_vectors + t->skip_n_vectors) * sizeof (u32x4)) - 1,
	 sizeof (u32x4));

      /* Set size, include skipped vectors */
      _vec_len (match) =
	(t->match_n_vectors + t->skip_n_vectors) * sizeof (u32x4);

      *matchp = match;

      return 1;
    }

  return 0;
}

int
vnet_classify_add_del_session (vnet_classify_main_t *cm, u32 table_index,
			       const u8 *match, u32 hit_next_index,
			       u32 opaque_index, i32 advance, u8 action,
			       u16 metadata, int is_add)
{
  vnet_classify_table_t *t;
  vnet_classify_entry_5_t _max_e __attribute__ ((aligned (16)));
  vnet_classify_entry_t *e;
  int i, rv;

  if (pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_TABLE;

  t = pool_elt_at_index (cm->tables, table_index);

  e = (vnet_classify_entry_t *) & _max_e;
  e->next_index = hit_next_index;
  e->opaque_index = opaque_index;
  e->advance = advance;
  e->hits = 0;
  e->last_heard = 0;
  e->flags = 0;
  e->action = action;
  if (e->action == CLASSIFY_ACTION_SET_IP4_FIB_INDEX)
    e->metadata = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
						     metadata,
						     FIB_SOURCE_CLASSIFY);
  else if (e->action == CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
    e->metadata = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6,
						     metadata,
						     FIB_SOURCE_CLASSIFY);
  else if (e->action == CLASSIFY_ACTION_SET_METADATA)
    e->metadata = metadata;
  else
    e->metadata = 0;

  /* Copy key data, honoring skip_n_vectors */
  clib_memcpy_fast (&e->key, match + t->skip_n_vectors * sizeof (u32x4),
		    t->match_n_vectors * sizeof (u32x4));

  /* Clear don't-care bits; likely when dynamically creating sessions */
  for (i = 0; i < t->match_n_vectors; i++)
    e->key[i] &= t->mask[i];

  rv = vnet_classify_add_del (t, e, is_add);

  vnet_classify_entry_release_resource (e);

  if (rv)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  return 0;
}

static clib_error_t *
classify_session_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  int is_add = 1;
  u32 table_index = ~0;
  u32 hit_next_index = ~0;
  u64 opaque_index = ~0;
  u8 *match = 0;
  i32 advance = 0;
  u32 action = 0;
  u32 metadata = 0;
  int i, rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "hit-next %U", unformat_ip_next_index,
			 &hit_next_index))
	;
      else
	if (unformat
	    (input, "l2-input-hit-next %U", unformat_l2_input_next_index,
	     &hit_next_index))
	;
      else
	if (unformat
	    (input, "l2-output-hit-next %U", unformat_l2_output_next_index,
	     &hit_next_index))
	;
      else if (unformat (input, "acl-hit-next %U", unformat_acl_next_index,
			 &hit_next_index))
	;
      else if (unformat (input, "policer-hit-next %U",
			 unformat_policer_next_index, &hit_next_index))
	;
      else if (unformat (input, "opaque-index %lld", &opaque_index))
	;
      else if (unformat (input, "match %U", unformat_classify_match,
			 cm, &match, table_index))
	;
      else if (unformat (input, "advance %d", &advance))
	;
      else if (unformat (input, "table-index %d", &table_index))
	;
      else if (unformat (input, "action set-ip4-fib-id %d", &metadata))
	action = 1;
      else if (unformat (input, "action set-ip6-fib-id %d", &metadata))
	action = 2;
      else if (unformat (input, "action set-sr-policy-index %d", &metadata))
	action = 3;
      else
	{
	  /* Try registered opaque-index unformat fns */
	  for (i = 0; i < vec_len (cm->unformat_opaque_index_fns); i++)
	    {
	      if (unformat (input, "%U", cm->unformat_opaque_index_fns[i],
			    &opaque_index))
		goto found_opaque;
	    }
	  break;
	}
    found_opaque:
      ;
    }

  if (table_index == ~0)
    return clib_error_return (0, "Table index required");

  if (is_add && match == 0)
    return clib_error_return (0, "Match value required");

  rv = vnet_classify_add_del_session (cm, table_index, match,
				      hit_next_index,
				      opaque_index, advance,
				      action, metadata, is_add);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0,
				"vnet_classify_add_del_session returned %d",
				rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (classify_session_command, static) = {
    .path = "classify session",
    .short_help =
    "classify session [hit-next|l2-input-hit-next|l2-output-hit-next|"
    "acl-hit-next <next_index>|policer-hit-next <policer_name>]"
    "\n table-index <nn> match [hex] [l2] [l3 ip4] [opaque-index <index>]"
    "\n [action set-ip4-fib-id|set-ip6-fib-id|set-sr-policy-index <n>] [del]",
    .function = classify_session_command_fn,
};
/* *INDENT-ON* */

static uword
unformat_opaque_sw_if_index (unformat_input_t * input, va_list * args)
{
  u64 *opaquep = va_arg (*args, u64 *);
  u32 sw_if_index;

  if (unformat (input, "opaque-sw_if_index %U", unformat_vnet_sw_interface,
		vnet_get_main (), &sw_if_index))
    {
      *opaquep = sw_if_index;
      return 1;
    }
  return 0;
}

static uword
unformat_ip_next_node (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index = ~0;

  if (unformat (input, "ip6-node %U", unformat_vlib_node,
		cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next (cm->vlib_main,
				       ip6_classify_node.index, node_index);
    }
  else if (unformat (input, "ip4-node %U", unformat_vlib_node,
		     cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next (cm->vlib_main,
				       ip4_classify_node.index, node_index);
    }
  else
    return 0;

  *next_indexp = next_index;
  return 1;
}

static uword
unformat_acl_next_node (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index;

  if (unformat (input, "ip6-node %U", unformat_vlib_node,
		cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next (cm->vlib_main,
				       ip6_inacl_node.index, node_index);
    }
  else if (unformat (input, "ip4-node %U", unformat_vlib_node,
		     cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next (cm->vlib_main,
				       ip4_inacl_node.index, node_index);
    }
  else
    return 0;

  *next_indexp = next_index;
  return 1;
}

static uword
unformat_l2_input_next_node (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index;

  if (unformat (input, "input-node %U", unformat_vlib_node,
		cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next
	(cm->vlib_main, l2_input_classify_node.index, node_index);

      *next_indexp = next_index;
      return 1;
    }
  return 0;
}

static uword
unformat_l2_output_next_node (unformat_input_t * input, va_list * args)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 *next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index;

  if (unformat (input, "output-node %U", unformat_vlib_node,
		cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next
	(cm->vlib_main, l2_output_classify_node.index, node_index);

      *next_indexp = next_index;
      return 1;
    }
  return 0;
}

static clib_error_t *
vnet_classify_init (vlib_main_t * vm)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();

  vnet_classify_register_unformat_opaque_index_fn
    (unformat_opaque_sw_if_index);

  vnet_classify_register_unformat_ip_next_index_fn (unformat_ip_next_node);

  vnet_classify_register_unformat_l2_next_index_fn
    (unformat_l2_input_next_node);

  vnet_classify_register_unformat_l2_next_index_fn
    (unformat_l2_output_next_node);

  vnet_classify_register_unformat_acl_next_index_fn (unformat_acl_next_node);

  vlib_global_main.trace_filter.classify_table_index = ~0;

  return 0;
}

VLIB_INIT_FUNCTION (vnet_classify_init);

int
vnet_is_packet_traced (vlib_buffer_t * b, u32 classify_table_index, int func)
{
  return vnet_is_packet_traced_inline (b, classify_table_index, func);
}


#define TEST_CODE 0

#if TEST_CODE > 0

typedef struct
{
  ip4_address_t addr;
  int in_table;
} test_entry_t;

typedef struct
{
  test_entry_t *entries;

  /* test parameters */
  u32 buckets;
  u32 sessions;
  u32 iterations;
  u32 memory_size;
  ip4_address_t src;
  vnet_classify_table_t *table;
  u32 table_index;
  int verbose;

  /* Random seed */
  u32 seed;

  /* Test data */
  classify_data_or_mask_t *mask;
  classify_data_or_mask_t *data;

  /* convenience */
  vnet_classify_main_t *classify_main;
  vlib_main_t *vlib_main;

} test_classify_main_t;

static test_classify_main_t test_classify_main;

static clib_error_t *
test_classify_churn (test_classify_main_t * tm)
{
  classify_data_or_mask_t *mask, *data;
  vlib_main_t *vm = tm->vlib_main;
  test_entry_t *ep;
  u8 *mp = 0, *dp = 0;
  u32 tmp;
  int i, rv;

  vec_validate_aligned (mp, 3 * sizeof (u32x4), sizeof (u32x4));
  vec_validate_aligned (dp, 3 * sizeof (u32x4), sizeof (u32x4));

  mask = (classify_data_or_mask_t *) mp;
  data = (classify_data_or_mask_t *) dp;

  /* Mask on src address */
  clib_memset (&mask->ip.src_address, 0xff, 4);

  tmp = clib_host_to_net_u32 (tm->src.as_u32);

  for (i = 0; i < tm->sessions; i++)
    {
      vec_add2 (tm->entries, ep, 1);
      ep->addr.as_u32 = clib_host_to_net_u32 (tmp);
      ep->in_table = 0;
      tmp++;
    }

  tm->table = vnet_classify_new_table (tm->classify_main,
				       (u8 *) mask,
				       tm->buckets,
				       tm->memory_size, 0 /* skip */ ,
				       3 /* vectors to match */ );
  tm->table->miss_next_index = IP_LOOKUP_NEXT_DROP;
  tm->table_index = tm->table - tm->classify_main->tables;
  vlib_cli_output (vm, "Created table %d, buckets %d",
		   tm->table_index, tm->buckets);

  vlib_cli_output (vm, "Initialize: add %d (approx. half of %d sessions)...",
		   tm->sessions / 2, tm->sessions);

  for (i = 0; i < tm->sessions / 2; i++)
    {
      ep = vec_elt_at_index (tm->entries, i);

      data->ip.src_address.as_u32 = ep->addr.as_u32;
      ep->in_table = 1;

      rv = vnet_classify_add_del_session (tm->classify_main,
					  tm->table_index,
					  (u8 *) data,
					  IP_LOOKUP_NEXT_DROP,
					  i /* opaque_index */ ,
					  0 /* advance */ ,
					  0 /* action */ ,
					  0 /* metadata */ ,
					  1 /* is_add */ );

      if (rv != 0)
	clib_warning ("add: returned %d", rv);

      if (tm->verbose)
	vlib_cli_output (vm, "add: %U", format_ip4_address, &ep->addr.as_u32);
    }

  vlib_cli_output (vm, "Execute %d random add/delete operations",
		   tm->iterations);

  for (i = 0; i < tm->iterations; i++)
    {
      int index, is_add;

      /* Pick a random entry */
      index = random_u32 (&tm->seed) % tm->sessions;

      ep = vec_elt_at_index (tm->entries, index);

      data->ip.src_address.as_u32 = ep->addr.as_u32;

      /* If it's in the table, remove it. Else, add it */
      is_add = !ep->in_table;

      if (tm->verbose)
	vlib_cli_output (vm, "%s: %U",
			 is_add ? "add" : "del",
			 format_ip4_address, &ep->addr.as_u32);

      rv = vnet_classify_add_del_session (tm->classify_main,
					  tm->table_index,
					  (u8 *) data,
					  IP_LOOKUP_NEXT_DROP,
					  i /* opaque_index */ ,
					  0 /* advance */ ,
					  0 /* action */ ,
					  0 /* metadata */ ,
					  is_add);
      if (rv != 0)
	vlib_cli_output (vm,
			 "%s[%d]: %U returned %d", is_add ? "add" : "del",
			 index, format_ip4_address, &ep->addr.as_u32, rv);
      else
	ep->in_table = is_add;
    }

  vlib_cli_output (vm, "Remove remaining %d entries from the table",
		   tm->table->active_elements);

  for (i = 0; i < tm->sessions; i++)
    {
      u8 *key_minus_skip;
      u64 hash;
      vnet_classify_entry_t *e;

      ep = tm->entries + i;
      if (ep->in_table == 0)
	continue;

      data->ip.src_address.as_u32 = ep->addr.as_u32;

      hash = vnet_classify_hash_packet (tm->table, (u8 *) data);

      e = vnet_classify_find_entry (tm->table,
				    (u8 *) data, hash, 0 /* time_now */ );
      if (e == 0)
	{
	  clib_warning ("Couldn't find %U index %d which should be present",
			format_ip4_address, ep->addr, i);
	  continue;
	}

      key_minus_skip = (u8 *) e->key;
      key_minus_skip -= tm->table->skip_n_vectors * sizeof (u32x4);

      rv = vnet_classify_add_del_session
	(tm->classify_main,
	 tm->table_index,
	 key_minus_skip, IP_LOOKUP_NEXT_DROP, i /* opaque_index */ ,
	 0 /* advance */ , 0, 0,
	 0 /* is_add */ );

      if (rv != 0)
	clib_warning ("del: returned %d", rv);

      if (tm->verbose)
	vlib_cli_output (vm, "del: %U", format_ip4_address, &ep->addr.as_u32);
    }

  vlib_cli_output (vm, "%d entries remain, MUST be zero",
		   tm->table->active_elements);

  vlib_cli_output (vm, "Table after cleanup: \n%U\n",
		   format_classify_table, tm->table, 0 /* verbose */ );

  vec_free (mp);
  vec_free (dp);

  vnet_classify_delete_table_index (tm->classify_main,
				    tm->table_index, 1 /* del_chain */ );
  tm->table = 0;
  tm->table_index = ~0;
  vec_free (tm->entries);

  return 0;
}

static clib_error_t *
test_classify_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  test_classify_main_t *tm = &test_classify_main;
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 tmp;
  int which = 0;
  clib_error_t *error = 0;

  tm->buckets = 1024;
  tm->sessions = 8192;
  tm->iterations = 8192;
  tm->memory_size = 64 << 20;
  tm->src.as_u32 = clib_net_to_host_u32 (0x0100000A);
  tm->table = 0;
  tm->seed = 0xDEADDABE;
  tm->classify_main = cm;
  tm->vlib_main = vm;
  tm->verbose = 0;

  /* Default starting address 1.0.0.10 */

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sessions %d", &tmp))
	tm->sessions = tmp;
      else
	if (unformat (input, "src %U", unformat_ip4_address, &tm->src.as_u32))
	;
      else if (unformat (input, "buckets %d", &tm->buckets))
	;
      else if (unformat (input, "memory-size %uM", &tmp))
	tm->memory_size = tmp << 20;
      else if (unformat (input, "memory-size %uG", &tmp))
	tm->memory_size = tmp << 30;
      else if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "verbose"))
	tm->verbose = 1;

      else if (unformat (input, "iterations %d", &tm->iterations))
	;
      else if (unformat (input, "churn-test"))
	which = 0;
      else
	break;
    }

  switch (which)
    {
    case 0:
      error = test_classify_churn (tm);
      break;
    default:
      error = clib_error_return (0, "No such test");
      break;
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_classify_command, static) = {
    .path = "test classify",
    .short_help =
    "test classify [src <ip>] [sessions <nn>] [buckets <nn>] [seed <nnn>]\n"
    "              [memory-size <nn>[M|G]]\n"
    "              [churn-test]",
    .function = test_classify_command_fn,
};
/* *INDENT-ON* */
#endif /* TEST_CODE */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
 * Author: Pierre Pfister <ppfister@cisco.com>
 *
 * DISCLAIMER !
 *
 *       This most likely is not the hash table you are looking for !!
 *
 *       This structure targets a very specific and quite narrow set of use-cases 
 *         that are not covered by other hash tables.
 *
 *       Read the following text carefully, or ask the author or one of VPP's
 *         committers to make sure this is what you are looking for.
 *
 *
 *  -- Abstract:
 * This hash table intends to provide a very fast lookup and insertion of
 * key-value pairs for flow tables (although it might be used for other
 * purposes), with additional support for lazy-timeouts.
 * In particular, it was designed to minimize blocking reads, register usage and
 * cache-lines accesses during a typical lookup.
 * This hash table therefore provides stateful packet processing
 * without performance degradation even when every single lookup has to fetch
 * memory from RAM.
 * This hash table is not thread-safe and requires executing a garbage
 * collection function to clean-up chained buckets.
 *
 *  -- Overview:
 *
 * One first aspect of this hash table is that it is self-contained in a single
 * bulk of memory. Each entry contains a key, a value, and a 32 bits timeout
 * value; occupies a full and single cache line; and is identified by a unique
 * 32 bits index. The entry index zero is reserved and used when an entry
 * could not be found nor inserted. Which means it is not necessary to
 * immediately check whether an insertion or lookup was successful before
 * behaving accordingly. One can just keep doing business as usual and
 * check for the error later.
 *
 * Each entry is associated with a timeout value (which unit or clock is up to
 * the user of the hash table). An entry which timeout is strictly smaller
 * than the current time is considered empty, whereas an entry which timeout is
 * greater or equal to the current time contains a valid key-value pair.
 *
 * Hash table lookup and insertion are equivalent:
 *  - An entry index is always returned (possibly index 0 if no entry could be
 *   found nor created).
 *  - The returned entry always has its key set to the provided key.
 *  - Timeout value will be greater than the provided current time whenever a
 *    valid entry was found, strictly smaller otherwise. In particular, one can
 *    not differentiate between an entry which was just created, and an entry
 *    which already existed in the past but got timeouted in between.
 *
 * As mentioned earlier, entry index zero is used as an invalid entry which may
 * be manipulated as a normal one. Entries which index go from 1 to
 * N (where N is a power of 2) are used as direct buckets, each containing a
 * single entry. In the absence of hash collision, a single entry which location
 * can deterministically be determined from the key-hash and the hash table
 * header is accessed (One single cache line, without indirection). This
 * allows for efficient pre-fetching of the key-value for more than 95% of
 * accesses.
 *
 * In order to handle hash collisions (i.e. when multiple keys
 * end-up in the same bucket), entries which index are greater than N are
 * grouped into M groups of 16 collision entries. Such groups are linked
 * with regular entries whenever a collision needs to be handled.
 * When looking up a key with a bucket where a collision occurred, unused bits
 * from the key hash are used to select two entries (from the collision bucket)
 * where the new entry might be inserted.
 *
 * Once an entry is inserted, it will never be moved as long as the entry
 * timeout value remains greater or equal to the provided current time value.
 * The entry index can therefore be stored in other data structure as a way
 * to bypass the hash lookup. But when doing so, one should check if the
 * present key is the actual looked-up key.
 *
 *  -- Garbage Collection:
 *
 *  Since there is no explicit element removal, a garbage collector mechanism
 *  is required in order to remove buckets used for hash collisions. This
 *  is done by calling the flowhash_gc function on a regular basis. Each call
 *  to this function examines a single fixed entry. It shall therefore be called
 *  as many times as there are fixed entries in the hash table in order to
 *  ensure a full inspection.
 *
 *  -- Time and timeout mechanism:
 *
 *  The hash table makes use of a time value between in [1, 2^32 - 1].
 *  The provided time value shall keep increasing, and looping is not handled.
 *  When seconds are used, the system should run for 136 years without any issue.
 *  If milliseconds are used, a shift should be operated on all timeout values
 *  on a regular basis (more than every 49 days).
 */

#ifndef __included_flowhash_template_h__
#define __included_flowhash_template_h__

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/cache.h>

#ifndef FLOWHASH_TYPE
#error FLOWHASH_TYPE not defined
#endif

#define _fv(a,b) a##b
#define __fv(a,b) _fv(a,b)
#define FV(a) __fv(a,FLOWHASH_TYPE)

#define _fvt(a,b) a##b##_t
#define __fvt(a,b) _fvt(a,b)
#define FVT(a) __fvt(a,FLOWHASH_TYPE)

/* Same for all flowhash variants */
#ifndef __included_flowhash_common__

#define FLOWHASH_INVALID_ENTRY_INDEX 0

#define FLOWHASH_ENTRIES_PER_BUCKETS_LOG 4
#define FLOWHASH_ENTRIES_PER_BUCKETS (1 << FLOWHASH_ENTRIES_PER_BUCKETS_LOG)

#endif /* ifndef __included_flowhash_common__ */

 /**
  * @brief Compare a stored key with a lookup key.
  *
  * This function must be defined to use this template. It must return 0
  * when the two keys are identical, and a different value otherwise.
  */
static_always_inline
u8 FV(flowhash_cmp_key)(FVT(flowhash_skey) *a, FVT(flowhash_lkey) *b);

 /**
  * @brief Hash a lookup key into a 32 bit integer.
  *
  * This function must be defined to use this template.
  * It must provides close to 32 bits of entropy distributed amongst
  * all 32 bits of the provided value.
  * Keys that are equal must have the same hash.
  */
 static_always_inline
 u32 FV(flowhash_hash)(FVT(flowhash_lkey) *k);

/**
 * @brief Copy a lookup key into a destination stored key.
 *
 * This function must be defined to use this template. It must modify the dst
 * key such that a later call to flowhash_cmp_key with the same arguments
 * would return 0.
 */
static_always_inline
void FV(flowhash_cpy_key)(FVT(flowhash_skey) *dst, FVT(flowhash_lkey) *src);

/**
 * @brief One flow hash entry used for both direct buckets and collision
 *        buckets.
 */
typedef struct {
  /* Each entry is cache-line aligned. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Key is first to take advantage of alignment. */
  FVT(flowhash_skey) key;

  /* Entry value. */
  FVT(flowhash_value) value;

  /* Timeout value */
  u32 timeout;

  /* Entry index to the chained bucket. */
  u32 chained_entry_index;
} FVT(flowhash_entry);

typedef struct FVT(__flowhash_struct) {
  /* Cache aligned to simplify allocation. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Array going downward containing free bucket indices */
  u32 free_buckets_indices[0];

  /* Negative index of the first free bucket */
  i32 free_buckets_position;

  /* Number of fixed buckets minus one */
  u32 fixed_entries_mask;

  /* Allocated pointer for this hash table */
  void *mem;

  u32 collision_buckets_mask;
  u32 total_entries;

  u64 not_enough_buckets_counter;
  u64 collision_lookup_counter;
  u64 garbage_collection_counter;

  u32 gc_counter;

  /* Entry array containing:
   * - 1 Dummy entry for error return
   * - (buckets_mask + 1) Fixed buckets
   * - chained_buckets Chained Buckets
   */
  FVT(flowhash_entry) entries[0];
} FVT(flowhash);

/* Same for all flowhash variants */
#ifndef __included_flowhash_common__
#define __included_flowhash_common__

/**
 * @brief Test whether a returned entry index corresponds to an overflow event.
 */
#define flowhash_is_overflow(ei) \
    ((ei) == FLOWHASH_INVALID_ENTRY_INDEX)

/**
 * @brief Iterate over all entries in the hash table.
 *
 * Iterate over all entries in the hash table, not including the first invalid
 * entry (at index 0), but including all chained hash collision buckets.
 *
 */
#define flowhash_foreach_entry(h, ei) \
      for (ei = 1; \
           ei < (h)->total_entries; \
           ei++)

/**
 * @brief Iterate over all currently valid entries.
 *
 * Iterate over all entries in the hash table which timeout value is greater
 * or equal to the current time.
 */
#define flowhash_foreach_valid_entry(h, ei, now) \
    flowhash_foreach_entry(h, ei) \
      if (((now) <= (h)->entries[ei].timeout))

/**
 * @brief Timeout variable from a given entry.
 */
#define flowhash_timeout(h, ei) (h)->entries[ei].timeout

/**
 * @brief Indicates whether the entry is being used.
 */
#define flowhash_is_timeouted(h, ei, time_now) \
    ((time_now) > flowhash_timeout(h, ei))

/**
 * @brief Get the key from the entry index, casted to the provided type.
 */
#define flowhash_key(h, ei) (&(h)->entries[ei].key)

/**
 * @brief Get the value from the entry index, casted to the provided type.
 */
#define flowhash_value(h, ei) (&(h)->entries[ei].value)

/**
 * @brief Get the number of octets allocated to this structure.
 */
#define flowhash_memory_size(h) clib_mem_size((h)->mem)

/**
 * @brief Test whether the entry index is in hash table boundaries.
 */
#define flowhash_is_valid_entry_index(h, ei) (ei < (h)->total_entries)

/**
 * @brief Adjust, if necessary, provided parameters such as being valid flowhash
 *        sizes.
 */
static
void flowhash_validate_sizes(u32 *fixed_entries, u32 *collision_buckets)
{
  /* Find power of two greater or equal to the provided value */
  if (*fixed_entries < FLOWHASH_ENTRIES_PER_BUCKETS)
    *fixed_entries = FLOWHASH_ENTRIES_PER_BUCKETS;
  if (*fixed_entries > (1 << (32 - FLOWHASH_ENTRIES_PER_BUCKETS_LOG)))
    *fixed_entries = (1 << (32 - FLOWHASH_ENTRIES_PER_BUCKETS_LOG));

  *fixed_entries -= 1;
  *fixed_entries |= *fixed_entries >> 16;
  *fixed_entries |= *fixed_entries >> 8;
  *fixed_entries |= *fixed_entries >> 4;
  *fixed_entries |= *fixed_entries >> 2;
  *fixed_entries |= *fixed_entries >> 1;
  *fixed_entries += 1;

  if (*collision_buckets != 0)
    {
      if (*collision_buckets < CLIB_CACHE_LINE_BYTES/sizeof(u32))
        *collision_buckets = CLIB_CACHE_LINE_BYTES/sizeof(u32);

      *collision_buckets -= 1;
      *collision_buckets |= *collision_buckets >> 16;
      *collision_buckets |= *collision_buckets >> 8;
      *collision_buckets |= *collision_buckets >> 4;
      *collision_buckets |= *collision_buckets >> 2;
      *collision_buckets |= *collision_buckets >> 1;
      *collision_buckets += 1;
    }
}

/**
 * @brief Prefetch the the hash entry bucket.
 *
 * This should be performed approximately 200-300 cycles before lookup
 * if the table is located in RAM. Or 30-40 cycles before lookup
 * in case the table is located in L3.
 */
#define flowhash_prefetch(h, hash) \
    CLIB_PREFETCH (&(h)->entries[((hash) & (h)->fixed_entries_mask) + 1], \
        	   sizeof((h)->entries[0]), LOAD)

#endif /* ifndef __included_flowhash_common__ */

/**
 * @brief Allocate a flowhash structure.
 *
 * @param[in] fixed_entries The number of fixed entries in the hash table.
 * @param[in] chained_buckets The number of chained buckets.
 *
 * fixed_entries and chained_buckets parameters may not be used as is but
 * modified in order to fit requirements.
 *
 * Since the flowhash does not support dynamic resizing, it is fairly
 * important to choose the parameters carefully. In particular the performance
 * gain from using this structure comes from an efficient lookup in the
 * absence of hash collision.
 * As a rule of thumbs, if the number of active entries (flows) is M,
 * there should be about 16*M fixed entries, and M/16 collision buckets.
 * Which represents 17*M allocated entries.
 *
 * For example:
 * M = 2^20 total_size ~= 1GiB    collision ~= 3%
 * M = 2^18 total_size ~= 250MiB  collision ~= 3%
 * M = 2^10 total_size ~= 1MiB    collision ~= 6%
 *
 */
static_always_inline
FVT(flowhash) *FV(flowhash_alloc)(u32 fixed_entries, u32 collision_buckets)
{
  FVT(flowhash) *h;
  uword size;
  void *mem;
  u32 entries;

  flowhash_validate_sizes(&fixed_entries, &collision_buckets);

  entries = 1 + fixed_entries +
      collision_buckets * FLOWHASH_ENTRIES_PER_BUCKETS;
  size = sizeof(*h) + sizeof(h->entries[0]) * entries +
      sizeof(h->free_buckets_indices[0]) * collision_buckets;

  mem = clib_mem_alloc_aligned(size, CLIB_CACHE_LINE_BYTES);
  h = mem + collision_buckets * sizeof(h->free_buckets_indices[0]);
  h->mem = mem;

  /* Fill free elements list */
  int i;
  clib_memset(h->entries, 0, sizeof(h->entries[0]) * entries);
  for (i = 1; i <= collision_buckets; i++)
    {
      h->free_buckets_indices[-i] =
          entries - i * FLOWHASH_ENTRIES_PER_BUCKETS;
    }

  /* Init buckets */
  for (i=0; i < entries; i++)
    {
      h->entries[i].chained_entry_index = FLOWHASH_INVALID_ENTRY_INDEX;
      h->entries[i].timeout = 0;
    }

  h->free_buckets_position = -collision_buckets;
  h->fixed_entries_mask = fixed_entries - 1;
  h->collision_buckets_mask = collision_buckets - 1;
  h->total_entries = entries;
  h->not_enough_buckets_counter = 0;
  h->collision_lookup_counter = 0;
  h->garbage_collection_counter = 0;
  h->gc_counter = 0;

  return h;
}

/**
 * @brief Free the flow hash memory.
 */
static_always_inline
void FV(flowhash_free)(FVT(flowhash) *h)
{
  clib_mem_free(h->mem);
}

static void
FV(__flowhash_get_chained) (FVT(flowhash) *h, FVT(flowhash_lkey) *k,
                            u32 hash, u32 time_now, u32 *ei);

/**
 * @brief Retrieves an entry index corresponding to a provided key and its hash.
 *
 * @param h            The hash table pointer.
 * @param k[in]        A pointer to the key value.
 * @param hash[in]     The hash of the key.
 * @param time_now[in] The current time.
 * @param ei[out]      A pointer set to the found entry index.
 *
 * This function always sets ei value to a valid entry index which can then be
 * used to access the stored value as well as get or set its associated timeout.
 * The key stored in the returned entry is always set to the provided key.
 *
 * In case the provided key is not found, and no entry could be created
 * (either because there is no hash collision bucket available or
 * the candidate entries in the collision bucket were already used), ei is
 * set to the special value FLOWHASH_INVALID_ENTRY_INDEX (which can be tested
 * with the flowhash_is_overflow macro).
 *
 * The timeout value is never modified during a lookup.
 * - Use the flowhash_is_timeouted macro to test whether the returned entry
 *   was already valid, or is proposed for insertion.
 * - Use the flowhash_timeout macro to get and set the entry timeout value.
 *
 */
static_always_inline
void FV(flowhash_get) (FVT(flowhash) *h, FVT(flowhash_lkey) *k,
                       u32 hash, u32 time_now, u32 *ei)
{
  *ei = (hash & h->fixed_entries_mask) + 1;

  if (PREDICT_FALSE(FV(flowhash_cmp_key)(&h->entries[*ei].key, k) != 0))
    {
      if (PREDICT_TRUE(time_now > h->entries[*ei].timeout &&
                       (h->entries[*ei].chained_entry_index ==
                           FLOWHASH_INVALID_ENTRY_INDEX)))
        {
          FV(flowhash_cpy_key)(&h->entries[*ei].key, k);
        }
      else
        {
          FV(__flowhash_get_chained)(h, k, hash, time_now, ei);
        }
    }
}

static_always_inline void
FV(__flowhash_get_chained) (FVT(flowhash) *h, FVT(flowhash_lkey) *k,
                            u32 hash, u32 time_now, u32 *ei)
{
  h->collision_lookup_counter++;

  if (h->entries[*ei].chained_entry_index == FLOWHASH_INVALID_ENTRY_INDEX)
    {
      /* No chained entry yet. Let's chain one. */
      if (h->free_buckets_position == 0)
        {
          /* Oops. No more buckets available. */
          h->not_enough_buckets_counter++;
          *ei = FLOWHASH_INVALID_ENTRY_INDEX;
          h->entries[FLOWHASH_INVALID_ENTRY_INDEX].timeout =
              time_now - 1;
          FV(flowhash_cpy_key)(
              &h->entries[FLOWHASH_INVALID_ENTRY_INDEX].key, k);
          return;
        }

      /* Forward link */
      h->entries[*ei].chained_entry_index =
          h->free_buckets_indices[h->free_buckets_position];

      /* Backward link (for garbage collection) */
      h->entries[h->free_buckets_indices[h->free_buckets_position]].
              chained_entry_index = *ei;

      /* Move pointer */
      h->free_buckets_position++;
    }

  /* Get the two indexes where to look at. */
  u32 bi0 = h->entries[*ei].chained_entry_index +
      (hash >> (32 - FLOWHASH_ENTRIES_PER_BUCKETS_LOG));
  u32 bi1 = bi0 + 1;
  bi1 = (bi0 & (FLOWHASH_ENTRIES_PER_BUCKETS - 1)) ? bi1 :
      bi1 - FLOWHASH_ENTRIES_PER_BUCKETS;

  /* It is possible that we wait while comparing bi0 key.
   * It's better to prefetch bi1 so we don't wait twice. */
  CLIB_PREFETCH(&h->entries[bi1], sizeof (h->entries[0]), READ);

  if (FV(flowhash_cmp_key)(&h->entries[bi0].key, k) == 0)
    {
      *ei = bi0;
      return;
    }

  if (FV(flowhash_cmp_key)(&h->entries[bi1].key, k) == 0)
    {
      *ei = bi1;
      return;
    }

  if (h->entries[*ei].timeout >= time_now)
    {
      *ei = FLOWHASH_INVALID_ENTRY_INDEX;
      *ei = (time_now > h->entries[bi0].timeout) ? bi0 : *ei;
      *ei = (time_now > h->entries[bi1].timeout) ? bi1 : *ei;
    }

  FV(flowhash_cpy_key)(&h->entries[*ei].key, k);
}

static_always_inline void
FV(flowhash_gc)(FVT(flowhash) *h, u32 time_now,
    u32 *freed_index, u32 *freed_len)
{
  u32 ei;
  if (freed_index)
    *freed_len = 0;

  if (PREDICT_FALSE(h->collision_buckets_mask == (((u32)0) - 1)))
    return;

  /* prefetch two rounds in advance */
  ei = 2 + h->fixed_entries_mask +
      ((h->gc_counter + 2) & h->collision_buckets_mask) *
        FLOWHASH_ENTRIES_PER_BUCKETS;
  CLIB_PREFETCH(&h->entries[ei], sizeof (h->entries[0]), READ);

  /* prefetch one round in advance */
  ei = 2 + h->fixed_entries_mask +
      ((h->gc_counter + 1) & h->collision_buckets_mask) *
        FLOWHASH_ENTRIES_PER_BUCKETS;
  if (h->entries[ei].chained_entry_index != FLOWHASH_INVALID_ENTRY_INDEX)
    {
      CLIB_PREFETCH(&h->entries[ei], 4 * CLIB_CACHE_LINE_BYTES, READ);
    }

  /* do GC */
  ei = 2 + h->fixed_entries_mask +
      ((h->gc_counter) & h->collision_buckets_mask) *
      FLOWHASH_ENTRIES_PER_BUCKETS;
  if (h->entries[ei].chained_entry_index != FLOWHASH_INVALID_ENTRY_INDEX)
    {
      u8 found = 0;
      int i;
      for (i=0; i<FLOWHASH_ENTRIES_PER_BUCKETS; i++)
        {
          if (time_now <= h->entries[ei + i].timeout)
            {
              found = 1;
              break;
            }
        }

      if (!found)
        {
          /* Tell caller we freed this */
          if (freed_index)
            {
              *freed_index = ei;
              *freed_len = FLOWHASH_ENTRIES_PER_BUCKETS;
            }
          /* The bucket is not used. Let's free it. */
          h->free_buckets_position--;
          /* Reset forward link */
          h->entries[h->entries[ei].chained_entry_index].chained_entry_index =
              FLOWHASH_INVALID_ENTRY_INDEX;
          /* Reset back link */
          h->entries[ei].chained_entry_index = FLOWHASH_INVALID_ENTRY_INDEX;
          /* Free element */
          h->free_buckets_indices[h->free_buckets_position] = ei;
          /* Count the garbage collection event */
          h->garbage_collection_counter++;
        }
    }

  h->gc_counter++;
}

static_always_inline
u32 FV(flowhash_elts)(FVT(flowhash) *h, u32 time_now)
{
  u32 tot = 0;
  u32 ei;

  flowhash_foreach_valid_entry(h, ei, time_now)
    tot++;

  return tot;
}

#endif /* __included_flowhash_template_h__ */

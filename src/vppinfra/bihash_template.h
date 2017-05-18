/*
  Copyright (c) 2014 Cisco and/or its affiliates.

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

/** @cond DOCUMENTATION_IS_IN_BIHASH_DOC_H */

/*
 * Note: to instantiate the template multiple times in a single file,
 * #undef __included_bihash_template_h__...
 */
#ifndef __included_bihash_template_h__
#define __included_bihash_template_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>

#ifndef BIHASH_TYPE
#error BIHASH_TYPE not defined
#endif

#define _bv(a,b) a##b
#define __bv(a,b) _bv(a,b)
#define BV(a) __bv(a,BIHASH_TYPE)

#define _bvt(a,b) a##b##_t
#define __bvt(a,b) _bvt(a,b)
#define BVT(a) __bvt(a,BIHASH_TYPE)

typedef struct BV (clib_bihash_value)
{
  union
  {
    BVT (clib_bihash_kv) kvp[BIHASH_KVP_PER_PAGE];
    struct BV (clib_bihash_value) * next_free;
  };
} BVT (clib_bihash_value);

/*
 * This is shared across all uses of the template, so it needs
 * a "personal" #include recursion block
 */
#ifndef __defined_clib_bihash_bucket_t__
#define __defined_clib_bihash_bucket_t__
typedef struct
{
  union
  {
    struct
    {
      u32 offset;
      u8 linear_search;
      u8 pad[2];
      u8 log2_pages;
    };
    u64 as_u64;
  };
} clib_bihash_bucket_t;
#endif /* __defined_clib_bihash_bucket_t__ */

typedef struct
{
  BVT (clib_bihash_value) * values;
  clib_bihash_bucket_t *buckets;
  volatile u32 *writer_lock;

    BVT (clib_bihash_value) ** working_copies;
  int *working_copy_lengths;
  clib_bihash_bucket_t saved_bucket;

  u32 nbuckets;
  u32 log2_nbuckets;
  u32 linear_buckets;
  u8 *name;

    BVT (clib_bihash_value) ** freelists;
  void *mheap;

} BVT (clib_bihash);


static inline void *BV (clib_bihash_get_value) (const BVT (clib_bihash) * h,
						uword offset)
{
  u8 *hp = h->mheap;
  u8 *vp = hp + offset;

  return (void *) vp;
}

static inline uword BV (clib_bihash_get_offset) (const BVT (clib_bihash) * h,
						 void *v)
{
  u8 *hp, *vp;

  hp = (u8 *) h->mheap;
  vp = (u8 *) v;

  ASSERT ((vp - hp) < 0x100000000ULL);
  return vp - hp;
}

void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size);

void BV (clib_bihash_free) (BVT (clib_bihash) * h);

int BV (clib_bihash_add_del) (BVT (clib_bihash) * h,
			      BVT (clib_bihash_kv) * add_v, int is_add);
int BV (clib_bihash_search) (const BVT (clib_bihash) * h,
			     BVT (clib_bihash_kv) * search_v,
			     BVT (clib_bihash_kv) * return_v);

void BV (clib_bihash_foreach_key_value_pair) (BVT (clib_bihash) * h,
					      void *callback, void *arg);

format_function_t BV (format_bihash);
format_function_t BV (format_bihash_kvp);


static inline int BV (clib_bihash_search_inline)
  (const BVT (clib_bihash) * h, BVT (clib_bihash_kv) * kvp)
{
  u64 hash;
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
  clib_bihash_bucket_t *b;
  int i, limit;

  hash = BV (clib_bihash_hash) (kvp);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (b->offset == 0)
    return -1;

  hash >>= h->log2_nbuckets;

  v = BV (clib_bihash_get_value) (h, b->offset);

  /* If the bucket has unresolvable collisions, use linear search */
  limit = BIHASH_KVP_PER_PAGE;
  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;
  if (PREDICT_FALSE (b->linear_search))
    limit <<= b->log2_pages;

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_key_compare) (v->kvp[i].key, kvp->key))
	{
	  *kvp = v->kvp[i];
	  return 0;
	}
    }
  return -1;
}

static inline int BV (clib_bihash_search_inline_2)
  (const BVT (clib_bihash) * h,
   BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  u64 hash;
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
  clib_bihash_bucket_t *b;
  int i, limit;

  ASSERT (valuep);

  hash = BV (clib_bihash_hash) (search_key);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (b->offset == 0)
    return -1;

  hash >>= h->log2_nbuckets;
  v = BV (clib_bihash_get_value) (h, b->offset);

  /* If the bucket has unresolvable collisions, use linear search */
  limit = BIHASH_KVP_PER_PAGE;
  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;
  if (PREDICT_FALSE (b->linear_search))
    limit <<= b->log2_pages;

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_key_compare) (v->kvp[i].key, search_key->key))
	{
	  *valuep = v->kvp[i];
	  return 0;
	}
    }
  return -1;
}


#endif /* __included_bihash_template_h__ */

/** @endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

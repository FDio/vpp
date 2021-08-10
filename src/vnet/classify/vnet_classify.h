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
#ifndef __included_vnet_classify_h__
#define __included_vnet_classify_h__

#include <vnet/vnet.h>
#include <vnet/api_errno.h>	/* for API error numbers */

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>
#include <vppinfra/crc32.h>
#include <vppinfra/xxhash.h>

extern vlib_node_registration_t ip4_classify_node;
extern vlib_node_registration_t ip6_classify_node;

#define CLASSIFY_TRACE 0

/*
 * Classify table option to process packets
 *  CLASSIFY_FLAG_USE_CURR_DATA:
 *   - classify packets starting from VPP node’s current data pointer
 */
typedef enum vnet_classify_flags_t_
{
  CLASSIFY_FLAG_NONE = 0,
  CLASSIFY_FLAG_USE_CURR_DATA = (1 << 0),
} __clib_packed vnet_classify_flags_t;

/*
 * Classify session action
 *  CLASSIFY_ACTION_SET_IP4_FIB_INDEX:
 *   - Classified IP packets will be looked up
 *     from the specified ipv4 fib table
 *  CLASSIFY_ACTION_SET_IP6_FIB_INDEX:
 *   - Classified IP packets will be looked up
 *     from the specified ipv6 fib table
 */
typedef enum vnet_classify_action_t_
{
  CLASSIFY_ACTION_NONE = 0,
  CLASSIFY_ACTION_SET_IP4_FIB_INDEX = 1,
  CLASSIFY_ACTION_SET_IP6_FIB_INDEX = 2,
  CLASSIFY_ACTION_SET_METADATA = 3,
} __clib_packed vnet_classify_action_t;

struct _vnet_classify_main;
typedef struct _vnet_classify_main vnet_classify_main_t;

#define foreach_size_in_u32x4                   \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)

typedef struct _vnet_classify_entry
{
  /* put into vnet_buffer(b)->l2_classfy.opaque_index */
  union
  {
    struct
    {
      u32 opaque_index;
      /* advance on hit, note it's a signed quantity... */
      i32 advance;
    };
    u64 opaque_count;
  };
  /* Hit counter */
  union
  {
    u64 hits;
    struct _vnet_classify_entry *next_free;
  };
  /* last heard time */
  f64 last_heard;

  /* Really only need 1 bit */
  u8 flags;
#define VNET_CLASSIFY_ENTRY_FREE	(1<<0)

  vnet_classify_action_t action;
  u16 metadata;
  /* Graph node next index */
  u32 next_index;

  /* Must be aligned to a 16-octet boundary */
  u32x4 key[0];
} vnet_classify_entry_t;

/**
 * Check there's no padding in the entry. the key lies on a 16 byte boundary.
 */
STATIC_ASSERT_OFFSET_OF (vnet_classify_entry_t, key, 32);

static inline int
vnet_classify_entry_is_free (vnet_classify_entry_t * e)
{
  return e->flags & VNET_CLASSIFY_ENTRY_FREE;
}

static inline int
vnet_classify_entry_is_busy (vnet_classify_entry_t * e)
{
  return ((e->flags & VNET_CLASSIFY_ENTRY_FREE) == 0);
}

/* Need these to con the vector allocator */
#define _(size)                                                               \
  typedef struct                                                              \
  {                                                                           \
    vnet_classify_entry_t e;                                                  \
    u32x4 key[size];                                                          \
  } __clib_packed vnet_classify_entry_##size##_t;
foreach_size_in_u32x4;
#undef _

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
} vnet_classify_bucket_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* hash Buckets */
  vnet_classify_bucket_t *buckets;

  /* Private allocation arena, protected by the writer lock,
   * where the entries are stored. */
  void *mheap;

  /* User/client data associated with the table */
  uword user_ctx;

  u32 nbuckets;
  u32 log2_nbuckets;
  u32 entries_per_page;
  u32 skip_n_vectors;
  u32 match_n_vectors;
  u16 load_mask;

  /* Index of next table to try */
  u32 next_table_index;

  /* packet offsets */
  i16 current_data_offset;
  vnet_classify_flags_t current_data_flag;
  /* Miss next index, return if next_table_index = 0 */
  u32 miss_next_index;

  /**
   * All members accessed in the DP above here
   */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /* Config parameters */
  u32 linear_buckets;
  u32 active_elements;
  u32 data_offset;

  /* Per-bucket working copies, one per thread */
  vnet_classify_entry_t **working_copies;
  int *working_copy_lengths;
  vnet_classify_bucket_t saved_bucket;

  /* Free entry freelists */
  vnet_classify_entry_t **freelists;

  /* Writer (only) lock for this table */
  clib_spinlock_t writer_lock;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  /* Mask to apply after skipping N vectors */
  union
  {
    u32x4 mask[8];
    u32 mask_u32[32];
  };

} vnet_classify_table_t;

/**
 * Ensure DP fields don't spill over to cache-line 2
 */
STATIC_ASSERT_OFFSET_OF (vnet_classify_table_t, cacheline1,
			 CLIB_CACHE_LINE_BYTES);

/**
 * The vector size for the classifier
 *  in the add/del table 'match' is the number of vectors of this size
 */
#define VNET_CLASSIFY_VECTOR_SIZE                                             \
  sizeof (((vnet_classify_table_t *) 0)->mask[0])

struct _vnet_classify_main
{
  /* Table pool */
  vnet_classify_table_t *tables;

  /* Registered next-index, opaque unformat fcns */
  unformat_function_t **unformat_l2_next_index_fns;
  unformat_function_t **unformat_ip_next_index_fns;
  unformat_function_t **unformat_acl_next_index_fns;
  unformat_function_t **unformat_policer_next_index_fns;
  unformat_function_t **unformat_opaque_index_fns;

  /* Per-interface filter table.  [0] is used for pcap */
  u32 *classify_table_index_by_sw_if_index;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
};

extern vnet_classify_main_t vnet_classify_main;

u8 *format_classify_table (u8 * s, va_list * args);
u8 *format_vnet_classify_table (u8 *s, va_list *args);

u64 vnet_classify_hash_packet (const vnet_classify_table_t *t, const u8 *h);

static_always_inline vnet_classify_table_t *
vnet_classify_table_get (u32 table_index)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;

  return (pool_elt_at_index (vcm->tables, table_index));
}

static inline u64
vnet_classify_hash_packet_inline (const vnet_classify_table_t *t, const u8 *h)
{
  u64 xor_sum;
  ASSERT (t);
  h += t->skip_n_vectors * 16;

#if defined(CLIB_HAVE_VEC512) && defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
  u64x8 xor_sum_x8, *mask = (u64x8 *) t->mask;
  u16 load_mask = t->load_mask;
  u64x8u *data = (u64x8u *) h;

  xor_sum_x8 = u64x8_mask_load_zero (data, load_mask) & mask[0];

  if (PREDICT_FALSE (load_mask >> 8))
    xor_sum_x8 ^= u64x8_mask_load_zero (data + 1, load_mask >> 8) & mask[1];

  xor_sum_x8 ^= u64x8_align_right (xor_sum_x8, xor_sum_x8, 4);
  xor_sum_x8 ^= u64x8_align_right (xor_sum_x8, xor_sum_x8, 2);
  xor_sum = xor_sum_x8[0] ^ xor_sum_x8[1];
#elif defined(CLIB_HAVE_VEC256) && defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  u64x4 xor_sum_x4, *mask = (u64x4 *) t->mask;
  u16 load_mask = t->load_mask;
  u64x4u *data = (u64x4u *) h;

  xor_sum_x4 = u64x4_mask_load_zero (data, load_mask) & mask[0];
  xor_sum_x4 ^= u64x4_mask_load_zero (data + 1, load_mask >> 4) & mask[1];

  if (PREDICT_FALSE (load_mask >> 8))
    xor_sum_x4 ^= u64x4_mask_load_zero (data + 2, load_mask >> 8) & mask[2];

  xor_sum_x4 ^= u64x4_align_right (xor_sum_x4, xor_sum_x4, 2);
  xor_sum = xor_sum_x4[0] ^ xor_sum_x4[1];
#elif defined(CLIB_HAVE_VEC128)
  u64x2 *mask = (u64x2 *) t->mask;
  u64x2u *data = (u64x2u *) h;
  u64x2 xor_sum_x2;

  xor_sum_x2 = data[0] & mask[0];

  switch (t->match_n_vectors)
    {
    case 5:
      xor_sum_x2 ^= data[4] & mask[4];
      /* FALLTHROUGH */
    case 4:
      xor_sum_x2 ^= data[3] & mask[3];
      /* FALLTHROUGH */
    case 3:
      xor_sum_x2 ^= data[2] & mask[2];
      /* FALLTHROUGH */
    case 2:
      xor_sum_x2 ^= data[1] & mask[1];
      /* FALLTHROUGH */
    case 1:
      break;
    default:
      abort ();
    }
  xor_sum = xor_sum_x2[0] ^ xor_sum_x2[1];
#else
  u64 *data = (u64 *) h;
  u64 *mask = (u64 *) t->mask;

  xor_sum = (data[0] & mask[0]) ^ (data[1] & mask[1]);

  switch (t->match_n_vectors)
    {
    case 5:
      xor_sum ^= (data[8] & mask[8]) ^ (data[9] & mask[9]);
      /* FALLTHROUGH */
    case 4:
      xor_sum ^= (data[6] & mask[6]) ^ (data[7] & mask[7]);
      /* FALLTHROUGH */
    case 3:
      xor_sum ^= (data[4] & mask[4]) ^ (data[5] & mask[5]);
      /* FALLTHROUGH */
    case 2:
      xor_sum ^= (data[2] & mask[2]) ^ (data[3] & mask[3]);
      /* FALLTHROUGH */
    case 1:
      break;

    default:
      abort ();
    }
#endif /* CLIB_HAVE_VEC128 */

#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) & xor_sum, sizeof (xor_sum));
#else
  return clib_xxhash (xor_sum);
#endif
}

static inline void
vnet_classify_prefetch_bucket (vnet_classify_table_t * t, u64 hash)
{
  u32 bucket_index;

  ASSERT (is_pow2 (t->nbuckets));

  bucket_index = hash & (t->nbuckets - 1);

  clib_prefetch_load (&t->buckets[bucket_index]);
}

static inline vnet_classify_entry_t *
vnet_classify_get_entry (vnet_classify_table_t * t, uword offset)
{
  u8 *hp = clib_mem_get_heap_base (t->mheap);
  u8 *vp = hp + offset;

  return (vnet_classify_entry_t *) vp;
}

static inline uword
vnet_classify_get_offset (vnet_classify_table_t * t,
			  vnet_classify_entry_t * v)
{
  u8 *hp, *vp;

  hp = (u8 *) clib_mem_get_heap_base (t->mheap);
  vp = (u8 *) v;

  ASSERT ((vp - hp) < 0x100000000ULL);
  return vp - hp;
}

static inline vnet_classify_entry_t *
vnet_classify_entry_at_index (vnet_classify_table_t * t,
			      vnet_classify_entry_t * e, u32 index)
{
  u8 *eu8;

  eu8 = (u8 *) e;

  eu8 += index * (sizeof (vnet_classify_entry_t) +
		  (t->match_n_vectors * sizeof (u32x4)));

  return (vnet_classify_entry_t *) eu8;
}

static inline void
vnet_classify_prefetch_entry (vnet_classify_table_t * t, u64 hash)
{
  u32 bucket_index;
  u32 value_index;
  vnet_classify_bucket_t *b;
  vnet_classify_entry_t *e;

  bucket_index = hash & (t->nbuckets - 1);

  b = &t->buckets[bucket_index];

  if (b->offset == 0)
    return;

  hash >>= t->log2_nbuckets;

  e = vnet_classify_get_entry (t, b->offset);
  value_index = hash & ((1 << b->log2_pages) - 1);

  e = vnet_classify_entry_at_index (t, e, value_index);

  clib_prefetch_load (e);
}

vnet_classify_entry_t *vnet_classify_find_entry (vnet_classify_table_t *t,
						 const u8 *h, u64 hash,
						 f64 now);

static_always_inline int
vnet_classify_entry_is_equal (vnet_classify_entry_t *v, const u8 *d, u8 *m,
			      u32 match_n_vectors, u16 load_mask)
{
#if defined(CLIB_HAVE_VEC512) && defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
  u64x8 r, *mask = (u64x8 *) m;
  u64x8u *data = (u64x8u *) d;
  u64x4 *key = (u64x4 *) v->key;

  r = (u64x8_mask_load_zero (data, load_mask) & mask[0]) ^
      u64x8_mask_load_zero (key, load_mask);
  load_mask >>= 8;

  if (PREDICT_FALSE (load_mask))
    r |= (u64x8_mask_load_zero (data + 1, load_mask) & mask[1]) ^
	 u64x8_mask_load_zero (key + 1, load_mask);

  if (u64x8_is_all_zero (r))
    return 1;

#elif defined(CLIB_HAVE_VEC256) && defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  u64x4 r, *mask = (u64x4 *) m;
  u64x4u *data = (u64x4u *) d;
  u64x4 *key = (u64x4 *) v->key;

  r = (u64x4_mask_load_zero (data, load_mask) & mask[0]) ^
      u64x4_mask_load_zero (key, load_mask);
  load_mask >>= 4;

  r |= (u64x4_mask_load_zero (data + 1, load_mask) & mask[1]) ^
       u64x4_mask_load_zero (key + 1, load_mask);
  load_mask >>= 4;

  if (PREDICT_FALSE (load_mask))
    r |= (u64x4_mask_load_zero (data + 2, load_mask) & mask[2]) ^
	 u64x4_mask_load_zero (key + 2, load_mask);

  if (u64x4_is_all_zero (r))
    return 1;

#elif defined(CLIB_HAVE_VEC128)
  u64x2u *data = (u64x2 *) d;
  u64x2 *key = (u64x2 *) v->key;
  u64x2 *mask = (u64x2 *) m;
  u64x2 r;

  r = (data[0] & mask[0]) ^ key[0];
  switch (match_n_vectors)
    {
    case 5:
      r |= (data[4] & mask[4]) ^ key[4];
      /* fall through */
    case 4:
      r |= (data[3] & mask[3]) ^ key[3];
      /* fall through */
    case 3:
      r |= (data[2] & mask[2]) ^ key[2];
      /* fall through */
    case 2:
      r |= (data[1] & mask[1]) ^ key[1];
      /* fall through */
    case 1:
      break;
    default:
      abort ();
    }

  if (u64x2_is_all_zero (r))
    return 1;

#else
  u64 *data = (u64 *) d;
  u64 *key = (u64 *) v->key;
  u64 *mask = (u64 *) m;
  u64 r;

  r = ((data[0] & mask[0]) ^ key[0]) | ((data[1] & mask[1]) ^ key[1]);
  switch (match_n_vectors)
    {
    case 5:
      r |= ((data[8] & mask[8]) ^ key[8]) | ((data[9] & mask[9]) ^ key[9]);
      /* fall through */
    case 4:
      r |= ((data[6] & mask[6]) ^ key[6]) | ((data[7] & mask[7]) ^ key[7]);
      /* fall through */
    case 3:
      r |= ((data[4] & mask[4]) ^ key[4]) | ((data[5] & mask[5]) ^ key[5]);
      /* fall through */
    case 2:
      r |= ((data[2] & mask[2]) ^ key[2]) | ((data[3] & mask[3]) ^ key[3]);
      /* fall through */
    case 1:
      break;
    default:
      abort ();
    }

  if (r == 0)
    return 1;

#endif /* CLIB_HAVE_VEC128 */
  return 0;
}

static inline vnet_classify_entry_t *
vnet_classify_find_entry_inline (vnet_classify_table_t *t, const u8 *h,
				 u64 hash, f64 now)
{
  vnet_classify_entry_t *v;
  vnet_classify_bucket_t *b;
  u32 bucket_index, limit, pages, match_n_vectors = t->match_n_vectors;
  u16 load_mask = t->load_mask;
  u8 *mask = (u8 *) t->mask;
  int i;

  bucket_index = hash & (t->nbuckets - 1);
  b = &t->buckets[bucket_index];

  if (b->offset == 0)
    return 0;

  pages = 1 << b->log2_pages;
  v = vnet_classify_get_entry (t, b->offset);
  limit = t->entries_per_page;
  if (PREDICT_FALSE (b->linear_search))
    {
      limit *= pages;
      v = vnet_classify_entry_at_index (t, v, 0);
    }
  else
    {
      hash >>= t->log2_nbuckets;
      v = vnet_classify_entry_at_index (t, v, hash & (pages - 1));
    }

  h += t->skip_n_vectors * 16;

  for (i = 0; i < limit; i++)
    {
      if (vnet_classify_entry_is_equal (v, h, mask, match_n_vectors,
					load_mask))
	{
	  if (PREDICT_TRUE (now))
	    {
	      v->hits++;
	      v->last_heard = now;
	    }
	  return (v);
	}
      v = vnet_classify_entry_at_index (t, v, 1);
    }
  return 0;
}

vnet_classify_table_t *vnet_classify_new_table (vnet_classify_main_t *cm,
						const u8 *mask, u32 nbuckets,
						u32 memory_size,
						u32 skip_n_vectors,
						u32 match_n_vectors);

int vnet_classify_add_del_session (vnet_classify_main_t *cm, u32 table_index,
				   const u8 *match, u32 hit_next_index,
				   u32 opaque_index, i32 advance, u8 action,
				   u16 metadata, int is_add);

int vnet_classify_add_del_table (vnet_classify_main_t *cm, const u8 *mask,
				 u32 nbuckets, u32 memory_size, u32 skip,
				 u32 match, u32 next_table_index,
				 u32 miss_next_index, u32 *table_index,
				 u8 current_data_flag, i16 current_data_offset,
				 int is_add, int del_chain);
void vnet_classify_delete_table_index (vnet_classify_main_t *cm,
				       u32 table_index, int del_chain);

unformat_function_t unformat_ip4_mask;
unformat_function_t unformat_ip6_mask;
unformat_function_t unformat_l3_mask;
unformat_function_t unformat_l2_mask;
unformat_function_t unformat_classify_mask;
unformat_function_t unformat_l2_next_index;
unformat_function_t unformat_ip_next_index;
unformat_function_t unformat_ip4_match;
unformat_function_t unformat_ip6_match;
unformat_function_t unformat_l3_match;
unformat_function_t unformat_l4_match;
unformat_function_t unformat_vlan_tag;
unformat_function_t unformat_l2_match;
unformat_function_t unformat_classify_match;

void vnet_classify_register_unformat_ip_next_index_fn
  (unformat_function_t * fn);

void vnet_classify_register_unformat_l2_next_index_fn
  (unformat_function_t * fn);

void vnet_classify_register_unformat_acl_next_index_fn
  (unformat_function_t * fn);

void vnet_classify_register_unformat_policer_next_index_fn
  (unformat_function_t * fn);

void vnet_classify_register_unformat_opaque_index_fn (unformat_function_t *
						      fn);

u32 classify_get_pcap_chain (vnet_classify_main_t * cm, u32 sw_if_index);
void classify_set_pcap_chain (vnet_classify_main_t * cm,
			      u32 sw_if_index, u32 table_index);

u32 classify_get_trace_chain (void);
void classify_set_trace_chain (vnet_classify_main_t * cm, u32 table_index);

u32 classify_sort_table_chain (vnet_classify_main_t * cm, u32 table_index);
u32 classify_lookup_chain (u32 table_index,
			   u8 * mask, u32 n_skip, u32 n_match);

#endif /* __included_vnet_classify_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

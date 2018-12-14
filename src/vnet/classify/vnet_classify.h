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

#include <stdarg.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vlib/cli.h>
#include <vnet/api_errno.h>	/* for API error numbers */

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>
#include <vppinfra/xxhash.h>

extern vlib_node_registration_t ip4_classify_node;
extern vlib_node_registration_t ip6_classify_node;

#define CLASSIFY_TRACE 0

#define U32X4_ALIGNED(p) PREDICT_TRUE((((intptr_t)p) & 0xf) == 0)

/*
 * Classify table option to process packets
 *  CLASSIFY_FLAG_USE_CURR_DATA:
 *   - classify packets starting from VPP node’s current data pointer
 */
#define CLASSIFY_FLAG_USE_CURR_DATA              1

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
  CLASSIFY_ACTION_SET_IP4_FIB_INDEX = 1,
  CLASSIFY_ACTION_SET_IP6_FIB_INDEX = 2,
  CLASSIFY_ACTION_SET_METADATA = 3,
} __attribute__ ((packed)) vnet_classify_action_t;

struct _vnet_classify_main;
typedef struct _vnet_classify_main vnet_classify_main_t;

#define foreach_size_in_u32x4                   \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct _vnet_classify_entry {
  /* Graph node next index */
  u32 next_index;

  /* put into vnet_buffer(b)->l2_classfy.opaque_index */
  union {
    struct {
      u32 opaque_index;
      /* advance on hit, note it's a signed quantity... */
      i32 advance;
    };
    u64 opaque_count;
  };

  /* Really only need 1 bit */
  u8 flags;
#define VNET_CLASSIFY_ENTRY_FREE	(1<<0)

  vnet_classify_action_t action;
  u16 metadata;

  /* Hit counter, last heard time */
  union {
    u64 hits;
    struct _vnet_classify_entry * next_free;
  };

  f64 last_heard;

  /* Must be aligned to a 16-octet boundary */
  u32x4 key[0];
}) vnet_classify_entry_t;
/* *INDENT-ON* */

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
/* *INDENT-OFF* */
#define _(size)                                 \
typedef CLIB_PACKED(struct {                    \
  u32 pad0[4];                                  \
  u64 pad1[2];                                  \
  u32x4 key[size];                              \
}) vnet_classify_entry_##size##_t;
foreach_size_in_u32x4;
/* *INDENT-ON* */
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
  /* Mask to apply after skipping N vectors */
  u32x4 *mask;
  /* Buckets and entries */
  vnet_classify_bucket_t *buckets;
  vnet_classify_entry_t *entries;

  /* Config parameters */
  u32 match_n_vectors;
  u32 skip_n_vectors;
  u32 nbuckets;
  u32 log2_nbuckets;
  u32 linear_buckets;
  int entries_per_page;
  u32 active_elements;
  u32 current_data_flag;
  int current_data_offset;
  u32 data_offset;
  /* Index of next table to try */
  u32 next_table_index;

  /* Miss next index, return if next_table_index = 0 */
  u32 miss_next_index;

  /* Per-bucket working copies, one per thread */
  vnet_classify_entry_t **working_copies;
  int *working_copy_lengths;
  vnet_classify_bucket_t saved_bucket;

  /* Free entry freelists */
  vnet_classify_entry_t **freelists;

  u8 *name;

  /* Private allocation arena, protected by the writer lock */
  void *mheap;

  /* Writer (only) lock for this table */
  volatile u32 *writer_lock;

} vnet_classify_table_t;

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

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
};

extern vnet_classify_main_t vnet_classify_main;

u8 *format_classify_table (u8 * s, va_list * args);

u64 vnet_classify_hash_packet (vnet_classify_table_t * t, u8 * h);

static inline u64
vnet_classify_hash_packet_inline (vnet_classify_table_t * t, u8 * h)
{
  u32x4 *mask;

  union
  {
    u32x4 as_u32x4;
    u64 as_u64[2];
  } xor_sum __attribute__ ((aligned (sizeof (u32x4))));

  ASSERT (t);
  mask = t->mask;
#ifdef CLIB_HAVE_VEC128
  if (U32X4_ALIGNED (h))
    {				//SSE can't handle unaligned data
      u32x4 *data = (u32x4 *) h;
      xor_sum.as_u32x4 = data[0 + t->skip_n_vectors] & mask[0];
      switch (t->match_n_vectors)
	{
	case 5:
	  xor_sum.as_u32x4 ^= data[4 + t->skip_n_vectors] & mask[4];
	  /* FALLTHROUGH */
	case 4:
	  xor_sum.as_u32x4 ^= data[3 + t->skip_n_vectors] & mask[3];
	  /* FALLTHROUGH */
	case 3:
	  xor_sum.as_u32x4 ^= data[2 + t->skip_n_vectors] & mask[2];
	  /* FALLTHROUGH */
	case 2:
	  xor_sum.as_u32x4 ^= data[1 + t->skip_n_vectors] & mask[1];
	  /* FALLTHROUGH */
	case 1:
	  break;
	default:
	  abort ();
	}
    }
  else
#endif /* CLIB_HAVE_VEC128 */
    {
      u32 skip_u64 = t->skip_n_vectors * 2;
      u64 *data64 = (u64 *) h;
      xor_sum.as_u64[0] = data64[0 + skip_u64] & ((u64 *) mask)[0];
      xor_sum.as_u64[1] = data64[1 + skip_u64] & ((u64 *) mask)[1];
      switch (t->match_n_vectors)
	{
	case 5:
	  xor_sum.as_u64[0] ^= data64[8 + skip_u64] & ((u64 *) mask)[8];
	  xor_sum.as_u64[1] ^= data64[9 + skip_u64] & ((u64 *) mask)[9];
	  /* FALLTHROUGH */
	case 4:
	  xor_sum.as_u64[0] ^= data64[6 + skip_u64] & ((u64 *) mask)[6];
	  xor_sum.as_u64[1] ^= data64[7 + skip_u64] & ((u64 *) mask)[7];
	  /* FALLTHROUGH */
	case 3:
	  xor_sum.as_u64[0] ^= data64[4 + skip_u64] & ((u64 *) mask)[4];
	  xor_sum.as_u64[1] ^= data64[5 + skip_u64] & ((u64 *) mask)[5];
	  /* FALLTHROUGH */
	case 2:
	  xor_sum.as_u64[0] ^= data64[2 + skip_u64] & ((u64 *) mask)[2];
	  xor_sum.as_u64[1] ^= data64[3 + skip_u64] & ((u64 *) mask)[3];
	  /* FALLTHROUGH */
	case 1:
	  break;

	default:
	  abort ();
	}
    }

  return clib_xxhash (xor_sum.as_u64[0] ^ xor_sum.as_u64[1]);
}

static inline void
vnet_classify_prefetch_bucket (vnet_classify_table_t * t, u64 hash)
{
  u32 bucket_index;

  ASSERT (is_pow2 (t->nbuckets));

  bucket_index = hash & (t->nbuckets - 1);

  CLIB_PREFETCH (&t->buckets[bucket_index], CLIB_CACHE_LINE_BYTES, LOAD);
}

static inline vnet_classify_entry_t *
vnet_classify_get_entry (vnet_classify_table_t * t, uword offset)
{
  u8 *hp = t->mheap;
  u8 *vp = hp + offset;

  return (void *) vp;
}

static inline uword
vnet_classify_get_offset (vnet_classify_table_t * t,
			  vnet_classify_entry_t * v)
{
  u8 *hp, *vp;

  hp = (u8 *) t->mheap;
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

  CLIB_PREFETCH (e, CLIB_CACHE_LINE_BYTES, LOAD);
}

vnet_classify_entry_t *vnet_classify_find_entry (vnet_classify_table_t * t,
						 u8 * h, u64 hash, f64 now);

static inline vnet_classify_entry_t *
vnet_classify_find_entry_inline (vnet_classify_table_t * t,
				 u8 * h, u64 hash, f64 now)
{
  vnet_classify_entry_t *v;
  u32x4 *mask, *key;
  union
  {
    u32x4 as_u32x4;
    u64 as_u64[2];
  } result __attribute__ ((aligned (sizeof (u32x4))));
  vnet_classify_bucket_t *b;
  u32 value_index;
  u32 bucket_index;
  u32 limit;
  int i;

  bucket_index = hash & (t->nbuckets - 1);
  b = &t->buckets[bucket_index];
  mask = t->mask;

  if (b->offset == 0)
    return 0;

  hash >>= t->log2_nbuckets;

  v = vnet_classify_get_entry (t, b->offset);
  value_index = hash & ((1 << b->log2_pages) - 1);
  limit = t->entries_per_page;
  if (PREDICT_FALSE (b->linear_search))
    {
      value_index = 0;
      limit *= (1 << b->log2_pages);
    }

  v = vnet_classify_entry_at_index (t, v, value_index);

#ifdef CLIB_HAVE_VEC128
  if (U32X4_ALIGNED (h))
    {
      u32x4 *data = (u32x4 *) h;
      for (i = 0; i < limit; i++)
	{
	  key = v->key;
	  result.as_u32x4 = (data[0 + t->skip_n_vectors] & mask[0]) ^ key[0];
	  switch (t->match_n_vectors)
	    {
	    case 5:
	      result.as_u32x4 |=
		(data[4 + t->skip_n_vectors] & mask[4]) ^ key[4];
	      /* FALLTHROUGH */
	    case 4:
	      result.as_u32x4 |=
		(data[3 + t->skip_n_vectors] & mask[3]) ^ key[3];
	      /* FALLTHROUGH */
	    case 3:
	      result.as_u32x4 |=
		(data[2 + t->skip_n_vectors] & mask[2]) ^ key[2];
	      /* FALLTHROUGH */
	    case 2:
	      result.as_u32x4 |=
		(data[1 + t->skip_n_vectors] & mask[1]) ^ key[1];
	      /* FALLTHROUGH */
	    case 1:
	      break;
	    default:
	      abort ();
	    }

	  if (u32x4_zero_byte_mask (result.as_u32x4) == 0xffff)
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
    }
  else
#endif /* CLIB_HAVE_VEC128 */
    {
      u32 skip_u64 = t->skip_n_vectors * 2;
      u64 *data64 = (u64 *) h;
      for (i = 0; i < limit; i++)
	{
	  key = v->key;

	  result.as_u64[0] =
	    (data64[0 + skip_u64] & ((u64 *) mask)[0]) ^ ((u64 *) key)[0];
	  result.as_u64[1] =
	    (data64[1 + skip_u64] & ((u64 *) mask)[1]) ^ ((u64 *) key)[1];
	  switch (t->match_n_vectors)
	    {
	    case 5:
	      result.as_u64[0] |=
		(data64[8 + skip_u64] & ((u64 *) mask)[8]) ^ ((u64 *) key)[8];
	      result.as_u64[1] |=
		(data64[9 + skip_u64] & ((u64 *) mask)[9]) ^ ((u64 *) key)[9];
	      /* FALLTHROUGH */
	    case 4:
	      result.as_u64[0] |=
		(data64[6 + skip_u64] & ((u64 *) mask)[6]) ^ ((u64 *) key)[6];
	      result.as_u64[1] |=
		(data64[7 + skip_u64] & ((u64 *) mask)[7]) ^ ((u64 *) key)[7];
	      /* FALLTHROUGH */
	    case 3:
	      result.as_u64[0] |=
		(data64[4 + skip_u64] & ((u64 *) mask)[4]) ^ ((u64 *) key)[4];
	      result.as_u64[1] |=
		(data64[5 + skip_u64] & ((u64 *) mask)[5]) ^ ((u64 *) key)[5];
	      /* FALLTHROUGH */
	    case 2:
	      result.as_u64[0] |=
		(data64[2 + skip_u64] & ((u64 *) mask)[2]) ^ ((u64 *) key)[2];
	      result.as_u64[1] |=
		(data64[3 + skip_u64] & ((u64 *) mask)[3]) ^ ((u64 *) key)[3];
	      /* FALLTHROUGH */
	    case 1:
	      break;
	    default:
	      abort ();
	    }

	  if (result.as_u64[0] == 0 && result.as_u64[1] == 0)
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
    }
  return 0;
}

vnet_classify_table_t *vnet_classify_new_table (vnet_classify_main_t * cm,
						u8 * mask, u32 nbuckets,
						u32 memory_size,
						u32 skip_n_vectors,
						u32 match_n_vectors);

int vnet_classify_add_del_session (vnet_classify_main_t * cm,
				   u32 table_index,
				   u8 * match,
				   u32 hit_next_index,
				   u32 opaque_index,
				   i32 advance,
				   u8 action, u32 metadata, int is_add);

int vnet_classify_add_del_table (vnet_classify_main_t * cm,
				 u8 * mask,
				 u32 nbuckets,
				 u32 memory_size,
				 u32 skip,
				 u32 match,
				 u32 next_table_index,
				 u32 miss_next_index,
				 u32 * table_index,
				 u8 current_data_flag,
				 i16 current_data_offset,
				 int is_add, int del_chain);

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

#endif /* __included_vnet_classify_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

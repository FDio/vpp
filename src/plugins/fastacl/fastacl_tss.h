/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_tss_h__
#define __included_fastacl_tss_h__

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <fastacl/fastacl_types.h>

#define FASTACL_MATCH_ADDR_BITS (FASTACL_MATCH_DST_PREFIX | FASTACL_MATCH_SRC_PREFIX)

#define FASTACL_TSS_MASK_FLAGS_BITS                                                                \
  (FASTACL_MATCH_DST_PREFIX | FASTACL_MATCH_SRC_PREFIX | FASTACL_MATCH_PROTO |                     \
   FASTACL_MATCH_DST_PORT | FASTACL_MATCH_SRC_PORT | FASTACL_MATCH_EITHER_PORT |                   \
   FASTACL_MATCH_IS_IP6)

typedef struct
{
  u32 flags;
  u8 dst_plen;
  u8 src_plen;
  u8 is_ip6;
  u8 _pad;
} fastacl_tuple_mask_t;

STATIC_ASSERT (sizeof (fastacl_tuple_mask_t) == 8,
	       "tuple mask must have no implicit padding (memcmp-keyed)");

typedef enum
{
  FASTACL_CHAIN_KEPT,
  FASTACL_CHAIN_COLLAPSED,
  FASTACL_CHAIN_EMPTY,
} fastacl_chain_outcome_t;

typedef struct
{
  u32 ri;
  fastacl_rule_t *rule;
  u8 action;
} fastacl_tss_best_t;

static_always_inline void
fastacl_tss_best_take (fastacl_tss_best_t *best, u32 ri, fastacl_rule_t *rule, u8 action)
{
  best->ri = ri;
  best->rule = rule;
  best->action = action;
}

typedef struct
{
  u32 *rule_indices;
} fastacl_chain_t;

#define foreach_fastacl_tss_width                                                                  \
  _ (8_8, 8, hash4c)                                                                               \
  _ (16_8, 16, hash6c)                                                                             \
  _ (24_8, 24, hash4)                                                                              \
  _ (40_8, 40, hash6)

typedef enum
{
#define _(sz, bytes, field) FASTACL_TSS_W_##sz,
  foreach_fastacl_tss_width
#undef _
} fastacl_tss_width_t;

typedef struct
{
  fastacl_tuple_mask_t mask;
  union
  {
    clib_bihash_24_8_t hash4;
    clib_bihash_40_8_t hash6;

    clib_bihash_8_8_t hash4c;
    clib_bihash_16_8_t hash6c;
  };
  u8 *hash_name;
  u8 width;
  u8 hash_initialized;
  u32 *chain_indices;
  u32 n_rules;
} fastacl_tuple_t;

typedef union
{
  clib_bihash_kv_24_8_t kv4;
  clib_bihash_kv_40_8_t kv6;
} fastacl_tss_key_t;

#define fastacl_tss_bihash_init(sz, hp, name_, nbuckets_)                                          \
  do                                                                                               \
    {                                                                                              \
      clib_bihash_init2_args_##sz##_t _a = {                                                       \
	.h = (hp),                                                                                 \
	.name = (name_),                                                                           \
	.nbuckets = (nbuckets_),                                                                   \
	.dont_add_to_all_bihash_list = 1,                                                          \
      };                                                                                           \
      clib_bihash_init2_##sz (&_a);                                                                \
    }                                                                                              \
  while (0)

static_always_inline const char *
fastacl_tss_width_name (u8 width)
{
  switch (width)
    {
#define _(sz, bytes, field)                                                                        \
  case FASTACL_TSS_W_##sz:                                                                         \
    return #bytes "B";
      foreach_fastacl_tss_width
#undef _
    }
  return "?";
}

#define fastacl_tss_bihash_ops(sz)                                                                 \
  static_always_inline int tss_search_##sz (clib_bihash_##sz##_t *h, clib_bihash_kv_##sz##_t *kv,  \
					    u64 *value_out)                                        \
  {                                                                                                \
    clib_bihash_kv_##sz##_t r;                                                                     \
    if (clib_bihash_search_##sz (h, kv, &r) != 0)                                                  \
      return -1;                                                                                   \
    *value_out = r.value;                                                                          \
    return 0;                                                                                      \
  }                                                                                                \
  static_always_inline void tss_store_##sz (clib_bihash_##sz##_t *h, clib_bihash_kv_##sz##_t *kv,  \
					    u64 value)                                             \
  {                                                                                                \
    kv->value = value;                                                                             \
    clib_bihash_add_del_##sz (h, kv, 1);                                                           \
  }                                                                                                \
  static_always_inline void tss_del_##sz (clib_bihash_##sz##_t *h, clib_bihash_kv_##sz##_t *kv)    \
  {                                                                                                \
    clib_bihash_add_del_##sz (h, kv, 0);                                                           \
  }                                                                                                \
  static_always_inline void tss_prefetch_##sz (clib_bihash_##sz##_t *h,                            \
					       clib_bihash_kv_##sz##_t *kv)                        \
  {                                                                                                \
    clib_bihash_prefetch_bucket_##sz (h, clib_bihash_hash_##sz (kv));                              \
  }

#define foreach_fastacl_tss_family                                                                 \
  _ (4, 8_8, 24_8, hash4c, hash4, tss4_compact_kv)                                                 \
  _ (6, 16_8, 40_8, hash6c, hash6, tss6_compact_kv)

#define fastacl_tss_family_ops(f, csz, wsz, cfield, wfield, conv)                                  \
  static_always_inline int tss##f##_search (fastacl_tuple_t *t, clib_bihash_kv_##wsz##_t *kv,      \
					    u64 *value_out)                                        \
  {                                                                                                \
    if (t->width == FASTACL_TSS_W_##csz)                                                           \
      {                                                                                            \
	clib_bihash_kv_##csz##_t k = conv (kv, 0);                                                 \
	return tss_search_##csz (&t->cfield, &k, value_out);                                       \
      }                                                                                            \
    return tss_search_##wsz (&t->wfield, kv, value_out);                                           \
  }                                                                                                \
  static_always_inline void tss##f##_store (fastacl_tuple_t *t, clib_bihash_kv_##wsz##_t *kv,      \
					    u64 value)                                             \
  {                                                                                                \
    if (t->width == FASTACL_TSS_W_##csz)                                                           \
      {                                                                                            \
	clib_bihash_kv_##csz##_t k = conv (kv, 0);                                                 \
	tss_store_##csz (&t->cfield, &k, value);                                                   \
	return;                                                                                    \
      }                                                                                            \
    tss_store_##wsz (&t->wfield, kv, value);                                                       \
  }                                                                                                \
  static_always_inline void tss##f##_del (fastacl_tuple_t *t, clib_bihash_kv_##wsz##_t *kv)        \
  {                                                                                                \
    if (t->width == FASTACL_TSS_W_##csz)                                                           \
      {                                                                                            \
	clib_bihash_kv_##csz##_t k = conv (kv, 0);                                                 \
	tss_del_##csz (&t->cfield, &k);                                                            \
	return;                                                                                    \
      }                                                                                            \
    tss_del_##wsz (&t->wfield, kv);                                                                \
  }                                                                                                \
  static_always_inline void tss##f##_prefetch (fastacl_tuple_t *t, clib_bihash_kv_##wsz##_t *kv)   \
  {                                                                                                \
    if (t->width == FASTACL_TSS_W_##csz)                                                           \
      {                                                                                            \
	clib_bihash_kv_##csz##_t k = conv (kv, 0);                                                 \
	tss_prefetch_##csz (&t->cfield, &k);                                                       \
	return;                                                                                    \
      }                                                                                            \
    tss_prefetch_##wsz (&t->wfield, kv);                                                           \
  }

#define FASTACL_VAL_CHAIN_BIT (1ull << 63)

#define FASTACL_VAL_EXACT_BIT	 (1ull << 62)
#define FASTACL_VAL_ACTION_SHIFT 60
#define FASTACL_VAL_ACTION_MASK	 (3ull << FASTACL_VAL_ACTION_SHIFT)

STATIC_ASSERT (FASTACL_ACTION_TYPE_PERMIT <= 3, "action type must fit the 2-bit TSS value field");

static_always_inline int
fastacl_val_is_chain (u64 v)
{
  return (v & FASTACL_VAL_CHAIN_BIT) != 0;
}

static_always_inline int
fastacl_val_is_exact (u64 v)
{
  return (v & FASTACL_VAL_EXACT_BIT) != 0;
}

static_always_inline u8
fastacl_val_action (u64 v)
{
  return (u8) ((v & FASTACL_VAL_ACTION_MASK) >> FASTACL_VAL_ACTION_SHIFT);
}

static_always_inline u32
fastacl_val_rule_index (u64 v)
{
  return (u32) (v & 0xFFFFFFFFu);
}

static_always_inline u32
fastacl_val_chain_index (u64 v)
{
  return (u32) (v & ~FASTACL_VAL_CHAIN_BIT);
}

static_always_inline u64
fastacl_val_make_rule (u32 rule_index, int exact, u8 action)
{
  return (u64) rule_index | (exact ? FASTACL_VAL_EXACT_BIT : 0) |
	 ((u64) (action & 3) << FASTACL_VAL_ACTION_SHIFT);
}

static_always_inline u64
fastacl_val_make_chain (u32 chain_index)
{
  return (u64) chain_index | FASTACL_VAL_CHAIN_BIT;
}

static_always_inline void
fastacl_chain_free_resources (fastacl_chain_t *c)
{
  vec_free (c->rule_indices);
}

static_always_inline void
fastacl_u32_vec_remove_value (u32 **pv, u32 value)
{
  u32 i = vec_search (*pv, value);

  if (i != ~0)
    vec_delete (*pv, 1, i);
}

void fastacl_tss_clear (fastacl_main_t *fsm);
void fastacl_tss_insert_rule (fastacl_main_t *fsm, u32 rule_index);
void fastacl_tss_finalize (fastacl_main_t *fsm);
void fastacl_tuple_chain_stats (fastacl_main_t *fsm, const fastacl_tuple_t *t, u32 *n_chains,
				u32 *max_depth, u32 *n_chained_rules);
int fastacl_tss_rule_exists (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match);
void fastacl_tss_remove_rule (fastacl_main_t *fsm, u32 rule_index);
u32 fastacl_tss_lookup_ip4 (fastacl_main_t *fsm, ip4_header_t *ip, u8 pkt_proto, u16 l4_src_port,
			    u16 l4_dst_port, u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp,
			    u8 pkt_frag_flags, u8 *action_out);
void fastacl_tss_prefetch_ip4 (fastacl_main_t *fsm, ip4_header_t *ip, u8 pkt_proto, u16 pkt_len);
void fastacl_tss_prefetch_ip6 (fastacl_main_t *fsm, ip6_header_t *ip6, u8 pkt_proto);
u32 fastacl_tss_lookup_ip6 (fastacl_main_t *fsm, ip6_header_t *ip6, u8 pkt_proto, u16 l4_src_port,
			    u16 l4_dst_port, u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp,
			    u8 pkt_frag_flags, u8 *action_out);

#endif

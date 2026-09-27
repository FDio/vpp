/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <fastacl/fastacl.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

static_always_inline u32 **
tuple_family_vec (fastacl_main_t *fsm, int is_ip6)
{
  return is_ip6 ? &fsm->tuple_index_v6 : &fsm->tuple_index_v4;
}

static_always_inline void
tuple_chain_free (fastacl_main_t *fsm, fastacl_tuple_t *t, u32 chain_index)
{
  fastacl_chain_free_resources (pool_elt_at_index (fsm->chains, chain_index));
  pool_put_index (fsm->chains, chain_index);
  fastacl_u32_vec_remove_value (&t->chain_indices, chain_index);
}

static_always_inline void
tuple_free_resources (fastacl_tuple_t *t)
{
  if (t->hash_initialized)
    {
      switch (t->width)
	{
#define _(sz, bytes, field)                                                                        \
  case FASTACL_TSS_W_##sz:                                                                         \
    clib_bihash_free_##sz (&t->field);                                                             \
    break;
	  foreach_fastacl_tss_width
#undef _
	}
      t->hash_initialized = 0;
    }
  vec_free (t->hash_name);
  vec_free (t->chain_indices);
}

static_always_inline u32
masked_ip4 (u32 flags, u32 want_flag, u32 addr, u8 plen)
{
  return (flags & want_flag) ? (addr & fastacl_ip4_mask (plen)) : 0;
}

static_always_inline int
rule_is_family_agnostic (const fastacl_match_t *m)
{
  return (m->flags & (FASTACL_MATCH_ADDR_BITS | FASTACL_MATCH_IS_IP6)) == 0;
}

static_always_inline void
mask_from_rule (const fastacl_match_t *m, fastacl_tuple_mask_t *out)
{
  clib_memset (out, 0, sizeof (*out));
  out->flags = m->flags & FASTACL_TSS_MASK_FLAGS_BITS;
  if (m->flags & FASTACL_MATCH_DST_PREFIX)
    out->dst_plen = m->dst_prefix_len;
  if (m->flags & FASTACL_MATCH_SRC_PREFIX)
    out->src_plen = m->src_prefix_len;
  out->is_ip6 = !!(m->flags & FASTACL_MATCH_IS_IP6);
}

static_always_inline void
tss_key_pack (clib_bihash_kv_24_8_t *kv, u32 src, u32 dst, u8 proto, u64 key2)
{
  kv->key[0] = ((u64) src << 32) | dst;
  kv->key[1] = proto;
  kv->key[2] = key2;
}

static_always_inline void
key_from_fields_ip4 (u32 flags, u32 dst, u8 dst_plen, u32 src, u8 src_plen, u8 proto,
		     clib_bihash_kv_24_8_t *kv)
{
  tss_key_pack (kv, masked_ip4 (flags, FASTACL_MATCH_SRC_PREFIX, src, src_plen),
		masked_ip4 (flags, FASTACL_MATCH_DST_PREFIX, dst, dst_plen),
		(flags & FASTACL_MATCH_PROTO) ? proto : 0, 0);
}

static_always_inline void
key_from_rule_ip4 (const fastacl_match_t *m, clib_bihash_kv_24_8_t *kv)
{
  key_from_fields_ip4 (m->flags, m->dst_addr.ip4.as_u32, m->dst_prefix_len, m->src_addr.ip4.as_u32,
		       m->src_prefix_len, m->proto, kv);
}

static_always_inline void
key_from_packet_ip4 (const fastacl_tuple_mask_t *mask, ip4_header_t *ip, u8 pkt_proto,
		     clib_bihash_kv_24_8_t *kv)
{
  key_from_fields_ip4 (mask->flags, ip->dst_address.as_u32, mask->dst_plen, ip->src_address.as_u32,
		       mask->src_plen, pkt_proto, kv);
}

static_always_inline void
tss6_key_pack (clib_bihash_kv_40_8_t *kv, u64 da0, u64 da1, u64 sa0, u64 sa1, u64 proto)
{
  kv->key[0] = da0;
  kv->key[1] = da1;
  kv->key[2] = sa0;
  kv->key[3] = sa1;
  kv->key[4] = proto;
}

static_always_inline void
key_from_fields_ip6 (u32 flags, const ip6_address_t *dst, u8 dst_plen, const ip6_address_t *src,
		     u8 src_plen, u8 proto, clib_bihash_kv_40_8_t *kv)
{
  u64 da0 = 0, da1 = 0, sa0 = 0, sa1 = 0;

  if (flags & FASTACL_MATCH_DST_PREFIX)
    fastacl_ip6_apply_mask (dst, dst_plen, &da0, &da1);
  if (flags & FASTACL_MATCH_SRC_PREFIX)
    fastacl_ip6_apply_mask (src, src_plen, &sa0, &sa1);

  tss6_key_pack (kv, da0, da1, sa0, sa1, (flags & FASTACL_MATCH_PROTO) ? proto : 0);
}

static_always_inline void
key_from_rule_ip6 (const fastacl_match_t *m, clib_bihash_kv_40_8_t *kv)
{
  key_from_fields_ip6 (m->flags, &m->dst_addr.ip6, m->dst_prefix_len, &m->src_addr.ip6,
		       m->src_prefix_len, m->proto, kv);
}

static_always_inline void
key_from_packet_ip6 (const fastacl_tuple_mask_t *mask, ip6_header_t *ip6, u8 pkt_proto,
		     clib_bihash_kv_40_8_t *kv)
{
  key_from_fields_ip6 (mask->flags, &ip6->dst_address, mask->dst_plen, &ip6->src_address,
		       mask->src_plen, pkt_proto, kv);
}

static_always_inline int
tss_full_rule_match_ip6 (fastacl_match_t *m, ip6_header_t *ip6, u8 pkt_proto, u16 l4_src_port,
			 u16 l4_dst_port, u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp,
			 u8 pkt_frag_flags)
{

  if (!(m->flags & FASTACL_MATCH_IS_IP6) && (m->flags & FASTACL_MATCH_ADDR_BITS))
    return 0;
  if ((m->flags & FASTACL_MATCH_DST_PREFIX) &&
      !fastacl_ip6_prefix_match (m->flags, FASTACL_MATCH_DST_PREFIX, &ip6->dst_address,
				 &m->dst_addr.ip6, m->dst_prefix_len))
    return 0;
  if ((m->flags & FASTACL_MATCH_SRC_PREFIX) &&
      !fastacl_ip6_prefix_match (m->flags, FASTACL_MATCH_SRC_PREFIX, &ip6->src_address,
				 &m->src_addr.ip6, m->src_prefix_len))
    return 0;
  return fastacl_match_fields (m, pkt_proto, l4_src_port, l4_dst_port, l4, l4_bytes, pkt_len,
			       pkt_dscp, pkt_frag_flags);
}

static_always_inline int
mask_is_compact (const fastacl_tuple_mask_t *mask)
{
  if (mask->is_ip6)
    return !(mask->flags & (FASTACL_MATCH_SRC_PREFIX | FASTACL_MATCH_PROTO));

  return !(mask->flags & FASTACL_MATCH_SRC_PREFIX) || !(mask->flags & FASTACL_MATCH_PROTO);
}

static_always_inline u8
tuple_width (const fastacl_tuple_mask_t *mask)
{
  if (mask->is_ip6)
    return mask_is_compact (mask) ? FASTACL_TSS_W_16_8 : FASTACL_TSS_W_40_8;

  return mask_is_compact (mask) ? FASTACL_TSS_W_8_8 : FASTACL_TSS_W_24_8;
}

static_always_inline clib_bihash_kv_8_8_t
tss4_compact_kv (const clib_bihash_kv_24_8_t *kv, u64 value)
{
  clib_bihash_kv_8_8_t k = { .key = kv->key[0] | (kv->key[1] << 32), .value = value };
  return k;
}

static_always_inline clib_bihash_kv_16_8_t
tss6_compact_kv (const clib_bihash_kv_40_8_t *kv, u64 value)
{
  clib_bihash_kv_16_8_t k = { .key = { kv->key[0], kv->key[1] }, .value = value };
  return k;
}

static_always_inline int
rule_key_complete (const fastacl_match_t *m)
{
  const u32 keyed = FASTACL_MATCH_DST_PREFIX | FASTACL_MATCH_SRC_PREFIX | FASTACL_MATCH_PROTO |
		    FASTACL_MATCH_IS_IP6;
  return (m->flags & ~keyed) == 0;
}

#define _(sz, bytes, field) fastacl_tss_bihash_ops (sz)
foreach_fastacl_tss_width;
#undef _

#define _(f, csz, wsz, cfield, wfield, conv)                                                       \
  fastacl_tss_family_ops (f, csz, wsz, cfield, wfield, conv)
foreach_fastacl_tss_family;
#undef _

void
fastacl_tss_clear (fastacl_main_t *fsm)
{
  fastacl_tuple_t *t;
  fastacl_chain_t *c;

  pool_foreach (t, fsm->tuples)
    {
      hash_unset_mem_free (&fsm->tuple_by_mask, &t->mask);
      tuple_free_resources (t);
    }
  pool_free (fsm->tuples);
  vec_free (fsm->tuple_index_v4);
  vec_free (fsm->tuple_index_v6);

  pool_foreach (c, fsm->chains)
    fastacl_chain_free_resources (c);
  pool_free (fsm->chains);

  hash_free (fsm->tuple_by_mask);
  fsm->tuple_by_mask = hash_create_mem (0, sizeof (fastacl_tuple_mask_t), sizeof (uword));
}

static fastacl_tuple_t *
tuple_get_or_create (fastacl_main_t *fsm, const fastacl_tuple_mask_t *mask)
{
  uword *p = hash_get_mem (fsm->tuple_by_mask, mask);
  fastacl_tuple_t *t;

  if (p)
    return pool_elt_at_index (fsm->tuples, p[0]);

  pool_get_zero (fsm->tuples, t);
  t->mask = *mask;
  hash_set_mem_alloc (&fsm->tuple_by_mask, mask, t - fsm->tuples);

  t->hash_name = format (0, "fastacl-tss-%u%c", t - fsm->tuples, 0);
  char *name = (char *) t->hash_name;
  t->width = tuple_width (&t->mask);

  switch (t->width)
    {
#define _(sz, bytes, field)                                                                        \
  case FASTACL_TSS_W_##sz:                                                                         \
    fastacl_tss_bihash_init (sz, &t->field, name, fsm->tss_buckets);                               \
    break;
      foreach_fastacl_tss_width
#undef _
    }
  t->hash_initialized = 1;

  vec_add1 (*tuple_family_vec (fsm, mask->is_ip6), t - fsm->tuples);

  return t;
}

static void
sorted_vec_insert (fastacl_main_t *fsm, u32 **pv, u32 rule_index)
{
  if (fsm->tss_bulk_mode)
    {
      vec_add1 (*pv, rule_index);
      return;
    }
  u32 *v = *pv;
  u32 i, n = vec_len (v);

  fastacl_rule_t *r = pool_elt_at_index (fsm->rules, rule_index);
  for (i = 0; i < n; i++)
    {
      fastacl_rule_t *cur = pool_elt_at_index (fsm->rules, v[i]);
      if (fastacl_rule_precedence_cmp (r, rule_index, cur, v[i]) < 0)
	break;
    }
  vec_insert_elts (v, &rule_index, 1, i);
  *pv = v;
}

static fastacl_chain_t *
tss_chain_for_insert (fastacl_main_t *fsm, fastacl_tuple_t *t, u64 value, u32 *new_chain_index)
{
  fastacl_chain_t *chain;

  *new_chain_index = ~0u;

  if (fastacl_val_is_chain (value))
    return pool_elt_at_index (fsm->chains, fastacl_val_chain_index (value));

  pool_get_zero (fsm->chains, chain);
  *new_chain_index = chain - fsm->chains;
  vec_add1 (t->chain_indices, *new_chain_index);
  sorted_vec_insert (fsm, &chain->rule_indices, fastacl_val_rule_index (value));
  return chain;
}

static u64
tss_rule_value (fastacl_main_t *fsm, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);

  return fastacl_val_make_rule (rule_index, rule_key_complete (&rule->match), rule->action.type);
}

static fastacl_chain_outcome_t
tss_chain_left (fastacl_main_t *fsm, fastacl_tuple_t *t, u64 value, u32 rule_index,
		u64 *replacement)
{
  u32 chain_index = fastacl_val_chain_index (value);
  fastacl_chain_t *chain = pool_elt_at_index (fsm->chains, chain_index);

  fastacl_u32_vec_remove_value (&chain->rule_indices, rule_index);

  u32 remaining = vec_len (chain->rule_indices);

  if (remaining == 0)
    {
      tuple_chain_free (fsm, t, chain_index);
      return FASTACL_CHAIN_EMPTY;
    }

  if (remaining == 1)
    {
      u32 last_ri = chain->rule_indices[0];

      tuple_chain_free (fsm, t, chain_index);
      *replacement = tss_rule_value (fsm, last_ri);
      return FASTACL_CHAIN_COLLAPSED;
    }

  return FASTACL_CHAIN_KEPT;
}

static_always_inline void
tss_key_from_rule (const fastacl_tuple_t *t, const fastacl_match_t *m, fastacl_tss_key_t *key)
{
  if (t->mask.is_ip6)
    key_from_rule_ip6 (m, &key->kv6);
  else
    key_from_rule_ip4 (m, &key->kv4);
}

static_always_inline int
tss_search (fastacl_tuple_t *t, fastacl_tss_key_t *key, u64 *value_out)
{
  if (t->mask.is_ip6)
    return tss6_search (t, &key->kv6, value_out);
  return tss4_search (t, &key->kv4, value_out);
}

static_always_inline void
tss_store (fastacl_tuple_t *t, fastacl_tss_key_t *key, u64 value)
{
  if (t->mask.is_ip6)
    tss6_store (t, &key->kv6, value);
  else
    tss4_store (t, &key->kv4, value);
}

static_always_inline void
tss_del (fastacl_tuple_t *t, fastacl_tss_key_t *key)
{
  if (t->mask.is_ip6)
    tss6_del (t, &key->kv6);
  else
    tss4_del (t, &key->kv4);
}

static void
tss_bihash_insert (fastacl_main_t *fsm, fastacl_tuple_t *t, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_tss_key_t key;
  u32 new_chain_index;
  u64 value;

  tss_key_from_rule (t, &rule->match, &key);

  if (tss_search (t, &key, &value) != 0)
    {
      tss_store (t, &key, tss_rule_value (fsm, rule_index));
      return;
    }

  fastacl_chain_t *chain = tss_chain_for_insert (fsm, t, value, &new_chain_index);
  if (new_chain_index != ~0u)
    tss_store (t, &key, fastacl_val_make_chain (new_chain_index));

  sorted_vec_insert (fsm, &chain->rule_indices, rule_index);
}

static int
tss_bihash_remove (fastacl_main_t *fsm, fastacl_tuple_t *t, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_tss_key_t key;
  u64 value, replacement;

  tss_key_from_rule (t, &rule->match, &key);

  if (tss_search (t, &key, &value) != 0)
    return 0;

  if (!fastacl_val_is_chain (value))
    {
      tss_del (t, &key);
      return 1;
    }

  switch (tss_chain_left (fsm, t, value, rule_index, &replacement))
    {
    case FASTACL_CHAIN_EMPTY:
      tss_del (t, &key);
      break;
    case FASTACL_CHAIN_COLLAPSED:
      tss_store (t, &key, replacement);
      break;
    case FASTACL_CHAIN_KEPT:
      break;
    }
  return 1;
}

static int
tss_value_holds_duplicate (fastacl_main_t *fsm, u64 value, u32 order, const fastacl_match_t *match)
{
  u32 lone_rule_index = fastacl_val_rule_index (value);
  const u32 *candidates = &lone_rule_index;
  u32 n_candidates = 1;

  if (fastacl_val_is_chain (value))
    {
      fastacl_chain_t *chain = pool_elt_at_index (fsm->chains, fastacl_val_chain_index (value));

      candidates = chain->rule_indices;
      n_candidates = vec_len (chain->rule_indices);
    }

  for (u32 i = 0; i < n_candidates; i++)
    {
      fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, candidates[i]);

      if (rule->order == order && clib_memcmp (&rule->match, match, sizeof (*match)) == 0)
	return 1;
    }

  return 0;
}

int
fastacl_tss_rule_exists (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match)
{
  fastacl_tuple_mask_t mask;
  fastacl_tuple_t *t;
  fastacl_tss_key_t key;
  uword *p;
  u64 value;

  mask_from_rule (match, &mask);

  p = hash_get_mem (fsm->tuple_by_mask, &mask);
  if (!p)
    return 0;

  t = pool_elt_at_index (fsm->tuples, p[0]);
  tss_key_from_rule (t, match, &key);
  if (tss_search (t, &key, &value) != 0)
    return 0;

  return tss_value_holds_duplicate (fsm, value, order, match);
}

static void
tss_insert_one (fastacl_main_t *fsm, u32 rule_index, const fastacl_tuple_mask_t *mask)
{
  fastacl_tuple_t *t = tuple_get_or_create (fsm, mask);

  t->n_rules++;
  tss_bihash_insert (fsm, t, rule_index);
}

void
fastacl_tss_insert_rule (fastacl_main_t *fsm, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_tuple_mask_t mask;

  mask_from_rule (&rule->match, &mask);
  tss_insert_one (fsm, rule_index, &mask);

  if (rule_is_family_agnostic (&rule->match))
    {
      mask.is_ip6 = 1;
      tss_insert_one (fsm, rule_index, &mask);
    }
}

static void
tss_remove_one (fastacl_main_t *fsm, u32 rule_index, const fastacl_tuple_mask_t *mask)
{
  uword *p = hash_get_mem (fsm->tuple_by_mask, mask);

  if (!p)
    return;

  fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, p[0]);

  if (!tss_bihash_remove (fsm, t, rule_index))
    return;

  t->n_rules--;

  if (t->n_rules != 0)
    return;

  fastacl_u32_vec_remove_value (tuple_family_vec (fsm, t->mask.is_ip6), t - fsm->tuples);
  hash_unset_mem_free (&fsm->tuple_by_mask, &t->mask);
  tuple_free_resources (t);
  pool_put (fsm->tuples, t);
}

void
fastacl_tuple_chain_stats (fastacl_main_t *fsm, const fastacl_tuple_t *t, u32 *n_chains,
			   u32 *max_depth, u32 *n_chained_rules)
{
  u32 chains = 0, deepest = 0, chained = 0;
  const u32 *ci;

  vec_foreach (ci, t->chain_indices)
    {
      fastacl_chain_t *c = pool_elt_at_index (fsm->chains, *ci);
      u32 depth = vec_len (c->rule_indices);

      chains++;
      chained += depth;
      if (depth > deepest)
	deepest = depth;
    }

  *n_chains = chains;
  *max_depth = deepest;
  *n_chained_rules = chained;
}

void
fastacl_tss_finalize (fastacl_main_t *fsm)
{
  fastacl_tuple_t *t;
  fastacl_chain_t *c;
  pool_foreach (t, fsm->tuples)
    {
      u32 *ci;
      vec_foreach (ci, t->chain_indices)
	{
	  c = pool_elt_at_index (fsm->chains, *ci);
	  vec_sort_with_function (c->rule_indices, fastacl_rule_order_cmp);
	}
    }
}

void
fastacl_tss_remove_rule (fastacl_main_t *fsm, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_tuple_mask_t mask;

  mask_from_rule (&rule->match, &mask);
  tss_remove_one (fsm, rule_index, &mask);

  if (rule_is_family_agnostic (&rule->match))
    {
      mask.is_ip6 = 1;
      tss_remove_one (fsm, rule_index, &mask);
    }
}

static_always_inline int
tss_full_rule_match_ip4 (fastacl_match_t *m, ip4_header_t *ip0, u8 pkt_proto, u16 l4_src_port,
			 u16 l4_dst_port, u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp,
			 u8 pkt_frag_flags)
{
  if (m->flags & FASTACL_MATCH_IS_IP6)
    return 0;
  if (!fastacl_ip4_prefix_match (m->flags, FASTACL_MATCH_DST_PREFIX, &ip0->dst_address,
				 &m->dst_addr.ip4, m->dst_prefix_len))
    return 0;
  if (!fastacl_ip4_prefix_match (m->flags, FASTACL_MATCH_SRC_PREFIX, &ip0->src_address,
				 &m->src_addr.ip4, m->src_prefix_len))
    return 0;
  return fastacl_match_fields (m, pkt_proto, l4_src_port, l4_dst_port, l4, l4_bytes, pkt_len,
			       pkt_dscp, pkt_frag_flags);
}

static_always_inline int
tss_candidate_matches (int is_ip6, fastacl_match_t *m, ip4_header_t *ip, ip6_header_t *ip6,
		       u8 pkt_proto, u16 l4_src_port, u16 l4_dst_port, u8 *l4, u16 l4_bytes,
		       u16 pkt_len, u8 pkt_dscp, u8 pkt_frag_flags)
{
  if (is_ip6)
    return tss_full_rule_match_ip6 (m, ip6, pkt_proto, l4_src_port, l4_dst_port, l4, l4_bytes,
				    pkt_len, pkt_dscp, pkt_frag_flags);
  return tss_full_rule_match_ip4 (m, ip, pkt_proto, l4_src_port, l4_dst_port, l4, l4_bytes, pkt_len,
				  pkt_dscp, pkt_frag_flags);
}

static_always_inline void
tss_consider (fastacl_main_t *fsm, u64 result_value, fastacl_tss_best_t *best, int is_ip6,
	      ip4_header_t *ip, ip6_header_t *ip6, u8 pkt_proto, u16 l4_src_port, u16 l4_dst_port,
	      u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp, u8 pkt_frag_flags)
{
  if (PREDICT_TRUE (!fastacl_val_is_chain (result_value)))
    {
      u32 ri = fastacl_val_rule_index (result_value);
      fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, ri);

      if (!fastacl_rule_outranks (rule, ri, best->rule, best->ri))
	return;

      if (fastacl_val_is_exact (result_value) ||
	  tss_candidate_matches (is_ip6, &rule->match, ip, ip6, pkt_proto, l4_src_port, l4_dst_port,
				 l4, l4_bytes, pkt_len, pkt_dscp, pkt_frag_flags))
	fastacl_tss_best_take (best, ri, rule, fastacl_val_action (result_value));
      return;
    }

  fastacl_chain_t *chain = pool_elt_at_index (fsm->chains, fastacl_val_chain_index (result_value));
  u32 n = vec_len (chain->rule_indices);

  for (u32 i = 0; i < n; i++)
    {
      u32 ri = chain->rule_indices[i];
      fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, ri);
      if (!fastacl_rule_outranks (rule, ri, best->rule, best->ri))
	break;
      if (tss_candidate_matches (is_ip6, &rule->match, ip, ip6, pkt_proto, l4_src_port, l4_dst_port,
				 l4, l4_bytes, pkt_len, pkt_dscp, pkt_frag_flags))
	{
	  fastacl_tss_best_take (best, ri, rule, rule->action.type);
	  break;
	}
    }
}

u32
fastacl_tss_lookup_ip4 (fastacl_main_t *fsm, ip4_header_t *ip, u8 pkt_proto, u16 l4_src_port,
			u16 l4_dst_port, u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp,
			u8 pkt_frag_flags, u8 *action_out)
{
  fastacl_tss_best_t best = { .ri = ~0u, .rule = 0, .action = 0 };
  u32 *ti;

  vec_foreach (ti, fsm->tuple_index_v4)
    {
      fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, *ti);
      clib_bihash_kv_24_8_t kv;
      u64 result_value;
      key_from_packet_ip4 (&t->mask, ip, pkt_proto, &kv);
      if (tss4_search (t, &kv, &result_value) != 0)
	continue;

      tss_consider (fsm, result_value, &best, 0, ip, 0, pkt_proto, l4_src_port, l4_dst_port, l4,
		    l4_bytes, pkt_len, pkt_dscp, pkt_frag_flags);
    }
  *action_out = best.action;
  return best.ri;
}

void
fastacl_tss_prefetch_ip4 (fastacl_main_t *fsm, ip4_header_t *ip, u8 pkt_proto, u16 pkt_len)
{
  u32 *ti;

  vec_foreach (ti, fsm->tuple_index_v4)
    {
      fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, *ti);
      clib_bihash_kv_24_8_t kv;

      key_from_packet_ip4 (&t->mask, ip, pkt_proto, &kv);
      tss4_prefetch (t, &kv);
    }
}

void
fastacl_tss_prefetch_ip6 (fastacl_main_t *fsm, ip6_header_t *ip6, u8 pkt_proto)
{
  u32 *ti;

  vec_foreach (ti, fsm->tuple_index_v6)
    {
      fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, *ti);
      clib_bihash_kv_40_8_t kv;

      key_from_packet_ip6 (&t->mask, ip6, pkt_proto, &kv);
      tss6_prefetch (t, &kv);
    }
}

u32
fastacl_tss_lookup_ip6 (fastacl_main_t *fsm, ip6_header_t *ip6, u8 pkt_proto, u16 l4_src_port,
			u16 l4_dst_port, u8 *l4, u16 l4_bytes, u16 pkt_len, u8 pkt_dscp,
			u8 pkt_frag_flags, u8 *action_out)
{
  fastacl_tss_best_t best = { .ri = ~0u, .rule = 0, .action = 0 };
  u32 *ti;

  vec_foreach (ti, fsm->tuple_index_v6)
    {
      fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, *ti);
      clib_bihash_kv_40_8_t kv;
      u64 result_value;
      key_from_packet_ip6 (&t->mask, ip6, pkt_proto, &kv);
      if (tss6_search (t, &kv, &result_value) != 0)
	continue;

      tss_consider (fsm, result_value, &best, 1, 0, ip6, pkt_proto, l4_src_port, l4_dst_port, l4,
		    l4_bytes, pkt_len, pkt_dscp, pkt_frag_flags);
    }
  *action_out = best.action;
  return best.ri;
}

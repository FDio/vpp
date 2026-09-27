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

static_always_inline int
rule_family (const fastacl_match_t *m)
{
  return !!(m->flags & FASTACL_MATCH_IS_IP6);
}

static_always_inline u8
mask_prefix_set (fastacl_tuple_mask_t *mask, u32 flag, u8 plen)
{
  if (plen)
    mask->flags |= flag;
  else
    mask->flags &= ~flag;
  return plen;
}

static_always_inline u8
match_prefix_len (const fastacl_match_t *m, u32 flag, u8 plen)
{
  return (m->flags & flag) ? plen : 0;
}

static_always_inline void
mask_from_rule (const fastacl_match_t *m, int is_ip6, fastacl_tuple_mask_t *out)
{
  clib_memset (out, 0, sizeof (*out));
  out->flags = m->flags & FASTACL_MATCH_PROTO;
  out->dst_plen =
    mask_prefix_set (out, FASTACL_MATCH_DST_PREFIX,
		     match_prefix_len (m, FASTACL_MATCH_DST_PREFIX, m->dst_prefix_len));
  out->src_plen =
    mask_prefix_set (out, FASTACL_MATCH_SRC_PREFIX,
		     match_prefix_len (m, FASTACL_MATCH_SRC_PREFIX, m->src_prefix_len));
  out->is_ip6 = is_ip6;
}

static_always_inline int
mask_eq (const fastacl_tuple_mask_t *a, const fastacl_tuple_mask_t *b)
{
  return clib_memcmp (a, b, sizeof (*a)) == 0;
}

static_always_inline int
mask_covers (const fastacl_tuple_mask_t *t, const fastacl_tuple_mask_t *r)
{
  return t->is_ip6 == r->is_ip6 && !(t->flags & ~r->flags) && t->dst_plen <= r->dst_plen &&
	 t->src_plen <= r->src_plen;
}

static_always_inline u32
mask_specificity (const fastacl_tuple_mask_t *m)
{
  return 2 * (m->dst_plen + m->src_plen) + !!(m->flags & FASTACL_MATCH_PROTO);
}

static_always_inline u8
plen_relax_ip4 (u8 plen, int gentle)
{
  if (plen == 32)
    return gentle ? 29 : 26;
  if (plen > 24)
    return plen - (gentle ? 2 : 5);
  if (plen > 16)
    return plen - (gentle ? 1 : 4);
  if (plen > 8)
    return plen - (gentle ? 1 : 2);
  return plen;
}

static_always_inline u8
plen_relax_ip6 (u8 plen)
{
  if (plen == 128)
    return 64;
  return plen >= 64 ? 56 : plen - plen % 8;
}

static_always_inline u8
plen_relax (u8 plen, int is_ip6, int gentle)
{
  return is_ip6 ? plen_relax_ip6 (plen) : plen_relax_ip4 (plen, gentle);
}

static_always_inline void
mask_drop_weaker_addr (fastacl_tuple_mask_t *m)
{
  if (!m->dst_plen || !m->src_plen)
    return;
  if (m->src_plen + FASTACL_TM_ADDR_DELTA < m->dst_plen)
    m->src_plen = mask_prefix_set (m, FASTACL_MATCH_SRC_PREFIX, 0);
  else if (m->dst_plen + FASTACL_TM_ADDR_DELTA < m->src_plen)
    m->dst_plen = mask_prefix_set (m, FASTACL_MATCH_DST_PREFIX, 0);
}

static_always_inline void
mask_relax (fastacl_tuple_mask_t *m, int gentle)
{
  mask_drop_weaker_addr (m);
  m->dst_plen =
    mask_prefix_set (m, FASTACL_MATCH_DST_PREFIX, plen_relax (m->dst_plen, m->is_ip6, gentle));
  m->src_plen =
    mask_prefix_set (m, FASTACL_MATCH_SRC_PREFIX, plen_relax (m->src_plen, m->is_ip6, gentle));
}

static_always_inline u8
mask_field_plen (const fastacl_tuple_mask_t *m, int is_src)
{
  return is_src ? m->src_plen : m->dst_plen;
}

static_always_inline void
mask_field_set (fastacl_tuple_mask_t *m, int is_src, u8 plen)
{
  if (is_src)
    m->src_plen = mask_prefix_set (m, FASTACL_MATCH_SRC_PREFIX, plen);
  else
    m->dst_plen = mask_prefix_set (m, FASTACL_MATCH_DST_PREFIX, plen);
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
key_from_rule_ip4 (const fastacl_tuple_mask_t *mask, const fastacl_match_t *m,
		   clib_bihash_kv_24_8_t *kv)
{
  key_from_fields_ip4 (mask->flags, m->dst_addr.ip4.as_u32, mask->dst_plen, m->src_addr.ip4.as_u32,
		       mask->src_plen, m->proto, kv);
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
key_from_rule_ip6 (const fastacl_tuple_mask_t *mask, const fastacl_match_t *m,
		   clib_bihash_kv_40_8_t *kv)
{
  key_from_fields_ip6 (mask->flags, &m->dst_addr.ip6, mask->dst_plen, &m->src_addr.ip6,
		       mask->src_plen, m->proto, kv);
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
  t->bound.index = ~0u;
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
tss_rule_value (fastacl_main_t *fsm, const fastacl_tuple_t *t, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_tuple_mask_t own;

  mask_from_rule (&rule->match, t->mask.is_ip6, &own);
  return fastacl_val_make_rule (
    rule_index, rule_key_complete (&rule->match) && mask_eq (&own, &t->mask), rule->action.type);
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
      *replacement = tss_rule_value (fsm, t, last_ri);
      return FASTACL_CHAIN_COLLAPSED;
    }

  return FASTACL_CHAIN_KEPT;
}

static_always_inline void
tss_key_from_rule (const fastacl_tuple_t *t, const fastacl_match_t *m, fastacl_tss_key_t *key)
{
  if (t->mask.is_ip6)
    key_from_rule_ip6 (&t->mask, m, &key->kv6);
  else
    key_from_rule_ip4 (&t->mask, m, &key->kv4);
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

static u32
tss_bihash_insert (fastacl_main_t *fsm, fastacl_tuple_t *t, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_tss_key_t key;
  u32 new_chain_index;
  u64 value;

  tss_key_from_rule (t, &rule->match, &key);

  if (tss_search (t, &key, &value) != 0)
    {
      tss_store (t, &key, tss_rule_value (fsm, t, rule_index));
      return ~0u;
    }

  fastacl_chain_t *chain = tss_chain_for_insert (fsm, t, value, &new_chain_index);
  if (new_chain_index != ~0u)
    tss_store (t, &key, fastacl_val_make_chain (new_chain_index));

  sorted_vec_insert (fsm, &chain->rule_indices, rule_index);
  return chain - fsm->chains;
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

static int
tuple_holds_duplicate (fastacl_main_t *fsm, fastacl_tuple_t *t, const fastacl_tuple_mask_t *mask,
		       u32 order, const fastacl_match_t *match)
{
  fastacl_tss_key_t key;
  u64 value;

  if (!mask_covers (&t->mask, mask))
    return 0;

  tss_key_from_rule (t, match, &key);
  if (tss_search (t, &key, &value) != 0)
    return 0;

  return tss_value_holds_duplicate (fsm, value, order, match);
}

int
fastacl_tss_rule_exists (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match)
{
  fastacl_tuple_mask_t mask;
  u32 *ti;

  mask_from_rule (match, rule_family (match), &mask);

  vec_foreach (ti, *tuple_family_vec (fsm, mask.is_ip6))
    if (tuple_holds_duplicate (fsm, pool_elt_at_index (fsm->tuples, *ti), &mask, order, match))
      return 1;

  return 0;
}

static void
tuple_order_place (fastacl_main_t *fsm, fastacl_tuple_t *t)
{
  u32 **pv = tuple_family_vec (fsm, t->mask.is_ip6);
  u32 tuple_index = t - fsm->tuples;
  u32 i;

  fastacl_u32_vec_remove_value (pv, tuple_index);
  for (i = 0; i < vec_len (*pv); i++)
    {
      fastacl_tuple_t *other = pool_elt_at_index (fsm->tuples, (*pv)[i]);

      if (fastacl_rule_outranks (&t->bound, t->bound.index, &other->bound, other->bound.index))
	break;
    }
  vec_insert_elts (*pv, &tuple_index, 1, i);
}

static void
tuple_bound_raise (fastacl_main_t *fsm, fastacl_tuple_t *t, const fastacl_rule_t *rule)
{
  if (!fastacl_rule_outranks (rule, rule->index, &t->bound, t->bound.index))
    return;

  t->bound = *rule;
  tuple_order_place (fsm, t);
}

static u32
tuple_select (fastacl_main_t *fsm, const fastacl_tuple_mask_t *mask)
{
  u32 best = ~0u, best_score = 0;
  uword *p;
  u32 *ti;

  if (!fsm->tuple_merge)
    {
      p = hash_get_mem (fsm->tuple_by_mask, mask);
      return p ? p[0] : ~0u;
    }

  vec_foreach (ti, *tuple_family_vec (fsm, mask->is_ip6))
    {
      fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, *ti);
      u32 score = mask_specificity (&t->mask) + 1;

      if (mask_covers (&t->mask, mask) && score > best_score)
	{
	  best = *ti;
	  best_score = score;
	}
    }
  return best;
}

static u32
tuple_add_rule (fastacl_main_t *fsm, u32 tuple_index, u32 rule_index)
{
  fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, tuple_index);
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);

  t->n_rules++;
  rule->tuple_index[t->mask.is_ip6] = tuple_index;
  tuple_bound_raise (fsm, t, rule);
  return tss_bihash_insert (fsm, t, rule_index);
}

static void
tuple_remove_rule (fastacl_main_t *fsm, u32 tuple_index, u32 rule_index)
{
  fastacl_tuple_t *t = pool_elt_at_index (fsm->tuples, tuple_index);

  if (!tss_bihash_remove (fsm, t, rule_index))
    return;

  if (--t->n_rules != 0)
    return;

  fastacl_u32_vec_remove_value (tuple_family_vec (fsm, t->mask.is_ip6), tuple_index);
  hash_unset_mem_free (&fsm->tuple_by_mask, &t->mask);
  tuple_free_resources (t);
  pool_put (fsm->tuples, t);
}

static_always_inline void
rule_own_mask (fastacl_main_t *fsm, u32 rule_index, int is_ip6, fastacl_tuple_mask_t *m)
{
  mask_from_rule (&pool_elt_at_index (fsm->rules, rule_index)->match, is_ip6, m);
}

static int
chain_split_mask (fastacl_main_t *fsm, const fastacl_tuple_t *t, const u32 *rule_indices,
		  fastacl_tuple_mask_t *target)
{
  u8 hi[2] = { 0, 0 };
  int f, best = -1, best_delta = 0;
  fastacl_tuple_mask_t m;
  const u32 *ri;

  vec_foreach (ri, rule_indices)
    {
      rule_own_mask (fsm, *ri, t->mask.is_ip6, &m);
      if (ri == rule_indices)
	*target = m;
      if (!(m.flags & FASTACL_MATCH_PROTO))
	target->flags &= ~FASTACL_MATCH_PROTO;
      for (f = 0; f < 2; f++)
	{
	  u8 plen = mask_field_plen (&m, f);

	  hi[f] = clib_max (hi[f], plen);
	  if (plen < mask_field_plen (target, f))
	    mask_field_set (target, f, plen);
	}
    }

  for (f = 0; f < 2; f++)
    if (hi[f] - mask_field_plen (target, f) > best_delta)
      {
	best = f;
	best_delta = hi[f] - mask_field_plen (target, f);
      }

  if (best < 0)
    mask_relax (target, 1);
  else
    mask_field_set (target, best, hi[best] - best_delta / 2);

  return mask_covers (&t->mask, target) && !mask_eq (&t->mask, target);
}

static_always_inline u32
chain_len (fastacl_main_t *fsm, u32 chain_index)
{
  return chain_index == ~0u ? 0 :
			      vec_len (pool_elt_at_index (fsm->chains, chain_index)->rule_indices);
}

static_always_inline int
chain_over_threshold (fastacl_main_t *fsm, u32 chain_index)
{
  return fsm->tuple_merge && chain_len (fsm, chain_index) > FASTACL_TM_SPLIT_THRESHOLD;
}

static_always_inline int
chain_needs_split (fastacl_main_t *fsm, u32 chain_index)
{
  return chain_over_threshold (fsm, chain_index) &&
	 is_pow2 (chain_len (fsm, chain_index) - FASTACL_TM_SPLIT_THRESHOLD);
}

static u32
tuple_move_rules (fastacl_main_t *fsm, u32 from, u32 to, const u32 *rule_indices)
{
  fastacl_tuple_mask_t target = pool_elt_at_index (fsm->tuples, to)->mask, own;
  u32 deepest = ~0u;
  const u32 *ri;

  vec_foreach (ri, rule_indices)
    {
      rule_own_mask (fsm, *ri, target.is_ip6, &own);
      if (!mask_covers (&target, &own))
	continue;
      tuple_remove_rule (fsm, from, *ri);
      u32 chain_index = tuple_add_rule (fsm, to, *ri);
      if (chain_len (fsm, chain_index) > chain_len (fsm, deepest))
	deepest = chain_index;
    }
  return deepest;
}

static void
tuple_split_chain (fastacl_main_t *fsm, u32 tuple_index, u32 chain_index)
{
  u32 *moved = vec_dup (pool_elt_at_index (fsm->chains, chain_index)->rule_indices);
  fastacl_tuple_mask_t target;
  u32 to, deepest;

  if (chain_split_mask (fsm, pool_elt_at_index (fsm->tuples, tuple_index), moved, &target))
    {
      to = tuple_get_or_create (fsm, &target) - fsm->tuples;
      deepest = tuple_move_rules (fsm, tuple_index, to, moved);
      if (chain_over_threshold (fsm, deepest))
	tuple_split_chain (fsm, to, deepest);
    }
  vec_free (moved);
}

static void
tss_insert_one (fastacl_main_t *fsm, u32 rule_index, int is_ip6)
{
  fastacl_tuple_mask_t mask;
  u32 tuple_index, chain_index;

  mask_from_rule (&pool_elt_at_index (fsm->rules, rule_index)->match, is_ip6, &mask);
  tuple_index = tuple_select (fsm, &mask);
  if (tuple_index == ~0u)
    {
      if (fsm->tuple_merge)
	mask_relax (&mask, 0);
      tuple_index = tuple_get_or_create (fsm, &mask) - fsm->tuples;
    }

  chain_index = tuple_add_rule (fsm, tuple_index, rule_index);
  if (chain_needs_split (fsm, chain_index))
    tuple_split_chain (fsm, tuple_index, chain_index);
}

void
fastacl_tss_insert_rule (fastacl_main_t *fsm, u32 rule_index)
{
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  int is_ip6 = rule_family (&rule->match);
  int agnostic = rule_is_family_agnostic (&rule->match);

  tss_insert_one (fsm, rule_index, is_ip6);
  if (agnostic)
    tss_insert_one (fsm, rule_index, 1);
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
  u32 v4_tuple = rule->tuple_index[0], v6_tuple = rule->tuple_index[1];
  int agnostic = rule_is_family_agnostic (&rule->match);

  tuple_remove_rule (fsm, rule_family (&rule->match) ? v6_tuple : v4_tuple, rule_index);
  if (agnostic)
    tuple_remove_rule (fsm, v6_tuple, rule_index);
}

static_always_inline int
tuple_outranked (const fastacl_tuple_t *t, const fastacl_tss_best_t *best)
{
  return !fastacl_rule_outranks (&t->bound, t->bound.index, best->rule, best->ri);
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

      if (tuple_outranked (t, &best))
	break;
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

      if (tuple_outranked (t, &best))
	break;
      key_from_packet_ip6 (&t->mask, ip6, pkt_proto, &kv);
      if (tss6_search (t, &kv, &result_value) != 0)
	continue;

      tss_consider (fsm, result_value, &best, 1, 0, ip6, pkt_proto, l4_src_port, l4_dst_port, l4,
		    l4_bytes, pkt_len, pkt_dscp, pkt_frag_flags);
    }
  *action_out = best.action;
  return best.ri;
}

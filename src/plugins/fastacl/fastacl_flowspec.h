/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_flowspec_h__
#define __included_fastacl_flowspec_h__

#include <fastacl/fastacl_types.h>

static_always_inline int
fastacl_fs_prefix_cmp (const ip46_address_t *aa, u8 apl, const ip46_address_t *ba, u8 bpl,
		       int is_ip6)
{
  u8 common = clib_min (apl, bpl);
  int cmp = 0;

  if (common)
    {
      ip46_address_t a = *aa, b = *ba;

      if (is_ip6)
	{
	  ip6_address_normalize (&a.ip6, common);
	  ip6_address_normalize (&b.ip6, common);
	  cmp = clib_memcmp (a.ip6.as_u8, b.ip6.as_u8, sizeof (a.ip6));
	}
      else
	{
	  ip4_address_normalize (&a.ip4, common);
	  ip4_address_normalize (&b.ip4, common);
	  cmp = clib_memcmp (a.ip4.as_u8, b.ip4.as_u8, sizeof (a.ip4));
	}
    }

  if (cmp)
    return cmp < 0 ? -1 : 1;

  if (apl != bpl)
    return apl > bpl ? -1 : 1;
  return 0;
}

static_always_inline int
fastacl_fs_u32_cmp (u32 a, u32 b)
{
  return (a > b) - (a < b);
}

static_always_inline int
fastacl_fs_pair_cmp (u32 a1, u32 a2, u32 b1, u32 b2)
{
  int c = fastacl_fs_u32_cmp (a1, b1);
  return c ? c : fastacl_fs_u32_cmp (a2, b2);
}

static_always_inline int
fastacl_fs_presence_cmp (u32 fa, u32 fb, u32 bit)
{
  return !!(fb & bit) - !!(fa & bit);
}

static_always_inline int
fastacl_flowspec_cmp (const fastacl_match_t *a, const fastacl_match_t *b)
{
  u32 fa = a->flags, fb = b->flags;
  int a6 = !!(fa & FASTACL_MATCH_IS_IP6), b6 = !!(fb & FASTACL_MATCH_IS_IP6);

  if (a6 != b6)
    return a6 ? 1 : -1;

#define COMPONENT(BIT, CMPEXPR)                                                                    \
  do                                                                                               \
    {                                                                                              \
      int _c = fastacl_fs_presence_cmp (fa, fb, (BIT));                                            \
      if (!_c && (fa & (BIT)))                                                                     \
	_c = (CMPEXPR);                                                                            \
      if (_c)                                                                                      \
	return _c;                                                                                 \
    }                                                                                              \
  while (0)

  COMPONENT (FASTACL_MATCH_DST_PREFIX, fastacl_fs_prefix_cmp (&a->dst_addr, a->dst_prefix_len,
							      &b->dst_addr, b->dst_prefix_len, a6));
  COMPONENT (FASTACL_MATCH_SRC_PREFIX, fastacl_fs_prefix_cmp (&a->src_addr, a->src_prefix_len,
							      &b->src_addr, b->src_prefix_len, a6));
  COMPONENT (FASTACL_MATCH_PROTO, fastacl_fs_u32_cmp (a->proto, b->proto));
  COMPONENT (FASTACL_MATCH_EITHER_PORT,
	     fastacl_fs_pair_cmp (a->either_port_min, a->either_port_max, b->either_port_min,
				  b->either_port_max));
  COMPONENT (FASTACL_MATCH_DST_PORT, fastacl_fs_pair_cmp (a->dst_port_min, a->dst_port_max,
							  b->dst_port_min, b->dst_port_max));
  COMPONENT (FASTACL_MATCH_SRC_PORT, fastacl_fs_pair_cmp (a->src_port_min, a->src_port_max,
							  b->src_port_min, b->src_port_max));
  COMPONENT (FASTACL_MATCH_ICMP_TYPE, fastacl_fs_u32_cmp (a->icmp_type, b->icmp_type));
  COMPONENT (FASTACL_MATCH_ICMP_CODE, fastacl_fs_u32_cmp (a->icmp_code, b->icmp_code));
  COMPONENT (FASTACL_MATCH_TCP_FLAGS, fastacl_fs_pair_cmp (a->tcp_flags_value, a->tcp_flags_mask,
							   b->tcp_flags_value, b->tcp_flags_mask));
  COMPONENT (FASTACL_MATCH_PKT_LEN,
	     fastacl_fs_pair_cmp (a->pkt_len_min, a->pkt_len_max, b->pkt_len_min, b->pkt_len_max));
  COMPONENT (FASTACL_MATCH_DSCP, fastacl_fs_u32_cmp (a->dscp, b->dscp));
  COMPONENT (FASTACL_MATCH_FRAGMENT, fastacl_fs_pair_cmp (a->fragment_flags, a->fragment_mask,
							  b->fragment_flags, b->fragment_mask));
#undef COMPONENT
  return 0;
}

static_always_inline int
fastacl_rule_precedence_cmp (const fastacl_rule_t *ra, u32 ai, const fastacl_rule_t *rb, u32 bi)
{
  int c = fastacl_fs_u32_cmp (ra->order, rb->order);
  if (c)
    return c;
  c = fastacl_flowspec_cmp (&ra->match, &rb->match);
  if (c)
    return c;
  return fastacl_fs_u32_cmp (ai, bi);
}

static_always_inline int
fastacl_rule_outranks (const fastacl_rule_t *cand, u32 cand_ri, const fastacl_rule_t *best,
		       u32 best_ri)
{
  if (best_ri == ~0u)
    return 1;
  return fastacl_rule_precedence_cmp (cand, cand_ri, best, best_ri) < 0;
}

#endif

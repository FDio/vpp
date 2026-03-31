/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __IPSEC_SPD_POLICY_H__
#define __IPSEC_SPD_POLICY_H__

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/ipsec/ipsec_spd.h>
/**
 * calculated as max number of flows (2^10) divided by KVP_PER_PAGE (4)
 */
#define IPSEC_FP_HASH_LOOKUP_HASH_BUCKETS (1 << 8)

#define IPSEC_POLICY_PROTOCOL_ANY IP_PROTOCOL_RESERVED

/**
 * This number is calculated as ceil power of 2 for the number
 * sizeof(clib_bihash_kv_16_8_t)=24 * BIHASH_KVP_PER_PAGE=4 * COLLISIONS_NO=8
 *
 */

#define IPSEC_FP_IP4_HASH_MEM_PER_BUCKET 1024

/**
 * This number is calculated as ceil power of 2 for the number
 * sizeof(clib_bihash_kv_40_8_t)=48 * BIHASH_KVP_PER_PAGE=4 * COLLISIONS_NO=8
 *
 */
#define IPSEC_FP_IP6_HASH_MEM_PER_BUCKET 2048

#define foreach_ipsec_policy_action \
  _ (0, BYPASS, "bypass")           \
  _ (1, DISCARD, "discard")         \
  _ (2, RESOLVE, "resolve")         \
  _ (3, PROTECT, "protect")

typedef enum
{
#define _(v, f, s) IPSEC_POLICY_ACTION_##f = v,
  foreach_ipsec_policy_action
#undef _
} ipsec_policy_action_t;

#define IPSEC_POLICY_N_ACTION (IPSEC_POLICY_ACTION_PROTECT + 1)

typedef struct
{
  ip46_address_t start, stop;
} ip46_address_range_t;

typedef struct
{
  u16 start, stop;
} port_range_t;

/**
 * @brief
 * Policy packet & bytes counters
 */
extern vlib_combined_counter_main_t ipsec_spd_policy_counters;

/**
 * @brief A Secruity Policy. An entry in an SPD
 */
typedef struct ipsec_policy_t_
{
  u32 id;
  i32 priority;

  // the type of policy
  ipsec_spd_policy_type_t type;

  // Selector
  u8 is_ipv6;
  ip46_address_range_t laddr;
  ip46_address_range_t raddr;
  u8 protocol;
  port_range_t lport;
  port_range_t rport;

  // Policy
  ipsec_policy_action_t policy;
  u32 sa_id;
  u32 sa_index;
  u32 fp_mask_type_id;
} ipsec_policy_t;

/**
 * @brief Add/Delete a SPD
 */
extern int ipsec_add_del_policy (vlib_main_t * vm,
				 ipsec_policy_t * policy,
				 int is_add, u32 * stat_index);

extern u8 *format_ipsec_policy (u8 * s, va_list * args);
extern u8 *format_ipsec_policy_action (u8 * s, va_list * args);
extern uword unformat_ipsec_policy_action (unformat_input_t * input,
					   va_list * args);


extern int ipsec_policy_mk_type (bool is_outbound,
				 bool is_ipv6,
				 ipsec_policy_action_t action,
				 ipsec_spd_policy_type_t * type);

/* A 5-tuple used to calculate the bihash entry  */
typedef union
{
  struct
  {
    union
    {
      struct
      {
	u32 l3_zero_pad[6];
	ip4_address_t laddr;
	ip4_address_t raddr;
      };
      struct
      {
	ip6_address_t ip6_laddr;
	ip6_address_t ip6_raddr;
      };
    };
    union
    {
      struct
      {
	u16 lport;
	u16 rport;
      };
      u32 spi;
    };
    u8 protocol;
    u8 action;
    u16 is_ipv6;
  };
  /* for ipv6 */
  clib_bihash_kv_40_8_t kv_40_8;
  /* for ipv4 */
  struct
  {
    u64 padding_for_kv_16_8[3];
    clib_bihash_kv_16_8_t kv_16_8;
  };
} ipsec_fp_5tuple_t;

/*
 * An element describing a particular policy  mask,
 * and refcount of policies with same mask.
 */
typedef struct
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ipsec_fp_5tuple_t mask;
  u32 refcount; /* counts how many policies use this mask */
} ipsec_fp_mask_type_entry_t;

/*
 * Bihash lookup value,
 * contains an unordered vector of policies indices in policy pool.
 */
typedef union
{
  u64 as_u64;
  struct
  {
    u32 *fp_policies_ids;
  };
} ipsec_fp_lookup_value_t;

/**
 *  @brief add or delete a fast path policy
 */
int ipsec_fp_add_del_policy (void *fp_spd, ipsec_policy_t *policy, int is_add,
			     u32 *stat_index);

static_always_inline u32
ipsec_spd_ip4_range_match_slot (const ipsec_policy_ip4_match4_t *match, u32 la, u32 ra)
{
  u32 lah = clib_net_to_host_u32 (la);
  u32 rah = clib_net_to_host_u32 (ra);
  u32 rv;

#if defined(CLIB_HAVE_VEC256)
  {
    ipsec_policy_ip4_addr_pair_t pair = {
      .laddr = lah,
      .raddr = rah,
    };
    u32x8 addr = (u32x8) u64x4_splat (pair.as_u64);
    u32x8 cmp = (addr >= match->start.as_u32x8) & (addr <= match->stop.as_u32x8);
    rv = u8x32_msb_mask ((u8x32) ((u64x4) cmp == u64x4_splat (~0)));
    return rv ? count_trailing_zeros (rv) >> 3 : ~0;
  }
#elif defined(CLIB_HAVE_VEC128)
  {
    ipsec_policy_ip4_addr_pair_t pair = {
      .laddr = lah,
      .raddr = rah,
    };
    u32x4 addr = (u32x4) u64x2_splat (pair.as_u64);
    u32x4 cmp = (addr >= match->start.as_u32x4[0]) & (addr <= match->stop.as_u32x4[0]);

    rv = u8x16_msb_mask ((u8x16) ((u64x2) cmp == u64x2_splat (~0)));
    if (rv)
      return count_trailing_zeros (rv) >> 3;

    cmp = (addr >= match->start.as_u32x4[1]) & (addr <= match->stop.as_u32x4[1]);
    rv = u8x16_msb_mask ((u8x16) ((u64x2) cmp == u64x2_splat (~0)));
    return rv ? 2 + (count_trailing_zeros (rv) >> 3) : ~0;
  }
#else
  {
    for (rv = 0; rv < ARRAY_LEN (match->start.pair); rv++)
      {
	if (lah < match->start.pair[rv].laddr)
	  continue;
	if (lah > match->stop.pair[rv].laddr)
	  continue;
	if (rah < match->start.pair[rv].raddr)
	  continue;
	if (rah > match->stop.pair[rv].raddr)
	  continue;

	return rv;
      }

    return ~0;
  }
#endif
}

static_always_inline u32
ipsec_spd_ip4_find_range_match (const ipsec_spd_t *spd, ipsec_spd_policy_type_t type, u32 la,
				u32 ra)
{
  u32 len = vec_len (spd->policies[type]);
  typeof (spd->ip4_policies[type][0]) *p = spd->ip4_policies[type];

  for (u32 i = 0; i < len; i += 4, p += 1)
    {
      u32 slot = ipsec_spd_ip4_range_match_slot (p, la, ra);

      if (slot != ~0 && i + slot < len)
	return i + slot;
    }

  return ~0;
}

static_always_inline int
ipsec_policy_is_equal (ipsec_policy_t *p1, ipsec_policy_t *p2)
{
  if (p1->priority != p2->priority)
    return 0;
  if (p1->type != p2->type)
    return (0);
  if (p1->policy != p2->policy)
    return (0);
  if (p1->sa_id != p2->sa_id)
    return (0);
  if (p1->protocol != p2->protocol)
    return (0);
  if (p1->lport.start != p2->lport.start)
    return (0);
  if (p1->lport.stop != p2->lport.stop)
    return (0);
  if (p1->rport.start != p2->rport.start)
    return (0);
  if (p1->rport.stop != p2->rport.stop)
    return (0);
  if (p1->is_ipv6 != p2->is_ipv6)
    return (0);
  if (p2->is_ipv6)
    {
      if (p1->laddr.start.ip6.as_u64[0] != p2->laddr.start.ip6.as_u64[0])
	return (0);
      if (p1->laddr.start.ip6.as_u64[1] != p2->laddr.start.ip6.as_u64[1])
	return (0);
      if (p1->laddr.stop.ip6.as_u64[0] != p2->laddr.stop.ip6.as_u64[0])
	return (0);
      if (p1->laddr.stop.ip6.as_u64[1] != p2->laddr.stop.ip6.as_u64[1])
	return (0);
      if (p1->raddr.start.ip6.as_u64[0] != p2->raddr.start.ip6.as_u64[0])
	return (0);
      if (p1->raddr.start.ip6.as_u64[1] != p2->raddr.start.ip6.as_u64[1])
	return (0);
      if (p1->raddr.stop.ip6.as_u64[0] != p2->raddr.stop.ip6.as_u64[0])
	return (0);
      if (p1->laddr.stop.ip6.as_u64[1] != p2->laddr.stop.ip6.as_u64[1])
	return (0);
    }
  else
    {
      if (p1->laddr.start.ip4.as_u32 != p2->laddr.start.ip4.as_u32)
	return (0);
      if (p1->laddr.stop.ip4.as_u32 != p2->laddr.stop.ip4.as_u32)
	return (0);
      if (p1->raddr.start.ip4.as_u32 != p2->raddr.start.ip4.as_u32)
	return (0);
      if (p1->raddr.stop.ip4.as_u32 != p2->raddr.stop.ip4.as_u32)
	return (0);
    }
  return (1);
}

#endif /* __IPSEC_SPD_POLICY_H__ */

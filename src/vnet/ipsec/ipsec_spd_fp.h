/*
 *------------------------------------------------------------------
 * Copyright (c) 2022 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef IPSEC_SPD_FP_H
#define IPSEC_SPD_FP_H

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_16_8.h>

#define IPSEC_FP_HASH_LOOKUP_HASH_BUCKETS (2 << 20)
#define IPSEC_FP_HASH_LOOKUP_HASH_MEMORY  (2 << 25)

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
      ip6_address_t ip6_laddr;
      ip6_address_t ip6_raddr;
    };

    u16 lport;
    u16 rport;
    u16 protocol;
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

typedef struct ipsec_policy_t_ ipsec_policy_t;

/**
 *  @brief add or delete a fast path policy
 */
int ipsec_fp_add_del_policy (void *fp_spd, ipsec_policy_t *policy, int is_add);

#endif /* !IPSEC_SPD_FP_H */

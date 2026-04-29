/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vppinfra/types.h>
#include <vppinfra/bihash_24_8.h>

enum lpm_type_e
{
  LPM_TYPE_KEY32,
  LPM_TYPE_KEY128,
  /* IPv4 LPM keyed on (fib_index, addr); the 32-bit address is widened by
   * prefixing it with the full 32-bit fib_index so two tenants with
   * overlapping v4 prefixes are distinguishable. Composite key fits
   * inside a single uword on 64-bit hosts. */
  LPM_TYPE_KEY_VRF_V4,
};

typedef struct lpm_ {
  /* Default (fib-agnostic) callers. */
  void (*add) (struct lpm_ *lpm, void *addr_v, u8 pfxlen, u32 value);
  void (*delete) (struct lpm_ *lpm, void *addr_v, u8 pfxlen);
  u32 (*lookup) (struct lpm_ *lpm, void *addr_v, u8 pfxlen);

  /* Per-VRF callers. Only populated for LPM_TYPE_KEY_VRF_V4. */
  void (*add_vrf) (struct lpm_ *lpm, u32 fib_index, void *addr_v, u8 pfxlen, u32 value);
  void (*delete_vrf) (struct lpm_ *lpm, u32 fib_index, void *addr_v, u8 pfxlen);
  u32 (*lookup_vrf) (struct lpm_ *lpm, u32 fib_index, void *addr_v, u8 pfxlen);

  /* IPv4 LPM */
  uword *hash[33];

  /* IPv6 LPM */
  BVT (clib_bihash) bihash;
  uword *prefix_lengths_bitmap;
  u32 prefix_length_refcount[129];
} lpm_t;

lpm_t *lpm_table_init (enum lpm_type_e lpm_type);

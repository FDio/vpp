/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __CNAT_SNAT_H__
#define __CNAT_SNAT_H__

#include <cnat/cnat_types.h>

/* function to use to decide whether to snat connections in the output
 * feature. Returns 1 if we should source NAT */
typedef int (*cnat_snat_policy_t) (vlib_buffer_t *b, ip_address_family_t af,
				   ip4_header_t *ip4, ip6_header_t *ip6,
				   ip_protocol_t iproto, udp_header_t *udp0);

typedef struct cnat_snat_pfx_table_meta_t_
{
  u32 dst_address_length_refcounts[129];
  u16 *prefix_lengths_in_search_order;
  uword *non_empty_dst_address_length_bitmap;
} cnat_snat_pfx_table_meta_t;

typedef struct cnat_snat_exclude_pfx_table_t_
{
  /* Stores (ip family, prefix & mask) */
  clib_bihash_24_8_t ip_hash;
  /* family dependant cache */
  cnat_snat_pfx_table_meta_t meta[2];
  /* Precomputed ip masks (ip4 & ip6) */
  ip6_address_t ip_masks[129];
} cnat_snat_exclude_pfx_table_t;

typedef enum cnat_snat_interface_map_type_t_
{
  CNAT_SNAT_IF_MAP_INCLUDE_V4 = AF_IP4,
  CNAT_SNAT_IF_MAP_INCLUDE_V6 = AF_IP6,
  CNAT_SNAT_IF_MAP_INCLUDE_POD,
  /* CNAT_SNAT_IF_MAP_INCLUDE_HOST is used for interfaces used for punt,
     replicating uplink */
  CNAT_SNAT_IF_MAP_INCLUDE_HOST,
  CNAT_N_SNAT_IF_MAP,
} __clib_packed cnat_snat_interface_map_type_t;

typedef enum cnat_snat_policy_type_t_
{
  CNAT_SNAT_POLICY_NONE = 0,
  CNAT_SNAT_POLICY_IF_PFX = 1,
  CNAT_SNAT_POLICY_K8S = 2,
} __clib_packed cnat_snat_policy_type_t;

typedef enum cnat_snat_policy_flags_t_
{
  CNAT_SNAT_POLICY_FLAG_NONE = 0,
  CNAT_SNAT_POLICY_FLAG_BUFFER_NEXT = 1,
} __clib_packed cnat_snat_policy_flags_t;
STATIC_ASSERT (CNAT_SNAT_POLICY_FLAG_BUFFER_NEXT < (1 << 4), "Value too big");

typedef struct cnat_snat_policy_entry_t_
{
  /* Longest prefix Match table for source NATing */
  cnat_snat_exclude_pfx_table_t excluded_pfx;

  /* interface maps including or excluding sw_if_indexes  */
  clib_bitmap_t *interface_maps[CNAT_N_SNAT_IF_MAP];

  /* Ip4 Address to use for source NATing */
  cnat_endpoint_t snat_ip4;

  /* Ip6 Address to use for source NATing */
  cnat_endpoint_t snat_ip6;

  u64 snat_ip6_mask;
  u32 snat_ip4_mask;

  u32 cti;

  u32 fwd_fib_index4;
  u32 fwd_fib_index6;

  u32 ret_fib_index4;
  u32 ret_fib_index6;

  /* SNAT policy for the output feature node */
  cnat_snat_policy_t snat_policy;

  cnat_snat_policy_flags_t flags;

} cnat_snat_policy_entry_t;

typedef struct cnat_snat_policy_main_t_
{
  cnat_snat_policy_entry_t *snat_policies_pool;
  u32 *snat_policy_per_fwd_fib_index4;
  u32 *snat_policy_per_fwd_fib_index6;
} cnat_snat_policy_main_t;

extern cnat_snat_policy_main_t cnat_snat_policy_main;

extern int cnat_set_snat (u32 fwd_fib_index, u32 ret_fib_index,
			  const ip4_address_t *ip4, u8 ip4_pfx_len,
			  const ip6_address_t *ip6, u8 ip6_pfx_len,
			  u32 sw_if_index, cnat_snat_policy_flags_t flags);
extern int cnat_snat_policy_add_pfx (ip_prefix_t *pfx);
extern int cnat_snat_policy_del_pfx (ip_prefix_t *pfx);
extern int cnat_set_snat_policy (cnat_snat_policy_type_t policy);
extern int cnat_snat_policy_add_del_if (u32 sw_if_index, u8 is_add,
					cnat_snat_interface_map_type_t table);

int cnat_search_snat_prefix (ip46_address_t *addr, ip_address_family_t af);

static_always_inline cnat_snat_policy_entry_t *
cnat_snat_policy_entry_get (ip_address_family_t af, u32 fwd_fib_index)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  u32 *cp_fwd_fib_index = AF_IP4 == af ? cpm->snat_policy_per_fwd_fib_index4 :
					       cpm->snat_policy_per_fwd_fib_index6;
  if (fwd_fib_index >= vec_len (cp_fwd_fib_index))
    return 0;
  u32 cpe_index = vec_elt (cp_fwd_fib_index, fwd_fib_index);
  if (~0 == cpe_index)
    return 0;
  return pool_elt_at_index (cpm->snat_policies_pool, cpe_index);
}

cnat_snat_policy_entry_t *cnat_snat_policy_entry_get_default (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif

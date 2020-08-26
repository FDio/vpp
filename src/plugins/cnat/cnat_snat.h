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


extern void cnat_set_snat (ip4_address_t * ip4, ip6_address_t * ip6,
			   u32 sw_if_index);
extern int cnat_add_snat_prefix (ip_prefix_t * pfx);
extern int cnat_del_snat_prefix (ip_prefix_t * pfx);

typedef struct
{
  u32 dst_address_length_refcounts[129];
  u16 *prefix_lengths_in_search_order;
  uword *non_empty_dst_address_length_bitmap;
} cnat_snat_pfx_table_meta_t;

typedef struct
{
  /* Stores (ip family, prefix & mask) */
  clib_bihash_24_8_t ip_hash;
  /* family dependant cache */
  cnat_snat_pfx_table_meta_t meta[2];
  /* Precomputed ip masks (ip4 & ip6) */
  ip6_address_t ip_masks[129];
} cnat_snat_pfx_table_t;

typedef struct cnat_snat_main_t_
{
  /* Longest prefix Match table for source NATing */
  cnat_snat_pfx_table_t snat_pfx_table;

  /* Bitmap */
  clib_bitmap_t *snat_interfaces_bm[N_AF];
} cnat_snat_main_t;

extern cnat_snat_main_t cnat_snat_main;

int cnat_search_snat_prefix (ip46_address_t * addr, ip_address_family_t af);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif

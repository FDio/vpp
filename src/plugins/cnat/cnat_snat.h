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

always_inline int
cnat_search_snat_prefix (ip46_address_t * addr, ip_address_family_t af)
{
  /* Returns 0 if addr matches any of the listed prefixes */
  cnat_snat_pfx_table_t *table = &cnat_main.snat_pfx_table;
  clib_bihash_kv_24_8_t kv, val;
  int i, n_p, rv;
  n_p = vec_len (table->meta[af].prefix_lengths_in_search_order);
  if (AF_IP4 == af)
    {
      kv.key[0] = addr->ip4.as_u32;
      kv.key[1] = 0;
    }
  else
    {
      kv.key[0] = addr->as_u64[0];
      kv.key[1] = addr->as_u64[1];
    }

  /*
   * start search from a mask length same length or shorter.
   * we don't want matches longer than the mask passed
   */
  i = 0;
  for (; i < n_p; i++)
    {
      int dst_address_length =
	table->meta[af].prefix_lengths_in_search_order[i];
      ip6_address_t *mask = &table->ip_masks[dst_address_length];

      ASSERT (dst_address_length >= 0 && dst_address_length <= 128);
      /* As lengths are decreasing, masks are increasingly specific. */
      kv.key[0] &= mask->as_u64[0];
      kv.key[1] &= mask->as_u64[1];
      kv.key[2] = ((u64) af << 32) | dst_address_length;
      rv = clib_bihash_search_inline_2_24_8 (&table->ip_hash, &kv, &val);
      if (rv == 0)
	return 0;
    }
  return -1;
}

extern void cnat_set_snat (ip4_address_t * ip4, ip6_address_t * ip6,
			   u32 sw_if_index);
extern int cnat_add_snat_prefix (ip_prefix_t * pfx);
extern int cnat_del_snat_prefix (ip_prefix_t * pfx);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif

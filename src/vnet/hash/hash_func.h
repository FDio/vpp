/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef __VNET_HASH_FUNC_H__
#define __VNET_HASH_FUNC_H__

#include <vnet/hash/hash.h>

static_always_inline void
hash_func_with_mask (vlib_buffer_t **b, u32 *hash, u32 n_packets,
		     u32 *lookup_table, u32 mask, vnet_hash_func tx_hash_func)
{
  u32 n_left_from = n_packets;

  /*
   * FIXME: function to be part of which
   * dev_class, hw_class, hardware_itf ?
   */
  if (tx_hash_func)
    tx_hash_func ((void **) b, hash, n_packets);
  else
    /*
     * use default function, hash set to 0
     */
    clib_memset_u32 (hash, 0, n_packets);

  // any vectorization possible ?
  while (n_left_from >= 4)
    {
      hash[0] = lookup_table[(hash[0] & mask)];
      hash[1] = lookup_table[(hash[1] & mask)];
      hash[2] = lookup_table[(hash[2] & mask)];
      hash[3] = lookup_table[(hash[3] & mask)];

      hash += 4;
      n_left_from -= 4;
    }

  while (n_left_from > 0)
    {
      hash[0] = lookup_table[(hash[0] & mask)];

      hash += 1;
      n_left_from -= 1;
    }
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

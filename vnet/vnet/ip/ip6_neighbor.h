/*
 *
 * ip6_neighboor.h: ip6 neighbor structures
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_ip6_neighbor_h
#define included_ip6_neighbor_h

#include <vnet/fib/fib_types.h>

typedef struct {
  ip6_address_t ip6_address;
  u32 sw_if_index;
  u32 pad;
} ip6_neighbor_key_t;

typedef struct {
  ip6_neighbor_key_t key;
  u8 link_layer_address[8];
  u16 flags;
#define IP6_NEIGHBOR_FLAG_STATIC (1 << 0)
#define IP6_NEIGHBOR_FLAG_DYNAMIC  (2 << 0)
  u64 cpu_time_last_updated;
  fib_node_index_t fib_entry_index;
} ip6_neighbor_t;

ip6_neighbor_t * ip6_neighbors_entries (u32 sw_if_index);

#endif  /* included_ip6_neighbor_h */

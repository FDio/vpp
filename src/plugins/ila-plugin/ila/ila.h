/*
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

#ifndef ILA_H
#define ILA_H

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_node.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

#define ila_foreach_type		\
  _(IID, 0, "iid")			\
  _(LUID, 1, "luid")			\
  _(VNID4, 2, "vnid-ip4")		\
  _(VNID6, 3, "vnid-ip6")		\
  _(VNIDM, 4, "vnid-multicast")

typedef enum {
#define _(i,n,s) ILA_TYPE_##i = n,
  ila_foreach_type
#undef _
} ila_type_t;

#define ila_csum_foreach_type \
_(NO_ACTION, 0, "no-action") \
_(NEUTRAL_MAP, 1, "neutral-map") \
_(ADJUST_TRANSPORT, 2, "adjust-transport")

typedef enum {
#define _(i,n,s) ILA_CSUM_MODE_##i = n,
  ila_csum_foreach_type
#undef _
  ILA_CSUM_N_TYPES
} ila_csum_mode_t;

#define ila_foreach_direction \
_(BIDIR, 0, "bidir") \
_(SIR2ILA, 1, "sir2ila") \
_(ILA2SIR, 2, "ila2sir")

typedef enum {
#define _(i,n,s) ILA_DIR_##i = n,
  ila_foreach_direction
#undef _
} ila_direction_t;

typedef struct {
  /**
   * Fib Node base class
   */
  fib_node_t ila_fib_node;
  ila_type_t type;
  ip6_address_t sir_address;
  ip6_address_t ila_address;
  ip6_address_t next_hop;
  ila_csum_mode_t csum_mode;
  ila_direction_t dir;

  /**
   * The FIB entry index for the next-hop
   */
  fib_node_index_t next_hop_fib_entry_index;

  /**
   * The child index on the FIB entry
   */
  u32 next_hop_child_index;

  /**
   * The next DPO in the grpah to follow
   */
  dpo_id_t ila_dpo;
} ila_entry_t;

typedef struct {
  ila_entry_t *entries;		//Pool of ILA entries

  u64 lookup_table_nbuckets;
  u64 lookup_table_size;
  clib_bihash_24_8_t id_to_entry_table;

  u32 ip6_lookup_next_index;
} ila_main_t;


typedef struct {
  ila_type_t type;
  ip6_address_t sir_address;
  ip6_address_t next_hop_address;
  u64 locator;
  u32 vnid;
  u32 local_adj_index;
  ila_csum_mode_t csum_mode;
  ila_direction_t dir;
  u8 is_del;
} ila_add_del_entry_args_t;

int ila_add_del_entry (ila_add_del_entry_args_t * args);
int ila_interface (u32 sw_if_index, u8 disable);

#endif //ILA_H

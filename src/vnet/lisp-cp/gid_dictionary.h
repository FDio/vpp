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

#ifndef VNET_LISP_GPE_GID_DICTIONARY_H_
#define VNET_LISP_GPE_GID_DICTIONARY_H_

#include <vnet/vnet.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

#define GID_LOOKUP_MISS ((u32)~0)
#define GID_LOOKUP_MISS_L2 ((u64)~0)

/* Default size of the ip4 hash table */
#define IP4_LOOKUP_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define IP4_LOOKUP_DEFAULT_HASH_MEMORY_SIZE (32<<20)

/* Default size of the ip6 hash table */
#define IP6_LOOKUP_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define IP6_LOOKUP_DEFAULT_HASH_MEMORY_SIZE (32<<20)

/* Default size of the MAC hash table */
#define MAC_LOOKUP_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define MAC_LOOKUP_DEFAULT_HASH_MEMORY_SIZE (32<<20)

/* Default size of the ARP hash table */
#define ARP_LOOKUP_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define ARP_LOOKUP_DEFAULT_HASH_MEMORY_SIZE (32<<20)

/* Default size of the NSH hash table */
#define NSH_LOOKUP_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define NSH_LOOKUP_DEFAULT_HASH_MEMORY_SIZE (32<<20)

typedef void (*foreach_subprefix_match_cb_t) (u32, void *);

typedef struct
{
  BVT (clib_bihash) ip4_lookup_table;

  /* bitmap/vector of mask widths to search */
  uword *ip4_non_empty_dst_address_length_bitmap;
  u8 *ip4_prefix_lengths_in_search_order;
  ip4_address_t ip4_fib_masks[33];
  u32 ip4_prefix_len_refcount[33];

  /* ip4 lookup table config parameters */
  u32 ip4_lookup_table_nbuckets;
  uword ip4_lookup_table_size;
  u32 count;
} gid_ip4_table_t;

typedef struct
{
  BVT (clib_bihash) ip6_lookup_table;

  /* bitmap/vector of mask widths to search */
  uword *ip6_non_empty_dst_address_length_bitmap;
  u8 *ip6_prefix_lengths_in_search_order;
  ip6_address_t ip6_fib_masks[129];
  u64 ip6_prefix_len_refcount[129];

  /* ip6 lookup table config parameters */
  u32 ip6_lookup_table_nbuckets;
  uword ip6_lookup_table_size;
  u64 count;
} gid_ip6_table_t;

typedef struct gid_mac_table
{
  BVT (clib_bihash) mac_lookup_table;

  /* mac lookup table config parameters */
  u32 mac_lookup_table_nbuckets;
  uword mac_lookup_table_size;
  u64 count;
} gid_mac_table_t;

typedef struct gid_nsh_table
{
  BVT (clib_bihash) nsh_lookup_table;

  /* nsh lookup table config parameters */
  u32 nsh_lookup_table_nbuckets;
  uword nsh_lookup_table_size;
  u64 count;
} gid_nsh_table_t;

typedef struct
{
  BVT (clib_bihash) arp_lookup_table;
  u32 arp_lookup_table_nbuckets;
  uword arp_lookup_table_size;
  u64 count;
} gid_l2_arp_table_t;

typedef struct
{
  /** L2 ARP table */
  gid_l2_arp_table_t arp_table;

  /** NSH lookup table */
  gid_nsh_table_t nsh_table;

  /** destination IP LPM ip4 lookup table */
  gid_ip4_table_t dst_ip4_table;

  /** pool of source IP LPM ip4 lookup tables */
  gid_ip4_table_t *src_ip4_table_pool;

  /** destination IP LPM ip6 lookup table */
  gid_ip6_table_t dst_ip6_table;

  /** pool of source IP LPM ip6 lookup tables */
  gid_ip6_table_t *src_ip6_table_pool;

  /** flat source/dest mac lookup table */
  gid_mac_table_t sd_mac_table;

} gid_dictionary_t;

u32
gid_dictionary_add_del (gid_dictionary_t * db, gid_address_t * key, u64 value,
			u8 is_add);

u64 gid_dictionary_lookup (gid_dictionary_t * db, gid_address_t * key);
u32 gid_dictionary_sd_lookup (gid_dictionary_t * db, gid_address_t * dst,
			      gid_address_t * src);

void gid_dictionary_init (gid_dictionary_t * db);

void
gid_dict_foreach_subprefix (gid_dictionary_t * db, gid_address_t * eid,
			    foreach_subprefix_match_cb_t cb, void *arg);

void
gid_dict_foreach_l2_arp_entry (gid_dictionary_t * db, void (*cb)
			       (BVT (clib_bihash_kv) * kvp, void *arg),
			       void *ht);

#endif /* VNET_LISP_GPE_GID_DICTIONARY_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

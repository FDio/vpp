/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT plugin virtual fragmentation reassembly
 */
#ifndef __included_nat_reass_h__
#define __included_nat_reass_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/dlist.h>

#define NAT_REASS_TIMEOUT_DEFAULT 2
#define NAT_MAX_REASS_DEAFULT 1024
#define NAT_MAX_FRAG_DEFAULT 5
#define NAT_REASS_HT_LOAD_FACTOR (0.75)

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t src;
      ip4_address_t dst;
      /* align by making this 4 octets even though its a 2 octets field */
      u32 frag_id;
      /* align by making this 4 octets even though its a 1 octet field */
      u32 proto;
    };
    u64 as_u64[2];
  };
} nat_reass_ip4_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  nat_reass_ip4_key_t key;
  u32 lru_list_index;
  u32 sess_index;
  f64 last_heard;
  u32 frags_per_reass_list_head_index;
  u8 frag_n;
}) nat_reass_ip4_t;
/* *INDENT-ON* */

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t src;
      ip6_address_t dst;
      u32 frag_id;
      /* align by making this 4 octets even though its a 1 octet field */
      u32 proto;
      u64 unused;
    };
    u64 as_u64[6];
  };
} nat_reass_ip6_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  nat_reass_ip6_key_t key;
  u32 lru_list_index;
  u32 sess_index;
  f64 last_heard;
  u32 frags_per_reass_list_head_index;
  u8 frag_n;
}) nat_reass_ip6_t;
/* *INDENT-ON* */

typedef struct
{
  /* IPv4 config */
  u32 ip4_timeout;
  u16 ip4_max_reass;
  u8 ip4_max_frag;
  u8 ip4_drop_frag;

  /* IPv6 config */
  u32 ip6_timeout;
  u16 ip6_max_reass;
  u8 ip6_max_frag;
  u8 ip6_drop_frag;

  /* IPv4 runtime */
  nat_reass_ip4_t *ip4_reass_pool;
  clib_bihash_16_8_t ip4_reass_hash;
  dlist_elt_t *ip4_reass_lru_list_pool;
  dlist_elt_t *ip4_frags_list_pool;
  u32 ip4_reass_head_index;
  u16 ip4_reass_n;
  clib_spinlock_t ip4_reass_lock;

  /* IPv6 runtime */
  nat_reass_ip6_t *ip6_reass_pool;
  clib_bihash_48_8_t ip6_reass_hash;
  dlist_elt_t *ip6_reass_lru_list_pool;
  dlist_elt_t *ip6_frags_list_pool;
  u32 ip6_reass_head_index;
  u16 ip6_reass_n;
  clib_spinlock_t ip6_reass_lock;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} nat_reass_main_t;

/**
 * @brief Set NAT virtual fragmentation reassembly configuration.
 *
 * @param timeout   Reassembly timeout.
 * @param max_reass Maximum number of concurrent reassemblies.
 * @param max_frag  Maximum number of fragmets per reassembly
 * @param drop_frag If zero translate fragments, otherwise drop fragments.
 * @param is_ip6    1 if IPv6, 0 if IPv4.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat_reass_set (u32 timeout, u16 max_reass, u8 max_frag, u8 drop_frag,
		   u8 is_ip6);

/**
 * @brief Get reassembly timeout.
 *
 * @param is_ip6 1 if IPv6, 0 if IPv4.
 *
 * @returns reassembly timeout.
 */
u32 nat_reass_get_timeout (u8 is_ip6);

/**
 * @brief Get maximum number of concurrent reassemblies.
 *
 * @param is_ip6 1 if IPv6, 0 if IPv4.
 *
 * @returns maximum number of concurrent reassemblies.
 */
u16 nat_reass_get_max_reass (u8 is_ip6);

/**
 * @brief Get maximum number of fragmets per reassembly.
 *
 * @param is_ip6 1 if IPv6, 0 if IPv4.
 *
 * @returns maximum number of fragmets per reassembly.
 */
u8 nat_reass_get_max_frag (u8 is_ip6);

/**
 * @brief Get status of virtual fragmentation reassembly.
 *
 * @param is_ip6 1 if IPv6, 0 if IPv4.
 *
 * @returns zero if translate fragments, non-zero value if drop fragments.
 */
u8 nat_reass_is_drop_frag (u8 is_ip6);

/**
 * @brief Initialize NAT virtual fragmentation reassembly.
 *
 * @param vm vlib main.
 *
 * @return error code.
 */
clib_error_t *nat_reass_init (vlib_main_t * vm);

/**
 * @brief Find or create reassembly.
 *
 * @param src Source IPv4 address.
 * @param dst Destination IPv4 address.
 * @param frag_id Fragment ID.
 * @param proto L4 protocol.
 * @param reset_timeout If non-zero value reset timeout.
 * @param bi_to_drop Fragments to drop.
 *
 * @returns Reassembly data or 0 on failure.
 */
nat_reass_ip4_t *nat_ip4_reass_find_or_create (ip4_address_t src,
					       ip4_address_t dst,
					       u16 frag_id, u8 proto,
					       u8 reset_timeout,
					       u32 ** bi_to_drop);
/**
 * @brief Cache fragment.
 *
 * @param reass Reassembly data.
 * @param bi Buffer index.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat_ip4_reass_add_fragment (nat_reass_ip4_t * reass, u32 bi);

/**
 * @brief Get cached fragments.
 *
 * @param reass Reassembly data.
 * @param bi Vector of buffer indexes.
 */
void nat_ip4_reass_get_frags (nat_reass_ip4_t * reass, u32 ** bi);

/**
 * @breif Call back function when walking IPv4 reassemblies, non-zero return
 * value stop walk.
 */
typedef int (*nat_ip4_reass_walk_fn_t) (nat_reass_ip4_t * reass, void *ctx);

/**
 * @brief Walk IPv4 reassemblies.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat_ip4_reass_walk (nat_ip4_reass_walk_fn_t fn, void *ctx);

/**
 * @brief Find or create reassembly.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param frag_id Fragment ID.
 * @param proto L4 protocol.
 * @param reset_timeout If non-zero value reset timeout.
 * @param bi_to_drop Fragments to drop.
 *
 * @returns Reassembly data or 0 on failure.
 */
nat_reass_ip6_t *nat_ip6_reass_find_or_create (ip6_address_t src,
					       ip6_address_t dst,
					       u32 frag_id, u8 proto,
					       u8 reset_timeout,
					       u32 ** bi_to_drop);
/**
 * @brief Cache fragment.
 *
 * @param reass Reassembly data.
 * @param bi Buffer index.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat_ip6_reass_add_fragment (nat_reass_ip6_t * reass, u32 bi);

/**
 * @brief Get cached fragments.
 *
 * @param reass Reassembly data.
 * @param bi Vector of buffer indexes.
 */
void nat_ip6_reass_get_frags (nat_reass_ip6_t * reass, u32 ** bi);

/**
 * @breif Call back function when walking IPv6 reassemblies, non-zero return
 * value stop walk.
 */
typedef int (*nat_ip6_reass_walk_fn_t) (nat_reass_ip6_t * reass, void *ctx);

/**
 * @brief Walk IPv6 reassemblies.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat_ip6_reass_walk (nat_ip6_reass_walk_fn_t fn, void *ctx);

#endif /* __included_nat_reass_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

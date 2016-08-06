/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef included_vnet_sr_h
#define included_vnet_sr_h

#include <vnet/vnet.h>
#include <vnet/sr/sr_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <openssl/opensslconf.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>
#include <openssl/hmac.h>

typedef struct
{
  ip6_address_t src;
  ip6_address_t dst;
} ip6_sr_tunnel_key_t;

typedef struct
{
  /* src, dst address */
  ip6_sr_tunnel_key_t key;

  /* optional tunnel name */
  u8 *name;

  /* mask width for FIB entry */
  u32 dst_mask_width;

  /* first hop, to save 1 elt in the segment list */
  ip6_address_t first_hop;

  /* Fib indices */
  u32 rx_fib_index;
  u32 tx_fib_index;

  /* The actual ip6 sr header */
  u8 *rewrite;

  /* Indicates that this tunnel is part of a policy comprising
     of multiple tunnels. */
  u32 policy_index;
} ip6_sr_tunnel_t;

typedef struct
{
  u8 *shared_secret;
} ip6_sr_hmac_key_t;

typedef struct
{
  /* Key (header imposition case) */
  ip6_address_t *src_address;
  ip6_address_t *dst_address;
  u32 dst_mask_width;
  u32 rx_table_id;
  u32 tx_table_id;

  /* optional name argument - for referencing SR tunnel/policy by name */
  u8 *name;

  /* optional policy name */
  u8 *policy_name;

  /* segment list, when inserting an ip6 SR header */
  ip6_address_t *segments;

  /* 
   * "Tag" list, aka segments inserted at the end of the list,
   * past last_seg
   */
  ip6_address_t *tags;

  /* Shared secret => generate SHA-256 HMAC security fields */
  u8 *shared_secret;

  /* Flags, e.g. cleanup, policy-list flags */
  u16 flags_net_byte_order;

  /* Delete the tunnnel? */
  u8 is_del;
} ip6_sr_add_del_tunnel_args_t;

typedef struct
{
  /* policy name */
  u8 *name;

  /* tunnel names */
  u8 **tunnel_names;

  /* Delete the policy? */
  u8 is_del;
} ip6_sr_add_del_policy_args_t;


typedef struct
{
  /* name of policy */
  u8 *name;

  /* vector to SR tunnel index */
  u32 *tunnel_indices;

} ip6_sr_policy_t;

typedef struct
{
  /* multicast IP6 address */
  ip6_address_t *multicast_address;

  /* name of policy to map to */
  u8 *policy_name;

  /* Delete the mapping */
  u8 is_del;

} ip6_sr_add_del_multicastmap_args_t;

typedef struct
{
  /* pool of tunnel instances, sr entry only */
  ip6_sr_tunnel_t *tunnels;

  /* find an sr "tunnel" by its outer-IP src/dst */
  uword *tunnel_index_by_key;

  /* find an sr "tunnel" by its name */
  uword *tunnel_index_by_name;

  /* policy pool */
  ip6_sr_policy_t *policies;

  /* find a policy by name */
  uword *policy_index_by_policy_name;

  /* multicast address to policy mapping */
  uword *policy_index_by_multicast_address;

  /* ip6-lookup next index for imposition FIB entries */
  u32 ip6_lookup_sr_next_index;

  /* hmac key id by shared secret */
  uword *hmac_key_by_shared_secret;

  /* ip6-rewrite next index for reinstalling the original dst address */
  u32 ip6_rewrite_sr_next_index;

  /* ip6-replicate next index for multicast tunnel */
  u32 ip6_lookup_sr_replicate_index;

  /* application API callback */
  void *sr_local_cb;

  /* validate hmac keys */
  u8 validate_hmac;

  /* pool of hmac keys */
  ip6_sr_hmac_key_t *hmac_keys;

  /* Openssl vbls */
  EVP_MD *md;
  HMAC_CTX *hmac_ctx;

  /* enable debug spew */
  u8 is_debug;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ip6_sr_main_t;

ip6_sr_main_t sr_main;

format_function_t format_ip6_sr_header;
format_function_t format_ip6_sr_header_with_length;

vlib_node_registration_t ip6_sr_input_node;

#if DPDK > 0
extern vlib_node_registration_t sr_replicate_node;
#endif /* DPDK */

int ip6_sr_add_del_tunnel (ip6_sr_add_del_tunnel_args_t * a);
int ip6_sr_add_del_policy (ip6_sr_add_del_policy_args_t * a);
int ip6_sr_add_del_multicastmap (ip6_sr_add_del_multicastmap_args_t * a);

void vnet_register_sr_app_callback (void *cb);

void sr_fix_hmac (ip6_sr_main_t * sm, ip6_header_t * ip,
		  ip6_sr_header_t * sr);

#endif /* included_vnet_sr_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

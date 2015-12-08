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

typedef struct {
  ip6_address_t src;
  ip6_address_t dst;
} ip6_sr_tunnel_key_t;

typedef struct {
  /* src, dst address */
  ip6_sr_tunnel_key_t key;

  /* mask width for FIB entry */
  u32 dst_mask_width;

  /* first hop, to save 1 elt in the segment list */
  ip6_address_t first_hop;

  /* Fib indices */
  u32 rx_fib_index;
  u32 tx_fib_index;

  /* The actual ip6 sr header */
  u8 * rewrite;
} ip6_sr_tunnel_t;

typedef struct {
  u8 * shared_secret;
} ip6_sr_hmac_key_t;

typedef struct {
  /* Key (header imposition case) */
  ip6_address_t *src_address;
  ip6_address_t *dst_address;
  u32 dst_mask_width;
  u32 rx_table_id;
  u32 tx_table_id;

  /* segment list, when inserting an ip6 SR header*/
  ip6_address_t *segments;

  /* 
   * "Tag" list, aka segments inserted at the end of the list,
   * past last_seg
   */
  ip6_address_t *tags;
     
  /* Shared secret => generate SHA-256 HMAC security fields */
  u8 * shared_secret;

  /* Flags, e.g. cleanup, policy-list flags */
  u16 flags_net_byte_order;

  /* Delete the tunnnel? */
  u8 is_del;
} ip6_sr_add_del_tunnel_args_t;

typedef struct {
  /* pool of tunnel instances, sr entry only */
  ip6_sr_tunnel_t *tunnels;

  /* find an sr "tunnel" by its outer-IP src/dst */
  uword * tunnel_index_by_key;
  
  /* ip6-lookup next index for imposition FIB entries */
  u32 ip6_lookup_sr_next_index;

  /* hmac key id by shared secret */
  uword * hmac_key_by_shared_secret;

  /* ip6-rewrite next index for reinstalling the original dst address */
  u32 ip6_rewrite_sr_next_index;

  /* application API callback */
  void *sr_local_cb;

  /* validate hmac keys */
  u8 validate_hmac;

  /* pool of hmac keys */
  ip6_sr_hmac_key_t * hmac_keys;

  /* Openssl vbls */
  EVP_MD * md;
  HMAC_CTX * hmac_ctx;

  /* enable debug spew */
  u8 is_debug;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} ip6_sr_main_t;

ip6_sr_main_t sr_main;

format_function_t format_ip6_sr_header;
format_function_t format_ip6_sr_header_with_length;

vlib_node_registration_t ip6_sr_input_node;

int ip6_sr_add_del_tunnel (ip6_sr_add_del_tunnel_args_t * a);
void vnet_register_sr_app_callback (void *cb);

#endif /* included_vnet_sr_h */

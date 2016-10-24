
/*
 * snat.h - simple nat definitions
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
#ifndef __included_snat_h__
#define __included_snat_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>

/* Key */
typedef struct {
  union 
  {
    struct 
    {
      ip4_address_t addr;
      u16 port;
      u16 protocol:3,
        fib_index:13;
    };
    u64 as_u64;
  };
} snat_session_key_t;

typedef struct {
  union
  {
    struct
    {
      ip4_address_t addr;
      u32 fib_index;
    };
    u64 as_u64;
  };
} snat_user_key_t;

typedef struct {
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u16 fib_index;
    };
    u64 as_u64;
  };
} snat_static_mapping_key_t;


typedef enum {
  SNAT_PROTOCOL_UDP = 0,
  SNAT_PROTOCOL_TCP,
  SNAT_PROTOCOL_ICMP,
} snat_protocol_t;


#define SNAT_SESSION_FLAG_STATIC_MAPPING 1

typedef CLIB_PACKED(struct {
  snat_session_key_t out2in;    /* 0-15 */

  snat_session_key_t in2out;    /* 16-31 */

  u32 flags;                    /* 32-35 */

  /* per-user translations */
  u32 per_user_index;           /* 36-39 */

  u32 per_user_list_head_index; /* 40-43 */

  /* Last heard timer */
  f64 last_heard;               /* 44-51 */

  u64 total_bytes;              /* 52-59 */
  
  u32 total_pkts;               /* 60-63 */

  /* Outside address */
  u32 outside_address_index;    /* 64-67 */

}) snat_session_t;


typedef struct {
  ip4_address_t addr;
  u32 sessions_per_user_list_head_index;
  u32 nsessions;
  u32 nstaticsessions;
} snat_user_t;

typedef struct {
  ip4_address_t addr;
  u32 busy_ports;
  uword * busy_port_bitmap;
} snat_address_t;

typedef struct {
  ip4_address_t local_addr;
  ip4_address_t external_addr;
  u16 local_port;
  u16 external_port;
  u8 addr_only;
  u32 vrf_id;
  u32 fib_index;
} snat_static_mapping_t;

typedef struct {
  u32 sw_if_index;
  u8 is_inside;
} snat_interface_t;

typedef struct {
  /* Main lookup tables */
  clib_bihash_8_8_t out2in;
  clib_bihash_8_8_t in2out;

  /* Find-a-user => src address lookup */
  clib_bihash_8_8_t user_hash;

  /* Find a static mapping by local */
  clib_bihash_8_8_t static_mapping_by_local;

  /* Find a static mapping by external */
  clib_bihash_8_8_t static_mapping_by_external;

  /* User pool */
  snat_user_t * users;

  /* Session pool */
  snat_session_t * sessions;

  /* Static mapping pool */
  snat_static_mapping_t * static_mappings;

  /* Interface pool */
  snat_interface_t * interfaces;

  /* Vector of outside addresses */
  snat_address_t * addresses;

  /* Pool of doubly-linked list elements */
  dlist_elt_t * list_pool;

  /* Randomize port allocation order */
  u32 random_seed;

  /* ip4 feature path indices */
  u32 rx_feature_in2out;
  u32 rx_feature_out2in;
  u32 rx_feature_in2out_fast;
  u32 rx_feature_out2in_fast;

  /* Config parameters */
  u8 static_mapping_only;
  u8 static_mapping_connection_tracking;
  u32 translation_buckets;
  u32 translation_memory_size;
  u32 user_buckets;
  u32 user_memory_size;
  u32 max_translations_per_user;
  u32 outside_vrf_id;
  u32 outside_fib_index;
  u32 inside_vrf_id;
  u32 inside_fib_index;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip_lookup_main_t * ip4_lookup_main;
  ethernet_main_t * ethernet_main;  
  api_main_t * api_main;
} snat_main_t;

extern snat_main_t snat_main;
extern vlib_node_registration_t snat_in2out_node;
extern vlib_node_registration_t snat_out2in_node;
extern vlib_node_registration_t snat_in2out_fast_node;
extern vlib_node_registration_t snat_out2in_fast_node;

void snat_free_outside_address_and_port (snat_main_t * sm, 
                                         snat_session_key_t * k, 
                                         u32 address_index);

int snat_alloc_outside_address_and_port (snat_main_t * sm, 
                                         snat_session_key_t * k,
                                         u32 * address_indexp);

int snat_static_mapping_match (snat_main_t * sm,
                               snat_session_key_t match,
                               snat_session_key_t * mapping,
                               u8 by_external);

format_function_t format_snat_user;

typedef struct {
  u32 cached_sw_if_index;
  u32 cached_ip4_address;
} snat_runtime_t;

/** \brief Check if SNAT session is created from static mapping.
    @param s SNAT session
    @return 1 if SNAT session is created from static mapping otherwise 0
*/
#define snat_is_session_static(s) s->flags & SNAT_SESSION_FLAG_STATIC_MAPPING

/* 
 * Why is this here? Because we don't need to touch this layer to
 * simply reply to an icmp. We need to change id to a unique
 * value to NAT an echo request/reply.
 */
   
typedef struct {
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;

#endif /* __included_snat_h__ */

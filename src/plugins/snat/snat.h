
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


#define SNAT_UDP_TIMEOUT 300
#define SNAT_TCP_TRANSITORY_TIMEOUT 240
#define SNAT_TCP_ESTABLISHED_TIMEOUT 7440

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
      ip4_address_t ext_host_addr;
      u16 ext_host_port;
      u16 out_port;
    };
    u64 as_u64;
  };
} snat_det_out_key_t;

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
} snat_worker_key_t;


#define foreach_snat_protocol \
  _(UDP, 0, udp, "udp")       \
  _(TCP, 1, tcp, "tcp")       \
  _(ICMP, 2, icmp, "icmp")

typedef enum {
#define _(N, i, n, s) SNAT_PROTOCOL_##N = i,
  foreach_snat_protocol
#undef _
} snat_protocol_t;


#define foreach_snat_session_state          \
  _(0, UNKNOWN, "unknown")                 \
  _(1, UDP_ACTIVE, "udp-active")           \
  _(2, TCP_SYN_SENT, "tcp-syn-sent")       \
  _(3, TCP_ESTABLISHED, "tcp-established") \
  _(4, TCP_FIN_WAIT, "tcp-fin-wait")       \
  _(5, TCP_CLOSE_WAIT, "tcp-close-wait")   \
  _(6, TCP_LAST_ACK, "tcp-last-ack")

typedef enum {
#define _(v, N, s) SNAT_SESSION_##N = v,
  foreach_snat_session_state
#undef _
} snat_session_state_t;


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
  u32 fib_index;
  u32 sessions_per_user_list_head_index;
  u32 nsessions;
  u32 nstaticsessions;
} snat_user_t;

typedef struct {
  ip4_address_t addr;
  u32 fib_index;
#define _(N, i, n, s) \
  u32 busy_##n##_ports; \
  uword * busy_##n##_port_bitmap;
  foreach_snat_protocol
#undef _
} snat_address_t;

typedef struct {
  u16 in_port;
  snat_det_out_key_t out;
  u8 state;
  u32 expire;
} snat_det_session_t;

typedef struct {
  ip4_address_t in_addr;
  u8 in_plen;
  ip4_address_t out_addr;
  u8 out_plen;
  u32 sharing_ratio;
  u16 ports_per_host;
  u32 ses_num;
  /* vector of sessions */
  snat_det_session_t * sessions;
} snat_det_map_t;

typedef struct {
  ip4_address_t local_addr;
  ip4_address_t external_addr;
  u16 local_port;
  u16 external_port;
  u8 addr_only;
  u32 vrf_id;
  u32 fib_index;
  snat_protocol_t proto;
} snat_static_mapping_t;

typedef struct {
  u32 sw_if_index;
  u8 is_inside;
} snat_interface_t;

typedef struct {
  ip4_address_t l_addr;
  u16 l_port;
  u16 e_port;
  u32 sw_if_index;
  u32 vrf_id;
  snat_protocol_t proto;
  int addr_only;
  int is_add;
} snat_static_map_resolve_t;

typedef struct {
  /* User pool */
  snat_user_t * users;

  /* Session pool */
  snat_session_t * sessions;

  /* Pool of doubly-linked list elements */
  dlist_elt_t * list_pool;
} snat_main_per_thread_data_t;

struct snat_main_s;

typedef u32 snat_icmp_match_function_t (struct snat_main_s *sm,
                                        vlib_node_runtime_t *node,
                                        u32 cpu_index,
                                        vlib_buffer_t *b0,
                                        snat_session_key_t *p_key,
                                        snat_session_key_t *p_value,
                                        u8 *p_dont_translate,
                                        void *d);

typedef u32 (snat_get_worker_function_t) (ip4_header_t * ip, u32 rx_fib_index);

typedef struct snat_main_s {
  /* Main lookup tables */
  clib_bihash_8_8_t out2in;
  clib_bihash_8_8_t in2out;

  /* Find-a-user => src address lookup */
  clib_bihash_8_8_t user_hash;

  /* Non-translated packets worker lookup => src address + VRF */
  clib_bihash_8_8_t worker_by_in;

  /* Translated packets worker lookup => IP address + port number */
  clib_bihash_8_8_t worker_by_out;

  snat_icmp_match_function_t * icmp_match_in2out_cb;
  snat_icmp_match_function_t * icmp_match_out2in_cb;

  u32 num_workers;
  u32 first_worker_index;
  u32 next_worker;
  u32 * workers;
  snat_get_worker_function_t * worker_in2out_cb;
  snat_get_worker_function_t * worker_out2in_cb;

  /* Per thread data */
  snat_main_per_thread_data_t * per_thread_data;

  /* Find a static mapping by local */
  clib_bihash_8_8_t static_mapping_by_local;

  /* Find a static mapping by external */
  clib_bihash_8_8_t static_mapping_by_external;

  /* Static mapping pool */
  snat_static_mapping_t * static_mappings;

  /* Interface pool */
  snat_interface_t * interfaces;

  /* Vector of outside addresses */
  snat_address_t * addresses;

  /* sw_if_indices whose intfc addresses should be auto-added */
  u32 * auto_add_sw_if_indices;

  /* vector of interface address static mappings to resolve. */
  snat_static_map_resolve_t *to_resolve;

  /* Randomize port allocation order */
  u32 random_seed;

  /* Worker handoff index */
  u32 fq_in2out_index;
  u32 fq_out2in_index;

  /* in2out and out2in node index */
  u32 in2out_node_index;
  u32 out2in_node_index;

  /* Deterministic NAT */
  snat_det_map_t * det_maps;

  /* Config parameters */
  u8 static_mapping_only;
  u8 static_mapping_connection_tracking;
  u8 deterministic;
  u32 translation_buckets;
  u32 translation_memory_size;
  u32 user_buckets;
  u32 user_memory_size;
  u32 max_translations_per_user;
  u32 outside_vrf_id;
  u32 outside_fib_index;
  u32 inside_vrf_id;
  u32 inside_fib_index;

  /* tenant VRF aware address pool activation flag */
  u8 vrf_mode;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip_lookup_main_t * ip4_lookup_main;
  api_main_t * api_main;
} snat_main_t;

extern snat_main_t snat_main;
extern vlib_node_registration_t snat_in2out_node;
extern vlib_node_registration_t snat_out2in_node;
extern vlib_node_registration_t snat_in2out_fast_node;
extern vlib_node_registration_t snat_out2in_fast_node;
extern vlib_node_registration_t snat_in2out_worker_handoff_node;
extern vlib_node_registration_t snat_out2in_worker_handoff_node;
extern vlib_node_registration_t snat_det_in2out_node;
extern vlib_node_registration_t snat_det_out2in_node;

void snat_free_outside_address_and_port (snat_main_t * sm, 
                                         snat_session_key_t * k, 
                                         u32 address_index);

int snat_alloc_outside_address_and_port (snat_main_t * sm, 
                                         u32 fib_index,
                                         snat_session_key_t * k,
                                         u32 * address_indexp);

int snat_static_mapping_match (snat_main_t * sm,
                               snat_session_key_t match,
                               snat_session_key_t * mapping,
                               u8 by_external,
                               u8 *is_addr_only);

void snat_add_del_addr_to_fib (ip4_address_t * addr,
                               u8 p_len,
                               u32 sw_if_index,
                               int is_add);

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

always_inline snat_protocol_t
ip_proto_to_snat_proto (u8 ip_proto)
{
  snat_protocol_t snat_proto = ~0;

  snat_proto = (ip_proto == IP_PROTOCOL_UDP) ? SNAT_PROTOCOL_UDP : snat_proto;
  snat_proto = (ip_proto == IP_PROTOCOL_TCP) ? SNAT_PROTOCOL_TCP : snat_proto;
  snat_proto = (ip_proto == IP_PROTOCOL_ICMP) ? SNAT_PROTOCOL_ICMP : snat_proto;

  return snat_proto;
}

always_inline u8
snat_proto_to_ip_proto (snat_protocol_t snat_proto)
{
  u8 ip_proto = ~0;

  ip_proto = (snat_proto == SNAT_PROTOCOL_UDP) ? IP_PROTOCOL_UDP : ip_proto;
  ip_proto = (snat_proto == SNAT_PROTOCOL_TCP) ? IP_PROTOCOL_TCP : ip_proto;
  ip_proto = (snat_proto == SNAT_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP : ip_proto;

  return ip_proto;
}

typedef struct {
  u16 src_port, dst_port;
} tcp_udp_header_t;

u32 icmp_match_in2out_fast(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 cpu_index, vlib_buffer_t *b0,
                           snat_session_key_t *p_key,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d);
u32 icmp_match_in2out_slow(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 cpu_index, vlib_buffer_t *b0,
                           snat_session_key_t *p_key,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d);
u32 icmp_match_out2in_fast(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 cpu_index, vlib_buffer_t *b0,
                           snat_session_key_t *p_key,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d);
u32 icmp_match_out2in_slow(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 cpu_index, vlib_buffer_t *b0,
                           snat_session_key_t *p_key,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d);

static_always_inline u8
icmp_is_error_message (icmp46_header_t * icmp)
{
  switch(icmp->type)
    {
    case ICMP4_destination_unreachable:
    case ICMP4_time_exceeded:
    case ICMP4_parameter_problem:
    case ICMP4_source_quench:
    case ICMP4_redirect:
    case ICMP4_alternate_host_address:
      return 1;
    }
  return 0;
}

#endif /* __included_snat_h__ */

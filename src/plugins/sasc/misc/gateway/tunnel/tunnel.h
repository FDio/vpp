// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tunnel_h
#define included_vcdp_tunnel_h

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <vppinfra/hash.h>
#include <vcdp/vcdp.h>

#include <vppinfra/bihash_16_8.h>

#include <gateway/gateway.api_types.h>

typedef struct {
  char tunnel_id[36+1];
  u32 tenant_id;
  vl_api_vcdp_tunnel_method_t method;
  ip_address_t src;
  ip_address_t dst;
  mac_address_t src_mac;
  mac_address_t dst_mac;
  u16 sport;
  u16 dport;
  u16 mtu;
  u8 *rewrite;
  u16 encap_size;
} vcdp_tunnel_t;

typedef enum {
  VCDP_TUNNEL_COUNTER_RX,
  VCDP_TUNNEL_COUNTER_TX,
  VCDP_TUNNEL_N_COUNTERS
} vcdp_tunnel_counter_t;

typedef struct {
  vcdp_tunnel_t *tunnels; // pool of tunnels
  clib_bihash_16_8_t tunnels_hash;
  uword *uuid_hash;

  // vlib_simple_counter_main_t *simple_counters;
  vlib_combined_counter_main_t combined_counters[VCDP_TUNNEL_N_COUNTERS];

  u32 number_of_tunnels_gauge;
  clib_spinlock_t counter_lock;
} vcdp_tunnel_main_t;

typedef struct {
  ip4_address_t src, dst;
  u16 sport;
  u16 dport;
  u32 context_id : 24;
  u8 proto;
} __clib_packed vcdp_tunnel_key_t;
STATIC_ASSERT_SIZEOF(vcdp_tunnel_key_t, 16);

extern vcdp_tunnel_main_t vcdp_tunnel_main;

typedef struct {
  bool is_encap;
  u32 tunnel_index;
  u16 tenant_index;
  u32 next_index;
  u32 error_index;
  int lookup_rv;
} vcdp_tunnel_trace_t;

clib_error_t *vcdp_tunnel_init(vlib_main_t *vm);
vcdp_tunnel_t *vcdp_tunnel_lookup_by_uuid(char *);
int vcdp_tunnel_add(char *tunnel_id, u32 tenant, vl_api_vcdp_tunnel_method_t method, ip_address_t *src, ip_address_t *dst,
                    u16 sport, u16 dport, u16 mtu, mac_address_t *src_mac, mac_address_t *dst_mac);
int vcdp_tunnel_lookup(u32 context_id, ip4_address_t src, ip4_address_t dst, u8 proto, u16 sport, u16 dport,
                       u64 *value);
int vcdp_tunnel_remove(char *tunnel_id);
int vcdp_tunnel_enable_disable_input(u32 sw_if_index, bool is_enable);
vcdp_tunnel_t *vcdp_tunnel_get(u32 index);

#endif
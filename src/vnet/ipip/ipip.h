/*
 * ipip.h: types/functions for ipip.
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or aipiped to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_ipip_h
#define included_ipip_h

#include <vnet/adj/adj_types.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip.h>
#include <vnet/vnet.h>

extern vnet_hw_interface_class_t ipip_hw_interface_class;

#define foreach_ipip_error			\
  /* Must be first. */				\
  _(DECAP_PKTS, "packets decapsulated")		\
  _(BAD_PROTOCOL, "bad protocol")		\
  _(NO_TUNNEL, "no tunnel")

typedef enum
{
#define _(sym, str) IPIP_ERROR_##sym,
  foreach_ipip_error
#undef _
    IPIP_N_ERROR,
} ipip_error_t;

/**
 * @brief IPIP Tunnel key
 */
typedef struct {
  ip46_type_t type;
  u32 fib_index;
  ip46_address_t src;
  ip46_address_t dst;
} __attribute__((packed)) ipip_tunnel_key_t;

enum ipip_transport_e {
  IPIP_TRANSPORT_IP4,
  IPIP_TRANSPORT_IP6,
};

/**
 * @brief A representation of a IPIP tunnel
 */
typedef struct {
  enum ipip_transport_e transport;
  fib_node_t node;
  ipip_tunnel_key_t *key;
  ip46_address_t tunnel_src;
  ip46_address_t tunnel_dst;
  u32 outer_fib_index;
  u32 hw_if_index;
  u32 sw_if_index;
  fib_node_index_t fib_entry_index;
  u32 sibling_index;
  u32 dev_instance;  /* Real device instance in tunnel vector */
  u32 user_instance; /* Instance name being shown to user */
} ipip_tunnel_t;

typedef struct {
  ipip_tunnel_t *tunnels;
  uword *tunnel_by_key;
  u32 *tunnel_index_by_sw_if_index;
  fib_node_type_t fib_node_type;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Record used instances */
  uword *instance_used;

  bool protocol_registered;
} ipip_main_t;

extern ipip_main_t ipip_main;
extern vlib_node_registration_t ipip4_input_node;
extern vlib_node_registration_t ipip6_input_node;

typedef struct {
  bool is_add;
  enum ipip_transport_e transport;
  u32 instance;
  ip46_address_t src, dst;
  u32 outer_fib_id;
} vnet_ipip_add_del_tunnel_args_t;

int vnet_ipip_add_del_tunnel(vnet_ipip_add_del_tunnel_args_t *a,
                             u32 *sw_if_indexp);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

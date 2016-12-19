/*
 * proxy.h: dhcp proxy 
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_dhcp_proxy_h
#define included_dhcp_proxy_h

#include <vnet/vnet.h>
#include <vnet/dhcp/packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>
#include <vnet/ip/udp.h>
#include <vnet/dhcp/client.h>

typedef enum {
#define dhcp_proxy_error(n,s) DHCP_PROXY_ERROR_##n,
#include <vnet/dhcp/proxy_error.def>
#undef dhcp_proxy_error
  DHCP_PROXY_N_ERROR,
} dhcp_proxy_error_t;

typedef struct {
  u32 oui;
  u32 fib_id;
} vss_id;

typedef union {
  u8 as_u8[8];
  vss_id vpn_id;
} vss_info;

typedef struct {
  ip4_address_t dhcp_server;
  ip4_address_t dhcp_src_address;
  u32 insert_option_82;
  u32 server_fib_index;
  u32 valid;
} dhcp_server_t;

typedef struct {
  /* Pool of DHCP servers */
  dhcp_server_t * dhcp_servers;

  /* Pool of selected DHCP server. Zero is the default server */
  u32 * dhcp_server_index_by_rx_fib_index;

  /* to drop pkts in server-to-client direction */
  u32 error_drop_node_index;

  vss_info *opt82vss;

  /* hash lookup specific vrf_id -> option 82 vss suboption  */
  uword * opt82vss_index_by_vrf_id;

  /* convenience */
  dhcp_client_main_t * dhcp_client_main;
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} dhcp_proxy_main_t;

dhcp_proxy_main_t dhcp_proxy_main;

int dhcp_proxy_set_server (ip4_address_t *addr, ip4_address_t *src_address,
                           u32 fib_id, int insert_option_82, int is_del);

int dhcp_proxy_set_server_2 (ip4_address_t *addr, ip4_address_t *src_address,
                             u32 rx_fib_id,
                             u32 server_fib_id, 
                             int insert_option_82, int is_del);

int dhcp_proxy_set_option82_vss(u32 vrf_id,
                                u32 oui,
                                u32 fib_id, 
                                int is_del);
#endif /* included_dhcp_proxy_h */

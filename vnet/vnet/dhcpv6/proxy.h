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

#ifndef included_dhcpv6_proxy_h
#define included_dhcpv6_proxy_h

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>
#include <vnet/ip/udp.h>
#include <vnet/dhcpv6/packet.h>

typedef enum {
#define dhcpv6_proxy_error(n,s) DHCPV6_PROXY_ERROR_##n,
#include <vnet/dhcpv6/proxy_error.def>
#undef dhcpv6_proxy_error
  DHCPV6_PROXY_N_ERROR,
} dhcpv6_proxy_error_t;

typedef struct {
  u32 oui;
  u32 fib_id;
} dhcpv6_vss_id;

typedef union {
  u8 as_u8[8];
  dhcpv6_vss_id vpn_id;
} dhcpv6_vss_info;

typedef struct {
  ip6_address_t dhcp6_server;
  ip6_address_t dhcp6_src_address;
  u32 insert_vss;
  u32 server_fib6_index;
  u32 valid;
} dhcpv6_server_t;

typedef struct {
  /* Pool of DHCP servers */
  dhcpv6_server_t * dhcp6_servers;

  /* Pool of selected DHCP server. Zero is the default server */
   u32 * dhcp6_server_index_by_rx_fib_index;

  /* all DHCP servers address */
  ip6_address_t all_dhcpv6_server_address;
  ip6_address_t all_dhcpv6_server_relay_agent_address;

  /* to drop pkts in server-to-client direction */
  u32 error_drop_node_index;

  dhcpv6_vss_info *vss;

  /* hash lookup specific vrf_id -> VSS vector index*/
  uword  *vss_index_by_vrf_id;
   
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} dhcpv6_proxy_main_t;

dhcpv6_proxy_main_t dhcpv6_proxy_main;

int dhcpv6_proxy_set_server (ip6_address_t *addr, ip6_address_t *src_address,
                             u32 fib_id, int insert_vss, int is_del);

int dhcpv6_proxy_set_vss(u32 tbl_id,
                         u32 oui,
                         u32 fib_id, 
                         int is_del);

int dhcpv6_proxy_set_server_2 (ip6_address_t *addr, ip6_address_t *src_address,
                             u32 rx_fib_id,
                             u32 server_fib_id,
                             int insert_vss, int is_del);

#endif /* included_dhcpv6_proxy_h */

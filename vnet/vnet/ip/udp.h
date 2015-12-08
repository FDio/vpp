/*
 * ip/udp.h: udp protocol
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

#ifndef included_udp_h
#define included_udp_h

#include <vnet/vnet.h>
#include <vnet/ip/udp_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>

typedef enum {
#define udp_error(n,s) UDP_ERROR_##n,
#include <vnet/ip/udp_error.def>
#undef udp_error
  UDP_N_ERROR,
} udp_error_t;

#define foreach_udp4_dst_port			\
_ (67, dhcp_to_server)                          \
_ (68, dhcp_to_client)                          \
_ (500, ikev2)                                  \
_ (4341, lisp_gpe)                              \
_ (4739, ipfix)                                 \
_ (4789, vxlan)					\
_ (4790, vxlan_gpe)				\
_ (6633, vpath_3)


#define foreach_udp6_dst_port                   \
_ (547, dhcpv6_to_server)                       \
_ (546, dhcpv6_to_client)			\
_ (6633, vpath6_3)

typedef enum {
#define _(n,f) UDP_DST_PORT_##f = n,
  foreach_udp4_dst_port
  foreach_udp6_dst_port
#undef _
} udp_dst_port_t;

typedef enum {
#define _(n,f) UDP6_DST_PORT_##f = n,
  foreach_udp6_dst_port
#undef _
} udp6_dst_port_t;

typedef struct {
  /* Name (a c string). */
  char * name;

  /* GRE protocol type in host byte order. */
  udp_dst_port_t dst_port;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} udp_dst_port_info_t;

typedef enum {
  UDP_IP6 = 0,
  UDP_IP4,                      /* the code is full of is_ip4... */
  N_UDP_AF,
} udp_af_t;

typedef struct {
  udp_dst_port_info_t * dst_port_infos [N_UDP_AF];

  /* Hash tables mapping name/protocol to protocol info index. */
  uword * dst_port_info_by_name[N_UDP_AF];
  uword * dst_port_info_by_dst_port[N_UDP_AF];

  /* convenience */
  vlib_main_t * vlib_main;
} udp_main_t;

always_inline udp_dst_port_info_t *
udp_get_dst_port_info (udp_main_t * um, udp_dst_port_t dst_port, u8 is_ip4)
{
  uword * p = hash_get (um->dst_port_info_by_dst_port[is_ip4], dst_port);
  return p ? vec_elt_at_index (um->dst_port_infos[is_ip4], p[0]) : 0;
}

format_function_t format_udp_header;
format_function_t format_udp_rx_trace;

unformat_function_t unformat_udp_header;

void udp_register_dst_port (vlib_main_t * vm,
                            udp_dst_port_t dst_port,
                            u32 node_index, u8 is_ip4);

#endif /* included_udp_h */


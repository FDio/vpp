/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_UDP_UDP_LOCAL_H_
#define SRC_VNET_UDP_UDP_LOCAL_H_

#include <vnet/vnet.h>

#define foreach_udp4_dst_port                                                 \
  _ (53, dns)                                                                 \
  _ (67, dhcp_to_server)                                                      \
  _ (68, dhcp_to_client)                                                      \
  _ (500, ikev2)                                                              \
  _ (2152, GTPU)                                                              \
  _ (3784, bfd4)                                                              \
  _ (3785, bfd_echo4)                                                         \
  _ (4341, lisp_gpe)                                                          \
  _ (4342, lisp_cp)                                                           \
  _ (4500, ipsec)                                                             \
  _ (4739, ipfix)                                                             \
  _ (4784, bfd4_mh)                                                           \
  _ (4789, vxlan)                                                             \
  _ (4789, vxlan6)                                                            \
  _ (48879, vxlan_gbp)                                                        \
  _ (4790, VXLAN_GPE)                                                         \
  _ (6633, vpath_3)                                                           \
  _ (6081, geneve)                                                            \
  _ (53053, dns_reply)

#define foreach_udp6_dst_port                                                 \
  _ (53, dns6)                                                                \
  _ (547, dhcpv6_to_server)                                                   \
  _ (546, dhcpv6_to_client)                                                   \
  _ (2152, GTPU6)                                                             \
  _ (3784, bfd6)                                                              \
  _ (3785, bfd_echo6)                                                         \
  _ (4341, lisp_gpe6)                                                         \
  _ (4342, lisp_cp6)                                                          \
  _ (48879, vxlan6_gbp)                                                       \
  _ (4784, bfd6_mh)                                                           \
  _ (4790, VXLAN6_GPE)                                                        \
  _ (6633, vpath6_3)                                                          \
  _ (6081, geneve6)                                                           \
  _ (8138, BIER)                                                              \
  _ (53053, dns_reply6)

typedef enum
{
#define _(n,f) UDP_DST_PORT_##f = n,
  foreach_udp4_dst_port foreach_udp6_dst_port
#undef _
} udp_dst_port_t;

typedef enum
{
#define _(n,f) UDP6_DST_PORT_##f = n,
  foreach_udp6_dst_port
#undef _
} udp6_dst_port_t;

void udp_register_dst_port (vlib_main_t * vm,
			    udp_dst_port_t dst_port,
			    u32 node_index, u8 is_ip4);
void udp_unregister_dst_port (vlib_main_t * vm,
			      udp_dst_port_t dst_port, u8 is_ip4);
u8 udp_is_valid_dst_port (udp_dst_port_t dst_port, u8 is_ip4);

#endif /* SRC_VNET_UDP_UDP_LOCAL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

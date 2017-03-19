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
/*
 * interface.h: VNET interfaces/sub-interfaces
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vnet_interface_types_h
#define included_vnet_interface_types_h

#include <vnet/l3_types.h>

/**
 * Link Type: A description of the protocol of packets on the link.
 * On an ethernet link this maps directly into the ethertype. On a GRE tunnel
 * it maps to the GRE-proto, etc for other lnk types.
 */
typedef enum vnet_link_t_
{
#if CLIB_DEBUG > 0
  VNET_LINK_IP4 = 1,
#else
  VNET_LINK_IP4 = 0,
#endif
  VNET_LINK_IP6,
  VNET_LINK_MPLS,
  VNET_LINK_ETHERNET,
  VNET_LINK_ARP,
  VNET_LINK_NSH,
} __attribute__ ((packed)) vnet_link_t;

#define VNET_LINKS {                   \
    [VNET_LINK_ETHERNET] = "ethernet", \
    [VNET_LINK_IP4] = "ipv4",          \
    [VNET_LINK_IP6] = "ipv6",          \
    [VNET_LINK_MPLS] = "mpls",         \
    [VNET_LINK_ARP] = "arp",	       \
    [VNET_LINK_NSH] = "nsh",           \
}

/**
 * @brief Number of link types. Not part of the enum so it does not have to be included in
 * switch statements
 */
#define VNET_LINK_NUM (VNET_LINK_NSH+1)

/**
 * @brief Convert a link to to an Ethertype
 */
extern vnet_l3_packet_type_t vnet_link_to_l3_proto (vnet_link_t link);

/**
 * @brief unicast or multicast
 */
typedef enum vnet_cast_t_
{
  VNET_UNICAST = 0,
  VNET_MULTICAST,
} __attribute__ ((packed)) vnet_cast_t;

#define VNET_CAST_NUM (VNET_MULTICAST + 1)

#define FOR_EACH_VNET_CAST(_item)    \
    for (_item = VNET_UNICAST;       \
	 _item <= VNET_MULTICAST;    \
	 _item++)

#endif /* included_vnet_interface_types_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

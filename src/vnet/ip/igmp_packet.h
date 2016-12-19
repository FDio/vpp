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
 * igmp_packet.h: igmp packet format
 *
 * Copyright (c) 2011 Eliot Dresselhaus
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

#ifndef included_vnet_igmp_packet_h
#define included_vnet_igmp_packet_h

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#define foreach_igmp_type			\
  _ (0x11, membership_query)			\
  _ (0x12, membership_report_v1)		\
  _ (0x13, dvmrp)				\
  _ (0x14, pim_v1)				\
  _ (0x15, cisco_trace)				\
  _ (0x16, membership_report_v2)		\
  _ (0x17, leave_group_v2)			\
  _ (0x1e, traceroute_response)			\
  _ (0x1f, traceroute_request)			\
  _ (0x22, membership_report_v3)		\
  _ (0x30, router_advertisement)		\
  _ (0x31, router_solicitation)			\
  _ (0x32, router_termination)

typedef enum
{
#define _(n,f) IGMP_TYPE_##f = n,
  foreach_igmp_type
#undef _
} igmp_type_t;

typedef struct
{
  igmp_type_t type:8;

  u8 code;

  u16 checksum;
} igmp_header_t;

typedef struct
{
  /* membership_query, version <= 2 reports. */
  igmp_header_t header;

  /* Multicast destination address. */
  ip4_address_t dst;
} igmp_message_t;

#define foreach_igmp_membership_group_v3_type	\
  _ (1, mode_is_filter_include)			\
  _ (2, mode_is_filter_exclude)			\
  _ (3, change_to_filter_include)		\
  _ (4, change_to_filter_exclude)		\
  _ (5, allow_new_sources)			\
  _ (6, block_old_sources)

typedef enum
{
#define _(n,f) IGMP_MEMBERSHIP_GROUP_##f = n,
  foreach_igmp_membership_group_v3_type
#undef _
} igmp_membership_group_v3_type_t;

typedef struct
{
  igmp_membership_group_v3_type_t type:8;

  /* Number of 32 bit words of aux data after source addresses. */
  u8 n_aux_u32s;

  /* Number of source addresses that follow. */
  u16 n_src_addresses;

  /* Destination multicast address. */
  ip4_address_t dst_address;

  ip4_address_t src_addresses[0];
} igmp_membership_group_v3_t;

always_inline igmp_membership_group_v3_t *
igmp_membership_group_v3_next (igmp_membership_group_v3_t * g)
{
  return ((void *) g
	  + g->n_src_addresses * sizeof (g->src_addresses[0])
	  + g->n_aux_u32s * sizeof (u32));
}

typedef struct
{
  /* Type 0x22. */
  igmp_header_t header;

  u16 unused;

  /* Number of groups which follow. */
  u16 n_groups;

  igmp_membership_group_v3_t groups[0];
} igmp_membership_report_v3_t;

/* IP6 flavor of IGMP is called MLD which is embedded in ICMP6. */
typedef struct
{
  /* Preceeded by ICMP v6 header. */
  u16 max_response_delay_in_milliseconds;
  u16 reserved;
  ip6_address_t dst;
} mld_header_t;

#endif /* included_vnet_igmp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

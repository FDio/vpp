/*---------------------------------------------------------------------------
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */
/*
 * IPv4 and IPv6 Fragmentation Nodes
 *
 * A packet sent to those nodes require the following
 * buffer attributes to be set:
 * ip_frag.header_offset :
 *     Where to find the IPv4 (or IPv6) header in the packet. Previous
 *     bytes are left untouched and copied in every fragment. The fragments
 *     are then appended. This option is used for fragmented packets
 *     that are encapsulated.
 * ip_frag.mtu :
 *     Maximum size of IP packets, header included, but ignoring
 *     the 'ip_frag.header_offset' copied bytes.
 * ip_frag.next_index :
 *     One of ip_frag_next_t, indicating to which exit node the fragments
 *     should be sent to.
 *
 */

#ifndef IP_FRAG_H
#define IP_FRAG_H

#include <vnet/vnet.h>

#define IP_FRAG_FLAG_IP4_HEADER 0x01	//Encapsulating IPv4 header
#define IP_FRAG_FLAG_IP6_HEADER 0x02	//Encapsulating IPv6 header

#define IP4_FRAG_NODE_NAME "ip4-frag"
#define IP6_FRAG_NODE_NAME "ip6-frag"

extern vlib_node_registration_t ip4_frag_node;
extern vlib_node_registration_t ip6_frag_node;

typedef enum
{
  IP_FRAG_NEXT_IP_REWRITE,
  IP_FRAG_NEXT_IP_REWRITE_MIDCHAIN,
  IP_FRAG_NEXT_IP4_LOOKUP,
  IP_FRAG_NEXT_IP6_LOOKUP,
  IP_FRAG_NEXT_ICMP_ERROR,
  IP_FRAG_NEXT_DROP,
  IP_FRAG_N_NEXT
} ip_frag_next_t;

#define foreach_ip_frag_error				\
  /* Must be first. */					\
 _(NONE, "packet fragmented")				\
 _(SMALL_PACKET, "packet smaller than MTU")             \
 _(FRAGMENT_SENT, "number of sent fragments")           \
 _(CANT_FRAGMENT_HEADER, "can't fragment header")	\
 _(DONT_FRAGMENT_SET, "can't fragment this packet")	\
 _(MALFORMED, "malformed packet")                       \
 _(MEMORY, "could not allocate buffer")                 \
 _(UNKNOWN, "unknown error")

typedef enum
{
#define _(sym,str) IP_FRAG_ERROR_##sym,
  foreach_ip_frag_error
#undef _
    IP_FRAG_N_ERROR,
} ip_frag_error_t;

void ip_frag_set_vnet_buffer (vlib_buffer_t * b, u16 mtu,
			      u8 next_index, u8 flags);

extern ip_frag_error_t ip4_frag_do_fragment (vlib_main_t * vm,
					     u32 from_bi,
					     u16 mtu,
					     u16 encapsize, u32 ** buffer);
extern ip_frag_error_t ip6_frag_do_fragment (vlib_main_t * vm,
					     u32 from_bi,
					     u16 mtu,
					     u16 encapsize, u32 ** buffer);

#endif /* ifndef IP_FRAG_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

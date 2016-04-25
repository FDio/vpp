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
 * ip6/packet.h: ip6 packet format
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

#ifndef included_ip6_packet_h
#define included_ip6_packet_h

#include <vnet/ip/tcp_packet.h>
#include <vnet/ip/ip4_packet.h>

typedef union {
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
  uword as_uword[16 / sizeof (uword)];
} ip6_address_t;

/* Packed so that the mhash key doesn't include uninitialized pad bytes */
typedef CLIB_PACKED (struct {
  /* IP address must be first for ip_interface_address_get_address() to work */
  ip6_address_t ip6_addr;
  u32 fib_index;
}) ip6_address_fib_t;

typedef CLIB_PACKED (union {
  struct {
    u32 pad[3];
    ip4_address_t ip4;
  };
  ip6_address_t ip6;
}) ip46_address_t;
#define ip46_address_is_ip4(ip46) (((ip46)->pad[0] | (ip46)->pad[1] | (ip46)->pad[2]) == 0)
#define ip46_address_mask_ip4(ip46) ((ip46)->pad[0] = (ip46)->pad[1] = (ip46)->pad[2] = 0)
#define ip46_address_set_ip4(ip46, ip) (ip46_address_mask_ip4(ip46), (ip46)->ip4 = (ip)[0])

always_inline void
ip6_addr_fib_init (ip6_address_fib_t * addr_fib, ip6_address_t * address,
		   u32 fib_index)
{
  addr_fib->ip6_addr.as_u64[0] = address->as_u64[0];
  addr_fib->ip6_addr.as_u64[1] = address->as_u64[1];
  addr_fib->fib_index = fib_index;
}

/* Special addresses:
   unspecified		::/128
   loopback		::1/128
   global unicast       2000::/3
   unique local unicast fc00::/7
   link local unicast	fe80::/10
   multicast		ff00::/8
   ietf reserved	everything else. */
   
#define foreach_ip6_multicast_address_scope	\
  _ (loopback, 0x1)				\
  _ (link_local, 0x2)				\
  _ (admin_local, 0x4)				\
  _ (site_local, 0x5)				\
  _ (organization_local, 0x8)			\
  _ (global, 0xe)

#define foreach_ip6_multicast_link_local_group_id	\
  _ (all_hosts, 0x1)					\
  _ (all_routers, 0x2)					\
  _ (rip_routers, 0x9)					\
  _ (eigrp_routers, 0xa)				\
  _ (pim_routers, 0xd)                            \
 _ (mldv2_routers, 0x16)

typedef enum {
#define _(f,n) IP6_MULTICAST_SCOPE_##f = n,
  foreach_ip6_multicast_address_scope
#undef _
} ip6_multicast_address_scope_t;

typedef enum {
#define _(f,n) IP6_MULTICAST_GROUP_ID_##f = n,
  foreach_ip6_multicast_link_local_group_id
#undef _
} ip6_multicast_link_local_group_id_t;

always_inline uword
ip6_address_is_multicast (ip6_address_t * a)
{ return a->as_u8[0] == 0xff; }

always_inline void
ip6_set_reserved_multicast_address (ip6_address_t * a,
				    ip6_multicast_address_scope_t scope,
				    u16 id)
{
  a->as_u64[0] = a->as_u64[1] = 0;
  a->as_u16[0] = clib_host_to_net_u16 (0xff00 | scope);
  a->as_u16[7] = clib_host_to_net_u16 (id);
}

always_inline void
ip6_set_solicited_node_multicast_address (ip6_address_t * a, u32 id)
{
  /* 0xff02::1:ffXX:XXXX. */
  a->as_u64[0] = a->as_u64[1] = 0;
  a->as_u16[0] = clib_host_to_net_u16 (0xff02);
  a->as_u8[11] = 1;
  ASSERT ((id >> 24) == 0);
  id |= 0xff << 24;
  a->as_u32[3] = clib_host_to_net_u32 (id);
}

always_inline void
ip6_link_local_address_from_ethernet_address (ip6_address_t * a, u8 * ethernet_address)
{
  a->as_u64[0] = a->as_u64[1] = 0;
  a->as_u16[0] = clib_host_to_net_u16 (0xfe80);
  /* Always set locally administered bit (6). */
  a->as_u8[0x8] = ethernet_address[0] | (1 << 6);
  a->as_u8[0x9] = ethernet_address[1];
  a->as_u8[0xa] = ethernet_address[2];
  a->as_u8[0xb] = 0xff;
  a->as_u8[0xc] = 0xfe;
  a->as_u8[0xd] = ethernet_address[3];
  a->as_u8[0xe] = ethernet_address[4];
  a->as_u8[0xf] = ethernet_address[5];
}

always_inline void
ip6_multicast_ethernet_address (u8 * ethernet_address, u32 group_id)
{
  ethernet_address[0] = 0x33;
  ethernet_address[1] = 0x33;
  ethernet_address[2] = ((group_id >> 24) & 0xff);
  ethernet_address[3] = ((group_id >> 16) & 0xff);
  ethernet_address[4] = ((group_id >>  8) & 0xff);
  ethernet_address[5] = ((group_id >>  0) & 0xff);
}

always_inline uword
ip6_address_is_equal (ip6_address_t * a, ip6_address_t * b)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    if (a->as_uword[i] != b->as_uword[i])
      return 0;
  return 1;
}

always_inline uword
ip6_address_is_equal_masked (ip6_address_t * a, ip6_address_t * b, 
                             ip6_address_t * mask)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    {
      uword a_masked, b_masked;
      a_masked = a->as_uword[i] & mask->as_uword[i];
      b_masked = b->as_uword[i] & mask->as_uword[i];

      if (a_masked != b_masked)
        return 0;
    }
  return 1;
}

always_inline void
ip6_address_mask (ip6_address_t * a, ip6_address_t * mask)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    a->as_uword[i] &= mask->as_uword[i];
}

always_inline void
ip6_address_set_zero (ip6_address_t * a)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    a->as_uword[i] = 0;
}

always_inline void
ip6_address_mask_from_width (ip6_address_t * a, u32 width)
{
  int i, byte, bit, bitnum;
  ASSERT (width <= 128);
  memset (a, 0, sizeof (a[0]));
  for (i = 0; i < width; i++)
    {
      bitnum = (7 - (i & 7));
      byte = i / 8;
      bit = 1<<bitnum;
      a->as_u8[byte] |= bit;
    }
}

always_inline uword
ip6_address_is_zero (ip6_address_t * a)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    if (a->as_uword[i] != 0)
      return 0;
  return 1;
}

/* Check for unspecified address ::0 */
always_inline uword
ip6_address_is_unspecified (ip6_address_t * a)
{ return ip6_address_is_zero (a); }

/* Check for loopback address ::1 */
always_inline uword
ip6_address_is_loopback (ip6_address_t * a)
{
  uword is_loopback;
  u8 save = a->as_u8[15];
  a->as_u8[15] = save ^ 1;
  is_loopback = ip6_address_is_zero (a);
  a->as_u8[15] = save;
  return is_loopback;
}

/* Check for link local unicast fe80::/10. */
always_inline uword
ip6_address_is_link_local_unicast (ip6_address_t * a)
{ return a->as_u8[0] == 0xfe && (a->as_u8[1] & 0xc0) == 0x80; }

/* Check for unique local unicast fc00::/7. */
always_inline uword
ip6_address_is_local_unicast (ip6_address_t * a)
{ return (a->as_u8[0] & 0xfe) == 0xfc; }

/* Check for solicited node multicast 0xff02::1:ff00:0/104 */
always_inline uword
ip6_is_solicited_node_multicast_address (ip6_address_t * a)
{
  return (a->as_u32[0] == clib_host_to_net_u32 (0xff020000)
	  && a->as_u32[1] == 0
	  && a->as_u32[2] == clib_host_to_net_u32 (1)
	  && a->as_u8[12] == 0xff);
}

typedef struct {
  /* 4 bit version, 8 bit traffic class and 20 bit flow label. */
  u32 ip_version_traffic_class_and_flow_label;

  /* Total packet length not including this header (but including
     any extension headers if present). */
  u16 payload_length;

  /* Protocol for next header. */
  u8 protocol;

  /* Hop limit decremented by router at each hop. */
  u8 hop_limit;

  /* Source and destination address. */
  ip6_address_t src_address, dst_address;
} ip6_header_t;

always_inline void *
ip6_next_header (ip6_header_t * i)
{ return (void *) (i + 1); }

always_inline void
ip6_tcp_reply_x1 (ip6_header_t * ip0, tcp_header_t * tcp0)
{
  {
    ip6_address_t src0, dst0;

    src0 = ip0->src_address;
    dst0 = ip0->dst_address;
    ip0->src_address = dst0;
    ip0->dst_address = src0;
  }

  {
    u16 src0, dst0;

    src0 = tcp0->ports.src;
    dst0 = tcp0->ports.dst;
    tcp0->ports.src = dst0;
    tcp0->ports.dst = src0;
  }
}

always_inline void
ip6_tcp_reply_x2 (ip6_header_t * ip0, ip6_header_t * ip1,
		  tcp_header_t * tcp0, tcp_header_t * tcp1)
{
  {
    ip6_address_t src0, dst0, src1, dst1;

    src0 = ip0->src_address;
    src1 = ip1->src_address;
    dst0 = ip0->dst_address;
    dst1 = ip1->dst_address;
    ip0->src_address = dst0;
    ip1->src_address = dst1;
    ip0->dst_address = src0;
    ip1->dst_address = src1;
  }

  {
    u16 src0, dst0, src1, dst1;

    src0 = tcp0->ports.src;
    src1 = tcp1->ports.src;
    dst0 = tcp0->ports.dst;
    dst1 = tcp1->ports.dst;
    tcp0->ports.src = dst0;
    tcp1->ports.src = dst1;
    tcp0->ports.dst = src0;
    tcp1->ports.dst = src1;
  }
}


typedef CLIB_PACKED (struct {
  u8 data;
}) ip6_pad1_option_t;

typedef CLIB_PACKED (struct {
  u8 type;
  u8 len;
  u8 data[0];
}) ip6_padN_option_t;

typedef CLIB_PACKED (struct {
#define IP6_MLDP_ALERT_TYPE  0x5 
  u8 type;
  u8 len;
  u16 value;
}) ip6_router_alert_option_t;

typedef CLIB_PACKED (struct {
  u8 next_hdr;
  /* Length of this header plus option data in 8 byte units. */
  u8 n_data_u64s;
  u8 data[0];
}) ip6_hop_by_hop_ext_t;

typedef CLIB_PACKED (struct {
  u8 next_hdr;
  u8 rsv;
  u16 fragment_offset_and_more;
  u32 identification;
}) ip6_frag_hdr_t;

#define ip6_frag_hdr_offset(hdr) \
  (clib_net_to_host_u16((hdr)->fragment_offset_and_more) >> 3)

#define ip6_frag_hdr_more(hdr) \
  (clib_net_to_host_u16((hdr)->fragment_offset_and_more) & 0x1)

#define ip6_frag_hdr_offset_and_more(offset, more) \
  clib_host_to_net_u16(((offset) << 3) + !!(more))

#endif /* included_ip6_packet_h */

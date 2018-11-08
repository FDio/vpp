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

#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip4_packet.h>

typedef union
{
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
  uword as_uword[16 / sizeof (uword)];
}
ip6_address_t;

typedef struct
{
  ip6_address_t addr, mask;
} ip6_address_and_mask_t;

/* Packed so that the mhash key doesn't include uninitialized pad bytes */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /* IP address must be first for ip_interface_address_get_address() to work */
  ip6_address_t ip6_addr;
  u32 fib_index;
}) ip6_address_fib_t;
/* *INDENT-ON* */

typedef enum
{
  IP46_TYPE_ANY,
  IP46_TYPE_IP4,
  IP46_TYPE_IP6
} ip46_type_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (union {
  struct {
    u32 pad[3];
    ip4_address_t ip4;
  };
  ip6_address_t ip6;
  u8 as_u8[16];
  u64 as_u64[2];
}) ip46_address_t;
/* *INDENT-ON* */
#define ip46_address_is_ip4(ip46)	(((ip46)->pad[0] | (ip46)->pad[1] | (ip46)->pad[2]) == 0)
#define ip46_address_mask_ip4(ip46)	((ip46)->pad[0] = (ip46)->pad[1] = (ip46)->pad[2] = 0)
#define ip46_address_set_ip4(ip46, ip)	(ip46_address_mask_ip4(ip46), (ip46)->ip4 = (ip)[0])
#define ip46_address_reset(ip46)	((ip46)->as_u64[0] = (ip46)->as_u64[1] = 0)
#define ip46_address_cmp(ip46_1, ip46_2) (memcmp(ip46_1, ip46_2, sizeof(*ip46_1)))
#define ip46_address_is_zero(ip46)	(((ip46)->as_u64[0] == 0) && ((ip46)->as_u64[1] == 0))
#define ip46_address_is_equal(a1, a2)	(((a1)->as_u64[0] == (a2)->as_u64[0]) \
                                         && ((a1)->as_u64[1] == (a2)->as_u64[1]))
#define ip46_address_initializer {{{ 0 }}}

static_always_inline void
ip46_address_copy (ip46_address_t * dst, const ip46_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

static_always_inline void
ip46_address_set_ip6 (ip46_address_t * dst, const ip6_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

always_inline ip46_address_t
to_ip46 (u32 is_ipv6, u8 * buf)
{
  ip46_address_t ip;
  if (is_ipv6)
    ip.ip6 = *((ip6_address_t *) buf);
  else
    ip46_address_set_ip4 (&ip, (ip4_address_t *) buf);
  return ip;
}


always_inline void
ip6_addr_fib_init (ip6_address_fib_t * addr_fib,
		   const ip6_address_t * address, u32 fib_index)
{
  addr_fib->ip6_addr = *address;
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

typedef enum
{
#define _(f,n) IP6_MULTICAST_SCOPE_##f = n,
  foreach_ip6_multicast_address_scope
#undef _
} ip6_multicast_address_scope_t;

typedef enum
{
#define _(f,n) IP6_MULTICAST_GROUP_ID_##f = n,
  foreach_ip6_multicast_link_local_group_id
#undef _
} ip6_multicast_link_local_group_id_t;

always_inline uword
ip6_address_is_multicast (const ip6_address_t * a)
{
  return a->as_u8[0] == 0xff;
}

always_inline uword
ip46_address_is_multicast (const ip46_address_t * a)
{
  return ip46_address_is_ip4 (a) ? ip4_address_is_multicast (&a->ip4) :
    ip6_address_is_multicast (&a->ip6);
}

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
ip6_link_local_address_from_ethernet_address (ip6_address_t * a,
					      const u8 * ethernet_address)
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
  ethernet_address[4] = ((group_id >> 8) & 0xff);
  ethernet_address[5] = ((group_id >> 0) & 0xff);
}

always_inline uword
ip6_address_is_equal (const ip6_address_t * a, const ip6_address_t * b)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    if (a->as_uword[i] != b->as_uword[i])
      return 0;
  return 1;
}

always_inline uword
ip6_address_is_equal_masked (const ip6_address_t * a,
			     const ip6_address_t * b,
			     const ip6_address_t * mask)
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
ip6_address_mask (ip6_address_t * a, const ip6_address_t * mask)
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
      bit = 1 << bitnum;
      a->as_u8[byte] |= bit;
    }
}

always_inline uword
ip6_address_is_zero (const ip6_address_t * a)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_uword); i++)
    if (a->as_uword[i] != 0)
      return 0;
  return 1;
}

/* Check for unspecified address ::0 */
always_inline uword
ip6_address_is_unspecified (const ip6_address_t * a)
{
  return ip6_address_is_zero (a);
}

/* Check for loopback address ::1 */
always_inline uword
ip6_address_is_loopback (const ip6_address_t * a)
{
  return (a->as_u64[0] == 0 &&
	  a->as_u32[2] == 0 &&
	  a->as_u16[6] == 0 && a->as_u8[14] == 0 && a->as_u8[15] == 1);
}

/* Check for link local unicast fe80::/10. */
always_inline uword
ip6_address_is_link_local_unicast (const ip6_address_t * a)
{
  return a->as_u8[0] == 0xfe && (a->as_u8[1] & 0xc0) == 0x80;
}

/* Check for unique local unicast fc00::/7. */
always_inline uword
ip6_address_is_local_unicast (const ip6_address_t * a)
{
  return (a->as_u8[0] & 0xfe) == 0xfc;
}

/* Check for unique global unicast 2000::/3. */
always_inline uword
ip6_address_is_global_unicast (const ip6_address_t * a)
{
  return (a->as_u8[0] & 0xe0) == 0x20;
}

/* Check for solicited node multicast 0xff02::1:ff00:0/104 */
always_inline uword
ip6_is_solicited_node_multicast_address (const ip6_address_t * a)
{
  return (a->as_u32[0] == clib_host_to_net_u32 (0xff020000)
	  && a->as_u32[1] == 0
	  && a->as_u32[2] == clib_host_to_net_u32 (1)
	  && a->as_u8[12] == 0xff);
}

typedef struct
{
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

always_inline u8
ip6_traffic_class (const ip6_header_t * i)
{
  return (i->ip_version_traffic_class_and_flow_label & 0x0FF00000) >> 20;
}

static_always_inline u8
ip6_traffic_class_network_order (const ip6_header_t * ip6)
{
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
	  & 0x0ff00000) >> 20;
}

static_always_inline void
ip6_set_traffic_class_network_order (ip6_header_t * ip6, u8 dscp)
{
  u32 tmp =
    clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label);
  tmp &= 0xf00fffff;
  tmp |= (dscp << 20);
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (tmp);
}

always_inline void *
ip6_next_header (ip6_header_t * i)
{
  return (void *) (i + 1);
}

always_inline void
ip6_copy_header (ip6_header_t * dst, const ip6_header_t * src)
{
  dst->ip_version_traffic_class_and_flow_label =
    src->ip_version_traffic_class_and_flow_label;
  dst->payload_length = src->payload_length;
  dst->protocol = src->protocol;
  dst->hop_limit = src->hop_limit;

  dst->src_address.as_uword[0] = src->src_address.as_uword[0];
  dst->src_address.as_uword[1] = src->src_address.as_uword[1];
  dst->dst_address.as_uword[0] = src->dst_address.as_uword[0];
  dst->dst_address.as_uword[1] = src->dst_address.as_uword[1];
}

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

    src0 = tcp0->src;
    dst0 = tcp0->dst;
    tcp0->src = dst0;
    tcp0->dst = src0;
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

    src0 = tcp0->src;
    src1 = tcp1->src;
    dst0 = tcp0->dst;
    dst1 = tcp1->dst;
    tcp0->src = dst0;
    tcp1->src = dst1;
    tcp0->dst = src0;
    tcp1->dst = src1;
  }
}


/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 data;
}) ip6_pad1_option_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 type;
  u8 len;
  u8 data[0];
}) ip6_padN_option_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
#define IP6_MLDP_ALERT_TYPE  0x5
  u8 type;
  u8 len;
  u16 value;
}) ip6_router_alert_option_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 next_hdr;
  /* Length of this header plus option data in 8 byte units. */
  u8 n_data_u64s;
}) ip6_ext_header_t;

always_inline u8 ip6_ext_hdr(u8 nexthdr)
{
  /*
   * find out if nexthdr is an extension header or a protocol
   */
  return   (nexthdr == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS) ||
    (nexthdr == IP_PROTOCOL_IPV6_FRAGMENTATION)  ||
    (nexthdr == IP_PROTOCOL_IPSEC_AH)      ||
    (nexthdr == IP_PROTOCOL_IPV6_ROUTE)      ||
    (nexthdr == IP_PROTOCOL_IP6_DESTINATION_OPTIONS);
}

#define ip6_ext_header_len(p)  ((((ip6_ext_header_t *)(p))->n_data_u64s+1) << 3)
#define ip6_ext_authhdr_len(p) ((((ip6_ext_header_t *)(p))->n_data_u64s+2) << 2)

always_inline void *
ip6_ext_next_header (ip6_ext_header_t *ext_hdr )
{ return (void *)((u8 *) ext_hdr + ip6_ext_header_len(ext_hdr)); }

/*
 * Macro to find the IPv6 ext header of type t
 * I is the IPv6 header
 * P is the previous IPv6 ext header (NULL if none)
 * M is the matched IPv6 ext header of type t
 */
#define ip6_ext_header_find_t(i, p, m, t)               \
if ((i)->protocol == t)                                 \
{                                                       \
  (m) = (void *)((i)+1);                                \
  (p) = NULL;                                           \
}                                                       \
else                                                    \
{                                                       \
  (m) = NULL;                                           \
  (p) = (void *)((i)+1);                                \
  while (ip6_ext_hdr((p)->next_hdr) &&                  \
    ((ip6_ext_header_t *)(p))->next_hdr != (t))         \
  {                                                     \
    (p) = ip6_ext_next_header((p));                     \
  }                                                     \
  if ( ((p)->next_hdr) == (t))                          \
  {                                                     \
    (m) = (void *)(ip6_ext_next_header((p)));           \
  }                                                     \
}


typedef CLIB_PACKED (struct {
  u8 next_hdr;
  /* Length of this header plus option data in 8 byte units. */
  u8 n_data_u64s;
  u8 data[0];
}) ip6_hop_by_hop_ext_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 next_hdr;
  u8 rsv;
  u16 fragment_offset_and_more;
  u32 identification;
}) ip6_frag_hdr_t;
/* *INDENT-ON* */

#define ip6_frag_hdr_offset(hdr) \
  (clib_net_to_host_u16((hdr)->fragment_offset_and_more) >> 3)

#define ip6_frag_hdr_offset_bytes(hdr) \
  (8 * ip6_frag_hdr_offset(hdr))

#define ip6_frag_hdr_more(hdr) \
  (clib_net_to_host_u16((hdr)->fragment_offset_and_more) & 0x1)

#define ip6_frag_hdr_offset_and_more(offset, more) \
  clib_host_to_net_u16(((offset) << 3) + !!(more))

#endif /* included_ip6_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

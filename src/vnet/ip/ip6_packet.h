/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip6/packet.h: ip6 packet format */

#ifndef included_ip6_packet_h
#define included_ip6_packet_h

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <stdbool.h>

typedef union
{
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
  u64x2 as_u128;
  u8x16 as_u8x16;
  u16x8 as_u16x8;
  uword as_uword[16 / sizeof (uword)];
}
__clib_packed ip6_address_t;

STATIC_ASSERT_SIZEOF (ip6_address_t, 16);

typedef struct
{
  ip6_address_t addr, mask;
} ip6_address_and_mask_t;

/* Packed so that the mhash key doesn't include uninitialized pad bytes */
typedef CLIB_PACKED (struct {
  /* IP address must be first for ip_interface_address_get_address() to work */
  ip6_address_t ip6_addr;
  u32 fib_index;
}) ip6_address_fib_t;

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

always_inline void
ip6_address_copy (ip6_address_t * dst, const ip6_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
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
  id |= 0xffU << 24;
  a->as_u32[3] = clib_host_to_net_u32 (id);
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
  clib_memset (a, 0, sizeof (a[0]));
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

always_inline u32
ip6_address_hash_to_u32 (const ip6_address_t * a)
{
  return (a->as_u32[0] ^ a->as_u32[1] ^ a->as_u32[2] ^ a->as_u32[3]);
}

always_inline u64
ip6_address_hash_to_u64 (const ip6_address_t * a)
{
  return (a->as_u64[0] ^ a->as_u64[1]);
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

#define IP6_PACKET_TC_MASK 0x0FF00000
#define IP6_PACKET_DSCP_MASK 0x0FC00000
#define IP6_PACKET_ECN_MASK 0x00300000
#define IP6_PACKET_FL_MASK   0x000FFFFF

always_inline ip_dscp_t
ip6_traffic_class (const ip6_header_t * i)
{
  return (i->ip_version_traffic_class_and_flow_label & IP6_PACKET_TC_MASK) >>
    20;
}

static_always_inline ip_dscp_t
ip6_traffic_class_network_order (const ip6_header_t * ip6)
{
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
	  & IP6_PACKET_TC_MASK) >> 20;
}

static_always_inline ip_dscp_t
ip6_dscp_network_order (const ip6_header_t * ip6)
{
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
	  & IP6_PACKET_DSCP_MASK) >> 22;
}

static_always_inline ip_ecn_t
ip6_ecn_network_order (const ip6_header_t * ip6)
{
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
	  & IP6_PACKET_ECN_MASK) >> 20;
}

static_always_inline void
ip6_set_traffic_class_network_order (ip6_header_t * ip6, ip_dscp_t dscp)
{
  u32 tmp =
    clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label);
  tmp &= 0xf00fffff;
  tmp |= (dscp << 20);
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (tmp);
}

static_always_inline void
ip6_set_dscp_network_order (ip6_header_t * ip6, ip_dscp_t dscp)
{
  u32 tmp =
    clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label);
  tmp &= 0xf03fffff;
  tmp |= (dscp << 22);
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (tmp);
}

static_always_inline void
ip6_set_ecn_network_order (ip6_header_t * ip6, ip_ecn_t ecn)
{
  u32 tmp =
    clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label);
  tmp &= 0xffcfffff;
  tmp |= ((0x3 & ecn) << 20);
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (tmp);
}

static_always_inline u32
ip6_flow_label_network_order (const ip6_header_t *ip6)
{
  u32 tmp =
    clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label);
  return (tmp & 0xfffff);
}

static_always_inline void
ip6_set_flow_label_network_order (ip6_header_t *ip6, u32 flow_label)
{
  u32 tmp =
    clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label);
  tmp &= 0xfff00000;
  tmp |= flow_label & 0x000fffff;
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (tmp);
}

static_always_inline u32
ip6_hop_limit_network_order (const ip6_header_t *ip6)
{
  return (ip6->hop_limit);
}

static_always_inline void
ip6_set_hop_limit_network_order (ip6_header_t *ip6, u8 hop_limit)
{
  ip6->hop_limit = hop_limit;
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
  u8 protocol;
  u8 reserved;
  u16 fragoff;
  u32 id;
}) ip6_fragment_ext_header_t;

typedef CLIB_PACKED (struct {
  u8 next_hdr;
  /* Length of this header plus option data in 8 byte units. */
  u8 n_data_u64s;
}) ip6_ext_header_t;

#define foreach_ext_hdr_type \
  _(IP6_HOP_BY_HOP_OPTIONS) \
  _(IPV6_ROUTE) \
  _(IP6_DESTINATION_OPTIONS) \
  _(MOBILITY) \
  _(HIP) \
  _(SHIM6)

always_inline u8
ip6_ext_hdr (u8 nexthdr)
{
#ifdef CLIB_HAVE_VEC128
  static const u8x16 ext_hdr_types = {
#define _(x) IP_PROTOCOL_##x,
    foreach_ext_hdr_type
#undef _
  };

  return !u8x16_is_all_zero (ext_hdr_types == u8x16_splat (nexthdr));
#else
  /*
   * find out if nexthdr is an extension header or a protocol
   */
  return 0
#define _(x) || (nexthdr == IP_PROTOCOL_##x)
    foreach_ext_hdr_type;
#undef _
#endif
}

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

#define ip6_frag_hdr_offset(hdr)                                              \
  (clib_net_to_host_u16 ((hdr)->fragment_offset_and_more) >> 3)

#define ip6_frag_hdr_offset_bytes(hdr) (8 * ip6_frag_hdr_offset (hdr))

#define ip6_frag_hdr_more(hdr)                                                \
  (clib_net_to_host_u16 ((hdr)->fragment_offset_and_more) & 0x1)

#define ip6_frag_hdr_offset_and_more(offset, more)                            \
  clib_host_to_net_u16 (((offset) << 3) + !!(more))

#define ip6_ext_header_len(p)  ((((ip6_ext_header_t *)(p))->n_data_u64s+1) << 3)
#define ip6_ext_authhdr_len(p) ((((ip6_ext_header_t *)(p))->n_data_u64s+2) << 2)

static inline int
ip6_ext_header_len_s (ip_protocol_t nh, void *p)
{
  if (ip6_ext_hdr (nh))
    return ip6_ext_header_len (p);
  switch (nh)
    {
    case IP_PROTOCOL_IPSEC_AH:
      return ip6_ext_authhdr_len (p);
    case IP_PROTOCOL_IPV6_FRAGMENTATION:
      return sizeof (ip6_frag_hdr_t);
    case IP_PROTOCOL_ICMP6:
      return 4;
    case IP_PROTOCOL_UDP:
      return 8;
    case IP_PROTOCOL_TCP:
      return 20;
    default: /* Caller is responsible for validating the length of terminating
	     protocols */
	     ;
    }
  return 0;
}

always_inline void *
ip6_ext_next_header (ip6_ext_header_t * ext_hdr)
{
  return (void *) ((u8 *) ext_hdr + ip6_ext_header_len (ext_hdr));
}

always_inline void *
ip6_ext_next_header_offset (void *hdr, u16 offset)
{
  return (hdr + offset);
}

always_inline int
vlib_object_within_buffer_data (vlib_main_t * vm, vlib_buffer_t * b,
				void *obj, size_t len)
{
  u8 *o = obj;
  if (o < b->data ||
      o + len > b->data + vlib_buffer_get_default_data_size (vm))
    return 0;
  return 1;
}

/* Returns the number of bytes left in buffer from p. */
static inline u32
vlib_bytes_left_in_buffer (vlib_buffer_t *b, void *obj)
{
  return b->current_length - (((u8 *) obj - b->data) - b->current_data);
}

#define IP6_EXT_HDR_MAX	      (4)   /* Maximum number of headers */
#define IP6_EXT_HDR_MAX_DEPTH (256) /* Maximum header depth */
typedef struct
{
  int length;
  bool complete;
  bool term_is_l4;
  bool l4_fits;
  u16 term_protocol;
  u16 term_offset;
  struct
  {
    u16 protocol;
    u16 offset;
  } eh[IP6_EXT_HDR_MAX];
} ip6_ext_hdr_chain_t;

/*
 * Walk the IPv6 extension header chain from ip, bounded by valid_end
 * bytes from ip. A header is recorded only when it fits entirely within
 * valid_end. The scan stops at IP6_EXT_HDR_MAX_DEPTH bytes, but a header
 * that starts before that limit is still recorded when it fits within
 * valid_end.
 *
 * When the walk reaches a terminating header, complete is true.
 * term_protocol and term_offset describe it: an L4 header, or the
 * protocol named by a non-first fragment header. term_is_l4 is true only
 * for an L4 header. Otherwise complete is false, and term_protocol and
 * term_offset describe the header that did not fit when the walk stopped
 * there; they are zero when the walk stopped at the depth or entry
 * limit.
 *
 * Returns the index of find_hdr_type if it is in the chain, otherwise
 * the index of the last extension header, or -1 when no extension
 * header was recorded. The found header is valid even when the walk did
 * not complete.
 */
always_inline int
ip6_ext_header_walk_bounded (const ip6_header_t *ip, u32 valid_end, int find_hdr_type,
			     ip6_ext_hdr_chain_t *res)
{
  const u8 *p = (const u8 *) ip;
  u8 next_proto = ip->protocol;
  u32 offset = sizeof (ip6_header_t);
  u32 scan_end = clib_min (valid_end, IP6_EXT_HDR_MAX_DEPTH);
  int i = 0;
  int found = -1;

  res->length = 0;
  res->complete = false;
  res->term_is_l4 = false;
  res->l4_fits = true;
  res->term_protocol = 0;
  res->term_offset = 0;

  while (offset <= scan_end && i < IP6_EXT_HDR_MAX)
    {
      u32 hdrlen;

      if (ip6_ext_hdr (next_proto))
	{
	  /* The length byte at offset + 1 must be readable. */
	  if (offset + sizeof (ip6_ext_header_t) > valid_end)
	    {
	      res->term_protocol = next_proto;
	      res->term_offset = offset;
	      break;
	    }
	  hdrlen = ip6_ext_header_len ((void *) (p + offset));
	}
      else if (next_proto == IP_PROTOCOL_IPV6_FRAGMENTATION)
	hdrlen = sizeof (ip6_frag_hdr_t);
      else if (next_proto == IP_PROTOCOL_IPSEC_AH)
	{
	  if (offset + sizeof (ip6_ext_header_t) > valid_end)
	    {
	      res->term_protocol = next_proto;
	      res->term_offset = offset;
	      break;
	    }
	  hdrlen = ip6_ext_authhdr_len ((void *) (p + offset));
	}
      else
	hdrlen = 0;

      if (offset + hdrlen > valid_end)
	{
	  res->term_protocol = next_proto;
	  res->term_offset = offset;
	  break;
	}

      if (hdrlen == 0)
	{
	  res->complete = true;
	  res->term_is_l4 = true;
	  res->term_protocol = next_proto;
	  res->term_offset = offset;
	  break;
	}

      res->eh[i].offset = offset;
      res->eh[i].protocol = next_proto;
      if (next_proto == find_hdr_type)
	found = i;
      i++;

      if (next_proto == IP_PROTOCOL_IPV6_FRAGMENTATION &&
	  ip6_frag_hdr_offset ((const ip6_frag_hdr_t *) (p + offset)) > 0)
	{
	  /*
	   * A non-first fragment carries no L4 header. Its fragment
	   * header names the datagram's protocol; report that protocol
	   * and the offset after the fragment header.
	   */
	  res->complete = true;
	  res->term_protocol = ((const ip6_frag_hdr_t *) (p + offset))->next_hdr;
	  res->term_offset = offset + hdrlen;
	  break;
	}

      next_proto = ((const ip6_ext_header_t *) (p + offset))->next_hdr;
      offset += hdrlen;
    }

  /*
   * The entry limit can stop the walk before a terminating header, but
   * the terminating protocol needs no chain slot. Record it when the
   * last extension header names one within the scan.
   */
  if (!res->complete && i == IP6_EXT_HDR_MAX && offset <= scan_end && !ip6_ext_hdr (next_proto) &&
      next_proto != IP_PROTOCOL_IPV6_FRAGMENTATION && next_proto != IP_PROTOCOL_IPSEC_AH)
    {
      res->complete = true;
      res->term_is_l4 = true;
      res->term_protocol = next_proto;
      res->term_offset = offset;
    }

  res->length = i;
  if (found != -1)
    return found;
  return i > 0 ? i - 1 : -1;
}

/*
 * Find an IPv6 extension header in the IPv6 header chain. The walk is
 * bounded by the bytes in the first buffer and the datagram's declared
 * length; the IP6_EXT_HDR_MAX_DEPTH limit stops the scan, not the
 * datagram.
 *
 * The extension header chain is returned in res. complete reports
 * whether the walk reached a terminating header; term_protocol and
 * term_offset describe it, and l4_fits reports whether a terminating
 * L4 header fits in full. When the walk stops at the depth or entry
 * limit, term_protocol and term_offset are zero.
 * Returns the index of find_hdr_type if it is in the chain, otherwise
 * the index of the last extension header, or -1 when the chain has no
 * extension header.
 */
always_inline int
ip6_ext_header_walk (vlib_buffer_t *b, ip6_header_t *ip, int find_hdr_type,
		     ip6_ext_hdr_chain_t *res)
{
  u32 valid_end = clib_min (vlib_bytes_left_in_buffer (b, ip),
			    sizeof (ip6_header_t) + clib_net_to_host_u16 (ip->payload_length));
  int walk_res = ip6_ext_header_walk_bounded (ip, valid_end, find_hdr_type, res);

  /*
   * Callers read the terminating L4 header without the tolerance for
   * truncated fields that the bounded walk allows, so require a
   * terminating L4 header to fit in full.
   */
  if (res->complete && res->term_is_l4)
    {
      u32 l4_len = ip6_ext_header_len_s (res->term_protocol, NULL);

      if (res->term_offset + l4_len > valid_end)
	res->l4_fits = false;
    }

  return walk_res;
}

always_inline void *
ip6_ext_header_find (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip,
		     int find_hdr_type, ip6_ext_header_t **prev_ext_header)
{
  ip6_ext_hdr_chain_t hdr_chain;
  int res = ip6_ext_header_walk (b, ip, find_hdr_type, &hdr_chain);

  if (res >= 0 && hdr_chain.eh[res].protocol == find_hdr_type)
    {
      if (prev_ext_header)
	{
	  if (res > 0)
	    *prev_ext_header = ip6_ext_next_header_offset (ip, hdr_chain.eh[res - 1].offset);
	  else
	    *prev_ext_header = 0;
	}
      return ip6_ext_next_header_offset (ip, hdr_chain.eh[res].offset);
    }

  if (hdr_chain.complete && hdr_chain.l4_fits && hdr_chain.term_protocol == find_hdr_type)
    {
      if (prev_ext_header)
	*prev_ext_header =
	  hdr_chain.length > 0 ?
	    ip6_ext_next_header_offset (ip, hdr_chain.eh[hdr_chain.length - 1].offset) :
	    0;
      return ip6_ext_next_header_offset (ip, hdr_chain.term_offset);
    }

  return 0;
}

/*
 * Whether the chain contains a first-fragment header.
 */
always_inline bool
ip6_ext_hdr_chain_is_first_fragment (const ip6_header_t *ip, const ip6_ext_hdr_chain_t *chain)
{
  int i;

  for (i = 0; i < chain->length; i++)
    if (chain->eh[i].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION &&
	0 == ip6_frag_hdr_offset ((const ip6_frag_hdr_t *) ((const u8 *) ip + chain->eh[i].offset)))
      return true;
  return false;
}

#endif /* included_ip6_packet_h */

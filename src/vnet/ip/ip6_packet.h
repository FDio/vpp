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

/*
 * Return true when a protocol starts an extension header chain: an
 * extension header, a fragment header or an IPsec AH header.
 */
static inline bool
ip6_is_chain_header (u8 protocol)
{
  return ip6_ext_hdr (protocol) || protocol == IP_PROTOCOL_IPV6_FRAGMENTATION ||
	 protocol == IP_PROTOCOL_IPSEC_AH;
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

#define ip6_ext_header_len(p)  ((((const ip6_ext_header_t *) (p))->n_data_u64s + 1) << 3)
#define ip6_ext_authhdr_len(p) ((((const ip6_ext_header_t *) (p))->n_data_u64s + 2) << 2)

static inline u32
ip6_l4_header_len (u8 protocol)
{
  switch (protocol)
    {
    case IP_PROTOCOL_ICMP6:
      return 4;
    case IP_PROTOCOL_UDP:
      return 8;
    case IP_PROTOCOL_TCP:
      return 20;
    default: /* The caller validates the length of other terminating
	       protocols. */
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

/*
 * Return the end of the datagram from ip: the smaller of the declared
 * IPv6 datagram length and the bytes from ip to the end of the buffer
 * chain. ip may precede the buffer's current data, as when a node has
 * already advanced past the IPv6 header.
 */
static inline u32
ip6_ext_header_datagram_end (vlib_buffer_t *b, const ip6_header_t *ip)
{
  u32 declared = sizeof (ip6_header_t) + clib_net_to_host_u16 (ip->payload_length);
  i64 offset = (u8 *) ip - (u8 *) vlib_buffer_get_current (b);
  i64 left = (i64) vlib_buffer_length_in_chain (vlib_get_main (), b) - offset;

  return clib_min (declared, left > 0 ? (u32) left : 0);
}

/*
 * Return the number of bytes from ip that belong to the datagram and are
 * present in the first buffer.
 */
static inline u32
ip6_ext_header_valid_end (vlib_buffer_t *b, const ip6_header_t *ip)
{
  return clib_min (vlib_bytes_left_in_buffer (b, (void *) ip), ip6_ext_header_datagram_end (b, ip));
}

#define IP6_EXT_HDR_MAX	      (4)   /* Maximum number of chain headers */
#define IP6_EXT_HDR_MAX_DEPTH (256) /* Maximum header depth */
/*
 * The outcome of the extension header walk.
 *
 * IP6_EXT_HDR_CHAIN_LIMIT: the depth or entry limit was reached with no
 * terminating header, or the bound does not cover the IPv6 header.
 * term_protocol and term_offset are zero. This is the zero value, so a
 * zero-initialized chain reports a limit stop.
 *
 * IP6_EXT_HDR_CHAIN_L4: a terminating L4 protocol whose fixed header
 * fits within the walk bound. term_protocol and term_offset describe the
 * header.
 *
 * IP6_EXT_HDR_CHAIN_L4_TRUNCATED: a terminating L4 protocol whose fixed
 * header does not fit within the walk bound. term_protocol and
 * term_offset describe where the header starts.
 *
 * IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG: a non-first fragment. Its fragment
 * header names the datagram's protocol in term_protocol, but the packet
 * contains no header of that protocol. term_offset is the start of the
 * fragment payload.
 *
 * IP6_EXT_HDR_CHAIN_TRUNCATED: a chain header that did not fit within
 * the walk bound. term_protocol and term_offset describe the header that
 * did not fit.
 */
typedef enum
{
  IP6_EXT_HDR_CHAIN_LIMIT,
  IP6_EXT_HDR_CHAIN_L4,		  /* the terminating L4 header fits */
  IP6_EXT_HDR_CHAIN_L4_TRUNCATED, /* the terminating L4 header does not fit */
  IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG,
  IP6_EXT_HDR_CHAIN_TRUNCATED,
} ip6_ext_hdr_chain_status_t;

/*
 * Reports whether the chain contains a fragment header, and whether that
 * fragment is the first one.
 */
typedef enum
{
  IP6_FRAG_NONE,
  IP6_FRAG_FIRST,
  IP6_FRAG_NON_FIRST,
} ip6_frag_kind_t;

typedef struct
{
  int length;
  ip6_ext_hdr_chain_status_t status;
  ip6_frag_kind_t frag_kind;
  bool entry_limit;  /* the entry limit stopped the walk */
  bool buffer_bound; /* a header fits in the datagram but not the walk bound */
  u16 term_protocol;
  u16 term_offset;
  struct
  {
    u16 protocol;
    u16 offset;
  } eh[IP6_EXT_HDR_MAX];
} ip6_ext_hdr_chain_t;

/*
 * Return true when the walk ended at an L4 header that fits in full.
 *
 * The walk validates the fixed header length only for TCP, UDP and
 * ICMP6. For every other terminating protocol it validates nothing, so
 * callers must validate the header themselves.
 */
always_inline bool
ip6_ext_hdr_chain_has_l4 (const ip6_ext_hdr_chain_t *chain)
{
  return chain->status == IP6_EXT_HDR_CHAIN_L4;
}

/*
 * Find the header named by find_hdr_type in a walked chain. The walk
 * records the last matching slot, so the search runs from the end of
 * eh[]. When no chain header matches, a terminating L4 header of that
 * protocol resolves to chain->length.
 *
 * Returns true when the chain has the header. index, protocol and
 * offset, when not NULL, receive the header's eh[] slot (chain->length
 * for the terminating L4 header), its protocol and its offset.
 */
always_inline bool
ip6_ext_hdr_chain_resolve (const ip6_ext_hdr_chain_t *chain, int find_hdr_type, int *index,
			   u16 *protocol, u16 *offset)
{
  int idx;
  u16 proto, off;

  for (idx = chain->length - 1; idx >= 0; idx--)
    if (chain->eh[idx].protocol == find_hdr_type)
      break;

  if (idx >= 0)
    {
      proto = chain->eh[idx].protocol;
      off = chain->eh[idx].offset;
    }
  else if (ip6_ext_hdr_chain_has_l4 (chain) && chain->term_protocol == find_hdr_type)
    {
      idx = chain->length;
      proto = chain->term_protocol;
      off = chain->term_offset;
    }
  else
    return false;

  if (index)
    *index = idx;
  if (protocol)
    *protocol = proto;
  if (offset)
    *offset = off;
  return true;
}

/*
 * Record a chain header that did not fit within the walk bound.
 */
static inline void
ip6_ext_hdr_chain_set_truncated (ip6_ext_hdr_chain_t *res, u8 next_proto, u32 offset)
{
  res->status = IP6_EXT_HDR_CHAIN_TRUNCATED;
  res->term_protocol = next_proto;
  res->term_offset = offset;
}

/*
 * Walk the IPv6 extension header chain from ip, bounded by valid_end
 * bytes from ip. A header is recorded only when it fits entirely within
 * valid_end. The scan stops at the first header that starts after
 * IP6_EXT_HDR_MAX_DEPTH bytes. A header that starts at or before that
 * depth is processed, and it may extend past the depth as long as it
 * fits within valid_end.
 *
 * datagram_end is the IPv6 header length plus the payload length. A
 * header that does not fit valid_end but fits datagram_end sets
 * buffer_bound, because the walk bound, not the datagram, ended the
 * walk.
 *
 * On return, status describes how the walk stopped; see
 * ip6_ext_hdr_chain_status_t. frag_kind reports whether the chain
 * contains a first or a non-first fragment header. The walk records the
 * fragment header before it sets frag_kind, so IP6_FRAG_FIRST or
 * IP6_FRAG_NON_FIRST implies length >= 1.
 */
always_inline void
ip6_ext_header_walk_bounded (const ip6_header_t *ip, u32 valid_end, u32 datagram_end,
			     ip6_ext_hdr_chain_t *res)
{
  const u8 *p = (const u8 *) ip;
  u8 next_proto = ip->protocol;
  u32 offset = sizeof (ip6_header_t);
  u32 scan_end = clib_min (valid_end, IP6_EXT_HDR_MAX_DEPTH);
  int i = 0;

  res->length = 0;
  res->status = IP6_EXT_HDR_CHAIN_LIMIT;
  res->frag_kind = IP6_FRAG_NONE;
  res->entry_limit = false;
  res->buffer_bound = false;
  res->term_protocol = 0;
  res->term_offset = 0;

  while (offset <= scan_end)
    {
      u32 hdrlen;

      /*
       * A terminating protocol needs no chain slot, so the walk checks
       * for it before the entry limit stops the walk.
       */
      if (!ip6_is_chain_header (next_proto))
	{
	  u32 l4_len = ip6_l4_header_len (next_proto);

	  res->status =
	    offset + l4_len <= valid_end ? IP6_EXT_HDR_CHAIN_L4 : IP6_EXT_HDR_CHAIN_L4_TRUNCATED;
	  res->buffer_bound = offset + l4_len > valid_end && offset + l4_len <= datagram_end;
	  res->term_protocol = next_proto;
	  res->term_offset = offset;
	  break;
	}

      if (i == IP6_EXT_HDR_MAX)
	{
	  res->entry_limit = true;
	  break; /* entry limit, no terminating header */
	}

      if (ip6_ext_hdr (next_proto) || next_proto == IP_PROTOCOL_IPSEC_AH)
	{
	  /* The length byte at offset + 1 must be readable. */
	  if (offset + sizeof (ip6_ext_header_t) > valid_end)
	    {
	      res->buffer_bound = offset + sizeof (ip6_ext_header_t) <= datagram_end;
	      ip6_ext_hdr_chain_set_truncated (res, next_proto, offset);
	      break;
	    }
	  hdrlen = ip6_ext_hdr (next_proto) ? ip6_ext_header_len (p + offset) :
					      ip6_ext_authhdr_len (p + offset);
	}
      else
	hdrlen = sizeof (ip6_frag_hdr_t);

      if (offset + hdrlen > valid_end)
	{
	  res->buffer_bound = offset + hdrlen <= datagram_end;
	  ip6_ext_hdr_chain_set_truncated (res, next_proto, offset);
	  break;
	}

      res->eh[i].offset = offset;
      res->eh[i].protocol = next_proto;
      i++;

      if (next_proto == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  if (ip6_frag_hdr_offset ((const ip6_frag_hdr_t *) (p + offset)) > 0)
	    {
	      /*
	       * A non-first fragment carries no L4 header. Its fragment
	       * header names the datagram's protocol, so record that
	       * protocol and the offset after the fragment header.
	       */
	      res->frag_kind = IP6_FRAG_NON_FIRST;
	      res->status = IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG;
	      res->term_protocol = ((const ip6_frag_hdr_t *) (p + offset))->next_hdr;
	      res->term_offset = offset + hdrlen;
	      break;
	    }
	  res->frag_kind = IP6_FRAG_FIRST;
	}

      next_proto = ((const ip6_ext_header_t *) (p + offset))->next_hdr;
      offset += hdrlen;
    }

  res->length = i;
}

/*
 * Find an IPv6 extension header in the IPv6 header chain. The walk is
 * bounded by the bytes in the first buffer and the datagram's declared
 * length. The IP6_EXT_HDR_MAX_DEPTH limit stops the scan, not the
 * datagram.
 *
 * The walk fills res with the extension header chain. status reports how
 * the walk stopped. term_protocol and term_offset describe the
 * terminating header for IP6_EXT_HDR_CHAIN_L4,
 * IP6_EXT_HDR_CHAIN_L4_TRUNCATED and
 * IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG, or the header that did not fit for
 * IP6_EXT_HDR_CHAIN_TRUNCATED. They are zero for
 * IP6_EXT_HDR_CHAIN_LIMIT.
 *
 * A non-negative find_hdr_type returns the index of that header in the
 * chain, or the index of the chain's last recorded header when the chain
 * does not contain it.
 *
 * A negative find_hdr_type reproduces the pre-bounded walk exactly. The
 * scan bound is the smaller of the datagram end and IP6_EXT_HDR_MAX_DEPTH.
 * The old walk recorded a header that started at the scan bound, and a
 * terminating header at the bound. A non-first fragment whose fragment
 * header ended past the bound stopped the old walk at the fragment
 * header, so the datagram protocol is not recorded. It recorded a later
 * chain header before checking whether that header fit, so the truncated
 * header is returned. It rejected a first chain header whose end passed the depth
 * limit and a plain packet whose fixed-length L4 header did not fit, so
 * both return -1. Otherwise the terminating header is recorded in eh[]
 * when a slot is free, and the index of the chain's last recorded header
 * is returned. External consumers read the terminating header from
 * eh[res] and treat a negative return as a malformed packet.
 */
always_inline int
ip6_ext_header_walk (vlib_buffer_t *b, ip6_header_t *ip, int find_hdr_type,
		     ip6_ext_hdr_chain_t *res)
{
  u32 valid_end = ip6_ext_header_valid_end (b, ip);
  u32 datagram_end = sizeof (ip6_header_t) + clib_net_to_host_u16 (ip->payload_length);
  u32 scan_end = clib_min (valid_end, IP6_EXT_HDR_MAX_DEPTH);
  int found;

  ip6_ext_header_walk_bounded (ip, valid_end, datagram_end, res);

  if (res->length == 0)
    {
      /* The old walk rejected a first header that did not fit. */
      if (res->status != IP6_EXT_HDR_CHAIN_L4)
	return -1;
      res->eh[0].protocol = res->term_protocol;
      res->eh[0].offset = res->term_offset;
      res->length = 1;
    }
  else if (res->status == IP6_EXT_HDR_CHAIN_LIMIT && res->length == 1)
    {
      /* The old walk rejected a first chain header whose end passed the
	 depth limit, but the bounded walk records it. */
      res->length = 0;
      return -1;
    }
  else if (res->status == IP6_EXT_HDR_CHAIN_TRUNCATED || res->status == IP6_EXT_HDR_CHAIN_L4 ||
	   res->status == IP6_EXT_HDR_CHAIN_L4_TRUNCATED ||
	   (res->status == IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG && res->term_offset <= scan_end))
    {
      /*
       * A non-first fragment whose header end passed the scan bound is
       * not recorded: the old walk stopped at the fragment header.
       */
      if (res->length < IP6_EXT_HDR_MAX)
	{
	  res->eh[res->length].protocol = res->term_protocol;
	  res->eh[res->length].offset = res->term_offset;
	  res->length++;
	}
    }

  if (find_hdr_type >= 0)
    {
      for (found = res->length - 1; found >= 0; found--)
	if (res->eh[found].protocol == find_hdr_type)
	  return found;
    }

  return res->length - 1;
}

always_inline void *
ip6_ext_header_find (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip,
		     int find_hdr_type, ip6_ext_header_t **prev_ext_header)
{
  ip6_ext_hdr_chain_t hdr_chain;
  int index;
  u16 offset;

  ip6_ext_header_walk_bounded (ip, ip6_ext_header_valid_end (b, ip),
			       ip6_ext_header_datagram_end (b, ip), &hdr_chain);
  if (!ip6_ext_hdr_chain_resolve (&hdr_chain, find_hdr_type, &index, NULL, &offset))
    return 0;

  if (prev_ext_header)
    *prev_ext_header =
      index > 0 ? ip6_ext_next_header_offset (ip, hdr_chain.eh[index - 1].offset) : 0;

  return ip6_ext_next_header_offset (ip, offset);
}

#endif /* included_ip6_packet_h */

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vxlan/vxlan.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

#define FLOW_IS_ETHERNET_CLASS(f) (f->type == VNET_FLOW_TYPE_ETHERNET)

#define FLOW_IS_IPV4_CLASS(f)                                                                      \
  ((f->type == VNET_FLOW_TYPE_IP4) || (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                   \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || (f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||      \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) || (f->type == VNET_FLOW_TYPE_IP4_GTPU) ||                 \
   (f->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP) || (f->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP) ||       \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_AH) || (f->type == VNET_FLOW_TYPE_IP4_IP4) ||              \
   (f->type == VNET_FLOW_TYPE_IP4_IP6) || (f->type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE) ||           \
   (f->type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE))

#define FLOW_IS_IPV6_CLASS(f)                                                                      \
  ((f->type == VNET_FLOW_TYPE_IP6) || (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                   \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED) || (f->type == VNET_FLOW_TYPE_IP6_VXLAN) ||      \
   (f->type == VNET_FLOW_TYPE_IP6_IP4) || (f->type == VNET_FLOW_TYPE_IP6_IP6) ||                   \
   (f->type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE) || (f->type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE))

/* check if flow is VLAN sensitive */
#define FLOW_HAS_VLAN_TAG(f)                                                                       \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L3 type */
#define FLOW_IS_L3_TYPE(f) ((f->type == VNET_FLOW_TYPE_IP4) || (f->type == VNET_FLOW_TYPE_IP6))

/* check if flow is L4 type */
#define FLOW_IS_L4_TYPE(f)                                                                         \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) || (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||           \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                                               \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L4 tunnel type */
#define FLOW_IS_L4_TUNNEL_TYPE(f)                                                                  \
  ((f->type == VNET_FLOW_TYPE_IP4_VXLAN) || (f->type == VNET_FLOW_TYPE_IP6_VXLAN) ||               \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) || (f->type == VNET_FLOW_TYPE_IP4_GTPU))

/* check if flow has a inner TCP/UDP header */
#define FLOW_HAS_INNER_N_TUPLE(f)                                                                  \
  ((f->type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE) || (f->type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE) ||   \
   (f->type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE) || (f->type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE))

#define FLOW_NEEDS_MARK(f)                                                                         \
  (f->actions &                                                                                    \
   (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE | VNET_FLOW_ACTION_BUFFER_ADVANCE))

#define FOREACH_FLOW_ITEM(_items, _item)                                                           \
  (_item) = &(_items)[0];                                                                          \
  for (int _it = 0; (_item)->type != RTE_FLOW_ITEM_TYPE_END; (_item) = &(_items)[++_it])

/* get source addr from ipv6 header */
#if (RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0))
#define IP6_SRC_ADDR(ip6) ip6.hdr.src_addr.a
#else
#define IP6_SRC_ADDR(ip6) ip6.hdr.src_addr
#endif

/* get destination addr from ipv6 header */
#if (RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0))
#define IP6_DST_ADDR(ip6) ip6.hdr.dst_addr.a
#else
#define IP6_DST_ADDR(ip6) ip6.hdr.dst_addr
#endif

/* constant structs */
static const struct rte_flow_attr ingress = { .transfer = 1, .group = 1 };
static const struct rte_flow_actions_template_attr action_attr = { .transfer = 1 };
static const struct rte_flow_pattern_template_attr pattern_attr = { .transfer = 1,
								    .relaxed_matching = 1 };
static const struct rte_flow_op_attr async_op = { .postpone = 1 };

static inline bool
mac_address_is_all_zero (const u8 addr[6])
{
  int i = 0;

  for (i = 0; i < 6; i++)
    if (addr[i] != 0)
      return false;

  return true;
}

static inline void
dpdk_flow_convert_rss_types (u64 type, u64 *dpdk_rss_type)
{
#define BIT_IS_SET(v, b) ((v) & (u64) 1 << (b))

  *dpdk_rss_type = 0;

#undef _
#define _(n, f, s)                                                                                 \
  if (n != -1 && BIT_IS_SET (type, n))                                                             \
    *dpdk_rss_type |= f;

  foreach_dpdk_rss_hf
#undef _
    return;
}

/** Maximum number of queue indices in struct rte_flow_action_rss. */
#define ACTION_RSS_QUEUE_NUM 128

static inline void
dpdk_flow_convert_rss_queues (u32 queue_index, u32 queue_num, struct rte_flow_action_rss *rss)
{
  u16 *queues = clib_mem_alloc (sizeof (*queues) * ACTION_RSS_QUEUE_NUM);
  int i;

  for (i = 0; i < queue_num; i++)
    queues[i] = queue_index++;

  rss->queue_num = queue_num;
  rss->queue = queues;

  return;
}

static inline enum rte_eth_hash_function
dpdk_flow_convert_rss_func (vnet_rss_function_t func)
{
  enum rte_eth_hash_function rss_func;

  switch (func)
    {
    case VNET_RSS_FUNC_DEFAULT:
      rss_func = RTE_ETH_HASH_FUNCTION_DEFAULT;
      break;
    case VNET_RSS_FUNC_TOEPLITZ:
      rss_func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
      break;
    case VNET_RSS_FUNC_SIMPLE_XOR:
      rss_func = RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
      break;
    case VNET_RSS_FUNC_SYMMETRIC_TOEPLITZ:
      rss_func = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
      break;
    default:
      rss_func = RTE_ETH_HASH_FUNCTION_MAX;
      break;
    }

  return rss_func;
}

static int
dpdk_flow_fill_items (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
		      struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS])
{
  static struct rte_flow_item_eth eth[2] = {};
  static struct rte_flow_item_ipv4 ip4[2] = {}, in_ip4[2] = {};
  static struct rte_flow_item_ipv6 ip6[2] = {}, in_ip6[2] = {};
  static struct rte_flow_item_udp udp[2] = {}, in_UDP[2] = {};
  static struct rte_flow_item_tcp tcp[2] = {}, in_TCP[2] = {};
  static struct rte_flow_item_gtp gtp[2] = {};
  static struct rte_flow_item_l2tpv3oip l2tp[2] = {};
  static struct rte_flow_item_esp esp[2] = {};
  static struct rte_flow_item_ah ah[2] = {};
  static struct rte_flow_item_raw generic[2] = {};
  struct rte_flow_item *item;

  enum
  {
    vxlan_hdr_sz = sizeof (vxlan_header_t),
    raw_sz = sizeof (struct rte_flow_item_raw)
  };

  static union
  {
    struct rte_flow_item_raw item;
    u8 val[raw_sz + vxlan_hdr_sz];
  } raw[2];

  u16 src_port = 0, dst_port = 0, src_port_mask = 0, dst_port_mask = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;
  int n = 0;
  int rv = 0;

  /* Handle generic flow first */
  if (f->type == VNET_FLOW_TYPE_GENERIC)
    {
      generic[0].pattern = f->generic.pattern.spec;
      generic[1].pattern = f->generic.pattern.mask;

      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_RAW;
      item->spec = generic;
      item->mask = generic + 1;
      item->last = NULL;

      goto pattern_end;
    }

  enum
  {
    FLOW_UNKNOWN_CLASS,
    FLOW_ETHERNET_CLASS,
    FLOW_IPV4_CLASS,
    FLOW_IPV6_CLASS,
  } flow_class = FLOW_UNKNOWN_CLASS;

  if (FLOW_IS_ETHERNET_CLASS (f))
    flow_class = FLOW_ETHERNET_CLASS;
  else if (FLOW_IS_IPV4_CLASS (f))
    flow_class = FLOW_IPV4_CLASS;
  else if (FLOW_IS_IPV6_CLASS (f))
    flow_class = FLOW_IPV6_CLASS;
  else
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (f->actions & (~xd->supported_flow_actions))
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Match items */
  /* Layer 2, Ethernet */

  if (flow_class == FLOW_ETHERNET_CLASS)
    {
      vnet_flow_ethernet_t *te = &f->ethernet;

      clib_memset (&eth[0], 0, sizeof (eth[0]));
      clib_memset (&eth[1], 0, sizeof (eth[1]));

      /* check if SMAC/DMAC/Ether_type assigned */
      if (!mac_address_is_all_zero (te->eth_hdr.dst_address))
	{
	  clib_memcpy_fast (&eth[0].dst, &te->eth_hdr.dst_address, sizeof (eth[0].dst));
	  clib_memset (&eth[1].dst, 0xFF, sizeof (eth[1].dst));
	}

      if (!mac_address_is_all_zero (te->eth_hdr.src_address))
	{
	  clib_memcpy_fast (&eth[0].src, &te->eth_hdr.src_address, sizeof (eth[0].src));
	  clib_memset (&eth[1].src, 0xFF, sizeof (eth[1].src));
	}

      if (te->eth_hdr.type)
	{
	  eth[0].type = clib_host_to_net_u16 (te->eth_hdr.type);
	  eth[1].type = clib_host_to_net_u16 (0xFFFF);
	}

      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_ETH;
      item->spec = eth;
      item->mask = eth + 1;
      item->last = NULL;
    }

  /* currently only single empty vlan tag is supported */
  if (FLOW_HAS_VLAN_TAG (f))
    {
      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_VLAN;
      item->spec = NULL;
      item->mask = NULL;
      item->last = NULL;
    }

  if (FLOW_IS_ETHERNET_CLASS (f))
    goto pattern_end;

  /* Layer 3, IP */
  if (flow_class == FLOW_IPV4_CLASS)
    {
      vnet_flow_ip4_t *ip4_ptr = &f->ip4;

      if (ip4_ptr->src_addr.mask.as_u32 != 0 || ip4_ptr->dst_addr.mask.as_u32 != 0 ||
	  ip4_ptr->protocol.mask != 0)
	{
	  ip4[0].hdr.src_addr = ip4_ptr->src_addr.addr.as_u32;
	  ip4[1].hdr.src_addr = ip4_ptr->src_addr.mask.as_u32;
	  ip4[0].hdr.dst_addr = ip4_ptr->dst_addr.addr.as_u32;
	  ip4[1].hdr.dst_addr = ip4_ptr->dst_addr.mask.as_u32;
	  ip4[0].hdr.next_proto_id = ip4_ptr->protocol.prot;
	  ip4[1].hdr.next_proto_id = ip4_ptr->protocol.mask;

	  item = &items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	  item->spec = ip4;
	  item->mask = ip4 + 1;
	  item->last = NULL;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip4_n_tuple_t *ip4_n_ptr = &f->ip4_n_tuple;

	  src_port = ip4_n_ptr->src_port.port;
	  dst_port = ip4_n_ptr->dst_port.port;
	  src_port_mask = ip4_n_ptr->src_port.mask;
	  dst_port_mask = ip4_n_ptr->dst_port.mask;
	}

      protocol = ip4_ptr->protocol.prot;
    }
  else if (flow_class == FLOW_IPV6_CLASS)
    {
      vnet_flow_ip6_t *ip6_ptr = &f->ip6;

      if (ip6_ptr->src_addr.mask.as_u64[0] != 0 || ip6_ptr->src_addr.mask.as_u64[1] != 0 ||
	  ip6_ptr->dst_addr.mask.as_u64[0] != 0 || ip6_ptr->dst_addr.mask.as_u64[1] != 0 ||
	  ip6_ptr->protocol.mask != 0)
	{
	  clib_memcpy (IP6_SRC_ADDR (ip6[0]), &ip6_ptr->src_addr.addr,
		       ARRAY_LEN (ip6_ptr->src_addr.addr.as_u8));
	  clib_memcpy (IP6_SRC_ADDR (ip6[1]), &ip6_ptr->src_addr.mask,
		       ARRAY_LEN (ip6_ptr->src_addr.mask.as_u8));
	  clib_memcpy (IP6_DST_ADDR (ip6[0]), &ip6_ptr->dst_addr.addr,
		       ARRAY_LEN (ip6_ptr->dst_addr.addr.as_u8));
	  clib_memcpy (IP6_DST_ADDR (ip6[1]), &ip6_ptr->dst_addr.mask,
		       ARRAY_LEN (ip6_ptr->dst_addr.mask.as_u8));
	  ip6[0].hdr.proto = ip6_ptr->protocol.prot;
	  ip6[1].hdr.proto = ip6_ptr->protocol.mask;

	  item = &items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	  item->spec = ip6;
	  item->mask = ip6 + 1;
	  item->last = NULL;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip6_n_tuple_t *ip6_n_ptr = &f->ip6_n_tuple;

	  src_port = ip6_n_ptr->src_port.port;
	  dst_port = ip6_n_ptr->dst_port.port;
	  src_port_mask = ip6_n_ptr->src_port.mask;
	  dst_port_mask = ip6_n_ptr->dst_port.mask;
	}

      protocol = ip6_ptr->protocol.prot;
    }

  if (FLOW_IS_L3_TYPE (f))
    goto pattern_end;

  /* Layer 3, IP */
  switch (protocol)
    {
    case IP_PROTOCOL_L2TP:
      l2tp[0].session_id = clib_host_to_net_u32 (f->ip4_l2tpv3oip.session_id);
      l2tp[1].session_id = ~0;

      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_L2TPV3OIP;
      item->spec = l2tp;
      item->mask = l2tp + 1;
      item->last = NULL;
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      esp[0].hdr.spi = clib_host_to_net_u32 (f->ip4_ipsec_esp.spi);
      esp[1].hdr.spi = ~0;

      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
      item->spec = esp;
      item->mask = esp + 1;
      item->last = NULL;
      break;

    case IP_PROTOCOL_IPSEC_AH:
      ah[0].spi = clib_host_to_net_u32 (f->ip4_ipsec_ah.spi);
      ah[1].spi = ~0;

      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_AH;
      item->spec = ah;
      item->mask = ah + 1;
      item->last = NULL;
      break;
    case IP_PROTOCOL_TCP:
      if (src_port_mask == 0 && dst_port_mask == 0)
	break;

      tcp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
      tcp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
      tcp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
      tcp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);

      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_TCP;
      item->spec = tcp;
      item->mask = tcp + 1;
      item->last = NULL;
      break;

    case IP_PROTOCOL_UDP:
      if (src_port_mask != 0 || dst_port_mask != 0)
	{
	  udp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
	  udp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
	  udp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
	  udp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);

	  item = &items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_UDP;
	  item->spec = udp;
	  item->mask = udp + 1;
	  item->last = NULL;
	}

      /* handle the UDP tunnels */
      if (f->type == VNET_FLOW_TYPE_IP4_GTPC)
	{
	  gtp[0].teid = clib_host_to_net_u32 (f->ip4_gtpc.teid);
	  gtp[1].teid = ~0;

	  item = &items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_GTPC;
	  item->spec = gtp;
	  item->mask = gtp + 1;
	  item->last = NULL;
	}
      else if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	{
	  gtp[0].teid = clib_host_to_net_u32 (f->ip4_gtpu.teid);
	  gtp[1].teid = ~0;

	  item = &items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_GTPU;
	  item->spec = gtp;
	  item->mask = gtp + 1;
	  item->last = NULL;
	}
      else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
	{
	  u32 vni = f->ip4_vxlan.vni;

	  vxlan_header_t spec_hdr = { .flags = VXLAN_FLAGS_I,
				      .vni_reserved = clib_host_to_net_u32 (vni << 8) };
	  vxlan_header_t mask_hdr = { .flags = 0xff,
				      .vni_reserved = clib_host_to_net_u32 (((u32) -1) << 8) };

	  clib_memset (raw, 0, sizeof raw);
	  raw[0].item.relative = 1;
	  raw[0].item.length = vxlan_hdr_sz;

	  clib_memcpy_fast (raw[0].val + raw_sz, &spec_hdr, vxlan_hdr_sz);
	  raw[0].item.pattern = raw[0].val + raw_sz;
	  clib_memcpy_fast (raw[1].val + raw_sz, &mask_hdr, vxlan_hdr_sz);
	  raw[1].item.pattern = raw[1].val + raw_sz;

	  item = &items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_RAW;
	  item->spec = raw;
	  item->mask = raw + 1;
	  item->last = NULL;
	}
      break;
    case IP_PROTOCOL_IPV6:

#define fill_inner_ip6_with_outer_ipv(OUTER_IP_VER)                                                \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP6 ||                                          \
      f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP6_N_TUPLE)                                    \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip6_t *ptr = &f->ip##OUTER_IP_VER##_ip6;                        \
      if ((ptr->in_src_addr.mask.as_u64[0] == 0) && (ptr->in_src_addr.mask.as_u64[1] == 0) &&      \
	  (ptr->in_dst_addr.mask.as_u64[0] == 0) && (ptr->in_dst_addr.mask.as_u64[1] == 0) &&      \
	  (!ptr->in_protocol.mask))                                                                \
	break;                                                                                     \
                                                                                                   \
      clib_memcpy (IP6_SRC_ADDR (in_ip6[0]), &ptr->in_src_addr.addr,                               \
		   ARRAY_LEN (ptr->in_src_addr.addr.as_u8));                                       \
      clib_memcpy (IP6_SRC_ADDR (in_ip6[1]), &ptr->in_src_addr.mask,                               \
		   ARRAY_LEN (ptr->in_src_addr.mask.as_u8));                                       \
      clib_memcpy (IP6_DST_ADDR (in_ip6[0]), &ptr->in_dst_addr.addr,                               \
		   ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));                                       \
      clib_memcpy (IP6_DST_ADDR (in_ip6[1]), &ptr->in_dst_addr.mask,                               \
		   ARRAY_LEN (ptr->in_dst_addr.mask.as_u8));                                       \
                                                                                                   \
      item = &items[n++];                                                                          \
      item->type = RTE_FLOW_ITEM_TYPE_IPV6;                                                        \
      item->spec = in_ip6;                                                                         \
      item->mask = in_ip6 + 1;                                                                     \
      item->last = NULL;                                                                           \
    }

      fill_inner_ip6_with_outer_ipv (6) fill_inner_ip6_with_outer_ipv (4)
#undef fill_inner_ip6_with_outer_ipv
	break;
    case IP_PROTOCOL_IP_IN_IP:
#define fill_inner_ip4_with_outer_ipv(OUTER_IP_VER)                                                \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP4 ||                                          \
      f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP4_N_TUPLE)                                    \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip4_t *ptr = &f->ip##OUTER_IP_VER##_ip4;                        \
      if ((!ptr->in_src_addr.mask.as_u32) && (!ptr->in_dst_addr.mask.as_u32) &&                    \
	  (!ptr->in_protocol.mask))                                                                \
	break;                                                                                     \
                                                                                                   \
      in_ip4[0].hdr.src_addr = ptr->in_src_addr.addr.as_u32;                                       \
      in_ip4[1].hdr.src_addr = ptr->in_src_addr.mask.as_u32;                                       \
      in_ip4[0].hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;                                       \
      in_ip4[1].hdr.dst_addr = ptr->in_dst_addr.mask.as_u32;                                       \
                                                                                                   \
      item = &items[n++];                                                                          \
      item->type = RTE_FLOW_ITEM_TYPE_IPV4;                                                        \
      item->spec = in_ip4;                                                                         \
      item->mask = in_ip4 + 1;                                                                     \
      item->last = NULL;                                                                           \
    }
      fill_inner_ip4_with_outer_ipv (6) fill_inner_ip4_with_outer_ipv (4)
#undef fill_inner_ip4_with_outer_ipv
	break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if (FLOW_HAS_INNER_N_TUPLE (f))
    {

#define fill_inner_n_tuple_of(proto)                                                               \
  if ((ptr->in_src_port.mask == 0) && (ptr->in_dst_port.mask == 0))                                \
    break;                                                                                         \
                                                                                                   \
  in_##proto[0].hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);                       \
  in_##proto[1].hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.mask);                       \
  in_##proto[0].hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);                       \
  in_##proto[1].hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.mask);                       \
                                                                                                   \
  item = &items[n++];                                                                              \
  item->type = RTE_FLOW_ITEM_TYPE_##proto;                                                         \
  item->spec = in_##proto;                                                                         \
  item->mask = in_##proto + 1;                                                                     \
  item->last = NULL;

#define fill_inner_n_tuple(OUTER_IP_VER, INNER_IP_VER)                                             \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP##INNER_IP_VER##_N_TUPLE)                     \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip##INNER_IP_VER##_n_tuple_t *ptr =                             \
	&f->ip##OUTER_IP_VER##_ip##INNER_IP_VER##_n_tuple;                                         \
      switch (ptr->in_protocol.prot)                                                               \
	{                                                                                          \
	case IP_PROTOCOL_UDP:                                                                      \
	  fill_inner_n_tuple_of (UDP) break;                                                       \
	case IP_PROTOCOL_TCP:                                                                      \
	  fill_inner_n_tuple_of (TCP) break;                                                       \
	default:                                                                                   \
	  break;                                                                                   \
	}                                                                                          \
    }
      fill_inner_n_tuple (6, 4) fill_inner_n_tuple (4, 4) fill_inner_n_tuple (6, 6)
	fill_inner_n_tuple (4, 6)
#undef fill_inner_n_tuple
#undef fill_inner_n_tuple_of
    }

pattern_end:
  if ((f->actions & VNET_FLOW_ACTION_RSS) && (f->rss_types & (1ULL << VNET_FLOW_RSS_TYPES_ESP)))
    {
      item = &items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
      item->spec = NULL;
      item->mask = NULL;
      item->last = NULL;
    }

  item = &items[n++];
  item->type = RTE_FLOW_ITEM_TYPE_END;
  item->spec = NULL;
  item->mask = NULL;
  item->last = NULL;

done:
  return rv;
}

static int
dpdk_flow_fill_actions (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS])
{
  static struct rte_flow_action_mark mark = { 0 };
  static struct rte_flow_action_queue queue = { 0 };
  static struct rte_flow_action_rss rss = { 0 };
  struct rte_flow_action *action;
  bool fate = false;
  int n = 0;

  /* Only one 'fate' can be assigned */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      action = &actions[n++];
      queue.index = f->redirect_queue;
      action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
      action->conf = &queue;
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;

      action = &actions[n++];
      action->type = RTE_FLOW_ACTION_TYPE_DROP;
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {

      if (fate == true)
	return VNET_FLOW_ERROR_INTERNAL;

      u64 rss_type = 0;

      action = &actions[n++];
      action->type = RTE_FLOW_ACTION_TYPE_RSS;
      action->conf = &rss;

      /* convert types to DPDK rss bitmask */
      dpdk_flow_convert_rss_types (f->rss_types, &rss_type);

      if (f->queue_num)
	/* convert rss queues to array */
	dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, &rss);

      rss.types = rss_type;
      if ((rss.func = dpdk_flow_convert_rss_func (f->rss_fun)) == RTE_ETH_HASH_FUNCTION_MAX)
	return VNET_FLOW_ERROR_NOT_SUPPORTED;

      fate = true;
    }

  if (!fate)
    {
      action = &actions[n++];
      action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    }

  if (FLOW_NEEDS_MARK (f))
    {
      action = &actions[n++];
      mark.id = fe->mark;
      action->type = RTE_FLOW_ACTION_TYPE_MARK;
      action->conf = &mark;
    }

  action = &actions[n++];
  action->type = RTE_FLOW_ACTION_TYPE_END;
  return 0;
}

int
dpdk_flow_fill_items_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			       struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS])
{
  struct rte_flow_item *item;
  int rv;

  // HACK: flow_entry is not used in fill_items
  if ((rv = dpdk_flow_fill_items (xd, t, NULL, items)))
    return rv;

  FOREACH_FLOW_ITEM (items, item) { item->spec = NULL; }

  return 0;
}

int
dpdk_flow_fill_actions_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
				 struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS],
				 struct rte_flow_action masks[DPDK_MAX_FLOW_ACTIONS])
{
  bool fate = false;
  int n = 0;

#define add_action_type(_type)                                                                     \
  {                                                                                                \
    actions[n].type = RTE_FLOW_ACTION_TYPE_##_type;                                                \
    masks[n].type = RTE_FLOW_ACTION_TYPE_##_type;                                                  \
    n++;                                                                                           \
  }

  /* Only one 'fate' can be assigned */
  if (t->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      add_action_type (QUEUE);
      fate = true;
    }

  if (t->actions & VNET_FLOW_ACTION_DROP)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;

      add_action_type (DROP);
      fate = true;
    }

  if (t->actions & VNET_FLOW_ACTION_RSS)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;

      add_action_type (RSS);
      fate = true;
    }

  if (!fate)
    add_action_type (PASSTHRU);

  if (FLOW_NEEDS_MARK (t))
    add_action_type (MARK);

  add_action_type (END);
  return 0;
}

static int
dpdk_flow_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  int rv;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, actions)) != 0)
    return rv;

  rv = rte_flow_validate (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (rv)
    {
      dpdk_device_flow_error (xd, "rte_flow_validate");

      if (rv == -EINVAL)
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      else if (rv == -EEXIST)
	rv = VNET_FLOW_ERROR_ALREADY_EXISTS;
      else
	rv = VNET_FLOW_ERROR_INTERNAL;

      return rv;
    }

  fe->handle = rte_flow_create (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (!fe->handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_create");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return 0;
}

static int
dpdk_flow_async_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_template_entry_t *fte,
		     dpdk_flow_entry_t *fe)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, actions)) != 0)
    return rv;

  fe->handle =
    rte_flow_async_create (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &async_op,
			   fte->table_handle, items, 0, actions, 0, NULL, &xd->last_flow_error);

  if (!fe->handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_async_create");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return 0;
}

static int
dpdk_flow_async_template_add (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			      u32 nb_flows)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_action actions_mask[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_template_table_attr template_attr = {
    .nb_flows = nb_flows,
  };
  int rv = 0;

  clib_memcpy (&template_attr.flow_attr, &ingress, sizeof (ingress));

  if ((rv = dpdk_flow_fill_items_template (xd, t, fte, items)) != 0)
    return rv;

  fte->pattern_handle =
    rte_flow_pattern_template_create (xd->port_id, &pattern_attr, items, &xd->last_flow_error);
  if (!fte->pattern_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_pattern_template_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if ((rv = dpdk_flow_fill_actions_template (xd, t, fte, actions, actions_mask)) != 0)
    goto done_pattern_handle;

  fte->actions_handle = rte_flow_actions_template_create (xd->port_id, &action_attr, actions,
							  actions_mask, &xd->last_flow_error);
  if (!fte->actions_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_actions_template_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_pattern_handle;
    }

  fte->table_handle =
    rte_flow_template_table_create (xd->port_id, &template_attr, &fte->pattern_handle, 1,
				    &fte->actions_handle, 1, &xd->last_flow_error);
  if (!fte->table_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_template_table_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_actions_handle;
    }

  return 0;

done_actions_handle:
  rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle, &xd->last_flow_error);
  fte->actions_handle = 0;

done_pattern_handle:
  rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle, &xd->last_flow_error);
  fte->pattern_handle = 0;

done:
  return rv;
}

int
dpdk_flow_ops_fn (vnet_main_t * vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		  u32 flow_index, uword * private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle = 0;
  int rv;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 &&
      xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fe = vec_elt_at_index (xd->flow_entries, *private_data);

      if ((rv = rte_flow_destroy (xd->port_id, fe->handle, &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if (fe->mark)
	{
	  /* make sure no action is taken for in-flight (marked) packets */
	  fle = pool_elt_at_index (xd->flow_lookup_entries, fe->mark);
	  clib_memset (fle, -1, sizeof (*fle));
	  vec_add1 (xd->parked_lookup_indexes, fe->mark);
	  xd->parked_loop_count = vm->main_loop_count;
	}

      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);

      goto disable_rx_offload;
    }

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  pool_get (xd->flow_entries, fe);
  fe->flow_index = flow->index;

  if (flow->actions == 0)
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* if we need to mark packets, assign one mark */
  if (FLOW_NEEDS_MARK (flow))
    {
      /* reserve slot 0 */
      if (xd->flow_lookup_entries == 0)
	pool_get_aligned (xd->flow_lookup_entries, fle,
			  CLIB_CACHE_LINE_BYTES);
      pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
      fe->mark = fle - xd->flow_lookup_entries;

      /* install entry in the lookup table */
      clib_memset (fle, -1, sizeof (*fle));
      if (flow->actions & VNET_FLOW_ACTION_MARK)
	fle->flow_id = flow->mark_flow_id;
      if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	fle->next_index = flow->redirect_device_input_next_index;
      if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	fle->buffer_advance = flow->buffer_advance;
    }
  else
    fe->mark = 0;

  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) == 0)
    {
      xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  switch (flow->type)
    {
    case VNET_FLOW_TYPE_ETHERNET:
    case VNET_FLOW_TYPE_IP4:
    case VNET_FLOW_TYPE_IP6:
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_VXLAN:
    case VNET_FLOW_TYPE_IP4_GTPC:
    case VNET_FLOW_TYPE_IP4_GTPU:
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
    case VNET_FLOW_TYPE_IP4_IP4:
    case VNET_FLOW_TYPE_IP4_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_IP6:
    case VNET_FLOW_TYPE_IP4_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP4:
    case VNET_FLOW_TYPE_IP6_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP6:
    case VNET_FLOW_TYPE_IP6_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_GENERIC:
      if ((rv = dpdk_flow_add (xd, flow, fe)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  *private_data = fe - xd->flow_entries;

done:
  if (rv)
    {
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
      if (fle)
	{
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put (xd->flow_lookup_entries, fle);
	}
    }
disable_rx_offload:
  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) != 0
      && pool_elts (xd->flow_entries) == 0)
    {
      xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  return rv;
}

static_always_inline int
dpdk_flow_async_push_pull (dpdk_device_t *xd, u32 enqueued, u32 *in_flight, bool force_push,
			   bool force_pull)
{
  static struct rte_flow_op_result results[DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH];
  static u32 max_in_flight = (DPDK_DEFAULT_ASYNC_FLOW_QUEUE_SIZE * 3) / 4;

  int rv;
  u32 pulled;
  /* When force_pull is set, wait for ALL operations to complete (in_flight == 0).
   * Otherwise, just keep in_flight below the threshold to avoid queue overflow. */
  u32 target_in_flight = force_pull ? 0 : max_in_flight;
  bool do_pull = force_pull || *in_flight >= target_in_flight;
  // When pulling, we always want the in flight work to be pushed beforehand
  bool do_push = do_pull || force_push || (enqueued % DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH) == 0;

  if (PREDICT_FALSE (do_push))
    {
      rv = rte_flow_push (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &xd->last_flow_error);
      if (rv)
	return VNET_FLOW_ERROR_INTERNAL;
    }

  if (PREDICT_FALSE (do_pull))
    {
      do
	{
	  pulled = rte_flow_pull (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, results,
				  DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH, &xd->last_flow_error);
	  if (pulled > 0)
	    *in_flight -= pulled;
	  else if (pulled == 0)
	    CLIB_PAUSE ();
	  else
	    return VNET_FLOW_ERROR_INTERNAL;
	}
      while (*in_flight > target_in_flight);
    }
  return 0;
}

static int
dpdk_flow_async_op_del (dpdk_device_t *xd, vnet_flow_range_t *range, uword *private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_flow_t *flow;
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle;
  uword per_flow_private_data;
  u32 in_flight = 0, enqueued = 0;
  int rv = 0;

  flow_range_foreach (range, flow)
  {
    per_flow_private_data = vec_elt (private_data, enqueued);
    fe = vec_elt_at_index (xd->flow_entries, per_flow_private_data);

    if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, false, false)))
      return rv;

    if ((rv = rte_flow_async_destroy (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &async_op,
				      fe->handle, NULL, &xd->last_flow_error)))
      {
	dpdk_device_flow_error (xd, "rte_flow_async_destroy");
	return VNET_FLOW_ERROR_INTERNAL;
      }

    in_flight++;
    enqueued++;

    if (fe->mark)
      {
	/* make sure no action is taken for in-flight (marked) packets */
	fle = pool_elt_at_index (xd->flow_lookup_entries, fe->mark);
	clib_memset (fle, -1, sizeof (*fle));
	vec_add1 (xd->parked_lookup_indexes, fe->mark);
	xd->parked_loop_count = vm->main_loop_count;
      }

    clib_memset (fe, 0, sizeof (*fe));
    pool_put (xd->flow_entries, fe);
  }

  if (pool_elts (xd->flow_entries) == 0)
    xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, true, true)))
    return rv;

  return 0;
}

static int
dpdk_flow_async_op_add (dpdk_device_t *xd, vnet_flow_range_t *range,
			dpdk_flow_template_entry_t *fte, uword *private_data)
{
  vnet_flow_t *flow;
  dpdk_flow_entry_t *fe = 0;
  dpdk_flow_lookup_entry_t *fle = 0;
  uword *per_flow_private_data;
  u32 in_flight = 0, enqueued = 0;
  int rv = 0;

  /* Set offload flag once before loop */
  xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  flow_range_foreach (range, flow)
  {
    per_flow_private_data = vec_elt_at_index (private_data, enqueued);

    if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, false, false)))
      return rv;

    pool_get (xd->flow_entries, fe);
    fe->flow_index = flow->index;
    *per_flow_private_data = fe - xd->flow_entries;

    /* if we need to mark packets, assign one mark */
    if (flow->actions & (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE |
			 VNET_FLOW_ACTION_BUFFER_ADVANCE))
      {
	/* reserve slot 0 */
	if (xd->flow_lookup_entries == 0)
	  pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
	pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
	fe->mark = fle - xd->flow_lookup_entries;

	/* install entry in the lookup table */
	clib_memset (fle, -1, sizeof (*fle));
	if (flow->actions & VNET_FLOW_ACTION_MARK)
	  fle->flow_id = flow->mark_flow_id;
	if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	  fle->next_index = flow->redirect_device_input_next_index;
	if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	  fle->buffer_advance = flow->buffer_advance;
      }
    else
      {
	fe->mark = 0;
      }

    /* Fast path uses function pointers from template, fallback to generic */
    if (PREDICT_FALSE ((rv = dpdk_flow_async_add (xd, flow, fte, fe))))
      goto insert_error;

    in_flight++;
    enqueued++;
  }

  if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, true, true)))
    return rv;

  return 0;

insert_error:
  if (fe)
    {
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
    }
  if (fle)
    {
      clib_memset (fle, -1, sizeof (*fle));
      pool_put (xd->flow_lookup_entries, fle);
    }
  return rv;
}

int
dpdk_flow_async_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
			vnet_flow_range_t *range, uword *private_template_data, uword *private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_template_entry_t *fte;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 && xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  switch (op)
    {
    case VNET_FLOW_DEV_OP_DEL_FLOW:
      return dpdk_flow_async_op_del (xd, range, private_data);
    case VNET_FLOW_DEV_OP_ADD_FLOW:
      if (private_template_data == 0)
	{
	  dpdk_log_err ("[%u] Cannot do async flow add operation without template private data",
			xd->port_id);
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
      fte = vec_elt_at_index (xd->flow_template_entries, *private_template_data);
      return dpdk_flow_async_op_add (xd, range, fte, private_data);
    default:
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }
}

int
dpdk_flow_async_template_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
				 u32 flow_template_index, uword *private_data)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  vnet_flow_t *template = vnet_get_flow_async_template (flow_template_index);
  dpdk_flow_template_entry_t *fte;
  u32 n_flows = 0;
  int rv;

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW && op != VNET_FLOW_DEV_OP_DEL_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (template == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fte = vec_elt_at_index (xd->flow_template_entries, *private_data);

      if ((rv = rte_flow_template_table_destroy (xd->port_id, fte->table_handle,
						 &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_template_table_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if ((rv = rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle,
						   &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_actions_template_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if ((rv = rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle,
						   &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_pattern_template_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      clib_memset (fte, 0, sizeof (*fte));
      pool_put (xd->flow_template_entries, fte);
      return 0;
    }

  if (template->actions == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  // when adding a flow template the private_data is set to the number of flow to allocate for
  n_flows = (u32) *private_data;

  pool_get (xd->flow_template_entries, fte);

  xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  switch (template->type)
    {
    case VNET_FLOW_TYPE_ETHERNET:
    case VNET_FLOW_TYPE_IP4:
    case VNET_FLOW_TYPE_IP6:
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_VXLAN:
    case VNET_FLOW_TYPE_IP4_GTPC:
    case VNET_FLOW_TYPE_IP4_GTPU:
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
    case VNET_FLOW_TYPE_IP4_IP4:
    case VNET_FLOW_TYPE_IP4_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_IP6:
    case VNET_FLOW_TYPE_IP4_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP4:
    case VNET_FLOW_TYPE_IP6_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP6:
    case VNET_FLOW_TYPE_IP6_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_GENERIC:
      if ((rv = dpdk_flow_async_template_add (xd, template, fte, n_flows)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  *private_data = fte - xd->flow_template_entries;

done:
  if (rv)
    {
      clib_memset (fte, 0, sizeof (*fte));
      pool_put (xd->flow_template_entries, fte);
    }
  return rv;
}

u8 *
format_dpdk_flow (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;

  if (flow_index == ~0)
    {
      s = format (s, "%-25s: %U\n", "supported flow actions", format_flow_actions,
		  xd->supported_flow_actions);
      s = format (s, "%-25s: %d\n", "last DPDK error type", xd->last_flow_error.type);
      s = format (s, "%-25s: %s\n", "last DPDK error message",
		  xd->last_flow_error.message ? xd->last_flow_error.message : "n/a");
      return s;
    }

  if (private_data >= vec_len (xd->flow_entries))
    return format (s, "unknown flow");

  fe = vec_elt_at_index (xd->flow_entries, private_data);
  s = format (s, "mark %u", fe->mark);
  return s;
}

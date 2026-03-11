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
#include <dpdk/device/flow.h>
#include <vppinfra/error.h>

#define FLOW_IS_ETHERNET_CLASS(f) \
  (f->type == VNET_FLOW_TYPE_ETHERNET)

#define FLOW_IS_IPV4_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP4) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_AH) ||                                \
   (f->type == VNET_FLOW_TYPE_IP4_IP4) ||                                     \
   (f->type == VNET_FLOW_TYPE_IP4_IP6) ||                                     \
   (f->type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE) ||                             \
   (f->type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE))

#define FLOW_IS_IPV6_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP6) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP6_IP4) ||                                     \
   (f->type == VNET_FLOW_TYPE_IP6_IP6) ||                                     \
   (f->type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE) ||                             \
   (f->type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE))

/* check if flow is VLAN sensitive */
#define FLOW_HAS_VLAN_TAG(f) \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L3 type */
#define FLOW_IS_L3_TYPE(f) \
  ((f->type == VNET_FLOW_TYPE_IP4) || \
    (f->type == VNET_FLOW_TYPE_IP6))

/* check if flow is L4 type */
#define FLOW_IS_L4_TYPE(f) \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) || \
    (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L4 tunnel type */
#define FLOW_IS_L4_TUNNEL_TYPE(f) \
  ((f->type == VNET_FLOW_TYPE_IP4_VXLAN) || \
    (f->type == VNET_FLOW_TYPE_IP6_VXLAN) || \
    (f->type == VNET_FLOW_TYPE_IP4_GTPC) || \
    (f->type == VNET_FLOW_TYPE_IP4_GTPU))

/* check if flow has a inner TCP/UDP header */
#define FLOW_HAS_INNER_N_TUPLE(f)                                             \
  ((f->type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE) ||                             \
   (f->type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE) ||                             \
   (f->type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE) ||                             \
   (f->type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE))

#define FLOW_NEEDS_MARK(f)                                                                         \
  (f->actions &                                                                                    \
   (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE | VNET_FLOW_ACTION_BUFFER_ADVANCE))

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
static const struct rte_flow_op_attr async_op = { .postpone = 1 };

static inline void
dpdk_flow_attr_init (dpdk_device_t *xd, struct rte_flow_attr *attr)
{
  clib_memset (attr, 0, sizeof (*attr));
  if (xd->flags & DPDK_DEVICE_FLAG_FLOW_TRANSFER)
    attr->transfer = 1;
  else
    attr->ingress = 1;
  if (xd->default_jump_flow)
    attr->group = 1;
}

static inline void
dpdk_flow_pattern_template_attr_init (dpdk_device_t *xd,
				      struct rte_flow_pattern_template_attr *attr)
{
  clib_memset (attr, 0, sizeof (*attr));
  attr->relaxed_matching = 1;
  if (xd->flags & DPDK_DEVICE_FLAG_FLOW_TRANSFER)
    attr->transfer = 1;
  else
    attr->ingress = 1;
}

static inline void
dpdk_flow_actions_template_attr_init (dpdk_device_t *xd,
				      struct rte_flow_actions_template_attr *attr)
{
  clib_memset (attr, 0, sizeof (*attr));
  if (xd->flags & DPDK_DEVICE_FLAG_FLOW_TRANSFER)
    attr->transfer = 1;
  else
    attr->ingress = 1;
}

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
dpdk_flow_convert_rss_types (u64 type, u64 * dpdk_rss_type)
{
#define BIT_IS_SET(v, b) \
  ((v) & (u64)1<<(b))

  *dpdk_rss_type = 0;

#undef _
#define _(n, f, s) \
      if (n != -1 && BIT_IS_SET(type, n)) \
        *dpdk_rss_type |= f;

  foreach_dpdk_rss_hf
#undef _
    return;
}

/** Maximum number of queue indices in struct rte_flow_action_rss. */
#define ACTION_RSS_QUEUE_NUM 128

/* Compound RSS struct: embeds queue array contiguously with the RSS conf
 * so it lives entirely inside a slot — no per-flow clib_mem_alloc. */
struct dpdk_action_rss_data
{
  struct rte_flow_action_rss conf;
  u16 queue[ACTION_RSS_QUEUE_NUM];
};

static inline u32
dpdk_flow_item_spec_size (enum rte_flow_item_type type)
{
  switch (type)
    {
    case RTE_FLOW_ITEM_TYPE_ETH:
      return sizeof (struct rte_flow_item_eth);
    case RTE_FLOW_ITEM_TYPE_IPV4:
      return sizeof (struct rte_flow_item_ipv4);
    case RTE_FLOW_ITEM_TYPE_IPV6:
      return sizeof (struct rte_flow_item_ipv6);
    case RTE_FLOW_ITEM_TYPE_TCP:
      return sizeof (struct rte_flow_item_tcp);
    case RTE_FLOW_ITEM_TYPE_UDP:
      return sizeof (struct rte_flow_item_udp);
    case RTE_FLOW_ITEM_TYPE_GTPC:
    case RTE_FLOW_ITEM_TYPE_GTPU:
      return sizeof (struct rte_flow_item_gtp);
    case RTE_FLOW_ITEM_TYPE_L2TPV3OIP:
      return sizeof (struct rte_flow_item_l2tpv3oip);
    case RTE_FLOW_ITEM_TYPE_ESP:
      return sizeof (struct rte_flow_item_esp);
    case RTE_FLOW_ITEM_TYPE_AH:
      return sizeof (struct rte_flow_item_ah);
    case RTE_FLOW_ITEM_TYPE_RAW:
      return sizeof (struct rte_flow_item_raw) + sizeof (vxlan_header_t);
    default:
      return 0;
    }
}

static inline u32
dpdk_flow_action_conf_size (enum rte_flow_action_type type)
{
  switch (type)
    {
    case RTE_FLOW_ACTION_TYPE_MARK:
      return sizeof (struct rte_flow_action_mark);
    case RTE_FLOW_ACTION_TYPE_QUEUE:
      return sizeof (struct rte_flow_action_queue);
    case RTE_FLOW_ACTION_TYPE_RSS:
      return sizeof (struct dpdk_action_rss_data);
    default:
      return 0;
    }
}

static inline void
dpdk_flow_convert_rss_queues (u32 queue_index, u32 queue_num,
			      struct rte_flow_action_rss *rss)
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
		      dpdk_flow_items_args_t *args)
{
  struct rte_flow_item *item;

  u16 src_port = 0, dst_port = 0, src_port_mask = 0, dst_port_mask = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;
  int n = 0;
  int rv = 0;

  /* Handle generic flow first */
  if (f->type == VNET_FLOW_TYPE_GENERIC)
    {
      args->generic[0].pattern = f->generic_pattern->spec;
      args->generic[1].pattern = f->generic_pattern->mask;

      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_RAW;
      item->spec = args->generic;
      item->mask = args->generic + 1;
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
      vnet_flow_ethernet_t *te = &f->pattern.ethernet;

      /* check if SMAC/DMAC/Ether_type assigned */
      if (!mac_address_is_all_zero (te->eth_hdr.dst_address))
	{
	  clib_memcpy_fast (&args->eth[0].dst, &te->eth_hdr.dst_address, sizeof (args->eth[0].dst));
	  clib_memset (&args->eth[1].dst, 0xFF, sizeof (args->eth[1].dst));
	}

      if (!mac_address_is_all_zero (te->eth_hdr.src_address))
	{
	  clib_memcpy_fast (&args->eth[0].src, &te->eth_hdr.src_address, sizeof (args->eth[0].src));
	  clib_memset (&args->eth[1].src, 0xFF, sizeof (args->eth[1].src));
	}

      if (te->eth_hdr.type)
	{
	  args->eth[0].type = clib_host_to_net_u16 (te->eth_hdr.type);
	  args->eth[1].type = clib_host_to_net_u16 (0xFFFF);
	}

      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_ETH;
      item->spec = args->eth;
      item->mask = args->eth + 1;
      item->last = NULL;
    }

  /* currently only single empty vlan tag is supported */
  if (FLOW_HAS_VLAN_TAG (f))
    {
      item = &args->items[n++];
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
      vnet_flow_ip4_t *ip4_ptr = &f->pattern.ip4;

      if (ip4_ptr->src_addr.mask.as_u32 != 0 || ip4_ptr->dst_addr.mask.as_u32 != 0 ||
	  ip4_ptr->protocol.mask != 0)
	{
	  args->ip4[0].hdr.src_addr = ip4_ptr->src_addr.addr.as_u32;
	  args->ip4[1].hdr.src_addr = ip4_ptr->src_addr.mask.as_u32;
	  args->ip4[0].hdr.dst_addr = ip4_ptr->dst_addr.addr.as_u32;
	  args->ip4[1].hdr.dst_addr = ip4_ptr->dst_addr.mask.as_u32;
	  args->ip4[0].hdr.next_proto_id = ip4_ptr->protocol.prot;
	  args->ip4[1].hdr.next_proto_id = ip4_ptr->protocol.mask;

	  item = &args->items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	  item->spec = args->ip4;
	  item->mask = args->ip4 + 1;
	  item->last = NULL;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip4_n_tuple_t *ip4_n_ptr = &f->pattern.ip4_n_tuple;

	  src_port = ip4_n_ptr->src_port.port;
	  dst_port = ip4_n_ptr->dst_port.port;
	  src_port_mask = ip4_n_ptr->src_port.mask;
	  dst_port_mask = ip4_n_ptr->dst_port.mask;
	}

      protocol = ip4_ptr->protocol.prot;
    }
  else if (flow_class == FLOW_IPV6_CLASS)
    {
      vnet_flow_ip6_t *ip6_ptr = &f->pattern.ip6;

      if (ip6_ptr->src_addr.mask.as_u64[0] != 0 || ip6_ptr->src_addr.mask.as_u64[1] != 0 ||
	  ip6_ptr->dst_addr.mask.as_u64[0] != 0 || ip6_ptr->dst_addr.mask.as_u64[1] != 0 ||
	  ip6_ptr->protocol.mask != 0)
	{
	  clib_memcpy (IP6_SRC_ADDR (args->ip6[0]), &ip6_ptr->src_addr.addr,
		       ARRAY_LEN (ip6_ptr->src_addr.addr.as_u8));
	  clib_memcpy (IP6_SRC_ADDR (args->ip6[1]), &ip6_ptr->src_addr.mask,
		       ARRAY_LEN (ip6_ptr->src_addr.mask.as_u8));
	  clib_memcpy (IP6_DST_ADDR (args->ip6[0]), &ip6_ptr->dst_addr.addr,
		       ARRAY_LEN (ip6_ptr->dst_addr.addr.as_u8));
	  clib_memcpy (IP6_DST_ADDR (args->ip6[1]), &ip6_ptr->dst_addr.mask,
		       ARRAY_LEN (ip6_ptr->dst_addr.mask.as_u8));
	  args->ip6[0].hdr.proto = ip6_ptr->protocol.prot;
	  args->ip6[1].hdr.proto = ip6_ptr->protocol.mask;

	  item = &args->items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	  item->spec = args->ip6;
	  item->mask = args->ip6 + 1;
	  item->last = NULL;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip6_n_tuple_t *ip6_n_ptr = &f->pattern.ip6_n_tuple;

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
      args->l2tp[0].session_id = clib_host_to_net_u32 (f->pattern.ip4_l2tpv3oip.session_id);
      args->l2tp[1].session_id = ~0;

      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_L2TPV3OIP;
      item->spec = args->l2tp;
      item->mask = args->l2tp + 1;
      item->last = NULL;
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      args->esp[0].hdr.spi = clib_host_to_net_u32 (f->pattern.ip4_ipsec_esp.spi);
      args->esp[1].hdr.spi = ~0;

      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
      item->spec = args->esp;
      item->mask = args->esp + 1;
      item->last = NULL;
      break;

    case IP_PROTOCOL_IPSEC_AH:
      args->ah[0].spi = clib_host_to_net_u32 (f->pattern.ip4_ipsec_ah.spi);
      args->ah[1].spi = ~0;

      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_AH;
      item->spec = args->ah;
      item->mask = args->ah + 1;
      item->last = NULL;
      break;
    case IP_PROTOCOL_TCP:
      if (src_port_mask == 0 && dst_port_mask == 0)
	break;

      args->tcp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
      args->tcp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
      args->tcp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
      args->tcp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);

      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_TCP;
      item->spec = args->tcp;
      item->mask = args->tcp + 1;
      item->last = NULL;
      break;

    case IP_PROTOCOL_UDP:
      if (src_port_mask != 0 || dst_port_mask != 0)
	{
	  args->udp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
	  args->udp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
	  args->udp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
	  args->udp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);

	  item = &args->items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_UDP;
	  item->spec = args->udp;
	  item->mask = args->udp + 1;
	  item->last = NULL;
	}

      /* handle the UDP tunnels */
      if (f->type == VNET_FLOW_TYPE_IP4_GTPC)
	{
	  args->gtp[0].teid = clib_host_to_net_u32 (f->pattern.ip4_gtpc.teid);
	  args->gtp[1].teid = ~0;

	  item = &args->items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_GTPC;
	  item->spec = args->gtp;
	  item->mask = args->gtp + 1;
	  item->last = NULL;
	}
      else if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	{
	  args->gtp[0].teid = clib_host_to_net_u32 (f->pattern.ip4_gtpu.teid);
	  args->gtp[1].teid = ~0;

	  item = &args->items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_GTPU;
	  item->spec = args->gtp;
	  item->mask = args->gtp + 1;
	  item->last = NULL;
	}
      else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
	{
	  u32 vni = f->pattern.ip4_vxlan.vni;

	  vxlan_header_t spec_hdr = { .flags = VXLAN_FLAGS_I,
				      .vni_reserved = clib_host_to_net_u32 (vni << 8) };
	  vxlan_header_t mask_hdr = { .flags = 0xff,
				      .vni_reserved = clib_host_to_net_u32 (((u32) -1) << 8) };

	  clib_memset (args->vxlan, 0, sizeof args->vxlan);
	  args->vxlan[0].item.relative = 1;
	  args->vxlan[0].item.length = vxlan_hdr_sz;

	  clib_memcpy_fast (args->vxlan[0].val + raw_sz, &spec_hdr, vxlan_hdr_sz);
	  args->vxlan[0].item.pattern = args->vxlan[0].val + raw_sz;
	  clib_memcpy_fast (args->vxlan[1].val + raw_sz, &mask_hdr, vxlan_hdr_sz);
	  args->vxlan[1].item.pattern = args->vxlan[1].val + raw_sz;

	  item = &args->items[n++];
	  item->type = RTE_FLOW_ITEM_TYPE_RAW;
	  item->spec = args->vxlan;
	  item->mask = args->vxlan + 1;
	  item->last = NULL;
	}
      break;
    case IP_PROTOCOL_IPV6:

#define fill_inner_ip6_with_outer_ipv(OUTER_IP_VER)                                                \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP6 ||                                          \
      f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP6_N_TUPLE)                                    \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip6_t *ptr = &f->pattern.ip##OUTER_IP_VER##_ip6;                \
      if ((ptr->in_src_addr.mask.as_u64[0] == 0) && (ptr->in_src_addr.mask.as_u64[1] == 0) &&      \
	  (ptr->in_dst_addr.mask.as_u64[0] == 0) && (ptr->in_dst_addr.mask.as_u64[1] == 0) &&      \
	  (!ptr->in_protocol.mask))                                                                \
	break;                                                                                     \
                                                                                                   \
      clib_memcpy (IP6_SRC_ADDR (args->in_ip6[0]), &ptr->in_src_addr.addr,                         \
		   ARRAY_LEN (ptr->in_src_addr.addr.as_u8));                                       \
      clib_memcpy (IP6_SRC_ADDR (args->in_ip6[1]), &ptr->in_src_addr.mask,                         \
		   ARRAY_LEN (ptr->in_src_addr.mask.as_u8));                                       \
      clib_memcpy (IP6_DST_ADDR (args->in_ip6[0]), &ptr->in_dst_addr.addr,                         \
		   ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));                                       \
      clib_memcpy (IP6_DST_ADDR (args->in_ip6[1]), &ptr->in_dst_addr.mask,                         \
		   ARRAY_LEN (ptr->in_dst_addr.mask.as_u8));                                       \
                                                                                                   \
      item = &args->items[n++];                                                                    \
      item->type = RTE_FLOW_ITEM_TYPE_IPV6;                                                        \
      item->spec = args->in_ip6;                                                                   \
      item->mask = args->in_ip6 + 1;                                                               \
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
      vnet_flow_ip##OUTER_IP_VER##_ip4_t *ptr = &f->pattern.ip##OUTER_IP_VER##_ip4;                \
      if ((!ptr->in_src_addr.mask.as_u32) && (!ptr->in_dst_addr.mask.as_u32) &&                    \
	  (!ptr->in_protocol.mask))                                                                \
	break;                                                                                     \
                                                                                                   \
      args->in_ip4[0].hdr.src_addr = ptr->in_src_addr.addr.as_u32;                                 \
      args->in_ip4[1].hdr.src_addr = ptr->in_src_addr.mask.as_u32;                                 \
      args->in_ip4[0].hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;                                 \
      args->in_ip4[1].hdr.dst_addr = ptr->in_dst_addr.mask.as_u32;                                 \
                                                                                                   \
      item = &args->items[n++];                                                                    \
      item->type = RTE_FLOW_ITEM_TYPE_IPV4;                                                        \
      item->spec = args->in_ip4;                                                                   \
      item->mask = args->in_ip4 + 1;                                                               \
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
  args->in_##proto[0].hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);                 \
  args->in_##proto[1].hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.mask);                 \
  args->in_##proto[0].hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);                 \
  args->in_##proto[1].hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.mask);                 \
                                                                                                   \
  item = &args->items[n++];                                                                        \
  item->type = RTE_FLOW_ITEM_TYPE_##proto;                                                         \
  item->spec = args->in_##proto;                                                                   \
  item->mask = args->in_##proto + 1;                                                               \
  item->last = NULL;

#define fill_inner_n_tuple(OUTER_IP_VER, INNER_IP_VER)                                             \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP##INNER_IP_VER##_N_TUPLE)                     \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip##INNER_IP_VER##_n_tuple_t *ptr =                             \
	&f->pattern.ip##OUTER_IP_VER##_ip##INNER_IP_VER##_n_tuple;                                 \
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
      item = &args->items[n++];
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
      item->spec = NULL;
      item->mask = NULL;
      item->last = NULL;
    }

  item = &args->items[n++];
  item->type = RTE_FLOW_ITEM_TYPE_END;
  item->spec = NULL;
  item->mask = NULL;
  item->last = NULL;

done:
  return rv;
}

static int
dpdk_flow_fill_actions (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			dpdk_flow_actions_args_t *args)
{
  struct rte_flow_action *action;
  bool fate = false;
  int n = 0;

  if (FLOW_NEEDS_MARK (f))
    {
      action = &args->actions[n++];
      args->mark.id = fe->mark;
      action->type = RTE_FLOW_ACTION_TYPE_MARK;
      action->conf = &args->mark;
    }

  /* Only one 'fate' can be assigned */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      action = &args->actions[n++];
      args->queue.index = f->redirect_queue;
      action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
      action->conf = &args->queue;
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;

      action = &args->actions[n++];
      action->type = RTE_FLOW_ACTION_TYPE_DROP;
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {

      if (fate == true)
	return VNET_FLOW_ERROR_INTERNAL;

      u64 rss_type = 0;

      action = &args->actions[n++];
      action->type = RTE_FLOW_ACTION_TYPE_RSS;
      action->conf = &args->rss;

      /* convert types to DPDK rss bitmask */
      dpdk_flow_convert_rss_types (f->rss_types, &rss_type);

      if (f->queue_num)
	/* convert rss queues to array */
	dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, &args->rss);

      args->rss.types = rss_type;
      if ((args->rss.func = dpdk_flow_convert_rss_func (f->rss_fun)) == RTE_ETH_HASH_FUNCTION_MAX)
	return VNET_FLOW_ERROR_NOT_SUPPORTED;

      fate = true;
    }

  if (!fate)
    {
      action = &args->actions[n++];
      action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    }

  action = &args->actions[n++];
  action->type = RTE_FLOW_ACTION_TYPE_END;
  return 0;
}

int
dpdk_flow_fill_items_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			       dpdk_flow_items_args_t *args)
{
  struct rte_flow_item *item;
  int i, rv;

  /*  HACK: flow_entry is not used in fill_items */
  if ((rv = dpdk_flow_fill_items (xd, t, NULL, args)))
    return rv;

  item = &args->items[0];
  for (i = 0; args->items[i].type != RTE_FLOW_ITEM_TYPE_END; item = &args->items[++i])
    item->spec = NULL;

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
    actions[n].conf = NULL;                                                                        \
    masks[n].conf = NULL;                                                                          \
    n++;                                                                                           \
  }

  if (FLOW_NEEDS_MARK (t))
    add_action_type (MARK);

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

  add_action_type (END);
  return 0;
}

static_always_inline void
init_slot_compound_actions (struct rte_flow_action *action)
{
  switch (action->type)
    {
      /* For RSS: wire internal queue pointer */
    case RTE_FLOW_ACTION_TYPE_RSS:
      {
	struct dpdk_action_rss_data *rss = (struct dpdk_action_rss_data *) action->conf;
	rss->conf.queue = rss->queue;
	break;
      }
    default:
      break;
    }
}

static_always_inline void
dpdk_flow_update_slot_items (struct rte_flow_item *items, u8 n_items, vnet_flow_t *f,
			     vnet_flow_type_t template_type)
{
  u32 ipv4_seen = 0, ipv6_seen = 0;

  for (u32 i = 0; i < n_items; i++)
    {
      switch (items[i].type)
	{
	case RTE_FLOW_ITEM_TYPE_ETH:
	  {
	    struct rte_flow_item_eth *spec = (struct rte_flow_item_eth *) items[i].spec;
	    vnet_flow_ethernet_t *te = &f->pattern.ethernet;
	    /* skip update when ETH header is all zeros (common for L3/L4 flow types) */
	    if (PREDICT_TRUE (te->eth_hdr.type == 0 &&
			      mac_address_is_all_zero ((u8 *) &te->eth_hdr.dst_address) &&
			      mac_address_is_all_zero ((u8 *) &te->eth_hdr.src_address)))
	      break;
	    clib_memcpy_fast (&spec->dst, &te->eth_hdr.dst_address, sizeof (spec->dst));
	    clib_memcpy_fast (&spec->src, &te->eth_hdr.src_address, sizeof (spec->src));
	    spec->type = clib_host_to_net_u16 (te->eth_hdr.type);
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_IPV4:
	  {
	    struct rte_flow_item_ipv4 *spec = (struct rte_flow_item_ipv4 *) items[i].spec;
	    if (spec == NULL)
	      break;
	    ipv4_seen++;
	    if (ipv4_seen == 1)
	      {
		/* Outer IPv4 */
		vnet_flow_ip4_t *ip4_ptr = &f->pattern.ip4;
		spec->hdr.src_addr = ip4_ptr->src_addr.addr.as_u32;
		spec->hdr.dst_addr = ip4_ptr->dst_addr.addr.as_u32;
		spec->hdr.next_proto_id = ip4_ptr->protocol.prot;
	      }
	    /* Inner IPv4 */
	    else if (template_type == VNET_FLOW_TYPE_IP4_IP4 ||
		     template_type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE)
	      {
		vnet_flow_ip4_ip4_t *ptr = &f->pattern.ip4_ip4;
		spec->hdr.src_addr = ptr->in_src_addr.addr.as_u32;
		spec->hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;
	      }
	    else if (template_type == VNET_FLOW_TYPE_IP6_IP4 ||
		     template_type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE)
	      {
		vnet_flow_ip6_ip4_t *ptr = &f->pattern.ip6_ip4;
		spec->hdr.src_addr = ptr->in_src_addr.addr.as_u32;
		spec->hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;
	      }
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_IPV6:
	  {
	    struct rte_flow_item_ipv6 *spec = (struct rte_flow_item_ipv6 *) items[i].spec;
	    if (spec == NULL)
	      break;
	    ipv6_seen++;
	    if (ipv6_seen == 1)
	      {
		/* Outer IPv6 */
		vnet_flow_ip6_t *ip6_ptr = &f->pattern.ip6;
		clib_memcpy (IP6_SRC_ADDR (spec[0]), &ip6_ptr->src_addr.addr,
			     ARRAY_LEN (ip6_ptr->src_addr.addr.as_u8));
		clib_memcpy (IP6_DST_ADDR (spec[0]), &ip6_ptr->dst_addr.addr,
			     ARRAY_LEN (ip6_ptr->dst_addr.addr.as_u8));
		spec->hdr.proto = ip6_ptr->protocol.prot;
	      }
	    /* Inner IPv6 */
	    else if (template_type == VNET_FLOW_TYPE_IP6_IP6 ||
		     template_type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE)
	      {
		vnet_flow_ip6_ip6_t *ptr = &f->pattern.ip6_ip6;
		clib_memcpy (IP6_SRC_ADDR (spec[0]), &ptr->in_src_addr.addr,
			     ARRAY_LEN (ptr->in_src_addr.addr.as_u8));
		clib_memcpy (IP6_DST_ADDR (spec[0]), &ptr->in_dst_addr.addr,
			     ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));
	      }
	    else if (template_type == VNET_FLOW_TYPE_IP4_IP6 ||
		     template_type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE)
	      {
		vnet_flow_ip4_ip6_t *ptr = &f->pattern.ip4_ip6;
		clib_memcpy (IP6_SRC_ADDR (spec[0]), &ptr->in_src_addr.addr,
			     ARRAY_LEN (ptr->in_src_addr.addr.as_u8));
		clib_memcpy (IP6_DST_ADDR (spec[0]), &ptr->in_dst_addr.addr,
			     ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));
	      }
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_TCP:
	  {
	    struct rte_flow_item_tcp *spec = (struct rte_flow_item_tcp *) items[i].spec;
	    if (spec == NULL)
	      break;
	    /* Check if this is an inner TCP (after inner IP) */
	    if (ipv4_seen > 1 || ipv6_seen > 1)
	      {
		/* Inner TCP — extract from inner n_tuple */
		if (template_type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE)
		  {
		    vnet_flow_ip4_ip4_n_tuple_t *ptr = &f->pattern.ip4_ip4_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
		else if (template_type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE)
		  {
		    vnet_flow_ip4_ip6_n_tuple_t *ptr = &f->pattern.ip4_ip6_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
		else if (template_type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE)
		  {
		    vnet_flow_ip6_ip4_n_tuple_t *ptr = &f->pattern.ip6_ip4_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
		else if (template_type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE)
		  {
		    vnet_flow_ip6_ip6_n_tuple_t *ptr = &f->pattern.ip6_ip6_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
	      }
	    else
	      {
		/* Outer TCP */
		vnet_flow_ip4_n_tuple_t *nt = &f->pattern.ip4_n_tuple;
		spec->hdr.src_port = clib_host_to_net_u16 (nt->src_port.port);
		spec->hdr.dst_port = clib_host_to_net_u16 (nt->dst_port.port);
	      }
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_UDP:
	  {
	    struct rte_flow_item_udp *spec = (struct rte_flow_item_udp *) items[i].spec;
	    if (spec == NULL)
	      break;
	    if (ipv4_seen > 1 || ipv6_seen > 1)
	      {
		/* Inner UDP */
		if (template_type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE)
		  {
		    vnet_flow_ip4_ip4_n_tuple_t *ptr = &f->pattern.ip4_ip4_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
		else if (template_type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE)
		  {
		    vnet_flow_ip4_ip6_n_tuple_t *ptr = &f->pattern.ip4_ip6_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
		else if (template_type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE)
		  {
		    vnet_flow_ip6_ip4_n_tuple_t *ptr = &f->pattern.ip6_ip4_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
		else if (template_type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE)
		  {
		    vnet_flow_ip6_ip6_n_tuple_t *ptr = &f->pattern.ip6_ip6_n_tuple;
		    spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);
		    spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);
		  }
	      }
	    else
	      {
		/* Outer UDP */
		vnet_flow_ip4_n_tuple_t *nt = &f->pattern.ip4_n_tuple;
		spec->hdr.src_port = clib_host_to_net_u16 (nt->src_port.port);
		spec->hdr.dst_port = clib_host_to_net_u16 (nt->dst_port.port);
	      }
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_GTPC:
	  {
	    struct rte_flow_item_gtp *spec = (struct rte_flow_item_gtp *) items[i].spec;
	    spec->teid = clib_host_to_net_u32 (f->pattern.ip4_gtpc.teid);
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_GTPU:
	  {
	    struct rte_flow_item_gtp *spec = (struct rte_flow_item_gtp *) items[i].spec;
	    spec->teid = clib_host_to_net_u32 (f->pattern.ip4_gtpu.teid);
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_L2TPV3OIP:
	  {
	    struct rte_flow_item_l2tpv3oip *spec = (struct rte_flow_item_l2tpv3oip *) items[i].spec;
	    spec->session_id = clib_host_to_net_u32 (f->pattern.ip4_l2tpv3oip.session_id);
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_ESP:
	  {
	    struct rte_flow_item_esp *spec = (struct rte_flow_item_esp *) items[i].spec;
	    if (spec == NULL)
	      break; /* RSS ESP marker — no spec */
	    spec->hdr.spi = clib_host_to_net_u32 (f->pattern.ip4_ipsec_esp.spi);
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_AH:
	  {
	    struct rte_flow_item_ah *spec = (struct rte_flow_item_ah *) items[i].spec;
	    if (spec == NULL)
	      break;
	    spec->spi = clib_host_to_net_u32 (f->pattern.ip4_ipsec_ah.spi);
	  }
	  break;

	case RTE_FLOW_ITEM_TYPE_RAW:
	  {
	    if (template_type == VNET_FLOW_TYPE_GENERIC)
	      {
		struct rte_flow_item_raw *spec = (struct rte_flow_item_raw *) items[i].spec;
		spec->pattern = f->generic_pattern->spec;
		break;
	      }
	    /* VXLAN via raw item */
	    struct rte_flow_item_raw *spec = (struct rte_flow_item_raw *) items[i].spec;
	    u8 *pattern_data = (u8 *) spec + sizeof (struct rte_flow_item_raw);
	    u32 vni = f->pattern.ip4_vxlan.vni;
	    vxlan_header_t hdr = { .flags = VXLAN_FLAGS_I,
				   .vni_reserved = clib_host_to_net_u32 (vni << 8) };
	    spec->relative = 1;
	    spec->length = sizeof (vxlan_header_t);
	    spec->pattern = pattern_data;
	    clib_memcpy_fast (pattern_data, &hdr, sizeof (vxlan_header_t));
	  }
	  break;

	default:
	  break;
	}
    }
}

static_always_inline void
dpdk_flow_update_slot_actions (struct rte_flow_action *actions, u8 n_actions, vnet_flow_t *f,
			       dpdk_flow_entry_t *fe)
{
  for (u32 i = 0; i < n_actions; i++)
    {
      switch (actions[i].type)
	{
	case RTE_FLOW_ACTION_TYPE_QUEUE:
	  {
	    struct rte_flow_action_queue *conf = (struct rte_flow_action_queue *) actions[i].conf;
	    conf->index = f->redirect_queue;
	  }
	  break;

	case RTE_FLOW_ACTION_TYPE_MARK:
	  {
	    struct rte_flow_action_mark *conf = (struct rte_flow_action_mark *) actions[i].conf;
	    conf->id = fe->mark;
	  }
	  break;

	case RTE_FLOW_ACTION_TYPE_RSS:
	  {
	    struct dpdk_action_rss_data *rss = (struct dpdk_action_rss_data *) actions[i].conf;
	    u64 rss_type = 0;

	    dpdk_flow_convert_rss_types (f->rss_types, &rss_type);
	    rss->conf.types = rss_type;
	    rss->conf.func = dpdk_flow_convert_rss_func (f->rss_fun);
	    rss->conf.queue = rss->queue;

	    if (f->queue_num)
	      {
		rss->conf.queue_num = f->queue_num;
		for (u32 q = 0; q < f->queue_num; q++)
		  rss->queue[q] = f->queue_index + q;
	      }
	    else
	      {
		rss->conf.queue_num = 0;
	      }
	  }
	  break;

	default:
	  break;
	}
    }
}

static_always_inline void
dpdk_flow_init_queue (dpdk_device_t *xd, dpdk_flow_template_entry_t *fte,
		      dpdk_flow_async_queue_t *q, u32 id)
{
  clib_memset (q, 0, sizeof (*q));
  q->batch_size = xd->async_flow_offload_queue_batch;
  q->n_slots = xd->async_flow_offload_queue_size;
  q->id = id;

  if (!fte)
    return;

  q->slot_size = fte->slot_size;
  q->in_slot_actions_offset = fte->in_slot_actions_offset;
  q->slots = fte->slot_pool + (uword) id * xd->async_flow_offload_queue_size * fte->slot_size;
  q->results = fte->results + (uword) id * xd->async_flow_offload_queue_size;
}

static int
dpdk_flow_init_slot_pool (dpdk_device_t *xd, dpdk_flow_template_entry_t *fte,
			  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS],
			  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS])
{
  u32 n_items = 0, n_actions = 0;
  u32 item_spec_sizes[DPDK_MAX_FLOW_ITEMS];
  u32 action_conf_sizes[DPDK_MAX_FLOW_ACTIONS];
  u32 total_spec = 0, total_conf = 0;
  u32 items_array_sz, actions_array_sz, slot_size;
  u32 slots_per_queue, nb_queues, num_slots;
  u32 i, s;
  struct rte_flow_op_result *results = 0;
  u8 *pool, *shared_masks, *mask_dst;

  /* Count items and compute spec sizes (excluding END) */
  for (i = 0; items[i].type != RTE_FLOW_ITEM_TYPE_END; i++)
    {
      item_spec_sizes[n_items] = dpdk_flow_item_spec_size (items[i].type);
      total_spec += item_spec_sizes[n_items];
      n_items++;
    }

  /* take END into account */
  item_spec_sizes[n_items++] = 0;

  /* Count actions and compute conf sizes (excluding END) */
  for (i = 0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++)
    {
      action_conf_sizes[n_actions] = dpdk_flow_action_conf_size (actions[i].type);
      total_conf += action_conf_sizes[n_actions];
      n_actions++;
    }

  /* take END into account */
  action_conf_sizes[n_actions++] = 0;

  /* Compute slot layout */
  items_array_sz = n_items * sizeof (struct rte_flow_item);
  actions_array_sz = n_actions * sizeof (struct rte_flow_action);
  slot_size =
    round_pow2 (items_array_sz + actions_array_sz + total_spec + total_conf, CLIB_CACHE_LINE_BYTES);

  slots_per_queue = xd->async_flow_offload_queue_size;
  nb_queues = xd->async_flow_offload_n_queues;
  num_slots = slots_per_queue * nb_queues;

  /* Allocate shared masks — pack mask data from template items */
  shared_masks = clib_mem_alloc_aligned (total_spec, CLIB_CACHE_LINE_BYTES);
  if (!shared_masks)
    return VNET_FLOW_ERROR_INTERNAL;

  mask_dst = shared_masks;
  for (i = 0; i < n_items; i++)
    {
      if (item_spec_sizes[i] > 0 && items[i].mask)
	clib_memcpy_fast (mask_dst, items[i].mask, item_spec_sizes[i]);
      else if (item_spec_sizes[i] > 0)
	clib_memset (mask_dst, 0, item_spec_sizes[i]);
      mask_dst += item_spec_sizes[i];
    }

  results = clib_mem_alloc (sizeof (*results) * nb_queues * slots_per_queue);
  if (!results)
    goto done_shared_masks;

  /* Allocate slot pool */
  pool = clib_mem_alloc_aligned ((uword) num_slots * slot_size, CLIB_CACHE_LINE_BYTES);
  if (!pool)
    goto done_results;
  clib_memset (pool, 0, (uword) num_slots * slot_size);

  /* Pre-initialize every slot */
  for (s = 0; s < num_slots; s++)
    {
      u8 *slot = pool + (uword) s * slot_size;
      struct rte_flow_item *slot_items = (struct rte_flow_item *) slot;
      struct rte_flow_action *slot_actions = (struct rte_flow_action *) (slot + items_array_sz);
      u8 *spec_data = slot + items_array_sz + actions_array_sz;
      u8 *conf_data = spec_data + total_spec;
      u8 *mptr = shared_masks;

      /* Wire items */
      for (i = 0; i < n_items; i++)
	{
	  slot_items[i].type = items[i].type;
	  if (item_spec_sizes[i] == 0)
	    continue;

	  slot_items[i].spec = spec_data;
	  slot_items[i].mask = mptr;
	  spec_data += item_spec_sizes[i];
	  mptr += item_spec_sizes[i];
	}

      /* Wire actions */
      for (i = 0; i < n_actions; i++)
	{
	  slot_actions[i].type = actions[i].type;
	  if (action_conf_sizes[i] == 0)
	    continue;

	  slot_actions[i].conf = conf_data;
	  conf_data += action_conf_sizes[i];

	  /* Initialize compound action types (RSS, etc.) */
	  init_slot_compound_actions (&slot_actions[i]);
	}
    }

  fte->slot_pool = pool;
  fte->shared_masks = shared_masks;
  fte->n_items = n_items;
  fte->n_actions = n_actions;
  fte->results = results;
  fte->in_slot_actions_offset = items_array_sz;
  fte->slot_size = slot_size;

  return 0;

done_results:
  clib_mem_free (results);
done_shared_masks:
  clib_mem_free (shared_masks);
  return VNET_FLOW_ERROR_INTERNAL;
}

static void
dpdk_flow_template_del (dpdk_device_t *xd, dpdk_flow_template_entry_t *fte)
{
  if (rte_flow_template_table_destroy (xd->port_id, fte->table_handle, &xd->last_flow_error))
    dpdk_device_flow_warning (xd, "rte_flow_template_table_destroy");

  if (rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle, &xd->last_flow_error))
    dpdk_device_flow_warning (xd, "rte_flow_actions_template_destroy");

  if (rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle, &xd->last_flow_error))
    dpdk_device_flow_warning (xd, "rte_flow_pattern_template_destroy");

  if (fte->slot_pool)
    {
      clib_mem_free (fte->slot_pool);
      fte->slot_pool = NULL;
    }
  if (fte->results)
    {
      clib_mem_free (fte->results);
      fte->results = 0;
    }
  if (fte->shared_masks)
    {
      clib_mem_free (fte->shared_masks);
      fte->shared_masks = NULL;
    }
}

static int
dpdk_flow_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe)
{
  dpdk_flow_items_args_t item_args = { 0 };
  dpdk_flow_actions_args_t action_args = { 0 };
  struct rte_flow_attr flow_attr;
  int rv;

  dpdk_flow_attr_init (xd, &flow_attr);

  if ((rv = dpdk_flow_fill_items (xd, f, fe, &item_args)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, &action_args)) != 0)
    return rv;

  rv = rte_flow_validate (xd->port_id, &flow_attr, item_args.items, action_args.actions,
			  &xd->last_flow_error);

  if (rv)
    {
      dpdk_device_flow_warning (xd, "rte_flow_validate");

      if (rv == -EINVAL)
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      else if (rv == -EEXIST)
	rv = VNET_FLOW_ERROR_ALREADY_EXISTS;
      else
	rv = VNET_FLOW_ERROR_INTERNAL;

      return rv;
    }

  fe->handle = rte_flow_create (xd->port_id, &flow_attr, item_args.items, action_args.actions,
				&xd->last_flow_error);

  if (!fe->handle)
    {
      dpdk_device_flow_warning (xd, "rte_flow_create");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return 0;
}

static int
dpdk_flow_template_add (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte)
{
  dpdk_flow_items_args_t item_args = { 0 };
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_action actions_mask[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_pattern_template_attr pattern_attr;
  struct rte_flow_actions_template_attr action_attr;
  struct rte_flow_template_table_attr template_attr = {
    .nb_flows = t->n_flows,
  };
  int rv = 0;

  dpdk_flow_attr_init (xd, &template_attr.flow_attr);
  dpdk_flow_pattern_template_attr_init (xd, &pattern_attr);
  dpdk_flow_actions_template_attr_init (xd, &action_attr);

  if ((rv = dpdk_flow_fill_items_template (xd, t, fte, &item_args)) != 0)
    return rv;

  fte->pattern_handle = rte_flow_pattern_template_create (xd->port_id, &pattern_attr,
							  item_args.items, &xd->last_flow_error);
  if (!fte->pattern_handle)
    {
      dpdk_device_flow_warning (xd, "rte_flow_pattern_template_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if ((rv = dpdk_flow_fill_actions_template (xd, t, fte, actions, actions_mask)) != 0)
    goto done_pattern_handle;

  fte->actions_handle = rte_flow_actions_template_create (xd->port_id, &action_attr, actions,
							  actions_mask, &xd->last_flow_error);
  if (!fte->actions_handle)
    {
      dpdk_device_flow_warning (xd, "rte_flow_actions_template_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_pattern_handle;
    }

  fte->table_handle =
    rte_flow_template_table_create (xd->port_id, &template_attr, &fte->pattern_handle, 1,
				    &fte->actions_handle, 1, &xd->last_flow_error);
  if (!fte->table_handle)
    {
      dpdk_device_flow_warning (xd, "rte_flow_template_table_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_actions_handle;
    }

  fte->template_type = t->type;
  if ((rv = dpdk_flow_init_slot_pool (xd, fte, item_args.items, actions)) != 0)
    goto done_table_handle;

  pool_alloc_aligned (xd->flow_lookup_entries, t->n_flows, CLIB_CACHE_LINE_BYTES);

  return 0;

done_table_handle:
  rte_flow_template_table_destroy (xd->port_id, fte->table_handle, &xd->last_flow_error);
  fte->table_handle = 0;

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
dpdk_flow_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance, u32 flow_index)
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
      fe = vec_elt_at_index (xd->flow_entries, flow->driver_data.opaque);

      if ((rv = rte_flow_destroy (xd->port_id, fe->handle, &xd->last_flow_error)))
	{
	  dpdk_device_flow_warning (xd, "rte_flow_destroy");
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
      flow->driver_data.hw_if_index = ~0;
      flow->driver_data.opaque = ~0;

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

  flow->driver_data.opaque = fe - xd->flow_entries;
  flow->driver_data.hw_if_index = xd->hw_if_index;

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
dpdk_flow_async_push_pull (dpdk_device_t *xd, dpdk_flow_async_queue_t *q, int *err, bool empty)
{
  uint32_t to_pull = (empty || q->batch_size > q->enqueued) ? q->enqueued : q->batch_size;
  uint32_t retries = 0;
  int pulled, success = 0;
  *err = 0;

  /* Push periodically to give HW work to do */
  *err = rte_flow_push (xd->port_id, q->id, &xd->last_flow_error);
  if (*err)
    return 0;
  q->push_counter++;

  /* Check if queue is getting full, if so push and drain completions */
  if (!empty && q->push_counter == 1)
    return 0;

  while (to_pull > 0)
    {
      pulled = rte_flow_pull (xd->port_id, q->id, q->results, to_pull, &xd->last_flow_error);
      if (pulled < 0)
	{
	  *err = -1;
	  return success;
	}
      else if (pulled == 0)
	{
	  retries++;
	  if (retries > DPDK_MAX_FLOW_PULL_RETRIES)
	    {
	      rte_flow_error_set (&xd->last_flow_error, ETIMEDOUT, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				  NULL, "Timeout waiting for async completions");
	      *err = -1;
	      return success;
	    }
	  else if (retries > DPDK_MAX_FLOW_PULL_RETRIES >> 1)
	    {
	      dpdk_log_warn ("[%d] async flow pull hanging...", xd->port_id);
	    }
	  CLIB_PAUSE ();
	  continue;
	}

      retries = 0;
      success += pulled;
      to_pull -= pulled;
      q->enqueued -= pulled;
    }

  return success;
}

static_always_inline int
dpdk_flow_async_op_add (dpdk_device_t *xd, dpdk_flow_template_entry_t *fte, u32 queue_id,
			u32 *flow_indices)
{
  dpdk_flow_async_queue_t q;
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle;
  struct rte_flow_item *items;
  struct rte_flow_action *actions;
  vnet_flow_t *flow;
  u32 count = vec_len (flow_indices);
  u32 idx, fi, bi, flow_index;
  int success = 0, rv = 0, err;
  u8 *slot;

  if (count == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  dpdk_flow_init_queue (xd, fte, &q, queue_id);

  pool_alloc (xd->flow_entries, count);

  for (fi = 0; fi < count;)
    {
      for (bi = 0; bi < q.batch_size && fi < count; bi++, fi++)
	{
	  flow_index = vec_elt (flow_indices, fi);
	  flow = vnet_get_flow (flow_index);

	  if (!flow)
	    goto error;

	  /* allocate new flow entry */
	  fle = 0;
	  pool_get (xd->flow_entries, fe);
	  fe->flow_index = flow->index;

	  if (FLOW_NEEDS_MARK (flow))
	    {
	      if (xd->flow_lookup_entries == 0)
		pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
	      pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
	      fe->mark = fle - xd->flow_lookup_entries;

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

	  /* flow slot */
	  idx = q.head;
	  slot = q.slots + (uword) idx * q.slot_size;
	  q.head = (idx + 1) & (q.n_slots - 1);

	  items = (struct rte_flow_item *) slot;
	  actions = (struct rte_flow_action *) (slot + q.in_slot_actions_offset);

	  dpdk_flow_update_slot_items (items, fte->n_items, flow, fte->template_type);
	  dpdk_flow_update_slot_actions (actions, fte->n_actions, flow, fe);

	  fe->handle = rte_flow_async_create (xd->port_id, q.id, &async_op, fte->table_handle,
					      items, 0, actions, 0, NULL, &xd->last_flow_error);
	  if (PREDICT_FALSE (!fe->handle))
	    {
	      dpdk_device_flow_warning (xd, "rte_flow_async_create");
	      if (fle)
		{
		  clib_memset (fle, -1, sizeof (*fle));
		  pool_put (xd->flow_lookup_entries, fle);
		}
	      clib_memset (fe, 0, sizeof (*fe));
	      pool_put (xd->flow_entries, fe);
	      goto error;
	    }

	  flow->driver_data.opaque = fe - xd->flow_entries;
	  flow->driver_data.hw_if_index = xd->hw_if_index;
	  q.enqueued++;
	}

      /* we count the number of success */
      rv = dpdk_flow_async_push_pull (xd, &q, &err, false);
      success += rv;
      if (err)
	{
	  dpdk_device_flow_warning (xd, "rte_flow_push/pull");
	  return success;
	}
    }

error:
  rv = dpdk_flow_async_push_pull (xd, &q, &err, true);
  success += rv;
  if (err)
    dpdk_device_flow_warning (xd, "rte_flow_push/pull");
  return success;
}

static_always_inline int
dpdk_flow_async_op_del (dpdk_device_t *xd, u32 queue_id, u32 *flow_indices)
{
  vlib_main_t *vm = vlib_get_main ();
  struct rte_flow_op_result results[DPDK_MAX_FLOW_QUEUE_SIZE];
  dpdk_flow_async_queue_t shadow_q;
  dpdk_flow_lookup_entry_t *fle;
  dpdk_flow_entry_t *fe;
  vnet_flow_t *flow;
  u32 count = vec_len (flow_indices);
  u32 fi, bi, flow_index;
  int success = 0, rv = 0, err;

  if (count == 0)
    return 0;

  dpdk_flow_init_queue (xd, NULL, &shadow_q, queue_id);
  shadow_q.results = results;

  for (fi = 0; fi < count;)
    {
      for (bi = 0; bi < shadow_q.batch_size && fi < count; bi++, fi++)
	{
	  flow_index = vec_elt (flow_indices, fi);
	  flow = vnet_get_flow (flow_index);

	  if (!flow || pool_is_free_index (xd->flow_entries, flow->driver_data.opaque))
	    goto error;

	  fe = pool_elt_at_index (xd->flow_entries, flow->driver_data.opaque);

	  if ((rv = rte_flow_async_destroy (xd->port_id, shadow_q.id, &async_op, fe->handle, NULL,
					    &xd->last_flow_error)))
	    {
	      dpdk_device_flow_warning (xd, "rte_flow_async_destroy");
	      goto error;
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

	  flow->driver_data.opaque = ~0;
	  flow->driver_data.hw_if_index = ~0;
	  shadow_q.enqueued++;
	}

      /* we count the number of success */
      rv = dpdk_flow_async_push_pull (xd, &shadow_q, &err, false);
      success += rv;
      if (err)
	{
	  dpdk_device_flow_warning (xd, "rte_flow_push/pull");
	  return success;
	}
    }

error:
  rv = dpdk_flow_async_push_pull (xd, &shadow_q, &err, true);
  success += rv;
  if (err)
    dpdk_device_flow_warning (xd, "rte_flow_push/pull");
  return success;
}

int
dpdk_flow_async_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
			u32 *flow_indices, u32 template_index)
{
  vnet_flow_t *template = vnet_get_flow_template (template_index);
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_template_entry_t *fte;
  int success = 0;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 && xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  if (op == VNET_FLOW_DEV_OP_ADD_FLOW)
    {
      if (!template || pool_is_free_index (xd->flow_template_entries, template->driver_data.opaque))
	{
	  dpdk_log_err ("[%u] Cannot do async flow add operation without template", xd->port_id);
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
      fte = pool_elt_at_index (xd->flow_template_entries, template->driver_data.opaque);
      success = dpdk_flow_async_op_add (xd, fte, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, flow_indices);
    }
  else if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      success = dpdk_flow_async_op_del (xd, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, flow_indices);
    }
  else
    {
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  if (pool_elts (xd->flow_entries) == 0)
    xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
  else
    xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  return success;
}

int
dpdk_flow_template_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
			   u32 flow_template_index)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  vnet_flow_t *template = vnet_get_flow_template (flow_template_index);
  dpdk_flow_template_entry_t *fte;
  int rv;

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW && op != VNET_FLOW_DEV_OP_DEL_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (template == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fte = pool_elt_at_index (xd->flow_template_entries, template->driver_data.opaque);

      dpdk_flow_template_del (xd, fte);

      clib_memset (fte, 0, sizeof (*fte));
      pool_put (xd->flow_template_entries, fte);
      template->driver_data.opaque = ~0;
      template->driver_data.hw_if_index = ~0;
      return 0;
    }

  if (template->actions == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  pool_get (xd->flow_template_entries, fte);

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
      if ((rv = dpdk_flow_template_add (xd, template, fte)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  template->driver_data.opaque = fte - xd->flow_template_entries;
  template->driver_data.hw_if_index = xd->hw_if_index;

done:
  if (rv)
    {
      clib_memset (fte, 0, sizeof (*fte));
      pool_put (xd->flow_template_entries, fte);
    }
  return rv;
}

u8 *
format_dpdk_flow (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;

  if (flow_index == ~0)
    {
      s = format (s, "%-25s: %U\n", "supported flow actions",
		  format_flow_actions, xd->supported_flow_actions);
      s = format (s, "%-25s: %d\n", "last DPDK error type",
		  xd->last_flow_error.type);
      s = format (s, "%-25s: %s\n", "last DPDK error message",
		  xd->last_flow_error.message ? xd->last_flow_error.message :
		  "n/a");
      return s;
    }

  if (pool_is_free_index (xd->flow_entries, private_data))
    return format (s, "unknown flow");

  fe = pool_elt_at_index (xd->flow_entries, private_data);
  s = format (s, "mark %u", fe->mark);
  return s;
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

/* get source addr from ipv6 header */
#if (RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0))
#define IP6_SRC_ADDR(ip6) ip6->hdr.src_addr.a
#else
#define IP6_SRC_ADDR(ip6) ip6->hdr.src_addr
#endif

/* get destination addr from ipv6 header */
#if (RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0))
#define IP6_DST_ADDR(ip6) ip6->hdr.dst_addr.a
#else
#define IP6_DST_ADDR(ip6) ip6->hdr.dst_addr
#endif

/* constant structs */
static const struct rte_flow_attr ingress = {.ingress = 1 };
static const struct rte_flow_actions_template_attr action_attr = { .ingress = 1 };
static const struct rte_flow_pattern_template_attr pattern_attr = { .ingress = 1,
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
		      struct rte_flow_item **pitems)
{
  struct rte_flow_item *item, *items = 0;

  *pitems = 0;

  enum
  {
    vxlan_hdr_sz = sizeof (vxlan_header_t),
    raw_sz = sizeof (struct rte_flow_item_raw)
  };

  typedef union
  {
    struct rte_flow_item_raw item;
    u8 val[raw_sz + vxlan_hdr_sz];
  } vxlan_t;

  u16 src_port = 0, dst_port = 0, src_port_mask = 0, dst_port_mask = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;
  int rv = 0;

  /* Handle generic flow first */
  if (f->type == VNET_FLOW_TYPE_GENERIC)
    {
      struct rte_flow_item_raw *spec = clib_mem_alloc (sizeof (*spec));
      struct rte_flow_item_raw *mask = clib_mem_alloc (sizeof (*mask));

      clib_memset (spec, 0, sizeof (*spec));
      clib_memset (mask, 0, sizeof (*mask));

      spec->pattern = f->generic.pattern.spec;
      mask->pattern = f->generic.pattern.mask;

      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_RAW;
      item->spec = spec;
      item->mask = mask;

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
  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_ETH;

  if (flow_class == FLOW_ETHERNET_CLASS)
    {
      vnet_flow_ethernet_t *te = &f->ethernet;

      struct rte_flow_item_eth *spec = clib_mem_alloc (sizeof (*spec));
      struct rte_flow_item_eth *mask = clib_mem_alloc (sizeof (*mask));

      clib_memset (spec, 0, sizeof (*spec));
      clib_memset (mask, 0, sizeof (*mask));

      /* check if SMAC/DMAC/Ether_type assigned */
      if (!mac_address_is_all_zero (te->eth_hdr.dst_address))
	{
	  clib_memcpy_fast (&spec->dst, &te->eth_hdr.dst_address, sizeof (spec->dst));
	  clib_memset (&mask->dst, 0xFF, sizeof (mask->dst));
	}

      if (!mac_address_is_all_zero (te->eth_hdr.src_address))
	{
	  clib_memcpy_fast (&spec->src, &te->eth_hdr.src_address, sizeof (spec->src));
	  clib_memset (&mask->src, 0xFF, sizeof (mask->src));
	}

      if (te->eth_hdr.type)
	{
	  spec->type = clib_host_to_net_u16 (te->eth_hdr.type);
	  mask->type = clib_host_to_net_u16 (0xFFFF);
	}

      item->spec = spec;
      item->mask = mask;
    }
  else
    {
      item->spec = NULL;
      item->mask = NULL;
    }

  /* currently only single empty vlan tag is supported */
  if (FLOW_HAS_VLAN_TAG (f))
    {
      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_VLAN;
      item->spec = NULL;
      item->mask = NULL;
    }

  if (FLOW_IS_ETHERNET_CLASS (f))
    goto pattern_end;

  /* Layer 3, IP */
  vec_add2 (items, item, 1);
  if (flow_class == FLOW_IPV4_CLASS)
    {
      vnet_flow_ip4_t *ip4_ptr = &f->ip4;

      item->type = RTE_FLOW_ITEM_TYPE_IPV4;
      if ((!ip4_ptr->src_addr.mask.as_u32) &&
	  (!ip4_ptr->dst_addr.mask.as_u32) && (!ip4_ptr->protocol.mask))
	{
	  item->spec = NULL;
	  item->mask = NULL;
	}
      else
	{
	  struct rte_flow_item_ipv4 *spec = clib_mem_alloc (sizeof (*spec));
	  struct rte_flow_item_ipv4 *mask = clib_mem_alloc (sizeof (*mask));

	  clib_memset (spec, 0, sizeof (*spec));
	  clib_memset (mask, 0, sizeof (*mask));

	  spec->hdr.src_addr = ip4_ptr->src_addr.addr.as_u32;
	  spec->hdr.dst_addr = ip4_ptr->dst_addr.addr.as_u32;
	  spec->hdr.next_proto_id = ip4_ptr->protocol.prot;
	  mask->hdr.src_addr = ip4_ptr->src_addr.mask.as_u32;
	  mask->hdr.dst_addr = ip4_ptr->dst_addr.mask.as_u32;
	  mask->hdr.next_proto_id = ip4_ptr->protocol.mask;

	  item->spec = spec;
	  item->mask = mask;
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

      item->type = RTE_FLOW_ITEM_TYPE_IPV6;

      if ((ip6_ptr->src_addr.mask.as_u64[0] == 0) &&
	  (ip6_ptr->src_addr.mask.as_u64[1] == 0) &&
	  (ip6_ptr->dst_addr.mask.as_u64[0] == 0) &&
	  (ip6_ptr->dst_addr.mask.as_u64[1] == 0) && (!ip6_ptr->protocol.mask))
	{
	  item->spec = NULL;
	  item->mask = NULL;
	}
      else
	{

	  struct rte_flow_item_ipv6 *spec = clib_mem_alloc (sizeof (*spec));
	  struct rte_flow_item_ipv6 *mask = clib_mem_alloc (sizeof (*mask));

	  clib_memset (spec, 0, sizeof (*spec));
	  clib_memset (mask, 0, sizeof (*mask));

	  clib_memcpy (IP6_SRC_ADDR (spec), &ip6_ptr->src_addr.addr,
		       ARRAY_LEN (ip6_ptr->src_addr.addr.as_u8));
	  clib_memcpy (IP6_SRC_ADDR (mask), &ip6_ptr->src_addr.mask,
		       ARRAY_LEN (ip6_ptr->src_addr.mask.as_u8));
	  clib_memcpy (IP6_DST_ADDR (spec), &ip6_ptr->dst_addr.addr,
		       ARRAY_LEN (ip6_ptr->dst_addr.addr.as_u8));
	  clib_memcpy (IP6_DST_ADDR (mask), &ip6_ptr->dst_addr.mask,
		       ARRAY_LEN (ip6_ptr->dst_addr.mask.as_u8));
	  spec->hdr.proto = ip6_ptr->protocol.prot;
	  mask->hdr.proto = ip6_ptr->protocol.mask;

	  item->spec = spec;
	  item->mask = mask;
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
  vec_add2 (items, item, 1);
  switch (protocol)
    {
    case IP_PROTOCOL_L2TP:
      {
	struct rte_flow_item_l2tpv3oip *spec = clib_mem_alloc (sizeof (*spec));
	struct rte_flow_item_l2tpv3oip *mask = clib_mem_alloc (sizeof (*mask));

	clib_memset (spec, 0, sizeof (*spec));
	clib_memset (mask, 0, sizeof (*mask));

	item->type = RTE_FLOW_ITEM_TYPE_L2TPV3OIP;
	spec->session_id = clib_host_to_net_u32 (f->ip4_l2tpv3oip.session_id);
	mask->session_id = ~0;

	item->spec = spec;
	item->mask = mask;
	break;
      }
    case IP_PROTOCOL_IPSEC_ESP:
      {
	struct rte_flow_item_esp *spec = clib_mem_alloc (sizeof (*spec));
	struct rte_flow_item_esp *mask = clib_mem_alloc (sizeof (*mask));

	clib_memset (spec, 0, sizeof (*spec));
	clib_memset (mask, 0, sizeof (*mask));

	item->type = RTE_FLOW_ITEM_TYPE_ESP;
	spec->hdr.spi = clib_host_to_net_u32 (f->ip4_ipsec_esp.spi);
	mask->hdr.spi = ~0;

	item->spec = spec;
	item->mask = mask;
	break;
      }
    case IP_PROTOCOL_IPSEC_AH:
      {
	struct rte_flow_item_ah *spec = clib_mem_alloc (sizeof (*spec));
	struct rte_flow_item_ah *mask = clib_mem_alloc (sizeof (*mask));

	clib_memset (spec, 0, sizeof (*spec));
	clib_memset (mask, 0, sizeof (*mask));

	item->type = RTE_FLOW_ITEM_TYPE_AH;
	spec->spi = clib_host_to_net_u32 (f->ip4_ipsec_ah.spi);
	mask->spi = ~0;

	item->spec = spec;
	item->mask = mask;
	break;
      }
    case IP_PROTOCOL_TCP:
      {
	item->type = RTE_FLOW_ITEM_TYPE_TCP;
	if ((src_port_mask == 0) && (dst_port_mask == 0))
	  {
	    item->spec = NULL;
	    item->mask = NULL;
	  }
	else
	  {
	    struct rte_flow_item_tcp *spec = clib_mem_alloc (sizeof (*spec));
	    struct rte_flow_item_tcp *mask = clib_mem_alloc (sizeof (*mask));

	    clib_memset (spec, 0, sizeof (*spec));
	    clib_memset (mask, 0, sizeof (*mask));

	    spec->hdr.src_port = clib_host_to_net_u16 (src_port);
	    spec->hdr.dst_port = clib_host_to_net_u16 (dst_port);
	    mask->hdr.src_port = clib_host_to_net_u16 (src_port_mask);
	    mask->hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);
	    item->spec = spec;
	    item->mask = mask;
	  }
	break;
      }
    case IP_PROTOCOL_UDP:
      {
	item->type = RTE_FLOW_ITEM_TYPE_UDP;
	if ((src_port_mask == 0) && (dst_port_mask == 0))
	  {
	    item->spec = NULL;
	    item->mask = NULL;
	  }
	else
	  {
	    struct rte_flow_item_udp *spec = clib_mem_alloc (sizeof (*spec));
	    struct rte_flow_item_udp *mask = clib_mem_alloc (sizeof (*mask));

	    clib_memset (spec, 0, sizeof (*spec));
	    clib_memset (mask, 0, sizeof (*mask));

	    spec->hdr.src_port = clib_host_to_net_u16 (src_port);
	    spec->hdr.dst_port = clib_host_to_net_u16 (dst_port);
	    mask->hdr.src_port = clib_host_to_net_u16 (src_port_mask);
	    mask->hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);
	    item->spec = spec;
	    item->mask = mask;
	  }

	/* handle the UDP tunnels */
	if (f->type == VNET_FLOW_TYPE_IP4_GTPC)
	  {
	    struct rte_flow_item_gtp *spec = clib_mem_alloc (sizeof (*spec));
	    struct rte_flow_item_gtp *mask = clib_mem_alloc (sizeof (*mask));

	    clib_memset (spec, 0, sizeof (*spec));
	    clib_memset (mask, 0, sizeof (*mask));

	    spec->teid = clib_host_to_net_u32 (f->ip4_gtpc.teid);
	    mask->teid = ~0;

	    vec_add2 (items, item, 1);
	    item->type = RTE_FLOW_ITEM_TYPE_GTPC;
	    item->spec = spec;
	    item->mask = mask;
	  }
	else if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	  {
	    struct rte_flow_item_gtp *spec = clib_mem_alloc (sizeof (*spec));
	    struct rte_flow_item_gtp *mask = clib_mem_alloc (sizeof (*mask));

	    spec->teid = clib_host_to_net_u32 (f->ip4_gtpu.teid);
	    mask->teid = ~0;

	    vec_add2 (items, item, 1);
	    item->type = RTE_FLOW_ITEM_TYPE_GTPU;
	    item->spec = spec;
	    item->mask = mask;
	  }
	else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
	  {
	    vxlan_t *spec = clib_mem_alloc (sizeof (*spec));
	    vxlan_t *mask = clib_mem_alloc (sizeof (*mask));
	    u32 vni = f->ip4_vxlan.vni;

	    vxlan_header_t spec_hdr = { .flags = VXLAN_FLAGS_I,
					.vni_reserved = clib_host_to_net_u32 (vni << 8) };
	    vxlan_header_t mask_hdr = { .flags = 0xff,
					.vni_reserved = clib_host_to_net_u32 (((u32) -1) << 8) };

	    clib_memset (spec, 0, sizeof (*spec));
	    clib_memset (mask, 0, sizeof (*mask));

	    spec->item.relative = 1;
	    spec->item.length = vxlan_hdr_sz;

	    clib_memcpy_fast (spec->val + raw_sz, &spec_hdr, vxlan_hdr_sz);
	    spec->item.pattern = spec->val + raw_sz;
	    clib_memcpy_fast (mask->val + raw_sz, &mask_hdr, vxlan_hdr_sz);
	    mask->item.pattern = mask->val + raw_sz;

	    vec_add2 (items, item, 1);
	    item->type = RTE_FLOW_ITEM_TYPE_RAW;
	    item->spec = spec;
	    item->mask = mask;
	  }
	break;
      }
    case IP_PROTOCOL_IPV6:
      {
	item->type = RTE_FLOW_ITEM_TYPE_IPV6;

#define fill_inner_ip6_with_outer_ipv(OUTER_IP_VER)                                                \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP6 ||                                          \
      f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP6_N_TUPLE)                                    \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip6_t *ptr = &f->ip##OUTER_IP_VER##_ip6;                        \
      if ((ptr->in_src_addr.mask.as_u64[0] == 0) && (ptr->in_src_addr.mask.as_u64[1] == 0) &&      \
	  (ptr->in_dst_addr.mask.as_u64[0] == 0) && (ptr->in_dst_addr.mask.as_u64[1] == 0) &&      \
	  (!ptr->in_protocol.mask))                                                                \
	{                                                                                          \
	  item->spec = NULL;                                                                       \
	  item->mask = NULL;                                                                       \
	}                                                                                          \
      else                                                                                         \
	{                                                                                          \
	  struct rte_flow_item_ipv6 *spec = clib_mem_alloc (sizeof (*spec));                       \
	  struct rte_flow_item_ipv6 *mask = clib_mem_alloc (sizeof (*mask));                       \
                                                                                                   \
	  clib_memset (spec, 0, sizeof (*spec));                                                   \
	  clib_memset (mask, 0, sizeof (*mask));                                                   \
                                                                                                   \
	  clib_memcpy (IP6_SRC_ADDR (spec), &ptr->in_src_addr.addr,                                \
		       ARRAY_LEN (ptr->in_src_addr.addr.as_u8));                                   \
	  clib_memcpy (IP6_SRC_ADDR (mask), &ptr->in_src_addr.mask,                                \
		       ARRAY_LEN (ptr->in_src_addr.mask.as_u8));                                   \
	  clib_memcpy (IP6_DST_ADDR (spec), &ptr->in_dst_addr.addr,                                \
		       ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));                                   \
	  clib_memcpy (IP6_DST_ADDR (mask), &ptr->in_dst_addr.mask,                                \
		       ARRAY_LEN (ptr->in_dst_addr.mask.as_u8));                                   \
	  item->spec = spec;                                                                       \
	  item->mask = mask;                                                                       \
	}                                                                                          \
    }
	fill_inner_ip6_with_outer_ipv (6) fill_inner_ip6_with_outer_ipv (4)
#undef fill_inner_ip6_with_outer_ipv
	  break;
      }
    case IP_PROTOCOL_IP_IN_IP:
      {
	item->type = RTE_FLOW_ITEM_TYPE_IPV4;

#define fill_inner_ip4_with_outer_ipv(OUTER_IP_VER)                                                \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP4 ||                                          \
      f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP4_N_TUPLE)                                    \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip4_t *ptr = &f->ip##OUTER_IP_VER##_ip4;                        \
      if ((!ptr->in_src_addr.mask.as_u32) && (!ptr->in_dst_addr.mask.as_u32) &&                    \
	  (!ptr->in_protocol.mask))                                                                \
	{                                                                                          \
	  item->spec = NULL;                                                                       \
	  item->mask = NULL;                                                                       \
	}                                                                                          \
      else                                                                                         \
	{                                                                                          \
	  struct rte_flow_item_ipv4 *spec = clib_mem_alloc (sizeof (*spec));                       \
	  struct rte_flow_item_ipv4 *mask = clib_mem_alloc (sizeof (*mask));                       \
                                                                                                   \
	  clib_memset (spec, 0, sizeof (*spec));                                                   \
	  clib_memset (mask, 0, sizeof (*mask));                                                   \
                                                                                                   \
	  spec->hdr.src_addr = ptr->in_src_addr.addr.as_u32;                                       \
	  mask->hdr.src_addr = ptr->in_src_addr.mask.as_u32;                                       \
	  spec->hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;                                       \
	  mask->hdr.dst_addr = ptr->in_dst_addr.mask.as_u32;                                       \
	  item->spec = spec;                                                                       \
	  item->mask = mask;                                                                       \
	}                                                                                          \
    }
	fill_inner_ip4_with_outer_ipv (6) fill_inner_ip4_with_outer_ipv (4)
#undef fill_inner_ip4_with_outer_ipv
	  break;
      }
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if (FLOW_HAS_INNER_N_TUPLE (f))
    {
      vec_add2 (items, item, 1);

#define fill_inner_n_tuple_of(proto, lproto)                                                       \
  {                                                                                                \
    item->type = RTE_FLOW_ITEM_TYPE_##proto;                                                       \
    if ((ptr->in_src_port.mask == 0) && (ptr->in_dst_port.mask == 0))                              \
      {                                                                                            \
	item->spec = NULL;                                                                         \
	item->mask = NULL;                                                                         \
      }                                                                                            \
    else                                                                                           \
      {                                                                                            \
	struct rte_flow_item_##lproto *spec = clib_mem_alloc (sizeof (*spec));                     \
	struct rte_flow_item_##lproto *mask = clib_mem_alloc (sizeof (*mask));                     \
                                                                                                   \
	clib_memset (spec, 0, sizeof (*spec));                                                     \
	clib_memset (mask, 0, sizeof (*mask));                                                     \
                                                                                                   \
	spec->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.port);                         \
	mask->hdr.src_port = clib_host_to_net_u16 (ptr->in_src_port.mask);                         \
	spec->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.port);                         \
	mask->hdr.dst_port = clib_host_to_net_u16 (ptr->in_dst_port.mask);                         \
	item->spec = spec;                                                                         \
	item->mask = mask;                                                                         \
      }                                                                                            \
  }

#define fill_inner_n_tuple(OUTER_IP_VER, INNER_IP_VER)                                             \
  if (f->type == VNET_FLOW_TYPE_IP##OUTER_IP_VER##_IP##INNER_IP_VER##_N_TUPLE)                     \
    {                                                                                              \
      vnet_flow_ip##OUTER_IP_VER##_ip##INNER_IP_VER##_n_tuple_t *ptr =                             \
	&f->ip##OUTER_IP_VER##_ip##INNER_IP_VER##_n_tuple;                                         \
      switch (ptr->in_protocol.prot)                                                               \
	{                                                                                          \
	case IP_PROTOCOL_UDP:                                                                      \
	  fill_inner_n_tuple_of (UDP, udp) break;                                                  \
	case IP_PROTOCOL_TCP:                                                                      \
	  fill_inner_n_tuple_of (TCP, tcp) break;                                                  \
	default:                                                                                   \
	  break;                                                                                   \
	}                                                                                          \
    }
      fill_inner_n_tuple (6, 4) fill_inner_n_tuple (4, 4)
	fill_inner_n_tuple (6, 6) fill_inner_n_tuple (4, 6)
#undef fill_inner_n_tuple
#undef fill_inner_n_tuple_of
    }

pattern_end:
  if ((f->actions & VNET_FLOW_ACTION_RSS) && (f->rss_types & (1ULL << VNET_FLOW_RSS_TYPES_ESP)))
    {
      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
    }

  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_END;

  *pitems = items;
  return 0;

done:
  vec_free (items);
  return rv;
}

static int
dpdk_flow_fill_actions (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			struct rte_flow_action **pactions)
{

  struct rte_flow_action *action, *actions = 0;
  bool fate = false;
  int rv;

  *pactions = 0;

  /* Only one 'fate' can be assigned */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      struct rte_flow_action_queue *conf = clib_mem_alloc (sizeof (*conf));
      clib_memset (conf, 0, sizeof (*conf));

      vec_add2 (actions, action, 1);
      conf->index = f->redirect_queue;
      action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
      action->conf = conf;
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      vec_add2 (actions, action, 1);
      action->type = RTE_FLOW_ACTION_TYPE_DROP;
      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      struct rte_flow_action_rss *conf = clib_mem_alloc (sizeof (*conf));
      clib_memset (conf, 0, sizeof (*conf));

      vec_add2 (actions, action, 1);

      action->type = RTE_FLOW_ACTION_TYPE_RSS;
      action->conf = conf;

      /* convert types to DPDK rss bitmask */
      dpdk_flow_convert_rss_types (f->rss_types, &conf->types);

      if (f->queue_num)
	/* convert rss queues to array */
	dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, conf);

      if ((conf->func = dpdk_flow_convert_rss_func (f->rss_fun)) == RTE_ETH_HASH_FUNCTION_MAX)
	{
	  rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	  goto done;
	}

      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;
    }

  if (!fate)
    {
      vec_add2 (actions, action, 1);
      action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    }

  if (f->actions & VNET_FLOW_ACTION_MARK)
    {
      struct rte_flow_action_mark *conf = clib_mem_alloc (sizeof (*conf));
      clib_memset (conf, 0, sizeof (*conf));

      vec_add2 (actions, action, 1);
      conf->id = fe->mark;
      action->type = RTE_FLOW_ACTION_TYPE_MARK;
      action->conf = conf;
    }

  vec_add2 (actions, action, 1);
  action->type = RTE_FLOW_ACTION_TYPE_END;

  *pactions = actions;
  return 0;

done:
  vec_free (actions);
  return rv;
}

static int
dpdk_flow_fill_items_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			       struct rte_flow_item **pitems)
{
  struct rte_flow_item *item;
  int rv;

  // HACK: flow_entry is not used in fill_items
  if ((rv = dpdk_flow_fill_items (xd, t, NULL, pitems)))
    return rv;

  vec_foreach (item, *pitems)
    {
      if (item->spec)
	{
	  clib_mem_free ((void *) item->spec);
	  item->spec = NULL;
	}
    }
  return 0;
}

static int
dpdk_flow_fill_actions_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
				 struct rte_flow_action **pactions, struct rte_flow_action **pmasks)
{
  struct rte_flow_action *action, *actions = 0;
  struct rte_flow_action *mask, *masks = 0;
  bool fate = false;
  int rv;

  *pactions = 0;
  *pmasks = 0;

  /* Only one 'fate' can be assigned */
  if (t->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      vec_add2 (actions, action, 1);
      vec_add2 (masks, mask, 1);
      action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
      mask->type = RTE_FLOW_ACTION_TYPE_QUEUE;
      fate = true;
    }

  if (t->actions & VNET_FLOW_ACTION_DROP)
    {
      vec_add2 (actions, action, 1);
      vec_add2 (masks, mask, 1);
      action->type = RTE_FLOW_ACTION_TYPE_DROP;
      mask->type = RTE_FLOW_ACTION_TYPE_DROP;
      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;
    }

  if (t->actions & VNET_FLOW_ACTION_RSS)
    {
      vec_add2 (actions, action, 1);
      vec_add2 (masks, mask, 1);
      action->type = RTE_FLOW_ACTION_TYPE_RSS;
      mask->type = RTE_FLOW_ACTION_TYPE_RSS;
      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;
    }

  if (!fate)
    {
      vec_add2 (actions, action, 1);
      vec_add2 (masks, mask, 1);
      action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
      mask->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    }

  if (t->actions & VNET_FLOW_ACTION_MARK)
    {
      vec_add2 (actions, action, 1);
      vec_add2 (masks, mask, 1);
      action->type = RTE_FLOW_ACTION_TYPE_MARK;
      mask->type = RTE_FLOW_ACTION_TYPE_MARK;
    }

  vec_add2 (actions, action, 1);
  vec_add2 (masks, mask, 1);
  action->type = RTE_FLOW_ACTION_TYPE_END;
  mask->type = RTE_FLOW_ACTION_TYPE_END;

  *pactions = actions;
  *pmasks = masks;
  return 0;

done:
  vec_free (actions);
  vec_free (masks);
  return rv;
}

static void
dpdk_flow_free_items (struct rte_flow_item *items)
{
  struct rte_flow_item *item;
  vec_foreach (item, items)
    {
      if (item->spec)
	clib_mem_free ((void *) item->spec);
      if (item->mask)
	clib_mem_free ((void *) item->mask);
    }
  vec_free (items);
}

static void
dpdk_flow_free_actions (struct rte_flow_action *actions)
{
  struct rte_flow_action *action;
  vec_foreach (action, actions)
    {
      if (action->conf)
	clib_mem_free ((void *) action->conf);
    }
  vec_free (actions);
}

static int
dpdk_flow_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe)
{
  struct rte_flow_item *items;
  struct rte_flow_action *actions;
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, &items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, &actions)) != 0)
    {
      dpdk_flow_free_items (items);
      return rv;
    }

  rv = rte_flow_validate (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (rv)
    {
      if (rv == -EINVAL)
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      else if (rv == -EEXIST)
	rv = VNET_FLOW_ERROR_ALREADY_EXISTS;
      else
	rv = VNET_FLOW_ERROR_INTERNAL;

      goto done;
    }

  fe->handle = rte_flow_create (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (!fe->handle)
    rv = VNET_FLOW_ERROR_NOT_SUPPORTED;

done:
  dpdk_flow_free_items (items);
  dpdk_flow_free_actions (actions);
  return rv;
}

static int
dpdk_flow_async_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_template_entry_t *fte,
		     dpdk_flow_entry_t *fe)
{
  struct rte_flow_item *items;
  struct rte_flow_action *actions;
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, &items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, &actions)) != 0)
    {
      dpdk_flow_free_items (items);
      return rv;
    }

  rv = rte_flow_validate (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (rv)
    {
      dpdk_device_flow_error (xd, "rte_flow_validate", rv);

      if (rv == -EINVAL)
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      else if (rv == -EEXIST)
	rv = VNET_FLOW_ERROR_ALREADY_EXISTS;
      else
	rv = VNET_FLOW_ERROR_INTERNAL;

      goto done;
    }

  fe->handle =
    rte_flow_async_create (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &async_op,
			   fte->table_handle, items, 0, actions, 0, NULL, &xd->last_flow_error);

  if (!fe->handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_async_create", rv);
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

done:
  if (!rv)
    clib_atomic_add_fetch (&fte->ref, 1);

  dpdk_flow_free_items (items);
  dpdk_flow_free_actions (actions);
  return rv;
}

static int
dpdk_flow_async_template_add (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			      u32 nb_flows)
{
  struct rte_flow_item *items;
  struct rte_flow_action *actions;
  struct rte_flow_action *actions_mask;
  struct rte_flow_template_table_attr template_attr = { .nb_flows = nb_flows };
  int rv = 0;

  clib_memcpy (&template_attr.flow_attr, &ingress, sizeof (ingress));

  if ((rv = dpdk_flow_fill_items_template (xd, t, fte, &items)) != 0)
    return rv;

  fte->pattern_handle =
    rte_flow_pattern_template_create (xd->port_id, &pattern_attr, items, &xd->last_flow_error);
  if (!fte->pattern_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_pattern_template_create", rv);
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_pattern;
    }

  if ((rv = dpdk_flow_fill_actions_template (xd, t, fte, &actions, &actions_mask)) != 0)
    goto done_pattern_handle;

  fte->actions_handle = rte_flow_actions_template_create (xd->port_id, &action_attr, actions,
							  actions_mask, &xd->last_flow_error);
  if (!fte->actions_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_actions_template_create", rv);
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_actions;
    }

  fte->table_handle =
    rte_flow_template_table_create (xd->port_id, &template_attr, &fte->pattern_handle, 1,
				    &fte->actions_handle, 1, &xd->last_flow_error);
  if (!fte->table_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_template_table_create", rv);
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_actions_handle;
    }

  dpdk_flow_free_items (items);
  dpdk_flow_free_actions (actions);
  dpdk_flow_free_actions (actions_mask);

  return 0;

done_actions_handle:
  rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle, &xd->last_flow_error);
  fte->actions_handle = 0;

done_actions:
  dpdk_flow_free_actions (actions);
  dpdk_flow_free_actions (actions_mask);

done_pattern_handle:
  rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle, &xd->last_flow_error);
  fte->pattern_handle = 0;

done_pattern:
  dpdk_flow_free_items (items);
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
	  dpdk_device_flow_error (xd, "rte_flow_destroy", rv);
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
  if (flow->actions & (VNET_FLOW_ACTION_MARK |
		       VNET_FLOW_ACTION_REDIRECT_TO_NODE |
		       VNET_FLOW_ACTION_BUFFER_ADVANCE))
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

int
dpdk_flow_async_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
			vnet_flow_range_t *range, uword *private_template_data, uword *private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  vnet_flow_t *flow;
  dpdk_flow_entry_t *fe;
  dpdk_flow_template_entry_t *fte;
  dpdk_flow_lookup_entry_t *fle = 0;
  uword *per_flow_private_data;
  u32 fi = 0;
  u32 total_enqueued = 0, total_completed = 0;
  u32 in_flight = 0, pulled;
  u32 max_in_flight = (DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH * 3) / 4;
  struct rte_flow_op_result *results;
  int rv;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 && xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW && op != VNET_FLOW_DEV_OP_DEL_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  results =
    clib_mem_alloc (sizeof (struct rte_flow_op_result) * DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH);

  flow_range_foreach (range, flow)
  {
    per_flow_private_data = vec_elt_at_index (private_data, fi);
    fi++;

    if (flow == 0)
      continue;

    in_flight = total_enqueued - total_completed;
    if (in_flight >= max_in_flight)
      {
	rv = rte_flow_push (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &xd->last_flow_error);
	if (rv)
	  {
	    dpdk_device_flow_error (xd, "rte_flow_push", rv);
	    return VNET_FLOW_ERROR_INTERNAL;
	  }

	do
	  {
	    pulled = rte_flow_pull (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, results,
				    DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH, &xd->last_flow_error);
	    if (pulled > 0)
	      total_completed += pulled;
	    else if (pulled == 0)
	      rte_pause ();
	    in_flight = total_enqueued - total_completed;
	  }
	while (in_flight >= max_in_flight);
      }

    if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
      {
	fe = vec_elt_at_index (xd->flow_entries, *per_flow_private_data);

	if ((rv = rte_flow_async_destroy (xd->port_id, 0, &async_op, fe->handle, NULL,
					  &xd->last_flow_error)))
	  {
	    dpdk_device_flow_error (xd, "rte_flow_async_destroy", rv);
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

	clib_atomic_sub_fetch (&fte->ref, 1);

	if (pool_elts (xd->flow_entries) == 0)
	  xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

	goto check_for_push;
      }

    if (flow->actions == 0)
      return VNET_FLOW_ERROR_NOT_SUPPORTED;

    fte = vec_elt_at_index (xd->flow_template_entries, *private_template_data);

    pool_get (xd->flow_entries, fe);
    fe->flow_index = flow->index;


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
      fe->mark = 0;

    xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

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
	if ((rv = dpdk_flow_async_add (xd, flow, fte, fe)))
	  goto done;
	break;
      default:
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	goto done;
      }

    *per_flow_private_data = fe - xd->flow_entries;

  check_for_push:
    if ((total_enqueued % DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH) == 0)
      {
	rv = rte_flow_push (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &xd->last_flow_error);
	if (rv)
	  return VNET_FLOW_ERROR_INTERNAL;
      }
  }

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
  return rv;
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
	  dpdk_device_flow_error (xd, "rte_flow_template_table_destroy", rv);
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if ((rv = rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle,
						   &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_actions_template_destroy", rv);
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if ((rv = rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle,
						   &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_pattern_template_destroy", rv);
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

  if (private_data >= vec_len (xd->flow_entries))
    return format (s, "unknown flow");

  fe = vec_elt_at_index (xd->flow_entries, private_data);
  s = format (s, "mark %u", fe->mark);
  return s;
}

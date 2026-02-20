/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include "vnet/flow/flow.h"
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
#define IP6_SRC_ADDR(_ip6) (_ip6)->hdr.src_addr.a
#else
#define IP6_SRC_ADDR(_ip6) (_ip6)->hdr.src_addr
#endif

/* get destination addr from ipv6 header */
#if (RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0))
#define IP6_DST_ADDR(_ip6) (_ip6)->hdr.dst_addr.a
#else
#define IP6_DST_ADDR(_ip6) (_ip6)->hdr.dst_addr
#endif

#define FOREACH_FLOW_ITEM(_items, _item)                                                           \
  (_item) = &(_items)[0];                                                                          \
  for (int _it = 0; (_item)->type != RTE_FLOW_ITEM_TYPE_END; (_item) = &(_items)[++_it])

#define FOREACH_FLOW_ACTION(_actions, _action)                                                     \
  (_action) = &(_actions)[0];                                                                      \
  for (int _it = 0; (_action)->type != RTE_FLOW_ACTION_TYPE_END; (_action) = &(_actions)[++_it])

#define foreach_ip_ip                                                                              \
  _ (4, 4)                                                                                         \
  _ (4, 6)                                                                                         \
  _ (6, 4)                                                                                         \
  _ (6, 6)

/* constant structs */
static const struct rte_flow_attr ingress = { .group = 1, .transfer = 1 };
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

/*
 * Specialized item fill functions for async flow path.
 * Each function fills exactly one item with no conditionals.
 * Static spec/mask buffers are used (single-threaded async path).
 */

static void
dpdk_fill_item_eth (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_eth spec;
  static struct rte_flow_item_eth mask;
  vnet_flow_ethernet_t *te = &f->ethernet;

  item->type = RTE_FLOW_ITEM_TYPE_ETH;
  item->last = NULL;

  /* Check if any ETH fields are specified */
  if (mac_address_is_all_zero (te->eth_hdr.dst_address) &&
      mac_address_is_all_zero (te->eth_hdr.src_address) && te->eth_hdr.type == 0)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  clib_memcpy_fast (&spec.dst, &te->eth_hdr.dst_address, sizeof (spec.dst));
  clib_memcpy_fast (&spec.src, &te->eth_hdr.src_address, sizeof (spec.src));
  spec.type = clib_host_to_net_u16 (te->eth_hdr.type);

  if (!mac_address_is_all_zero (te->eth_hdr.dst_address))
    clib_memset (&mask.dst, 0xFF, sizeof (mask.dst));
  else
    clib_memset (&mask.dst, 0, sizeof (mask.dst));

  if (!mac_address_is_all_zero (te->eth_hdr.src_address))
    clib_memset (&mask.src, 0xFF, sizeof (mask.src));
  else
    clib_memset (&mask.src, 0, sizeof (mask.src));

  mask.type = te->eth_hdr.type ? clib_host_to_net_u16 (0xFFFF) : 0;

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_vlan (vnet_flow_t *f, struct rte_flow_item *item)
{
  item->type = RTE_FLOW_ITEM_TYPE_VLAN;
  item->spec = NULL;
  item->mask = NULL;
  item->last = NULL;
}

static void
dpdk_fill_item_ipv4 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_ipv4 spec;
  static struct rte_flow_item_ipv4 mask;
  vnet_flow_ip4_t *ip4 = &f->ip4;

  item->type = RTE_FLOW_ITEM_TYPE_IPV4;
  item->last = NULL;

  /* Check if all masks are zero */
  if (!ip4->src_addr.mask.as_u32 && !ip4->dst_addr.mask.as_u32 && !ip4->protocol.mask)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  spec.hdr.src_addr = ip4->src_addr.addr.as_u32;
  spec.hdr.dst_addr = ip4->dst_addr.addr.as_u32;
  spec.hdr.next_proto_id = ip4->protocol.prot;
  mask.hdr.src_addr = ip4->src_addr.mask.as_u32;
  mask.hdr.dst_addr = ip4->dst_addr.mask.as_u32;
  mask.hdr.next_proto_id = ip4->protocol.mask;

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_ipv6 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_ipv6 spec;
  static struct rte_flow_item_ipv6 mask;
  vnet_flow_ip6_t *ip6 = &f->ip6;

  item->type = RTE_FLOW_ITEM_TYPE_IPV6;
  item->last = NULL;

  /* Check if all masks are zero */
  if (!ip6->src_addr.mask.as_u64[0] && !ip6->src_addr.mask.as_u64[1] &&
      !ip6->dst_addr.mask.as_u64[0] && !ip6->dst_addr.mask.as_u64[1] && !ip6->protocol.mask)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  clib_memcpy (IP6_SRC_ADDR (&spec), &ip6->src_addr.addr, ARRAY_LEN (ip6->src_addr.addr.as_u8));
  clib_memcpy (IP6_SRC_ADDR (&mask), &ip6->src_addr.mask, ARRAY_LEN (ip6->src_addr.mask.as_u8));
  clib_memcpy (IP6_DST_ADDR (&spec), &ip6->dst_addr.addr, ARRAY_LEN (ip6->dst_addr.addr.as_u8));
  clib_memcpy (IP6_DST_ADDR (&mask), &ip6->dst_addr.mask, ARRAY_LEN (ip6->dst_addr.mask.as_u8));
  spec.hdr.proto = ip6->protocol.prot;
  mask.hdr.proto = ip6->protocol.mask;

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_tcp4 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_tcp spec;
  static struct rte_flow_item_tcp mask;
  vnet_flow_ip4_n_tuple_t *t = &f->ip4_n_tuple;

  item->type = RTE_FLOW_ITEM_TYPE_TCP;
  item->last = NULL;

  if (!t->src_port.mask && !t->dst_port.mask)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  spec.hdr.src_port = clib_host_to_net_u16 (t->src_port.port);
  spec.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.port);
  mask.hdr.src_port = clib_host_to_net_u16 (t->src_port.mask);
  mask.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.mask);

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_tcp6 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_tcp spec;
  static struct rte_flow_item_tcp mask;
  vnet_flow_ip6_n_tuple_t *t = &f->ip6_n_tuple;

  item->type = RTE_FLOW_ITEM_TYPE_TCP;
  item->last = NULL;

  if (!t->src_port.mask && !t->dst_port.mask)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  spec.hdr.src_port = clib_host_to_net_u16 (t->src_port.port);
  spec.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.port);
  mask.hdr.src_port = clib_host_to_net_u16 (t->src_port.mask);
  mask.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.mask);

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_udp4 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_udp spec;
  static struct rte_flow_item_udp mask;
  vnet_flow_ip4_n_tuple_t *t = &f->ip4_n_tuple;

  item->type = RTE_FLOW_ITEM_TYPE_UDP;
  item->last = NULL;

  if (!t->src_port.mask && !t->dst_port.mask)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  spec.hdr.src_port = clib_host_to_net_u16 (t->src_port.port);
  spec.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.port);
  mask.hdr.src_port = clib_host_to_net_u16 (t->src_port.mask);
  mask.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.mask);

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_udp6 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_udp spec;
  static struct rte_flow_item_udp mask;
  vnet_flow_ip6_n_tuple_t *t = &f->ip6_n_tuple;

  item->type = RTE_FLOW_ITEM_TYPE_UDP;
  item->last = NULL;

  if (!t->src_port.mask && !t->dst_port.mask)
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  spec.hdr.src_port = clib_host_to_net_u16 (t->src_port.port);
  spec.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.port);
  mask.hdr.src_port = clib_host_to_net_u16 (t->src_port.mask);
  mask.hdr.dst_port = clib_host_to_net_u16 (t->dst_port.mask);

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_l2tp (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_l2tpv3oip spec;
  static struct rte_flow_item_l2tpv3oip mask;

  spec.session_id = clib_host_to_net_u32 (f->ip4_l2tpv3oip.session_id);
  mask.session_id = ~0;

  item->type = RTE_FLOW_ITEM_TYPE_L2TPV3OIP;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_esp (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_esp spec;
  static struct rte_flow_item_esp mask;

  spec.hdr.spi = clib_host_to_net_u32 (f->ip4_ipsec_esp.spi);
  mask.hdr.spi = ~0;

  item->type = RTE_FLOW_ITEM_TYPE_ESP;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_ah (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_ah spec;
  static struct rte_flow_item_ah mask;

  spec.spi = clib_host_to_net_u32 (f->ip4_ipsec_ah.spi);
  mask.spi = ~0;

  item->type = RTE_FLOW_ITEM_TYPE_AH;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_gtpc (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_gtp spec;
  static struct rte_flow_item_gtp mask;

  spec.teid = clib_host_to_net_u32 (f->ip4_gtpc.teid);
  mask.teid = ~0;

  item->type = RTE_FLOW_ITEM_TYPE_GTPC;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_gtpu (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_gtp spec;
  static struct rte_flow_item_gtp mask;

  spec.teid = clib_host_to_net_u32 (f->ip4_gtpu.teid);
  mask.teid = ~0;

  item->type = RTE_FLOW_ITEM_TYPE_GTPU;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_end (vnet_flow_t *f, struct rte_flow_item *item)
{
  item->type = RTE_FLOW_ITEM_TYPE_END;
}

static void
dpdk_fill_item_generic (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_raw spec;
  static struct rte_flow_item_raw mask;

  spec.pattern = f->generic.pattern.spec;
  mask.pattern = f->generic.pattern.mask;

  item->type = RTE_FLOW_ITEM_TYPE_RAW;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_vxlan (vnet_flow_t *f, struct rte_flow_item *item)
{
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

  static vxlan_t spec;
  static vxlan_t mask;
  u32 vni = f->ip4_vxlan.vni;

  vxlan_header_t spec_hdr = { .flags = VXLAN_FLAGS_I,
			      .vni_reserved = clib_host_to_net_u32 (vni << 8) };
  vxlan_header_t mask_hdr = { .flags = 0xff,
			      .vni_reserved = clib_host_to_net_u32 (((u32) -1) << 8) };

  spec.item.relative = 1;
  spec.item.length = vxlan_hdr_sz;

  clib_memcpy_fast (spec.val + raw_sz, &spec_hdr, vxlan_hdr_sz);
  spec.item.pattern = spec.val + raw_sz;
  clib_memcpy_fast (mask.val + raw_sz, &mask_hdr, vxlan_hdr_sz);
  mask.item.pattern = mask.val + raw_sz;

  item->type = RTE_FLOW_ITEM_TYPE_RAW;
  item->spec = &spec;
  item->mask = &mask;
  item->last = NULL;
}

static void
dpdk_fill_item_esp_empty (vnet_flow_t *f, struct rte_flow_item *item)
{
  item->type = RTE_FLOW_ITEM_TYPE_ESP;
  item->spec = NULL;
  item->mask = NULL;
  item->last = NULL;
}

static void
dpdk_fill_item_inner_ipv6 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_ipv6 spec;
  static struct rte_flow_item_ipv6 mask;

  item->type = RTE_FLOW_ITEM_TYPE_IPV6;
  item->last = NULL;

  /* Try IP4_IP6 first, then IP6_IP6 */
  if (f->type == VNET_FLOW_TYPE_IP4_IP6 || f->type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE)
    {
      vnet_flow_ip4_ip6_t *ptr = &f->ip4_ip6;
      if (!ptr->in_src_addr.mask.as_u64[0] && !ptr->in_src_addr.mask.as_u64[1] &&
	  !ptr->in_dst_addr.mask.as_u64[0] && !ptr->in_dst_addr.mask.as_u64[1] &&
	  !ptr->in_protocol.mask)
	{
	  item->spec = NULL;
	  item->mask = NULL;
	  return;
	}
      clib_memcpy (IP6_SRC_ADDR (&spec), &ptr->in_src_addr.addr,
		   ARRAY_LEN (ptr->in_src_addr.addr.as_u8));
      clib_memcpy (IP6_SRC_ADDR (&mask), &ptr->in_src_addr.mask,
		   ARRAY_LEN (ptr->in_src_addr.mask.as_u8));
      clib_memcpy (IP6_DST_ADDR (&spec), &ptr->in_dst_addr.addr,
		   ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));
      clib_memcpy (IP6_DST_ADDR (&mask), &ptr->in_dst_addr.mask,
		   ARRAY_LEN (ptr->in_dst_addr.mask.as_u8));
    }
  else if (f->type == VNET_FLOW_TYPE_IP6_IP6 || f->type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE)
    {
      vnet_flow_ip6_ip6_t *ptr = &f->ip6_ip6;
      if (!ptr->in_src_addr.mask.as_u64[0] && !ptr->in_src_addr.mask.as_u64[1] &&
	  !ptr->in_dst_addr.mask.as_u64[0] && !ptr->in_dst_addr.mask.as_u64[1] &&
	  !ptr->in_protocol.mask)
	{
	  item->spec = NULL;
	  item->mask = NULL;
	  return;
	}
      clib_memcpy (IP6_SRC_ADDR (&spec), &ptr->in_src_addr.addr,
		   ARRAY_LEN (ptr->in_src_addr.addr.as_u8));
      clib_memcpy (IP6_SRC_ADDR (&mask), &ptr->in_src_addr.mask,
		   ARRAY_LEN (ptr->in_src_addr.mask.as_u8));
      clib_memcpy (IP6_DST_ADDR (&spec), &ptr->in_dst_addr.addr,
		   ARRAY_LEN (ptr->in_dst_addr.addr.as_u8));
      clib_memcpy (IP6_DST_ADDR (&mask), &ptr->in_dst_addr.mask,
		   ARRAY_LEN (ptr->in_dst_addr.mask.as_u8));
    }
  else
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  item->spec = &spec;
  item->mask = &mask;
}

static void
dpdk_fill_item_inner_ipv4 (vnet_flow_t *f, struct rte_flow_item *item)
{
  static struct rte_flow_item_ipv4 spec;
  static struct rte_flow_item_ipv4 mask;

  item->type = RTE_FLOW_ITEM_TYPE_IPV4;
  item->last = NULL;

  /* Try IP6_IP4 first, then IP4_IP4 */
  if (f->type == VNET_FLOW_TYPE_IP6_IP4 || f->type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE)
    {
      vnet_flow_ip6_ip4_t *ptr = &f->ip6_ip4;
      if (!ptr->in_src_addr.mask.as_u32 && !ptr->in_dst_addr.mask.as_u32 && !ptr->in_protocol.mask)
	{
	  item->spec = NULL;
	  item->mask = NULL;
	  return;
	}
      spec.hdr.src_addr = ptr->in_src_addr.addr.as_u32;
      mask.hdr.src_addr = ptr->in_src_addr.mask.as_u32;
      spec.hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;
      mask.hdr.dst_addr = ptr->in_dst_addr.mask.as_u32;
    }
  else if (f->type == VNET_FLOW_TYPE_IP4_IP4 || f->type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE)
    {
      vnet_flow_ip4_ip4_t *ptr = &f->ip4_ip4;
      if (!ptr->in_src_addr.mask.as_u32 && !ptr->in_dst_addr.mask.as_u32 && !ptr->in_protocol.mask)
	{
	  item->spec = NULL;
	  item->mask = NULL;
	  return;
	}
      spec.hdr.src_addr = ptr->in_src_addr.addr.as_u32;
      mask.hdr.src_addr = ptr->in_src_addr.mask.as_u32;
      spec.hdr.dst_addr = ptr->in_dst_addr.addr.as_u32;
      mask.hdr.dst_addr = ptr->in_dst_addr.mask.as_u32;
    }
  else
    {
      item->spec = NULL;
      item->mask = NULL;
      return;
    }

  item->spec = &spec;
  item->mask = &mask;
}

/*
 * Specialized action fill functions for async flow path.
 */

static void
dpdk_fill_action_drop (vnet_flow_t *f, struct rte_flow_action *action)
{
  action->type = RTE_FLOW_ACTION_TYPE_DROP;
  action->conf = NULL;
}

static void
dpdk_fill_action_queue (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_queue conf;
  conf.index = f->redirect_queue;
  action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
  action->conf = &conf;
}

static void
dpdk_fill_action_passthru (vnet_flow_t *f, struct rte_flow_action *action)
{
  action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
  action->conf = NULL;
}

/* Async path - validation done at template creation, no error return needed */
static void
dpdk_fill_action_rss (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_rss conf;

  dpdk_flow_convert_rss_types (f->rss_types, &conf.types);
  if (f->queue_num)
    dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, &conf);
  conf.func = dpdk_flow_convert_rss_func (f->rss_fun);

  action->type = RTE_FLOW_ACTION_TYPE_RSS;
  action->conf = &conf;
}

/* Sync path - returns error if RSS function is invalid */
static int
dpdk_fill_action_rss_validated (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_rss conf;

  dpdk_flow_convert_rss_types (f->rss_types, &conf.types);
  if (f->queue_num)
    dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, &conf);

  conf.func = dpdk_flow_convert_rss_func (f->rss_fun);
  if (conf.func == RTE_ETH_HASH_FUNCTION_MAX)
    return -1;

  action->type = RTE_FLOW_ACTION_TYPE_RSS;
  action->conf = &conf;
  return 0;
}

static void
dpdk_fill_action_mark (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_mark conf;
  conf.id = f->mark_flow_id;
  action->type = RTE_FLOW_ACTION_TYPE_MARK;
  action->conf = &conf;
}

static void
dpdk_fill_action_mark_with_id (vnet_flow_t *f, struct rte_flow_action *action, u32 mark_id)
{
  static struct rte_flow_action_mark conf;
  conf.id = mark_id;
  action->type = RTE_FLOW_ACTION_TYPE_MARK;
  action->conf = &conf;
}

static void
dpdk_fill_action_end (vnet_flow_t *f, struct rte_flow_action *action)
{
  action->type = RTE_FLOW_ACTION_TYPE_END;
}

/*
 * Populate template function pointer arrays based on flow type.
 * Called once at template creation time.
 * Returns 0 on success, sets n_item_fns=0 to fallback to generic path.
 */
static void
dpdk_flow_template_populate_fns (vnet_flow_t *t, dpdk_flow_template_entry_t *fte)
{
  u8 n_items = 0;
  u8 n_actions = 0;
  u8 protocol = 0;

  fte->n_item_fns = 0;
  fte->n_action_fns = 0;

  /* Handle Ethernet class */
  if (FLOW_IS_ETHERNET_CLASS (t))
    fte->item_fns[n_items++] = dpdk_fill_item_eth;

  /* Handle VLAN tagged flows */
  if (FLOW_HAS_VLAN_TAG (t))
    fte->item_fns[n_items++] = dpdk_fill_item_vlan;

  if (FLOW_IS_ETHERNET_CLASS (t))
    goto done_items;

  /* Handle IPv4 class */
  if (FLOW_IS_IPV4_CLASS (t))
    {
      fte->item_fns[n_items++] = dpdk_fill_item_ipv4;
      protocol = t->ip4.protocol.prot;

      /* L3-only type - no L4 */
      if (FLOW_IS_L3_TYPE (t))
	goto done_items;

      /* L4 protocol handling */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  fte->item_fns[n_items++] = dpdk_fill_item_tcp4;
	  break;
	case IP_PROTOCOL_UDP:
	  fte->item_fns[n_items++] = dpdk_fill_item_udp4;
	  /* Handle UDP tunnels */
	  if (t->type == VNET_FLOW_TYPE_IP4_GTPC)
	    fte->item_fns[n_items++] = dpdk_fill_item_gtpc;
	  else if (t->type == VNET_FLOW_TYPE_IP4_GTPU)
	    fte->item_fns[n_items++] = dpdk_fill_item_gtpu;
	  else if (t->type == VNET_FLOW_TYPE_IP4_VXLAN)
	    goto fallback; /* VXLAN uses RAW item, complex */
	  break;
	case IP_PROTOCOL_L2TP:
	  fte->item_fns[n_items++] = dpdk_fill_item_l2tp;
	  break;
	case IP_PROTOCOL_IPSEC_ESP:
	  fte->item_fns[n_items++] = dpdk_fill_item_esp;
	  break;
	case IP_PROTOCOL_IPSEC_AH:
	  fte->item_fns[n_items++] = dpdk_fill_item_ah;
	  break;
	case IP_PROTOCOL_IPV6:
	case IP_PROTOCOL_IP_IN_IP:
	  /* IP-in-IP tunnels - complex, fallback */
	  goto fallback;
	default:
	  goto fallback;
	}
      goto done_items;
    }

  /* Handle IPv6 class */
  if (FLOW_IS_IPV6_CLASS (t))
    {
      fte->item_fns[n_items++] = dpdk_fill_item_ipv6;
      protocol = t->ip6.protocol.prot;

      /* L3-only type - no L4 */
      if (FLOW_IS_L3_TYPE (t))
	goto done_items;

      /* L4 protocol handling */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  fte->item_fns[n_items++] = dpdk_fill_item_tcp6;
	  break;
	case IP_PROTOCOL_UDP:
	  fte->item_fns[n_items++] = dpdk_fill_item_udp6;
	  break;
	case IP_PROTOCOL_IPV6:
	case IP_PROTOCOL_IP_IN_IP:
	  /* IP-in-IP tunnels - complex, fallback */
	  goto fallback;
	default:
	  goto fallback;
	}
      goto done_items;
    }

  /* Unknown flow class */
  goto fallback;

done_items:
  fte->item_fns[n_items++] = dpdk_fill_item_end;
  fte->n_item_fns = n_items;

  /* Determine action fill functions based on actions bitmap */
  /* Only one fate action allowed */
  if (t->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    fte->action_fns[n_actions++] = dpdk_fill_action_queue;
  else if (t->actions & VNET_FLOW_ACTION_DROP)
    fte->action_fns[n_actions++] = dpdk_fill_action_drop;
  else if (t->actions & VNET_FLOW_ACTION_RSS)
    fte->action_fns[n_actions++] = dpdk_fill_action_rss;
  else
    fte->action_fns[n_actions++] = dpdk_fill_action_passthru;

  if (t->actions & VNET_FLOW_ACTION_MARK)
    fte->action_fns[n_actions++] = dpdk_fill_action_mark;

  fte->action_fns[n_actions++] = dpdk_fill_action_end;
  fte->n_action_fns = n_actions;
  return;

fallback:
  /* Complex cases - use generic fill functions */
  fte->n_item_fns = 0;
  fte->n_action_fns = 0;
}

static_always_inline int
dpdk_flow_fill_items (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
		      struct rte_flow_item *items)
{
  int n = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;

  if (f->actions & (~xd->supported_flow_actions))
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Handle generic flow first */
  if (f->type == VNET_FLOW_TYPE_GENERIC)
    {
      dpdk_fill_item_generic (f, &items[n++]);
      dpdk_fill_item_end (f, &items[n]);
      return 0;
    }

  /* Layer 2: Ethernet */
  if (FLOW_IS_ETHERNET_CLASS (f))
    dpdk_fill_item_eth (f, &items[n++]);

  if (FLOW_HAS_VLAN_TAG (f))
    dpdk_fill_item_vlan (f, &items[n++]);

  if (FLOW_IS_ETHERNET_CLASS (f))
    goto pattern_end;

  /* Layer 3: IPv4 */
  if (FLOW_IS_IPV4_CLASS (f))
    {
      dpdk_fill_item_ipv4 (f, &items[n++]);
      protocol = f->ip4.protocol.prot;

      if (FLOW_IS_L3_TYPE (f))
	goto pattern_end;

      /* Layer 4 */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  dpdk_fill_item_tcp4 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_UDP:
	  dpdk_fill_item_udp4 (f, &items[n++]);
	  if (f->type == VNET_FLOW_TYPE_IP4_GTPC)
	    dpdk_fill_item_gtpc (f, &items[n++]);
	  else if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	    dpdk_fill_item_gtpu (f, &items[n++]);
	  else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
	    dpdk_fill_item_vxlan (f, &items[n++]);
	  break;
	case IP_PROTOCOL_L2TP:
	  dpdk_fill_item_l2tp (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPSEC_ESP:
	  dpdk_fill_item_esp (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPSEC_AH:
	  dpdk_fill_item_ah (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPV6:
	  dpdk_fill_item_inner_ipv6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IP_IN_IP:
	  dpdk_fill_item_inner_ipv4 (f, &items[n++]);
	  break;
	default:
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
    }

  /* Layer 3: IPv6 */
  else if (FLOW_IS_IPV6_CLASS (f))
    {
      dpdk_fill_item_ipv6 (f, &items[n++]);
      protocol = f->ip6.protocol.prot;

      if (FLOW_IS_L3_TYPE (f))
	goto pattern_end;

      /* Layer 4 */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  dpdk_fill_item_tcp6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_UDP:
	  dpdk_fill_item_udp6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPV6:
	  dpdk_fill_item_inner_ipv6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IP_IN_IP:
	  dpdk_fill_item_inner_ipv4 (f, &items[n++]);
	  break;
	default:
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
    }

  /* Handle inner N-tuple for IP-in-IP tunnels */
  if (FLOW_HAS_INNER_N_TUPLE (f))
    {
      /* Inner TCP/UDP based on inner protocol */
      u8 in_proto = 0;
      if (0)
	;
#define _(_inner, _outer)                                                                          \
  else if (f->type == VNET_FLOW_TYPE_IP##_outer##_IP##_inner##_N_TUPLE) in_proto =                 \
    f->ip##_outer##_ip##_inner##_n_tuple.in_protocol.prot;
      foreach_ip_ip
#undef _

	u16 src_port = 0,
	    dst_port = 0, src_mask = 0, dst_mask = 0;
      if (0)
	;
#define _(_inner, _outer)                                                                          \
  else if (f->type == VNET_FLOW_TYPE_IP##_outer##_IP##_inner##_N_TUPLE)                            \
  {                                                                                                \
    src_port = f->ip##_outer##_ip##_inner##_n_tuple.in_src_port.port;                              \
    dst_port = f->ip##_outer##_ip##_inner##_n_tuple.in_dst_port.port;                              \
    src_mask = f->ip##_outer##_ip##_inner##_n_tuple.in_src_port.mask;                              \
    dst_mask = f->ip##_outer##_ip##_inner##_n_tuple.in_dst_port.mask;                              \
  }
      foreach_ip_ip
#undef _

	items[n]
	  .spec = NULL;
      items[n].mask = NULL;
      items[n].last = NULL;

      if (in_proto == IP_PROTOCOL_TCP)
	{
	  /* Use generic inner TCP fill - reuse tcp4 structure */
	  static struct rte_flow_item_tcp spec, mask;
	  items[n].type = RTE_FLOW_ITEM_TYPE_TCP;

	  if (src_mask || dst_mask)
	    {
	      spec.hdr.src_port = clib_host_to_net_u16 (src_port);
	      spec.hdr.dst_port = clib_host_to_net_u16 (dst_port);
	      mask.hdr.src_port = clib_host_to_net_u16 (src_mask);
	      mask.hdr.dst_port = clib_host_to_net_u16 (dst_mask);
	      items[n].spec = &spec;
	      items[n].mask = &mask;
	    }
	  n++;
	}
      else if (in_proto == IP_PROTOCOL_UDP)
	{
	  static struct rte_flow_item_udp spec, mask;
	  items[n].type = RTE_FLOW_ITEM_TYPE_UDP;

	  if (src_mask || dst_mask)
	    {
	      spec.hdr.src_port = clib_host_to_net_u16 (src_port);
	      spec.hdr.dst_port = clib_host_to_net_u16 (dst_port);
	      mask.hdr.src_port = clib_host_to_net_u16 (src_mask);
	      mask.hdr.dst_port = clib_host_to_net_u16 (dst_mask);
	      items[n].spec = &spec;
	      items[n].mask = &mask;
	    }
	  n++;
	}
    }

pattern_end:
  /* RSS ESP item */
  if ((f->actions & VNET_FLOW_ACTION_RSS) && (f->rss_types & (1ULL << VNET_FLOW_RSS_TYPES_ESP)))
    dpdk_fill_item_esp_empty (f, &items[n++]);

  dpdk_fill_item_end (f, &items[n]);
  return 0;
}

static_always_inline int
dpdk_flow_fill_actions (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			struct rte_flow_action *actions)
{
  int n = 0;
  bool fate = false;

  /* Only one 'fate' action is allowed */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      dpdk_fill_action_queue (f, &actions[n++]);
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;
      dpdk_fill_action_drop (f, &actions[n++]);
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;
      if (dpdk_fill_action_rss_validated (f, &actions[n++]))
	return VNET_FLOW_ERROR_NOT_SUPPORTED;
      fate = true;
    }

  if (!fate)
    dpdk_fill_action_passthru (f, &actions[n++]);

  if (f->actions & VNET_FLOW_ACTION_MARK)
    dpdk_fill_action_mark_with_id (f, &actions[n++], fe->mark);

  dpdk_fill_action_end (f, &actions[n]);
  return 0;
}

static int
dpdk_flow_fill_items_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			       struct rte_flow_item *items)
{
  struct rte_flow_item *item;
  int rv;

  // HACK: flow_entry is not used in fill_items
  if ((rv = dpdk_flow_fill_items (xd, t, NULL, items)))
    return rv;

  FOREACH_FLOW_ITEM (items, item) { item->spec = NULL; }

  return 0;
}

static int
dpdk_flow_fill_actions_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
				 struct rte_flow_action *actions, struct rte_flow_action *masks)
{
  int action_counter = 0;
  bool fate = false;
  int rv;

#define add_action_type(_type)                                                                     \
  {                                                                                                \
    actions[action_counter].type = RTE_FLOW_ACTION_TYPE_##_type;                                   \
    masks[action_counter].type = RTE_FLOW_ACTION_TYPE_##_type;                                     \
    action_counter++;                                                                              \
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
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;

      add_action_type (DROP);
    }

  if (t->actions & VNET_FLOW_ACTION_RSS)
    {
      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;

      add_action_type (RSS);
    }

  if (!fate)
    add_action_type (PASSTHRU);

  if (t->actions & VNET_FLOW_ACTION_MARK)
    add_action_type (MARK);

  add_action_type (END);
  return 0;

done:
  return rv;
#undef add_action_type
}


static int
dpdk_flow_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, actions)) != 0)
    return rv;

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
  return rv;
}

/*
 * Fast async flow add using pre-computed function pointer arrays.
 * No conditionals in the hot path - all decisions made at template creation.
 */
static int
dpdk_flow_async_add_fast (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_template_entry_t *fte,
			  dpdk_flow_entry_t *fe)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];

  /* Fill items using function pointer array - no conditionals */
  for (u8 i = 0; i < fte->n_item_fns; i++)
    fte->item_fns[i](f, &items[i]);

  /* Fill actions using function pointer array - no conditionals */
  for (u8 i = 0; i < fte->n_action_fns; i++)
    fte->action_fns[i](f, &actions[i]);

  fe->handle =
    rte_flow_async_create (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &async_op,
			   fte->table_handle, items, 0, actions, 0, NULL, &xd->last_flow_error);

  return fe->handle ? 0 : VNET_FLOW_ERROR_NOT_SUPPORTED;
}

/*
 * Generic async flow add - uses conditional-heavy fill functions.
 * Used as fallback when function pointers are not populated.
 */
static int
dpdk_flow_async_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_template_entry_t *fte,
		     dpdk_flow_entry_t *fe)
{
  /* Use fast path if function pointers are populated */
  if (PREDICT_TRUE (fte->n_item_fns > 0))
    return dpdk_flow_async_add_fast (xd, f, fte, fe);

  /* Fallback to generic path */
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, actions)) != 0)
    return rv;

  fe->handle =
    rte_flow_async_create (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &async_op,
			   fte->table_handle, items, 0, actions, 0, NULL, &xd->last_flow_error);

  if (!fe->handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_async_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return rv;
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

  /* Populate function pointer arrays for fast async flow insertion */
  dpdk_flow_template_populate_fns (t, fte);

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
      rv = rte_flow_push (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &xd->last_flow_error);
      if (rv)
	return VNET_FLOW_ERROR_INTERNAL;
    }

  if (PREDICT_FALSE (do_pull))
    {
      do
	{
	  pulled = rte_flow_pull (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, results,
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
dpdk_flow_async_op_del (dpdk_device_t *xd, vnet_flow_range_t *range,
			dpdk_flow_template_entry_t *fte, uword *private_data)
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

    if ((rv = rte_flow_async_destroy (xd->port_id, DPDK_DEFAULT_ASYNC_QUEUE_INDEX, &async_op,
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

  fte = vec_elt_at_index (xd->flow_template_entries, *private_template_data);

  switch (op)
    {
    case VNET_FLOW_DEV_OP_DEL_FLOW:
      return dpdk_flow_async_op_del (xd, range, fte, private_data);
    case VNET_FLOW_DEV_OP_ADD_FLOW:
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

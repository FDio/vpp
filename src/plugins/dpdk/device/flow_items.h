/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __FLOW_ITEMS_H__
#define __FLOW_ITEMS_H__

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vxlan/vxlan.h>
#include <dpdk/device/dpdk.h>

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

static inline bool
mac_address_is_all_zero (const u8 addr[6])
{
  int i = 0;

  for (i = 0; i < 6; i++)
    if (addr[i] != 0)
      return false;

  return true;
}

/*
 * Specialized item fill functions for async flow path.
 * Each function fills exactly one item.
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

#endif /* __FLOW_ITEMS_H__ */

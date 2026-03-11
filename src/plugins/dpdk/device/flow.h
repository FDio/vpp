/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __DPDK_FLOW_H__
#define __DPDK_FLOW_H__

#include <rte_flow.h>

#include <vlib/vlib.h>
#include <vxlan/vxlan_packet.h>

#define DPDK_MAX_FLOW_ITEMS   32
#define DPDK_MAX_FLOW_ACTIONS 32

enum
{
  vxlan_hdr_sz = sizeof (vxlan_header_t),
  raw_sz = sizeof (struct rte_flow_item_raw)
};

typedef union
{
  struct rte_flow_item_raw item;
  u8 val[raw_sz + vxlan_hdr_sz];
} vxlan_item_t;

typedef struct
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];

  struct rte_flow_item_eth eth[2];
  struct rte_flow_item_ipv4 ip4[2];
  struct rte_flow_item_ipv4 in_ip4[2];
  struct rte_flow_item_ipv6 ip6[2];
  struct rte_flow_item_ipv6 in_ip6[2];
  struct rte_flow_item_udp udp[2];
  struct rte_flow_item_udp in_UDP[2];
  struct rte_flow_item_tcp tcp[2];
  struct rte_flow_item_tcp in_TCP[2];
  struct rte_flow_item_gtp gtp[2];
  struct rte_flow_item_l2tpv3oip l2tp[2];
  struct rte_flow_item_esp esp[2];
  struct rte_flow_item_ah ah[2];
  struct rte_flow_item_raw generic[2];
  vxlan_item_t vxlan[2];
} dpdk_flow_items_args_t;

typedef struct
{
  struct rte_flow_action actions[DPDK_MAX_FLOW_ITEMS];

  struct rte_flow_action_mark mark;
  struct rte_flow_action_queue queue;
  struct rte_flow_action_rss rss;
} dpdk_flow_actions_args_t;

#endif /* __DPDK_FLOW_H__ */

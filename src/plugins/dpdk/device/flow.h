/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __DPDK_FLOW_H__
#define __DPDK_FLOW_H__

#include <rte_flow.h>

#include <vlib/vlib.h>
#include <vxlan/vxlan_packet.h>
#include <vnet/flow/flow.h>

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
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];

  struct rte_flow_action_mark mark;
  struct rte_flow_action_queue queue;
  struct rte_flow_action_rss rss;
} dpdk_flow_actions_args_t;

typedef struct
{
  u32 flow_index;
  u32 mark;
  struct rte_flow *handle;
} dpdk_flow_entry_t;

/* Per-queue slot ring — tracks which slot to use next */
typedef struct
{
  struct rte_flow_op_result *results; /* store results of operation pushed in the queue */
  u8 *slots;			      /* pointer to this queue's region within slot_pool */
  u32 push_counter;		      /* how many time this queue has been pushed */
  u32 slot_size;		      /* cache-line aligned */
  u32 in_slot_actions_offset;	      /* offset to get to actions in a slot */
  u16 head;			      /* next slot index (wraps mod slots_per_queue) */
  u16 enqueued;			      /* number of slots currently used */
  u16 batch_size;		      /* number of slots to use before pushing */
  u16 n_slots;			      /* number of slots */
  u16 id;			      /* queue id */
} dpdk_flow_async_queue_t;

typedef struct
{
  struct rte_flow_actions_template *actions_handle;
  struct rte_flow_pattern_template *pattern_handle;
  struct rte_flow_template_table *table_handle;
} dpdk_flow_template_table_t;

typedef struct
{
  dpdk_flow_template_table_t table;
  u8 *slot_pool;		      /* flat buffer pool for all slots */
  u8 *shared_masks;		      /* shared item mask data (one copy for all slots) */
  struct rte_flow_op_result *results; /* results pool for all queues */
  u32 in_slot_actions_offset;
  u32 slot_size;
  u8 n_items;
  u8 n_actions;
  vnet_flow_type_t template_type;
} dpdk_flow_template_entry_t;

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} dpdk_flow_lookup_entry_t;

int dpdk_flow_async_template_table_create (
  int port_id, struct rte_flow_template_table_attr *template_attr, struct rte_flow_item *pattern,
  struct rte_flow_action *actions_conf, struct rte_flow_action *actions_mask,
  dpdk_flow_template_table_t *table, struct rte_flow_error *error);
int dpdk_flow_async_template_table_destroy (int port_id, dpdk_flow_template_table_t *table,
					    struct rte_flow_error *error);
#endif /* __DPDK_FLOW_H__ */

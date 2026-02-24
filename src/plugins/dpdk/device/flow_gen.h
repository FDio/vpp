/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __FLOW_GEN_H__
#define __FLOW_GEN_H__

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <dpdk/device/dpdk.h>

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

void dpdk_flow_template_populate_fns (vnet_flow_t *t, dpdk_flow_template_entry_t *fte);
int dpdk_flow_fill_items (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			  struct rte_flow_item *items);
int dpdk_flow_fill_actions (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			    struct rte_flow_action *actions);
int dpdk_flow_fill_items_template (dpdk_device_t *xd, vnet_flow_t *t,
				   dpdk_flow_template_entry_t *fte, struct rte_flow_item *items);
int dpdk_flow_fill_actions_template (dpdk_device_t *xd, vnet_flow_t *t,
				     dpdk_flow_template_entry_t *fte,
				     struct rte_flow_action *actions,
				     struct rte_flow_action *masks);
#endif /* __FLOW_GEN_H__ */

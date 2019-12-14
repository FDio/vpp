/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_vnet_flow_flow_h
#define included_vnet_flow_flow_h

#include <vppinfra/clib.h>
#include <vppinfra/pcap.h>
#include <vnet/l3_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/packet.h>

#define foreach_flow_type \
  /* l2 flow*/ \
  _(ETHERNET, ethernet, "ethernet") \
  /* l4 flow*/ \
  _(IP4_N_TUPLE, ip4_n_tuple, "ipv4-n-tuple") \
  _(IP6_N_TUPLE, ip6_n_tuple, "ipv6-n-tuple") \
  /* L4 tunnel flow*/ \
  _(IP4_VXLAN, ip4_vxlan, "ipv4-vxlan") \
  _(IP6_VXLAN, ip6_vxlan, "ipv6-vxlan") \
  _(IP4_GTPC, ip4_gtpc, "ipv4-gtpc") \
  _(IP4_GTPU, ip4_gtpu, "ipv4-gtpu") \
  _(IP4_GTPU_IP4, ip4_gtpu_ip4, "ipv4-gtpu-ipv4") \
  _(IP4_GTPU_IP6, ip4_gtpu_ip6, "ipv4-gtpu-ipv6") \
  _(IP6_GTPC, ip6_gtpc, "ipv6-gtpc") \
  _(IP6_GTPU, ip6_gtpu, "ipv6-gtpu") \
  _(IP6_GTPU_IP4, ip6_gtpu_ip4, "ipv6-gtpu-ipv4") \
  _(IP6_GTPU_IP6, ip6_gtpu_ip6, "ipv6-gtpu-ipv6")

#define foreach_flow_entry_ethernet \
  _fe(ethernet_header_t, eth_hdr)

#define foreach_flow_entry_ip4_n_tuple \
  _fe(ip4_address_and_mask_t, src_addr) \
  _fe(ip4_address_and_mask_t, dst_addr) \
  _fe(ip_port_and_mask_t, src_port) \
  _fe(ip_port_and_mask_t, dst_port) \
  _fe(ip_protocol_t, protocol)

#define foreach_flow_entry_ip6_n_tuple \
  _fe(ip6_address_and_mask_t, src_addr) \
  _fe(ip6_address_and_mask_t, dst_addr) \
  _fe(ip_port_and_mask_t, src_port) \
  _fe(ip_port_and_mask_t, dst_port) \
  _fe(ip_protocol_t, protocol)

#define foreach_flow_entry_ip4_vxlan \
  _fe(ip4_address_t, src_addr) \
  _fe(ip4_address_t, dst_addr) \
  _fe(u16, dst_port) \
  _fe(u16, vni)

#define foreach_flow_entry_ip6_vxlan \
  _fe(ip6_address_t, src_addr) \
  _fe(ip6_address_t, dst_addr) \
  _fe(u16, dst_port) \
  _fe(u16, vni)

#define foreach_flow_entry_ip4_gtpc \
  foreach_flow_entry_ip4_n_tuple \
  _fe(u32, teid)

#define foreach_flow_entry_ip4_gtpu \
  foreach_flow_entry_ip4_n_tuple \
  _fe(u32, teid)

#define foreach_flow_entry_ip4_gtpu_ip4 \
  foreach_flow_entry_ip4_gtpu \
  _fe(ip4_address_and_mask_t, inner_src_addr) \
  _fe(ip4_address_and_mask_t, inner_dst_addr)

#define foreach_flow_entry_ip4_gtpu_ip6 \
  foreach_flow_entry_ip4_gtpu \
  _fe(ip6_address_and_mask_t, inner_src_addr) \
  _fe(ip6_address_and_mask_t, inner_dst_addr)

#define foreach_flow_entry_ip6_gtpc \
  foreach_flow_entry_ip6_n_tuple \
  _fe(u32, teid)

#define foreach_flow_entry_ip6_gtpu \
  foreach_flow_entry_ip6_n_tuple \
  _fe(u32, teid)

#define foreach_flow_entry_ip6_gtpu_ip4 \
  foreach_flow_entry_ip6_gtpu \
  _fe(ip4_address_and_mask_t, inner_src_addr) \
  _fe(ip4_address_and_mask_t, inner_dst_addr)

#define foreach_flow_entry_ip6_gtpu_ip6 \
  foreach_flow_entry_ip6_gtpu \
  _fe(ip6_address_and_mask_t, inner_src_addr) \
  _fe(ip6_address_and_mask_t, inner_dst_addr)

#define foreach_flow_action \
  _(0, COUNT, "count") \
  _(1, MARK, "mark") \
  _(2, BUFFER_ADVANCE, "buffer-advance") \
  _(3, REDIRECT_TO_NODE, "redirect-to-node") \
  _(4, REDIRECT_TO_QUEUE, "redirect-to-queue") \
  _(5, DROP, "drop")

typedef enum
{
#define _(v,n,s)  VNET_FLOW_ACTION_##n = (1 << v),
  foreach_flow_action
#undef _
} vnet_flow_action_t;


#define foreach_flow_error \
  _( -1, NOT_SUPPORTED, "not supported")			\
  _( -2, ALREADY_DONE, "already done")				\
  _( -3, ALREADY_EXISTS, "already exists")			\
  _( -4, NO_SUCH_ENTRY, "no such entry")			\
  _( -5, NO_SUCH_INTERFACE, "no such interface")		\
  _( -6, INTERNAL, "internal error")

typedef enum
{
  VNET_FLOW_NO_ERROR = 0,
#define _(v,n,s)  VNET_FLOW_ERROR_##n = v,
  foreach_flow_error
#undef _
} vnet_flow_error_t;

typedef struct
{
  u16 port, mask;
} ip_port_and_mask_t;

typedef enum
{
  VNET_FLOW_TYPE_UNKNOWN,
#define _(a,b,c) VNET_FLOW_TYPE_##a,
  foreach_flow_type
#undef _
    VNET_FLOW_N_TYPES,
} vnet_flow_type_t;


/*
 * Create typedef struct vnet_flow_XXX_t
 */
#define _fe(a, b) a b;
#define _(a,b,c) \
typedef struct { \
int foo; \
foreach_flow_entry_##b \
} vnet_flow_##b##_t;
foreach_flow_type;
#undef _
#undef _fe

/* main flow struct */
typedef struct
{
  /* flow type */
  vnet_flow_type_t type;

  /* flow index */
  u32 index;

  /* bitmap of flow actions (VNET_FLOW_ACTION_*) */
  u32 actions;

  /* flow id for VNET_FLOW_ACTION_MARK */
  u32 mark_flow_id;

  /* node index and next index for VNET_FLOW_ACTION_REDIRECT_TO_NODE */
  u32 redirect_node_index;
  u32 redirect_device_input_next_index;

  /* queue for VNET_FLOW_ACTION_REDIRECT_TO_QUEUE */
  u32 redirect_queue;

  /* buffer offset for VNET_FLOW_ACTION_BUFFER_ADVANCE */
  i32 buffer_advance;

  union
  {
#define _(a,b,c) vnet_flow_##b##_t b;
    foreach_flow_type
#undef _
  };

  /* per-interface private data */
  uword *private_data;
} vnet_flow_t;

int vnet_flow_get_range (vnet_main_t * vnm, char *owner, u32 count,
			 u32 * start);
int vnet_flow_add (vnet_main_t * vnm, vnet_flow_t * flow, u32 * flow_index);
int vnet_flow_enable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index);
int vnet_flow_disable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index);
int vnet_flow_del (vnet_main_t * vnm, u32 flow_index);
vnet_flow_t *vnet_get_flow (u32 flow_index);

typedef struct
{
  u32 start;
  u32 count;
  u8 *owner;
} vnet_flow_range_t;

typedef struct
{
  /* pool of device flow entries */
  vnet_flow_t *global_flow_pool;

  /* flow ids allocated */
  u32 flows_used;

  /* vector of flow ranges */
  vnet_flow_range_t *ranges;

} vnet_flow_main_t;

extern vnet_flow_main_t flow_main;

format_function_t format_flow_actions;
format_function_t format_flow_enabled_hw;

#endif /* included_vnet_flow_flow_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

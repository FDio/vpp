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
#include <vnet/unix/pcap.h>
#include <vnet/l3_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#define foreach_flow_type \
  _(IP4_5TUPLE, ip4_5tuple, "ipv4-5tuple") \
  _(IP6_5TUPLE, ip6_5tuple, "ipv4-5tuple") \
  _(IP4_VXLAN, ip4_vxlan, "ipv4-vxlan") \
  _(IP6_VXLAN, ip6_vxlan, "ipv6-vxlan")

#define foreach_flow_entry_ip4_5tuple \
  _fe(ip4_address_t, src_addr) \
  _fe(ip4_address_t, src_addr_mask) \
  _fe(ip4_address_t, dst_addr) \
  _fe(ip4_address_t, dst_addr_mask) \
  _fe(u16, src_port) \
  _fe(u16, src_port_mask) \
  _fe(u16, dst_port) \
  _fe(u16, dst_port_mask) \
  _fe(ip_protocol_t, protocol)

#define foreach_flow_entry_ip6_5tuple \
  _fe(ip6_address_t, src_addr) \
  _fe(ip6_address_t, src_addr_mask) \
  _fe(ip6_address_t, dst_addr) \
  _fe(ip6_address_t, dst_addr_mask) \
  _fe(u16, src_port) \
  _fe(u16, src_port_mask) \
  _fe(u16, dst_port) \
  _fe(u16, dst_port_mask) \
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

typedef enum
{
  VNET_FLOW_TYPE_UNKNOWN,
#define _(a,b,c) VNET_FLOW_TYPE_##a,
  foreach_flow_type
#undef _
    VNET_FLOW_N_TYPES,
} vnet_flow_type_t;

typedef enum
{
  VNET_FLOW_INTERFACE_ADD_FLOW,
  VNET_FLOW_INTERFACE_DEL_FLOW,
} vnet_flow_interface_action_t;

typedef enum
{
  VNET_FLOW_NO_ERROR = 0,
  VNET_FLOW_ERROR_NOT_SUPPORTED = -1,
  VNET_FLOW_ERROR_ALREADY_DONE = -2,
  VNET_FLOW_ERROR_NO_SUCH_ENTRY = -3,
  VNET_FLOW_ERROR_INTERNAL = -4,
} vnet_flow_error_t;

/*
 * Create typedef struct vnet_flow_XXX_t
 */
#define _fe(a, b) a b;
#define _(a,b,c) \
typedef struct { \
int foo; \
foreach_flow_entry_##b \
} vnet_flow_##b##_t;
foreach_flow_type
#undef _
#undef _fe

typedef struct
{
  vnet_flow_type_t type;
  u32 id;
  union
  {
#define _(a,b,c) vnet_flow_##b##_t b;
    foreach_flow_type
#undef _
  };

  /* bitmap of hw_if_index where flow is enabled */
  clib_bitmap_t *hw_if_bmp;
} vnet_flow_t;

typedef int (vnet_flow_interface_cb_t) (vnet_flow_interface_action_t action,
					vnet_flow_t * flow, u32 hw_if_index);

typedef struct
{
  /* callback registered by driver */
  vnet_flow_interface_cb_t *callback;

  /* format function for driver specific data */
  format_function_t *format_interface_flow;
} vnet_flow_hw_if_t;

u32 vnet_flow_request_range (u32 n_entries);
int vnet_flow_add (vnet_flow_t * flow);
int vnet_flow_enable (u32 flow_id, u32 hw_if_index);
int vnet_flow_disable (u32 flow_id, u32 hw_if_index);
int vnet_flow_del (u32 flow_id);
int vnet_flow_register_cb (u32 hw_if_index, vnet_flow_interface_cb_t * fn);

typedef struct
{
  /* pool of device flow entries */
  vnet_flow_t *global_flow_pool;

  /* hash */
  uword *global_flow_pool_index_by_flow_id;

  /* per hw_if_index data */
  vnet_flow_hw_if_t *interfaces;

  /* flow ids allocated */
  u32 flows_used;

} vnet_flow_main_t;

extern vnet_flow_main_t flow_main;

#endif /* included_vnet_flow_flow_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

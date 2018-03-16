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

#ifndef included_vnet_devices_flow_h
#define included_vnet_devices_flow_h

#include <vppinfra/clib.h>
#include <vnet/unix/pcap.h>
#include <vnet/l3_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#define foreach_device_flow_type \
  _(IP4_5TUPLE, ip4_5tuple, "ipv4-5tuple") \
  _(IP6_5TUPLE, ip6_5tuple, "ipv4-5tuple") \
  _(IP4_VXLAN, ip4_vxlan, "ipv4-vxlan") \
  _(IP6_VXLAN, ip6_vxlan, "ipv6-vxlan")

#define foreach_device_flow_entry_ip4_5tuple \
  _fe(ip4_address_t, src_addr) \
  _fe(ip4_address_t, dst_addr) \
  _fe(u16, src_port) \
  _fe(u16, dst_port) \
  _fe(u16, protocol)

#define foreach_device_flow_entry_ip6_5tuple \
  _fe(ip6_address_t, src_addr) \
  _fe(ip6_address_t, dst_addr) \
  _fe(u16, src_port) \
  _fe(u16, dst_port) \
  _fe(u16, protocol)

#define foreach_device_flow_entry_ip4_vxlan \
  _fe(ip4_address_t, src_addr) \
  _fe(ip4_address_t, dst_addr) \
  _fe(u16, src_port) \
  _fe(u16, dst_port) \
  _fe(u16, vni)

#define foreach_device_flow_entry_ip6_vxlan \
  _fe(ip6_address_t, src_addr) \
  _fe(ip6_address_t, dst_addr) \
  _fe(u16, src_port) \
  _fe(u16, dst_port) \
  _fe(u16, vni)

typedef enum
{
  VNET_DEVICE_FLOW_TYPE_UNKNOWN,
#define _(a,b,c) VNET_DEVICE_FLOW_TYPE_##a,
  foreach_device_flow_type
#undef _
    VNET_DEVICE_FLOW_N_TYPES,
} vnet_device_flow_type_t;

typedef enum
{
  VNET_DEVICE_FLOW_ADD,
  VNET_DEVICE_FLOW_DEL,
} vnet_device_flow_action_t;

/*
 * Create typedef struct vnet_device_flow_XXX_t
 */
#define _fe(a, b) a b;
#define _(a,b,c) \
typedef struct { \
int foo; \
foreach_device_flow_entry_##b \
} vnet_device_flow_##b##_t;
foreach_device_flow_type
#undef _
#undef _fe

typedef struct
{
  vnet_device_flow_type_t type;
  u32 id;
  union
  {
#define _(a,b,c) vnet_device_flow_##b##_t b;
    foreach_device_flow_type
#undef _
  };

  /* private data */

  /* bitmap of hw_if_index where flow is enabled */
  clib_bitmap_t *hw_if_bmp;
} vnet_device_flow_t;

typedef void (vnet_device_flow_cb_t) (vnet_device_flow_action_t action,
				      vnet_device_flow_t * flow,
				      u32 hW_if_index, u32 local_flow_index);

typedef struct
{
  /* callback registered by driver */
  vnet_device_flow_cb_t *callback;

  /* pool of local interfaces */
  u32 *flows;

  /* hash */
  uword *flow_index_by_flow_id;
} vnet_device_flow_hw_if_t;

u32 vnet_device_flow_request_range (u32 n_entries);
void vnet_device_flow_add (vnet_device_flow_t * flow);
void vnet_device_flow_enable (u32 flow_id, u32 hw_if_index);
void vnet_device_flow_disable (u32 flow_id, u32 hw_if_index);
void vnet_device_flow_del (u32 flow_id);
void vnet_device_flow_register_cb (u32 hw_if_index,
				   vnet_device_flow_cb_t * fn);

#endif /* included_vnet_devices_flow_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

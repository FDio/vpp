/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _VNET_DEVICES_VIRTIO_TAP_H_
#define _VNET_DEVICES_VIRTIO_TAP_H_

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

#define foreach_tapv2_flags  \
  _ (GSO, 0)                 \
  _ (CSUM_OFFLOAD, 1)        \
  _ (PERSIST, 2)             \
  _ (ATTACH, 3)              \
  _ (TUN, 4)                 \
  _ (GRO_COALESCE, 5)

typedef enum
{
#define _(a, b) TAP_FLAG_##a = (1 << b),
  foreach_tapv2_flags
#undef _
} tap_flag_t;

typedef struct
{
  u32 id;
  u8 mac_addr_set;
  mac_address_t mac_addr;
  u8 num_rx_queues;
  u16 rx_ring_sz;
  u16 tx_ring_sz;
  u32 tap_flags;
  u8 *host_namespace;
  u8 *host_if_name;
  mac_address_t host_mac_addr;
  u8 *host_bridge;
  ip4_address_t host_ip4_addr;
  u8 host_ip4_prefix_len;
  ip4_address_t host_ip4_gw;
  u8 host_ip4_gw_set;
  ip6_address_t host_ip6_addr;
  u8 host_ip6_prefix_len;
  ip6_address_t host_ip6_gw;
  u8 host_ip6_gw_set;
  u8 host_mtu_set;
  u32 host_mtu_size;
  /* return */
  u32 sw_if_index;
  int rv;
  clib_error_t *error;
} tap_create_if_args_t;

/** TAP interface details struct */
typedef struct
{
  u32 id;
  u32 sw_if_index;
  u32 tap_flags;
  u8 dev_name[64];
  u16 tx_ring_sz;
  u16 rx_ring_sz;
  mac_address_t host_mac_addr;
  u8 host_if_name[64];
  u8 host_namespace[64];
  u8 host_bridge[64];
  ip4_address_t host_ip4_addr;
  u8 host_ip4_prefix_len;
  ip6_address_t host_ip6_addr;
  u8 host_ip6_prefix_len;
  u32 host_mtu_size;
} tap_interface_details_t;

typedef struct
{
  /* logging */
  vlib_log_class_t log_default;

  /* bit-map of in-use IDs */
  uword *tap_ids;

  /* host mtu size, configurable through startup.conf */
  int host_mtu_size;
} tap_main_t;

void tap_create_if (vlib_main_t * vm, tap_create_if_args_t * args);
int tap_delete_if (vlib_main_t * vm, u32 sw_if_index);
int tap_gso_enable_disable (vlib_main_t * vm, u32 sw_if_index,
			    int enable_disable);
int
tap_csum_offload_enable_disable (vlib_main_t * vm, u32 sw_if_index,
				 int enable_disable);
int tap_dump_ifs (tap_interface_details_t ** out_tapids);

#endif /* _VNET_DEVICES_VIRTIO_TAP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

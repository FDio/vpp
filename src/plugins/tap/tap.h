/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2025 Cisco and/or its affiliates.
 */
#pragma once

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/error.h>

#define foreach_tapv2_flags                                                   \
  _ (GSO, 0)                                                                  \
  _ (CSUM_OFFLOAD, 1)                                                         \
  _ (PERSIST, 2)                                                              \
  _ (ATTACH, 3)                                                               \
  _ (TUN, 4)                                                                  \
  _ (GRO_COALESCE, 5)                                                         \
  _ (PACKED, 6)                                                               \
  _ (IN_ORDER, 7)                                                             \
  _ (CONSISTENT_QP, 8)

typedef enum
{
#define _(a, b) TAP_FLAG_##a = (1 << b),
  foreach_tapv2_flags
#undef _
} tap_flag_t;

typedef struct
{
  u32 id;
  u32 auto_id_offset;
  u8 mac_addr_set;
  mac_address_t mac_addr;
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rx_ring_sz;
  u16 tx_ring_sz;
  tap_flag_t tap_flags;
  u8 *host_namespace;
  u8 *if_name;
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

typedef void (tap_create_if_fn_t) (vlib_main_t *vm,
				   tap_create_if_args_t *args);
typedef int (tap_delete_if_fn_t) (vlib_main_t *vm, u32 sw_if_index);
typedef int (tap_set_carrier_fn_t) (u32 hw_if_index, u32 carrier_up);
typedef int (tap_set_speed_fn_t) (u32 hw_if_index, u32 speed);
typedef unsigned int (tap_get_ifindex_fn_t) (vlib_main_t *vm, u32 sw_if_index);
typedef int (tap_is_tun_fn_t) (vlib_main_t *vm, u32 sw_if_index);

#ifdef TAP_PLUGIN_INTERNAL

tap_create_if_fn_t tap_create_if;
tap_delete_if_fn_t tap_delete_if;
tap_set_carrier_fn_t tap_set_carrier;
tap_set_speed_fn_t tap_set_speed;
tap_get_ifindex_fn_t tap_get_ifindex;
tap_is_tun_fn_t tap_is_tun;

#else /* TAP_PLUGIN_INTERNAL */

static inline void
tap_create_if (vlib_main_t *vm, tap_create_if_args_t *args)
{
  tap_create_if_fn_t *fn = (tap_create_if_fn_t *) vlib_get_plugin_symbol (
    "tap_plugin.so", "tap_create_if");
  if (!fn)
    {
      args->error = clib_error_return (0, "tap plugin not loaded");
      return;
    }
  fn (vm, args);
}

static inline int
tap_delete_if (vlib_main_t *vm, u32 sw_if_index)
{
  tap_delete_if_fn_t *fn = (tap_delete_if_fn_t *) vlib_get_plugin_symbol (
    "tap_plugin.so", "tap_delete_if");
  if (!fn)
    return -1;
  return fn (vm, sw_if_index);
}

static inline int
tap_set_carrier (u32 hw_if_index, u32 carrier_up)
{
  tap_set_carrier_fn_t *fn = (tap_set_carrier_fn_t *) vlib_get_plugin_symbol (
    "tap_plugin.so", "tap_set_carrier");
  if (!fn)
    return -1;
  return fn (hw_if_index, carrier_up);
}

static inline int
tap_set_speed (u32 hw_if_index, u32 speed)
{
  tap_set_speed_fn_t *fn = (tap_set_speed_fn_t *) vlib_get_plugin_symbol (
    "tap_plugin.so", "tap_set_speed");
  if (!fn)
    return -1;
  return fn (hw_if_index, speed);
}

static inline unsigned int
tap_get_ifindex (vlib_main_t *vm, u32 sw_if_index)
{
  tap_get_ifindex_fn_t *fn = (tap_get_ifindex_fn_t *) vlib_get_plugin_symbol (
    "tap_plugin.so", "tap_get_ifindex");
  if (!fn)
    return ~0;
  return fn (vm, sw_if_index);
}

static inline int
tap_is_tun (vlib_main_t *vm, u32 sw_if_index)
{
  tap_is_tun_fn_t *fn =
    (tap_is_tun_fn_t *) vlib_get_plugin_symbol ("tap_plugin.so", "tap_is_tun");
  if (!fn)
    return 0;
  return fn (vm, sw_if_index);
}

#endif /* TAP_PLUGIN_INTERNAL */

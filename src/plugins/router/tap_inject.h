/*
 * Copyright 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _TAP_INJECT_H
#define _TAP_INJECT_H

#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

typedef struct {
  /*
   * tap-inject can be enabled or disabled in config file or during runtime.
   * When disabled in config, it is not possible to enable during runtime.
   *
   * When the netlink-only option is used, netlink configuration is monitored
   * and mirrored to the data plane but no traffic is passed between the host
   * and the data plane.
   */
#define TAP_INJECT_F_CONFIG_ENABLE  (1U << 0)
#define TAP_INJECT_F_CONFIG_DISABLE (1U << 1)
#define TAP_INJECT_F_CONFIG_NETLINK (1U << 2)
#define TAP_INJECT_F_ENABLED        (1U << 3)

  u32 flags;

  u32 * sw_if_index_to_tap_fd;
  u32 * sw_if_index_to_tap_if_index;
  u32 * tap_fd_to_sw_if_index;
  u32 * tap_if_index_to_sw_if_index;

  u32 * interfaces_to_enable;
  u32 * interfaces_to_disable;

  u32 * rx_file_descriptors;

  u32 rx_node_index;
  u32 tx_node_index;
  u32 neighbor_node_index;

  u32 * rx_buffers;

} tap_inject_main_t;


tap_inject_main_t * tap_inject_get_main (void);

void tap_inject_insert_tap (u32 sw_if_index, u32 tap_fd, u32 tap_if_index);
void tap_inject_delete_tap (u32 sw_if_index);

u32 tap_inject_lookup_tap_fd (u32 sw_if_index);
u32 tap_inject_lookup_sw_if_index_from_tap_fd (u32 tap_fd);
u32 tap_inject_lookup_sw_if_index_from_tap_if_index (u32 tap_if_index);

static inline int
tap_inject_is_enabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_ENABLED);
}

static inline int
tap_inject_is_config_enabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_CONFIG_ENABLE);
}

static inline int
tap_inject_is_config_disabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_CONFIG_DISABLE);
}


/* Netlink */

void tap_inject_enable_netlink (void);


/* Tap */

clib_error_t * tap_inject_tap_connect (vnet_hw_interface_t * hw);
clib_error_t * tap_inject_tap_disconnect (u32 sw_if_index);

u8 * format_tap_inject_tap_name (u8 * s, va_list * args);

#endif /* _TAP_INJECT_H */

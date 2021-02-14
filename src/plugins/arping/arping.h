/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef included_arping_arping_h
#define included_arping_arping_h

#include <vnet/ip/ip_types.h>
#include <vnet/ethernet/arp_packet.h>

#define ARPING_DEFAULT_INTERVAL 1.0
#define ARPING_DEFAULT_REPEAT	1

typedef struct arping6_ip6_reply_t
{
  mac_address_t mac;
  ip6_address_t ip6;
} arping6_ip6_reply_t;

typedef CLIB_PACKED (union arping46_reply_ {
  ethernet_arp_ip4_over_ethernet_address_t from4;
  arping6_ip6_reply_t from6;
}) arping46_reply_t;

typedef struct arping_intf_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 interval;
  u32 repeat;
  ip_address_t address;

  arping46_reply_t recv;
  u32 reply_count;
} arping_intf_t;

typedef struct arping_main_t
{
  arping_intf_t *arping_interfaces;
  arping_intf_t **interfaces;
  u16 msg_id_base;
} arping_main_t;

typedef struct arping_args_t
{
  ip_address_t address;
  u32 sw_if_index;
  u32 repeat;
  u64 interval;
  u8 is_garp;
  u8 silence;

  /* reply */
  i32 rv;
  u32 reply_count;
  arping46_reply_t recv;
  clib_error_t *error;
} arping_args_t;

extern arping_main_t arping_main;

extern clib_error_t *arping_plugin_api_hookup (vlib_main_t *vm);
extern void arping_run_command (vlib_main_t *vm, arping_args_t *args);

#endif /* included_arping_arping_h */

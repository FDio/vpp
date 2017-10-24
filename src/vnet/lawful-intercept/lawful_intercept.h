/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __lawful_intercept_h__
#define __lawful_intercept_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

typedef struct {
  /* LI collector info */
  ip4_address_t * src_addrs;
  ip4_address_t * collectors;
  u16 * ports;

  /* Hit node index */
  u32 hit_node_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} li_main_t;

extern li_main_t li_main;

typedef CLIB_PACKED(struct {
  ip4_header_t ip4;
  udp_header_t udp;
}) ip4_udp_header_t;

extern vlib_node_registration_t li_hit_node;

#endif /* __lawful_intercept_h__ */

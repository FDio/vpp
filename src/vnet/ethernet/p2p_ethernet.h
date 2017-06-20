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
#ifndef included_vnet_p2p_ethernet_h
#define included_vnet_p2p_ethernet_h

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>


typedef struct {
  /**
   * Hash mapping parent sw_if_index and client mac address to p2p_ethernet sub-interface
   */
  uword * p2p_ethernet_by_key;

  u32 *p2p_ethernet_by_sw_if_index;

  // Pool of p2p subifs;
  subint_config_t *p2p_subif_pool;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} p2p_ethernet_main_t;

extern p2p_ethernet_main_t p2p_main;

typedef struct
{
  u32 sw_if_index;
  u32 p2pe_sw_if_index;
  u8  client_mac[6];
} p2p_ethernet_trace_t;

/**
 * @brief Key struct for P2P Ethernet
 * Key fields: parent sw_if_index and client mac address
 * all fields in NET byte order
 */

typedef struct {
  u8 mac[6];
  u16 pad1;         // padding for u64 mac address
  u32 hw_if_index;
  u32 pad2;         // padding for u64
} p2p_key_t;

u32 p2p_ethernet_lookup (u32 parent_sw_if_index, u8* client_mac);
int p2p_ethernet_add_del (vlib_main_t * vm, u32 parent_if_index, u8 * client_mac, u32 sub_id, int is_add, u32 *p2pe_if_index);

#endif /* included_vnet_p2p_ethernet_h */

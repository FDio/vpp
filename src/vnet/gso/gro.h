/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_gro_h
#define included_gro_h

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>



typedef union
{
  struct
  {
    mac_address_t saddr;
    mac_address_t daddr;
    ip4_address_pair_t address_pair;
    u16 src_port;
    u16 dst_port;
    u32 ack_number;
  };
  struct
  {
    u64 flow_data[4];
    u32 flow_data_32;
  };
} gro_ip4_flow_key_t;

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;
} gro_main_t;

extern gro_main_t gro_main;

int vnet_sw_interface_gro_enable_disable (u32 sw_if_index, u8 enable);

#endif /* included_gro_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

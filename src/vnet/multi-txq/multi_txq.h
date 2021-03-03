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

#ifndef included_multi_txq_h
#define included_multi_txq_h

#include <vnet/vnet.h>
#include <vnet/ip/ip46_address.h>

typedef union
{
  struct
  {
    u32 sw_if_index[VLIB_N_RX_TX];
    ip46_address_t src_address;
    ip46_address_t dst_address;
    u16 src_port;
    u16 dst_port;
  };

  u8 as_u8[44];
} multi_txq_key_t;

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;
} multi_txq_main_t;

extern multi_txq_main_t multi_txq_main;
extern vlib_node_registration_t multi_txq_node;
int vnet_sw_interface_multi_txq_enable_disable (u32 sw_if_index, u32 num_txqs,
						u8 enable);

#endif /* included_multi_txq_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

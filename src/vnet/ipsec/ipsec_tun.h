/*
 * ipsec_tun.h : IPSEC tunnel protection
 *
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

#include <vnet/ipsec/ipsec.h>

typedef enum ipsec_tun_dir_t_
{
  IPSEC_TUN_DIR_INBOUND,
  IPSEC_TUN_DIR_OUTBOUND,
} ipsec_tun_dir_t;

#define IPSEC_TUN_N_DIR 2

typedef struct ipsec_tun_t_
{
  u32 sa[IPSEC_TUN_N_DIR];

  u32 sw_if_index;

  ip46_address_t src;
  ip46_address_t dst;
  u32 decap_node_index;
} ipsec_tun_t;


extern int ipsec_tun_protect_update(u32 sw_if_index,
                                    u32 sa_in,
                                    u32 sa_out);

extern vlib_node_registration_t ipsec_tun_protect_node;

extern ipsec_tun_t *ipsec_tun_pool;
always_inline ipsec_tun_t* ipsec_tun_get(u32 index)
{
  return (pool_elt_at_index(ipsec_tun_pool, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

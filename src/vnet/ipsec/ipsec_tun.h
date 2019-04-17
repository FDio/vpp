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

typedef enum ipsec_protect_dir_t_
{
  IPSEC_PROTECT_DIR_INBOUND,
  IPSEC_PROTECT_DIR_OUTBOUND,
} ipsec_protect_dir_t;

#define IPSEC_PROTECT_N_DIR 2

typedef enum ipsec_protect_flags_t_
{
  IPSEC_PROTECT_TUN = (1 << 0),
} ipsec_protect_flags_t;

typedef struct ipsec_protect_t_
{
  u32 it_sa[IPSEC_PROTECT_N_DIR];

  u32 it_sw_if_index;

  ipsec_protect_flags_t it_flags;
  ip46_address_t it_tun_src;
  ip46_address_t it_tun_dst;
  ip46_address_t it_crypto_src;
  ip46_address_t it_crypto_dst;
  u32 it_decap_node_index;
  u32 it_edge;
} ipsec_protect_t;


extern int ipsec_tun_protect_update (u32 sw_if_index, u32 sa_in, u32 sa_out);

extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

extern ipsec_protect_t *ipsec_protect_pool;

always_inline ipsec_protect_t *
ipsec_protect_get (u32 index)
{
  return (pool_elt_at_index (ipsec_protect_pool, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

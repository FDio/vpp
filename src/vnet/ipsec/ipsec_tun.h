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

typedef enum direction_t_
{
  INBOUND = 0,
  INGRESS = INBOUND,
  INPUT = INBOUND,
  OUTBOUND = 1,
  OUTPUT = OUTBOUND,
  EGRESS = OUTBOUND,
} direction_t;

#define N_DIRECTIONS 2

typedef enum ipsec_protect_flags_t_
{
  IPSEC_PROTECT_TUN = (1 << 0),
} ipsec_protect_flags_t;

typedef struct ipsec_ep_t_
{
  ip46_address_t src;
  ip46_address_t dst;
} ipsec_ep_t;

typedef struct ipsec_protect_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 itp_sa[N_DIRECTIONS];

  u32 itp_sw_if_index;
  u32 itp_edge;

  ipsec_ep_t itp_crypto;

  ipsec_protect_flags_t itp_flags;

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  ipsec_ep_t itp_tun;
  u32 itp_decap_node_index;
} ipsec_protect_t;

STATIC_ASSERT_OFFSET_OF (ipsec_protect_t, itp_tun, CLIB_CACHE_LINE_BYTES);

extern int ipsec_tun_protect_update (u32 sw_if_index, u32 sa_in, u32 sa_out);
extern int ipsec_tun_protect_del (u32 sw_if_index);

typedef walk_rc_t (*ipsec_tun_protect_walk_cb_t) (index_t itpi, void *arg);
extern void ipsec_tun_protect_walk (ipsec_tun_protect_walk_cb_t fn,
				    void *cttx);

extern u8 *format_ipsec_tun_protect (u8 * s, va_list * args);

// FIXME
extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

/*
 * DP API
 */
extern ipsec_protect_t *ipsec_protect_pool;

always_inline ipsec_protect_t *
ipsec_tun_protect_get (u32 index)
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

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

typedef enum ipsec_protect_flags_t_
{
  IPSEC_PROTECT_L2 = (1 << 0),
  IPSEC_PROTECT_ENCAPED = (1 << 1),
} __clib_packed ipsec_protect_flags_t;

typedef struct ipsec_ep_t_
{
  ip46_address_t src;
  ip46_address_t dst;
} ipsec_ep_t;

typedef struct ipsec_tun_protect_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  index_t itp_out_sa;

  /* not using a vector since we want the memory inline
   * with this struct */
  u32 itp_n_sa_in;
  index_t itp_in_sas[4];

  u32 itp_sw_if_index;

  ipsec_ep_t itp_crypto;

  ipsec_protect_flags_t itp_flags;

  ipsec_ep_t itp_tun;

} ipsec_tun_protect_t;

#define FOR_EACH_IPSEC_PROTECT_INPUT_SAI(_itp, _sai, body) \
{                                                          \
  u32 __ii;                                                \
  for (__ii = 0; __ii < _itp->itp_n_sa_in; __ii++) {       \
    _sai = itp->itp_in_sas[__ii];                          \
    body;                                                  \
  }                                                        \
}
#define FOR_EACH_IPSEC_PROTECT_INPUT_SA(_itp, _sa, body)   \
{                                                          \
  u32 __ii;                                                \
  for (__ii = 0; __ii < _itp->itp_n_sa_in; __ii++) {       \
    _sa = ipsec_sa_get(itp->itp_in_sas[__ii]);             \
    body;                                                  \
  }                                                        \
}

extern int ipsec_tun_protect_update (u32 sw_if_index, u32 sa_out,
				     u32 sa_ins[2]);
extern int ipsec_tun_protect_del (u32 sw_if_index);

typedef walk_rc_t (*ipsec_tun_protect_walk_cb_t) (index_t itpi, void *arg);
extern void ipsec_tun_protect_walk (ipsec_tun_protect_walk_cb_t fn,
				    void *cttx);
extern index_t ipsec_tun_protect_find (u32 sw_if_index);

extern u8 *format_ipsec_tun_protect (u8 * s, va_list * args);

// FIXME
extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

/*
 * DP API
 */
extern ipsec_tun_protect_t *ipsec_protect_pool;

typedef struct ipsec_tun_lkup_result_t_
{
  union
  {
    struct
    {
      u32 tun_index;
      u32 sa_index;
    };
    u64 as_u64;
  };
} ipsec_tun_lkup_result_t;

always_inline ipsec_tun_protect_t *
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

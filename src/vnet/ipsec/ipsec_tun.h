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

#define foreach_ipsec_protect_flags \
  _(L2, 1, "l2")                    \
  _(ENCAPED, 2, "encapped")         \
  _(ITF, 4, "itf")                  \

typedef enum ipsec_protect_flags_t_
{
  IPSEC_PROTECT_NONE = 0,
#define _(a,b,c) IPSEC_PROTECT_##a = b,
  foreach_ipsec_protect_flags
#undef _
} __clib_packed ipsec_protect_flags_t;

extern u8 *format_ipsec_tun_protect_flags (u8 * s, va_list * args);

/**
 * result of a lookup in the protection bihash
 */
typedef struct ipsec_tun_lkup_result_t_
{
  u32 tun_index;
  u32 sa_index;
  u32 sw_if_index;
  ipsec_protect_flags_t flags;
  u8 __pad[3];
} ipsec_tun_lkup_result_t;

typedef struct ipsec4_tunnel_kv_t
{
  /*
   * Key fields: remote ip and spi on incoming packet
   * all fields in NET byte order
   */
  u64 key;
  ipsec_tun_lkup_result_t value;
} __clib_packed ipsec4_tunnel_kv_t;

STATIC_ASSERT_SIZEOF (ipsec4_tunnel_kv_t, sizeof (clib_bihash_kv_8_16_t));
STATIC_ASSERT_OFFSET_OF (ipsec4_tunnel_kv_t, value,
			 STRUCT_OFFSET_OF (clib_bihash_kv_8_16_t, value));

static inline void
ipsec4_tunnel_mk_key (ipsec4_tunnel_kv_t * k,
		      const ip4_address_t * ip, u32 spi)
{
  k->key = (((u64) ip->as_u32) << 32 | spi);
}

static inline void
ipsec4_tunnel_extract_key (const ipsec4_tunnel_kv_t * k,
			   ip4_address_t * ip, u32 * spi)
{
  *spi = (u32) k->key;
  (*ip).as_u32 = k->key >> 32;
}

typedef struct ipsec6_tunnel_kv_t_
{
  /*
   * Key fields: remote ip and spi on incoming packet
   * all fields in NET byte order
   */
  struct
  {
    ip6_address_t remote_ip;
    u32 spi;
    u32 __pad;
  } key;
  ipsec_tun_lkup_result_t value;
} __clib_packed ipsec6_tunnel_kv_t;

STATIC_ASSERT_SIZEOF (ipsec6_tunnel_kv_t, sizeof (clib_bihash_kv_24_16_t));
STATIC_ASSERT_OFFSET_OF (ipsec6_tunnel_kv_t, value,
			 STRUCT_OFFSET_OF (clib_bihash_kv_24_16_t, value));

extern u8 *format_ipsec4_tunnel_kv (u8 * s, va_list * args);
extern u8 *format_ipsec6_tunnel_kv (u8 * s, va_list * args);

typedef struct ipsec_ep_t_
{
  ip46_address_t src;
  ip46_address_t dst;
} ipsec_ep_t;

#define ITP_MAX_N_SA_IN 4

typedef struct ipsec_tun_protect_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  index_t itp_out_sa;

  /* not using a vector since we want the memory inline
   * with this struct */
  u32 itp_n_sa_in;
  index_t itp_in_sas[ITP_MAX_N_SA_IN];

  u32 itp_sw_if_index;

  ipsec_ep_t itp_crypto;

  ipsec_protect_flags_t itp_flags;
  adj_index_t itp_ai;

  ipsec_ep_t itp_tun;

  ip_address_t *itp_key;

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

extern int ipsec_tun_protect_update (u32 sw_if_index,
				     const ip_address_t * nh,
				     u32 sa_out, u32 * sa_ins);

extern int ipsec_tun_protect_del (u32 sw_if_index, const ip_address_t * nh);

typedef walk_rc_t (*ipsec_tun_protect_walk_cb_t) (index_t itpi, void *arg);
extern void ipsec_tun_protect_walk (ipsec_tun_protect_walk_cb_t fn,
				    void *cttx);
extern void ipsec_tun_protect_walk_itf (u32 sw_if_index,
					ipsec_tun_protect_walk_cb_t fn,
					void *cttx);

extern u8 *format_ipsec_tun_protect (u8 * s, va_list * args);
extern u8 *format_ipsec_tun_protect_index (u8 * s, va_list * args);

extern void ipsec_tun_register_nodes (ip_address_family_t af);
extern void ipsec_tun_unregister_nodes (ip_address_family_t af);

/*
 * DP API
 */
extern ipsec_tun_protect_t *ipsec_tun_protect_pool;

always_inline ipsec_tun_protect_t *
ipsec_tun_protect_get (u32 index)
{
  return (pool_elt_at_index (ipsec_tun_protect_pool, index));
}

extern index_t *ipsec_tun_protect_sa_by_adj_index;
always_inline index_t
ipsec_tun_protect_get_sa_out (adj_index_t ai)
{
  ASSERT (vec_len (ipsec_tun_protect_sa_by_adj_index) > ai);
  ASSERT (INDEX_INVALID != ipsec_tun_protect_sa_by_adj_index[ai]);

  return (ipsec_tun_protect_sa_by_adj_index[ai]);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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
#ifndef __IPSEC_IF_H__
#define __IPSEC_IF_H__

#include <vnet/ipsec/ipsec_sa.h>

typedef enum
{
  IPSEC_IF_SET_KEY_TYPE_NONE,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG,
} ipsec_if_set_key_type_t;

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 input_sa_index;
  u32 output_sa_index;
  u32 hw_if_index;
  u32 sw_if_index;
  vnet_hw_interface_flags_t flags;
  u32 show_instance;
} ipsec_tunnel_if_t;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u8 esn;
  u8 anti_replay;
  ip46_address_t local_ip, remote_ip;
  u32 local_spi;
  u32 remote_spi;
  ipsec_crypto_alg_t crypto_alg;
  u8 local_crypto_key_len;
  u8 local_crypto_key[128];
  u8 remote_crypto_key_len;
  u8 remote_crypto_key[128];
  ipsec_integ_alg_t integ_alg;
  u8 local_integ_key_len;
  u8 local_integ_key[128];
  u8 remote_integ_key_len;
  u8 remote_integ_key[128];
  u8 renumber;
  u32 show_instance;
  u8 udp_encap;
  u32 tx_table_id;
  u32 salt;
} ipsec_add_del_tunnel_args_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: remote ip and spi on incoming packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 remote_ip;
      u32 spi;
    };
    u64 as_u64;
  };
}) ipsec4_tunnel_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: remote ip and spi on incoming packet
   * all fields in NET byte order
   */
  ip6_address_t remote_ip;
  u32 spi;
}) ipsec6_tunnel_key_t;
/* *INDENT-ON* */

typedef struct
{
  u8 is_add;
  u32 local_sa_id;
  u32 remote_sa_id;
  ip4_address_t src;
  ip4_address_t dst;
} ipsec_gre_tunnel_add_del_args_t;

extern int ipsec_add_del_tunnel_if_internal (vnet_main_t * vnm,
					     ipsec_add_del_tunnel_args_t *
					     args, u32 * sw_if_index);
extern int ipsec_add_del_tunnel_if (ipsec_add_del_tunnel_args_t * args);
extern int ipsec_add_del_ipsec_gre_tunnel (vnet_main_t * vnm,
					   const
					   ipsec_gre_tunnel_add_del_args_t *
					   args);

extern int ipsec_set_interface_key (vnet_main_t * vnm, u32 hw_if_index,
				    ipsec_if_set_key_type_t type,
				    u8 alg, u8 * key);
extern int ipsec_set_interface_sa (vnet_main_t * vnm, u32 hw_if_index,
				   u32 sa_id, u8 is_outbound);

extern u8 *format_ipsec_tunnel (u8 * s, va_list * args);

#endif /* __IPSEC_IF_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

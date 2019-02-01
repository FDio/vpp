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
#ifndef __IPSEC_SPD_SA_H__
#define __IPSEC_SPD_SA_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

#define foreach_ipsec_crypto_alg    \
  _ (0, NONE, "none")               \
  _ (1, AES_CBC_128, "aes-cbc-128") \
  _ (2, AES_CBC_192, "aes-cbc-192") \
  _ (3, AES_CBC_256, "aes-cbc-256") \
  _ (4, AES_CTR_128, "aes-ctr-128") \
  _ (5, AES_CTR_192, "aes-ctr-192") \
  _ (6, AES_CTR_256, "aes-ctr-256") \
  _ (7, AES_GCM_128, "aes-gcm-128") \
  _ (8, AES_GCM_192, "aes-gcm-192") \
  _ (9, AES_GCM_256, "aes-gcm-256") \
  _ (10, DES_CBC, "des-cbc")        \
  _ (11, 3DES_CBC, "3des-cbc")

typedef enum
{
#define _(v, f, s) IPSEC_CRYPTO_ALG_##f = v,
  foreach_ipsec_crypto_alg
#undef _
    IPSEC_CRYPTO_N_ALG,
} ipsec_crypto_alg_t;

#define foreach_ipsec_integ_alg                                            \
  _ (0, NONE, "none")                                                      \
  _ (1, MD5_96, "md5-96")           /* RFC2403 */                          \
  _ (2, SHA1_96, "sha1-96")         /* RFC2404 */                          \
  _ (3, SHA_256_96, "sha-256-96")   /* draft-ietf-ipsec-ciph-sha-256-00 */ \
  _ (4, SHA_256_128, "sha-256-128") /* RFC4868 */                          \
  _ (5, SHA_384_192, "sha-384-192") /* RFC4868 */                          \
  _ (6, SHA_512_256, "sha-512-256")	/* RFC4868 */

typedef enum
{
#define _(v, f, s) IPSEC_INTEG_ALG_##f = v,
  foreach_ipsec_integ_alg
#undef _
    IPSEC_INTEG_N_ALG,
} ipsec_integ_alg_t;

typedef enum
{
  IPSEC_PROTOCOL_AH = 0,
  IPSEC_PROTOCOL_ESP = 1
} ipsec_protocol_t;

typedef struct
{
  u32 id;
  u32 spi;
  ipsec_protocol_t protocol;

  ipsec_crypto_alg_t crypto_alg;
  u8 crypto_key_len;
  u8 crypto_key[128];

  ipsec_integ_alg_t integ_alg;
  u8 integ_key_len;
  u8 integ_key[128];

  u8 use_esn;
  u8 use_anti_replay;

  u8 is_tunnel;
  u8 is_tunnel_ip6;
  u8 udp_encap;
  ip46_address_t tunnel_src_addr;
  ip46_address_t tunnel_dst_addr;

  u32 tx_fib_index;
  u32 salt;

  /* runtime */
  u32 seq;
  u32 seq_hi;
  u32 last_seq;
  u32 last_seq_hi;
  u64 replay_window;

  /* lifetime data */
  u64 total_data_size;
} ipsec_sa_t;

extern int ipsec_add_del_sa (vlib_main_t * vm, ipsec_sa_t * new_sa,
			     int is_add);
extern u8 ipsec_is_sa_used (u32 sa_index);
extern int ipsec_set_sa_key (vlib_main_t * vm, ipsec_sa_t * sa_update);
extern u32 ipsec_get_sa_index_by_sa_id (u32 sa_id);

extern u8 *format_ipsec_crypto_alg (u8 * s, va_list * args);
extern u8 *format_ipsec_integ_alg (u8 * s, va_list * args);
extern uword unformat_ipsec_crypto_alg (unformat_input_t * input,
					va_list * args);
extern uword unformat_ipsec_integ_alg (unformat_input_t * input,
				       va_list * args);

#endif /* __IPSEC_SPD_SA_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

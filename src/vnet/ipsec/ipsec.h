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
#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <vnet/ip/ip.h>
#include <vnet/crypto/crypto.h>
#include <vnet/feature/feature.h>

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_policy.h>

#include <vppinfra/bihash_8_16.h>

#include <vppinfra/bihash_24_16.h>

typedef struct
{
  vnet_crypto_op_id_t enc_op_id;
  vnet_crypto_op_id_t dec_op_id;
  vnet_crypto_alg_t alg;
  u8 iv_size;
  u8 block_align;
  u8 icv_size;
} ipsec_main_crypto_alg_t;

typedef struct
{
  vnet_crypto_op_id_t op_id;
  vnet_crypto_alg_t alg;
  u8 icv_size;
} ipsec_main_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *integ_ops;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_t *chained_integ_ops;
  vnet_crypto_op_chunk_t *chunks;
  vnet_crypto_async_frame_t **async_frames;
} ipsec_per_thread_data_t;

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  /* pool of policies */
  ipsec_policy_t *policies;

  /* hash tables of UDP port registrations */
  uword *udp_port_registrations;

  uword *tunnel_index_by_key;

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec4_if_pool_index_by_key;
  uword *ipsec6_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;
  uword *ipsec_if_by_sw_if_index;

  clib_bihash_8_16_t tun4_protect_by_key;
  clib_bihash_24_16_t tun6_protect_by_key;

  /* crypto alg data */
  ipsec_main_crypto_alg_t *crypto_algs;

  /* crypto integ data */
  ipsec_main_integ_alg_t *integ_algs;

  /* per-thread data */
  ipsec_per_thread_data_t *ptd;

  /** Worker handoff */
  u32 ah4_enc_fq_index;
  u32 ah4_dec_fq_index;
  u32 ah6_enc_fq_index;
  u32 ah6_dec_fq_index;

  u32 esp4_enc_fq_index;
  u32 esp4_dec_fq_index;
  u32 esp6_enc_fq_index;
  u32 esp6_dec_fq_index;
  u32 esp4_enc_tun_fq_index;
  u32 esp6_enc_tun_fq_index;
  u32 esp_mpls_enc_tun_fq_index;
  u32 esp4_dec_tun_fq_index;
  u32 esp6_dec_tun_fq_index;

  u8 async_mode;
} ipsec_main_t;

typedef enum ipsec_format_flags_t_
{
  IPSEC_FORMAT_BRIEF = 0,
  IPSEC_FORMAT_DETAIL = (1 << 0),
  IPSEC_FORMAT_INSECURE = (1 << 1),
} ipsec_format_flags_t;

extern ipsec_main_t ipsec_main;

extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

extern void ipsec_set_async_mode (u32 is_enabled);
extern void ipsec_register_udp_port (u16 udp_port);
extern void ipsec_unregister_udp_port (u16 udp_port);

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

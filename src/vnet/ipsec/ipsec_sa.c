/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include <sys/random.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp_local.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec.api_enum.h>

/**
 * @brief
 * SA packet & bytes counters
 */
vlib_combined_counter_main_t ipsec_sa_counters = {
  .name = "SA",
  .stat_segment_name = "/net/ipsec/sa",
};
/* Per-SA error counters */
vlib_simple_counter_main_t ipsec_sa_err_counters[IPSEC_SA_N_ERRORS];

typedef struct
{
  vnet_crypto_alg_t alg __clib_packed;
  vnet_crypto_alg_t esn_alg __clib_packed;
  u8 integ_icv_size;
  u8 iv_size;
  u8 block_align;
  u8 is_aead : 1;
  u8 is_ctr : 1;
  u8 is_null_gmac : 1;
  u8 is_hmac_only : 1;
} ipsec_sa_crypto_integ_map_t;

static const ipsec_sa_crypto_integ_map_t
  ipsec_sa_crypto_integ_map[IPSEC_CRYPTO_N_ALG][IPSEC_INTEG_N_ALG] = {
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_NONE,
    .block_align = 1,
  },
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_MD5_96] = {
    .alg = VNET_CRYPTO_ALG_MD5_ICV12,
    .integ_icv_size = 12,
    .block_align = 1,
    .is_hmac_only = 1,
  },
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .block_align = 1,
    .is_hmac_only = 1,
  },
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_SHA_256_ICV12,
    .integ_icv_size = 12,
    .block_align = 1,
    .is_hmac_only = 1,
  },
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_SHA_256_ICV16,
    .integ_icv_size = 16,
    .block_align = 1,
    .is_hmac_only = 1,
  },
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_SHA_384_ICV24,
    .integ_icv_size = 24,
    .block_align = 1,
    .is_hmac_only = 1,
  },
  [IPSEC_CRYPTO_ALG_NONE][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_SHA_512_ICV32,
    .integ_icv_size = 32,
    .block_align = 1,
    .is_hmac_only = 1,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_MD5_96] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC_MD5_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_MD5_96] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC_MD5_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_MD5_96] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC_MD5_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_MD5_96] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC_MD5_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_128][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_192][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_256][IPSEC_INTEG_ALG_SHA1_96] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA1_160_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_128][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_192][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_256][IPSEC_INTEG_ALG_SHA_256_96] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA_256_ICV12,
    .integ_icv_size = 12,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_128][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_192][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_256][IPSEC_INTEG_ALG_SHA_256_128] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA_256_ICV16,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_128][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_192][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_256][IPSEC_INTEG_ALG_SHA_384_192] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA_384_ICV24,
    .integ_icv_size = 24,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_128][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_192][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_256][IPSEC_INTEG_ALG_SHA_512_256] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA_512_ICV32,
    .integ_icv_size = 32,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_DES_CBC][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_DES_CBC,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_3DES_CBC][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_3DES_CBC,
    .iv_size = 8,
    .block_align = 8,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_128][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CBC,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_192][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CBC,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CBC_256][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CBC,
    .iv_size = 16,
    .block_align = 16,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_128][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_AES_128_CTR,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_192][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_AES_192_CTR,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_CTR_256][IPSEC_INTEG_ALG_NONE] = {
    .alg = VNET_CRYPTO_ALG_AES_256_CTR,
    .iv_size = 8,
    .block_align = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_GCM_128][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_AES_128_GCM_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_AES_128_GCM_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_GCM_192][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_AES_192_GCM_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_AES_192_GCM_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_GCM_256][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_AES_256_GCM_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_AES_256_GCM_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_CHACHA20_POLY1305][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_NULL_GMAC_128][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_AES_128_NULL_GMAC_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_AES_128_NULL_GMAC_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
    .is_null_gmac = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_NULL_GMAC_192][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_AES_192_NULL_GMAC_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_AES_192_NULL_GMAC_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
    .is_null_gmac = 1,
  },
  [IPSEC_CRYPTO_ALG_AES_NULL_GMAC_256][IPSEC_INTEG_ALG_NONE] = {
    .esn_alg = VNET_CRYPTO_ALG_AES_256_NULL_GMAC_ICV16_AAD12,
    .alg = VNET_CRYPTO_ALG_AES_256_NULL_GMAC_ICV16_AAD8,
    .integ_icv_size = 16,
    .iv_size = 8,
    .block_align = 1,
    .is_aead = 1,
    .is_ctr = 1,
    .is_null_gmac = 1,
  },
};

static_always_inline const ipsec_sa_crypto_integ_map_t *
ipsec_sa_get_crypto_integ_map (ipsec_crypto_alg_t crypto_alg, ipsec_integ_alg_t integ_alg)
{
  const ipsec_sa_crypto_integ_map_t *m;

  if (crypto_alg >= IPSEC_CRYPTO_N_ALG || integ_alg >= IPSEC_INTEG_N_ALG)
    return 0;

  m = &ipsec_sa_crypto_integ_map[crypto_alg][integ_alg];
  if (crypto_alg == IPSEC_CRYPTO_ALG_NONE && integ_alg == IPSEC_INTEG_ALG_NONE)
    return m;
  if (m->alg == 0)
    return 0;

  return m;
}

static void ipsec_sa_del (ipsec_sa_t *sa);

static_always_inline u8
ipsec_sa_outer_ip_protocol (const ipsec_sa_t *sa)
{
  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    return IP_PROTOCOL_UDP;

  return sa->protocol == IPSEC_PROTOCOL_AH ? IP_PROTOCOL_IPSEC_AH : IP_PROTOCOL_IPSEC_ESP;
}

static_always_inline void
ipsec_sa_refresh_op_tmpl (vnet_crypto_op_t *op_tmpl, vnet_crypto_ctx_t *ctx,
			  vnet_crypto_op_type_t type, u8 is_aead, u8 use_esn, u8 integ_icv_size,
			  u8 hmac_check)
{
  vnet_crypto_op_init (ctx, op_tmpl);
  op_tmpl->type = type;

  if (is_aead)
    {
      op_tmpl->aad_len = use_esn ? 12 : 8;
      op_tmpl->auth_len = integ_icv_size;
    }
  else
    {
      op_tmpl->aad_len = 0;
      op_tmpl->auth_len = integ_icv_size;
      if (hmac_check)
	op_tmpl->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
    }
}

static_always_inline void
ipsec_sa_inb_refresh_op_tmpl (ipsec_sa_inb_rt_t *irt)
{
  vnet_crypto_op_type_t type;

  if (!irt)
    return;

  if (irt->is_async || !irt->ctx)
    {
      irt->op_tmpl = (vnet_crypto_op_t){};
      return;
    }

  type = irt->is_hmac_only ? VNET_CRYPTO_OP_TYPE_HMAC : VNET_CRYPTO_OP_TYPE_DECRYPT;
  ipsec_sa_refresh_op_tmpl (&irt->op_tmpl, irt->ctx, type, irt->is_aead, irt->use_esn,
			    irt->integ_icv_size, irt->integ_icv_size != 0 && !irt->is_aead);
}

static_always_inline void
ipsec_sa_outb_refresh_op_tmpl (ipsec_sa_outb_rt_t *ort)
{
  vnet_crypto_op_type_t type;

  if (!ort)
    return;

  if (ort->cached.is_async || !ort->ctx)
    {
      ort->op_tmpl = (vnet_crypto_op_t){};
      ort->cached.prepare_sync_op = 0;
      return;
    }

  type = ort->is_hmac_only ? VNET_CRYPTO_OP_TYPE_HMAC : VNET_CRYPTO_OP_TYPE_ENCRYPT;
  ipsec_sa_refresh_op_tmpl (&ort->op_tmpl, ort->ctx, type, ort->cached.is_aead, ort->cached.use_esn,
			    ort->cached.integ_icv_size, 0);
  ort->cached.prepare_sync_op = 1;
}

void
ipsec_mk_key (ipsec_key_t * key, const u8 * data, u8 len)
{
  memset (key, 0, sizeof (*key));

  if (len > sizeof (key->data))
    key->len = sizeof (key->data);
  else
    key->len = len;

  memcpy (key->data, data, key->len);
}

/**
 * 'stack' (resolve the recursion for) the SA tunnel destination
 */
static void
ipsec_sa_stack (ipsec_sa_t * sa)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt (sa);
  dpo_id_t tmp = DPO_INVALID;

  tunnel_contribute_forwarding (&sa->tunnel, &tmp);

  if (IPSEC_PROTOCOL_AH == sa->protocol)
    dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			    im->ah6_encrypt_node_index :
			    im->ah4_encrypt_node_index),
			 &ort->dpo, &tmp);
  else
    dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			    im->esp6_encrypt_node_index :
			    im->esp4_encrypt_node_index),
			 &ort->dpo, &tmp);
  dpo_reset (&tmp);
}

void
ipsec_sa_set_async_mode (ipsec_sa_t *sa, int is_enabled)
{
  u32 is_async;

  is_async = is_enabled ? 1 : 0;

  if (ipsec_sa_get_inb_rt (sa))
    {
      ipsec_sa_inb_rt_t *irt = ipsec_sa_get_inb_rt (sa);
      irt->ctx = sa->ctx;
      irt->is_async = is_async;
      ipsec_sa_inb_refresh_op_tmpl (irt);
    }

  if (ipsec_sa_get_outb_rt (sa))
    {
      ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt (sa);
      ort->ctx = sa->ctx;
      ort->cached.is_async = is_async;
      ipsec_sa_outb_refresh_op_tmpl (ort);
    }
}

static void
ipsec_sa_init_runtime (ipsec_sa_t *sa, const ipsec_sa_crypto_integ_map_t *m)
{
  u8 is_ctr;
  u8 is_aead;
  u8 is_null_gmac;
  u8 is_hmac_only;
  u8 cipher_iv_size;
  u8 block_align;
  u8 integ_icv_size;

  is_ctr = m->is_ctr;
  is_aead = m->is_aead;
  is_null_gmac = m->is_null_gmac;
  is_hmac_only = m->is_hmac_only;
  cipher_iv_size = m->iv_size;
  block_align = m->block_align;
  integ_icv_size = m->integ_icv_size;

  ASSERT (integ_icv_size <= ESP_MAX_ICV_SIZE);

  if (ipsec_sa_get_inb_rt (sa))
    {
      ipsec_sa_inb_rt_t *irt = ipsec_sa_get_inb_rt (sa);
      irt->use_anti_replay = ipsec_sa_is_set_USE_ANTI_REPLAY (sa);
      irt->use_esn = ipsec_sa_is_set_USE_ESN (sa);
      irt->is_tunnel = ipsec_sa_is_set_IS_TUNNEL (sa);
      irt->is_transport =
	!(ipsec_sa_is_set_IS_TUNNEL (sa) || ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
      irt->udp_sz = ipsec_sa_is_set_UDP_ENCAP (sa) ? sizeof (udp_header_t) : 0;
      irt->is_ctr = is_ctr;
      irt->is_aead = is_aead;
      irt->is_null_gmac = is_null_gmac;
      irt->is_hmac_only = is_hmac_only;
      irt->cipher_iv_size = cipher_iv_size;
      irt->esp_advance = irt->cipher_iv_size + sizeof (esp_header_t);
      irt->integ_icv_size = integ_icv_size;
      irt->tail_base = sizeof (esp_footer_t) + irt->integ_icv_size;
      irt->salt = sa->salt;
      ipsec_sa_inb_refresh_op_tmpl (irt);
      ASSERT (irt->cipher_iv_size <= ESP_MAX_IV_SIZE);
    }

  if (ipsec_sa_get_outb_rt (sa))
    {
      ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt (sa);
      ort->cached.use_esn = ipsec_sa_is_set_USE_ESN (sa);
      ort->cached.integ_add_seq_hi = ort->cached.use_esn && !is_aead;
      ort->cached.is_ctr = is_ctr;
      ort->cached.is_aead = is_aead;
      ort->cached.is_null_gmac = is_null_gmac;
      ort->is_hmac_only = is_hmac_only;
      ort->cached.esp_block_align = clib_max (4, block_align);
      ort->cached.cipher_iv_size = cipher_iv_size;
      ort->cached.esp_iv_bytes = cipher_iv_size + sizeof (esp_header_t);
      ort->cached.cbc_src_pre_bytes = cipher_iv_size;
      ort->cached.cbc_len_pre_bytes = cipher_iv_size;
      ort->cached.integ_src_pre_bytes = cipher_iv_size + sizeof (esp_header_t);
      ort->cached.integ_len_pre_bytes = cipher_iv_size + sizeof (esp_header_t);
      ort->cached.has_cipher = cipher_iv_size != 0 && !is_null_gmac;
      ort->cached.needs_integ = integ_icv_size != 0 && !is_aead;
      ort->cached.needs_sync_enc = ort->cached.has_cipher || is_null_gmac || is_aead;
      ort->cached.is_tunnel = ipsec_sa_is_set_IS_TUNNEL (sa);
      ort->cached.is_tunnel_v6 = ipsec_sa_is_set_IS_TUNNEL_V6 (sa);
      ort->cached.udp_encap = ipsec_sa_is_set_UDP_ENCAP (sa);
      ort->cached.next_hdr_protocol =
	ort->cached.udp_encap ? IP_PROTOCOL_UDP : IP_PROTOCOL_IPSEC_ESP;
      ort->cached.tunnel_fixed_hdr_bytes =
	ort->cached.esp_iv_bytes + (ort->cached.udp_encap ? sizeof (udp_header_t) : 0) +
	(ort->cached.is_tunnel_v6 ? sizeof (ip6_header_t) : sizeof (ip4_header_t));
      ort->cached.need_udp_cksum = ort->cached.udp_encap && ort->cached.is_tunnel_v6;
      ort->cached.integ_icv_size = integ_icv_size;
      ort->salt = sa->salt;
      ort->cached.spi_be = clib_host_to_net_u32 (sa->spi);
      ort->tunnel_flags = sa->tunnel.t_encap_decap_flags;
      ort->cached.need_tunnel_fixup = (ort->tunnel_flags != 0);
      ort->t_dscp = sa->tunnel.t_dscp;
      ipsec_sa_outb_refresh_op_tmpl (ort);

      ASSERT (ort->cached.cipher_iv_size <= ESP_MAX_IV_SIZE);
      ASSERT (ort->cached.esp_block_align <= ESP_MAX_BLOCK_SIZE);
    }
  ipsec_sa_update_runtime (sa);
}

void
ipsec_sa_update_runtime (ipsec_sa_t *sa)
{
  if (ipsec_sa_get_inb_rt (sa))
    {
      ipsec_sa_inb_rt_t *irt = ipsec_sa_get_inb_rt (sa);
      irt->is_protect = ipsec_sa_is_set_IS_PROTECT (sa);
    }
  if (ipsec_sa_get_outb_rt (sa))
    {
      ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt (sa);
      ort->cached.drop_no_crypto = sa->crypto_alg == IPSEC_CRYPTO_ALG_NONE &&
				   sa->integ_alg == IPSEC_INTEG_ALG_NONE &&
				   !ipsec_sa_is_set_NO_ALGO_NO_DROP (sa);
    }
}

int
ipsec_sa_update (u32 id, u16 src_port, u16 dst_port, const tunnel_t *tun,
		 bool is_tun)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;
  ipsec_sa_outb_rt_t *ort;
  u32 sa_index;
  uword *p;
  int rv;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sa = ipsec_sa_get (p[0]);
  ort = ipsec_sa_get_outb_rt (sa);
  sa_index = sa - im->sa_pool;

  if (is_tun && ipsec_sa_is_set_IS_TUNNEL (sa) &&
      (ip_address_cmp (&tun->t_src, &sa->tunnel.t_src) != 0 ||
       ip_address_cmp (&tun->t_dst, &sa->tunnel.t_dst) != 0))
    {
      /* if the source IP is updated for an inbound SA under a tunnel protect,
       we need to update the tun_protect DB with the new src IP */
      if (ipsec_sa_is_set_IS_INBOUND (sa) &&
	  ip_address_cmp (&tun->t_src, &sa->tunnel.t_src) != 0 &&
	  !ip46_address_is_zero (&tun->t_src.ip))
	{
	  if (ip46_address_is_ip4 (&sa->tunnel.t_src.ip))
	    {
	      ipsec4_tunnel_kv_t old_key, new_key;
	      clib_bihash_kv_8_16_t res,
		*bkey = (clib_bihash_kv_8_16_t *) &old_key;

	      ipsec4_tunnel_mk_key (&old_key, &sa->tunnel.t_src.ip.ip4,
				    clib_host_to_net_u32 (sa->spi));
	      ipsec4_tunnel_mk_key (&new_key, &tun->t_src.ip.ip4,
				    clib_host_to_net_u32 (sa->spi));

	      if (!clib_bihash_search_8_16 (&im->tun4_protect_by_key, bkey,
					    &res))
		{
		  clib_bihash_add_del_8_16 (&im->tun4_protect_by_key, &res, 0);
		  res.key = new_key.key;
		  clib_bihash_add_del_8_16 (&im->tun4_protect_by_key, &res, 1);
		}
	    }
	  else
	    {
	      ipsec6_tunnel_kv_t old_key = {
          .key = {
            .remote_ip =  sa->tunnel.t_src.ip.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          },
        }, new_key = {
          .key = {
            .remote_ip = tun->t_src.ip.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          }};
	      clib_bihash_kv_24_16_t res,
		*bkey = (clib_bihash_kv_24_16_t *) &old_key;

	      if (!clib_bihash_search_24_16 (&im->tun6_protect_by_key, bkey,
					     &res))
		{
		  clib_bihash_add_del_24_16 (&im->tun6_protect_by_key, &res,
					     0);
		  clib_memcpy (&res.key, &new_key.key, 3);
		  clib_bihash_add_del_24_16 (&im->tun6_protect_by_key, &res,
					     1);
		}
	    }
	}
      tunnel_unresolve (&sa->tunnel);
      tunnel_copy (tun, &sa->tunnel);
      if (!ipsec_sa_is_set_IS_INBOUND (sa))
	{
	  dpo_reset (&ort->dpo);

	  ort->tunnel_flags = sa->tunnel.t_encap_decap_flags;
	  ort->cached.need_tunnel_fixup = (ort->tunnel_flags != 0);
	  ort->cached.need_udp_cksum = ort->cached.udp_encap && ort->cached.is_tunnel_v6;

	  rv = tunnel_resolve (&sa->tunnel, FIB_NODE_TYPE_IPSEC_SA, sa_index);

	  if (rv)
	    {
	      hash_unset (im->sa_index_by_sa_id, sa->id);
	      pool_put (im->sa_pool, sa);
	      return rv;
	    }
	  ipsec_sa_stack (sa);
	  /* generate header templates */
	  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	    {
	      tunnel_build_v6_hdr (&sa->tunnel, ipsec_sa_outer_ip_protocol (sa), &ort->ip6_hdr);
	    }
	  else
	    {
	      tunnel_build_v4_hdr (&sa->tunnel, ipsec_sa_outer_ip_protocol (sa), &ort->ip4_hdr);
	    }
	}
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      if (dst_port != IPSEC_UDP_PORT_NONE && dst_port != sa->udp_dst_port)
	{
	  if (ipsec_sa_is_set_IS_INBOUND (sa))
	    {
	      ipsec_unregister_udp_port (sa->udp_dst_port,
					 !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
	      ipsec_register_udp_port (dst_port,
				       !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
	    }
	  sa->udp_dst_port = dst_port;
	  ort->udp_hdr.dst_port = clib_host_to_net_u16 (dst_port);
	}
      if (src_port != IPSEC_UDP_PORT_NONE && src_port != (sa->udp_src_port))
	{
	  sa->udp_src_port = src_port;
	  ort->udp_hdr.src_port = clib_host_to_net_u16 (src_port);
	}
    }
  return (0);
}

int
ipsec_sa_add_and_lock (u32 id, u32 spi, ipsec_protocol_t proto,
		       ipsec_crypto_alg_t crypto_alg, const ipsec_key_t *ck,
		       ipsec_integ_alg_t integ_alg, const ipsec_key_t *ik,
		       ipsec_sa_flags_t flags, u32 salt, u16 src_port,
		       u16 dst_port, u32 anti_replay_window_size,
		       const tunnel_t *tun, u32 *sa_out_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_inb_rt_t *irt;
  ipsec_sa_outb_rt_t *ort;
  ipsec_sa_t *sa;
  const u8 *crypto_key_data = 0;
  const u8 *integ_key_data = 0;
  u8 crypto_key_len = 0;
  u8 integ_key_len = 0;
  u32 sa_index, irt_sz;
  clib_thread_index_t thread_index = (vlib_num_workers ()) ? ~0 : 0;
  const ipsec_sa_crypto_integ_map_t *m;
  vnet_crypto_alg_t key_alg;
  u64 rand[2];
  uword *p;
  int rv;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (p)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  if ((proto == IPSEC_PROTOCOL_AH && integ_alg == IPSEC_INTEG_ALG_NONE) ||
      (proto != IPSEC_PROTOCOL_AH && proto != IPSEC_PROTOCOL_ESP))
    return VNET_API_ERROR_UNIMPLEMENTED;

  if (proto == IPSEC_PROTOCOL_AH)
    crypto_alg = IPSEC_CRYPTO_ALG_NONE;

  m = ipsec_sa_get_crypto_integ_map (crypto_alg, integ_alg);
  if (m == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  key_alg = ((flags & IPSEC_SA_FLAG_USE_ESN) && m->esn_alg) ? m->esn_alg : m->alg;

  if (getrandom (rand, sizeof (rand), 0) != sizeof (rand))
    return VNET_API_ERROR_INIT_FAILED;

  pool_get_aligned_zero (im->sa_pool, sa, CLIB_CACHE_LINE_BYTES);
  sa_index = sa - im->sa_pool;
  sa->flags = flags;

  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa) && anti_replay_window_size > 64)
    /* window size rounded up to next power of 2 */
    anti_replay_window_size = 1 << max_log2 (anti_replay_window_size);
  else
    anti_replay_window_size = 64;

  vec_validate (im->inb_sa_runtimes, sa_index);
  vec_validate (im->outb_sa_runtimes, sa_index);

  irt_sz = sizeof (ipsec_sa_inb_rt_t);
  irt_sz += anti_replay_window_size / 8;
  irt_sz = round_pow2 (irt_sz, CLIB_CACHE_LINE_BYTES);

  irt = clib_mem_alloc_aligned (irt_sz, alignof (ipsec_sa_inb_rt_t));
  ort = clib_mem_alloc_aligned (sizeof (ipsec_sa_outb_rt_t),
				alignof (ipsec_sa_outb_rt_t));
  im->inb_sa_runtimes[sa_index] = irt;
  im->outb_sa_runtimes[sa_index] = ort;

  *irt = (ipsec_sa_inb_rt_t){
    .thread_index = thread_index,
    .anti_replay_window_size = anti_replay_window_size,
  };

  *ort = (ipsec_sa_outb_rt_t){
    .thread_index = thread_index,
  };

  clib_pcg64i_srandom_r (&ort->iv_prng, rand[0], rand[1]);

  fib_node_init (&sa->node, FIB_NODE_TYPE_IPSEC_SA);
  fib_node_lock (&sa->node);

  vlib_validate_combined_counter (&ipsec_sa_counters, sa_index);
  vlib_zero_combined_counter (&ipsec_sa_counters, sa_index);
  for (int i = 0; i < IPSEC_SA_N_ERRORS; i++)
    {
      vlib_validate_simple_counter (&ipsec_sa_err_counters[i], sa_index);
      vlib_zero_simple_counter (&ipsec_sa_err_counters[i], sa_index);
    }

  tunnel_copy (tun, &sa->tunnel);
  sa->id = id;
  sa->spi = spi;
  sa->stat_index = sa_index;
  sa->protocol = proto;
  sa->salt = salt;
  sa->ctx = 0;
  sa->crypto_alg = crypto_alg;
  sa->integ_alg = integ_alg;

  if (integ_alg != IPSEC_INTEG_ALG_NONE)
    {
      clib_memcpy (&sa->integ_key, ik, sizeof (sa->integ_key));
      if (proto == IPSEC_PROTOCOL_AH || crypto_alg == IPSEC_CRYPTO_ALG_NONE)
	{
	  integ_key_data = ik->data;
	  integ_key_len = ik->len;
	}
      else
	{
	  integ_key_data = ik->data;
	  integ_key_len = ik->len;
	}
    }
  clib_memcpy (&sa->crypto_key, ck, sizeof (sa->crypto_key));
  if (proto != IPSEC_PROTOCOL_AH && crypto_alg != IPSEC_CRYPTO_ALG_NONE)
    {
      crypto_key_data = ck->data;
      crypto_key_len = ck->len;
    }
  if (key_alg != VNET_CRYPTO_ALG_NONE)
    {
      vnet_crypto_ctx_t *ctx = vnet_crypto_ctx_create (key_alg);

      if (ctx && crypto_key_len &&
	  !vnet_crypto_ctx_set_cipher_key (ctx, crypto_key_data, crypto_key_len))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  ctx = 0;
	}

      if (ctx && integ_key_len &&
	  !vnet_crypto_ctx_set_auth_key (ctx, integ_key_data, integ_key_len))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  ctx = 0;
	}

      if (!ctx)
	{
	  clib_mem_free (irt);
	  clib_mem_free (ort);
	  im->inb_sa_runtimes[sa_index] = 0;
	  im->outb_sa_runtimes[sa_index] = 0;
	  fib_node_unlock (&sa->node);
	  return VNET_API_ERROR_KEY_LENGTH;
	}

      sa->ctx = ctx;
    }

  ipsec_sa_set_async_mode (sa, im->async_mode || ipsec_sa_is_set_IS_ASYNC (sa));

  if (ipsec_sa_is_set_IS_TUNNEL (sa) &&
      AF_IP6 == ip_addr_version (&tun->t_src))
    ipsec_sa_set_IS_TUNNEL_V6 (sa);

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    {

      rv = tunnel_resolve (&sa->tunnel, FIB_NODE_TYPE_IPSEC_SA, sa_index);

      if (rv)
	{
	  vnet_crypto_ctx_destroy (vm, sa->ctx);
	  clib_mem_free (irt);
	  clib_mem_free (ort);
	  im->inb_sa_runtimes[sa_index] = 0;
	  im->outb_sa_runtimes[sa_index] = 0;
	  fib_node_unlock (&sa->node);
	  return rv;
	}
      ipsec_sa_stack (sa);

      /* generate header templates */
      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	{
	  tunnel_build_v6_hdr (&sa->tunnel, ipsec_sa_outer_ip_protocol (sa), &ort->ip6_hdr);
	}
      else
	{
	  tunnel_build_v4_hdr (&sa->tunnel, ipsec_sa_outer_ip_protocol (sa), &ort->ip4_hdr);
	}
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      if (dst_port == IPSEC_UDP_PORT_NONE)
	dst_port = UDP_DST_PORT_ipsec;
      if (src_port == IPSEC_UDP_PORT_NONE)
	src_port = UDP_DST_PORT_ipsec;

      sa->udp_dst_port = dst_port;
      sa->udp_src_port = src_port;
      ort->udp_hdr.src_port = clib_host_to_net_u16 (src_port);
      ort->udp_hdr.dst_port = clib_host_to_net_u16 (dst_port);
      if (ipsec_sa_is_set_IS_INBOUND (sa))
	ipsec_register_udp_port (dst_port, !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
    }

  for (u32 i = 0; i < anti_replay_window_size / uword_bits; i++)
    irt->replay_window[i] = ~0ULL;

  hash_set (im->sa_index_by_sa_id, sa->id, sa_index);

  if (sa_out_index)
    *sa_out_index = sa_index;

  ipsec_sa_init_runtime (sa, m);

  return (0);
}

static void
ipsec_sa_del (ipsec_sa_t * sa)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  u32 sa_index;
  ipsec_sa_inb_rt_t *irt = ipsec_sa_get_inb_rt (sa);
  ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt (sa);

  sa_index = sa - im->sa_pool;
  hash_unset (im->sa_index_by_sa_id, sa->id);
  tunnel_unresolve (&sa->tunnel);

  if (sa->ctx)
    vnet_crypto_ctx_destroy (vm, sa->ctx);

  if (ipsec_sa_is_set_UDP_ENCAP (sa) && ipsec_sa_is_set_IS_INBOUND (sa))
    ipsec_unregister_udp_port (sa->udp_dst_port,
			       !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    dpo_reset (&ort->dpo);
  foreach_pointer (p, irt, ort)
    if (p)
      clib_mem_free (p);

  im->inb_sa_runtimes[sa_index] = 0;
  im->outb_sa_runtimes[sa_index] = 0;

  pool_put (im->sa_pool, sa);
}

int
ipsec_sa_bind (u32 id, u32 worker, bool bind)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  ipsec_sa_t *sa;
  ipsec_sa_inb_rt_t *irt;
  ipsec_sa_outb_rt_t *ort;
  clib_thread_index_t thread_index;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;

  sa = ipsec_sa_get (p[0]);
  irt = ipsec_sa_get_inb_rt (sa);
  ort = ipsec_sa_get_outb_rt (sa);

  if (!bind)
    {
      thread_index = ~0;
      goto done;
    }

  if (worker >= vlib_num_workers ())
    return VNET_API_ERROR_INVALID_WORKER;

  thread_index = vlib_get_worker_thread_index (worker);
done:
  if (irt)
    irt->thread_index = thread_index;
  if (ort)
    ort->thread_index = thread_index;
  return 0;
}

void
ipsec_sa_unlock (index_t sai)
{
  ipsec_sa_t *sa;

  if (INDEX_INVALID == sai)
    return;

  sa = ipsec_sa_get (sai);

  fib_node_unlock (&sa->node);
}

void
ipsec_sa_lock (index_t sai)
{
  ipsec_sa_t *sa;

  if (INDEX_INVALID == sai)
    return;

  sa = ipsec_sa_get (sai);

  fib_node_lock (&sa->node);
}

index_t
ipsec_sa_find_and_lock (u32 id)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return INDEX_INVALID;

  sa = ipsec_sa_get (p[0]);

  fib_node_lock (&sa->node);

  return (p[0]);
}

int
ipsec_sa_unlock_id (u32 id)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  ipsec_sa_unlock (p[0]);

  return (0);
}

void
ipsec_sa_clear (index_t sai)
{
  vlib_zero_combined_counter (&ipsec_sa_counters, sai);
  for (int i = 0; i < IPSEC_SA_N_ERRORS; i++)
    vlib_zero_simple_counter (&ipsec_sa_err_counters[i], sai);
}

void
ipsec_sa_walk (ipsec_sa_walk_cb_t cb, void *ctx)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;

  pool_foreach (sa, im->sa_pool)
    {
      if (WALK_CONTINUE != cb (sa, ctx))
	break;
    }
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
ipsec_sa_fib_node_get (fib_node_index_t index)
{
  ipsec_sa_t *sa;

  sa = ipsec_sa_get (index);

  return (&sa->node);
}

static ipsec_sa_t *
ipsec_sa_from_fib_node (fib_node_t *node)
{
  ASSERT (FIB_NODE_TYPE_IPSEC_SA == node->fn_type);
  return (
    (ipsec_sa_t *) (((char *) node) - STRUCT_OFFSET_OF (ipsec_sa_t, node)));
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
ipsec_sa_last_lock_gone (fib_node_t *node)
{
  /*
   * The ipsec SA is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ipsec_sa_del (ipsec_sa_from_fib_node (node));
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
ipsec_sa_back_walk (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
{
  ipsec_sa_stack (ipsec_sa_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * Virtual function table registered by SAs
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t ipsec_sa_vft = {
  .fnv_get = ipsec_sa_fib_node_get,
  .fnv_last_lock = ipsec_sa_last_lock_gone,
  .fnv_back_walk = ipsec_sa_back_walk,
};

/* Init per-SA error counters and node type */
clib_error_t *
ipsec_sa_init (vlib_main_t *vm)
{
  fib_node_register_type (FIB_NODE_TYPE_IPSEC_SA, &ipsec_sa_vft);

#define _(index, val, err, desc)                                              \
  ipsec_sa_err_counters[index].name =                                         \
    (char *) format (0, "SA-" #err "%c", 0);                                  \
  ipsec_sa_err_counters[index].stat_segment_name =                            \
    (char *) format (0, "/net/ipsec/sa/err/" #err "%c", 0);                   \
  ipsec_sa_err_counters[index].counters = 0;
  foreach_ipsec_sa_err
#undef _
    return 0;
}

VLIB_INIT_FUNCTION (ipsec_sa_init);

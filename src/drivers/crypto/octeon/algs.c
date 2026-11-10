/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

vnet_dev_node_t oct_crypto_deq_node = {
  .format_trace = format_oct_cpt_deq_trace,
};

#define _(n, s, is_aead, aad_len, is_enc)                                                          \
  vnet_dev_node_t oct_crypto_enq_##n##_node = {                                                    \
    .name = s,                                                                                     \
    .format_trace = format_oct_cpt_enq_trace,                                                      \
  };
foreach_oct_crypto_enqueue_node
#undef _

const oct_crypto_alg_data_t oct_crypto_algs[VNET_CRYPTO_N_ALGS] = {
  [VNET_CRYPTO_ALG_AES_128_CBC] = {
    .cipher_type = ROC_SE_AES_CBC,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC] = {
    .cipher_type = ROC_SE_AES_CBC,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC] = {
    .cipher_type = ROC_SE_AES_CBC,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR] = {
    .cipher_type = ROC_SE_AES_CTR,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR] = {
    .cipher_type = ROC_SE_AES_CTR,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR] = {
    .cipher_type = ROC_SE_AES_CTR,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_MD5_ICV12] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_MD5_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_MD5_ICV12] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_MD5_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_MD5_ICV12] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_MD5_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA1_160_ICV12] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA1_160_ICV12] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA1_160_ICV12] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA2_256_ICV16] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA2_256_ICV16] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA2_256_ICV16] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA2_384_ICV24] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA2_384_ICV24] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA2_384_ICV24] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA2_512_ICV32] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA2_512_ICV32] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA2_512_ICV32] = {
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA1_160_ICV12] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA1_160_ICV12] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA1_160_ICV12] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA2_256_ICV16] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA2_256_ICV16] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA2_256_ICV16] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA2_384_ICV24] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA2_384_ICV24] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA2_384_ICV24] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA2_512_ICV32] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA2_512_ICV32] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA2_512_ICV32] = {
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_GCM_ICV16_AAD8] = {
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_GCM_ICV16_AAD12] = {
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_GCM_ICV16_AAD8] = {
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_GCM_ICV16_AAD12] = {
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_GCM_ICV16_AAD8] = {
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_GCM_ICV16_AAD12] = {
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD0] = {
    .cipher_type = ROC_SE_CHACHA20,
    .auth_type = ROC_SE_POLY1305,
    .digest_len = 16,
    .iv_length = 12,
    .opcode_minor_flags = BIT (5),
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD8] = {
    .cipher_type = ROC_SE_CHACHA20,
    .auth_type = ROC_SE_POLY1305,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 12,
    .opcode_minor_flags = BIT (5),
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD12] = {
    .cipher_type = ROC_SE_CHACHA20,
    .auth_type = ROC_SE_POLY1305,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 12,
    .opcode_minor_flags = BIT (5),
    .valid = 1,
  },
};

static int
oct_crypto_alg_supported (const oct_crypto_alg_data_t *a, union cpt_eng_caps *caps)
{
  switch (a->cipher_type)
    {
    case ROC_SE_AES_CBC:
    case ROC_SE_AES_CTR:
    case ROC_SE_AES_GCM:
      if (caps->aes == 0)
	return 0;
      break;
    case ROC_SE_CHACHA20:
      if (caps->chacha20 == 0)
	return 0;
      break;
    default:
      break;
    }

  switch (a->auth_type)
    {
    case ROC_SE_MD5_TYPE:
    case ROC_SE_SHA1_TYPE:
    case ROC_SE_SHA2_SHA256:
    case ROC_SE_SHA2_SHA384:
    case ROC_SE_SHA2_SHA512:
      return caps->sha1_sha2;
    case ROC_SE_POLY1305:
      return caps->chacha20;
    default:
      return 1;
    }
}

vnet_dev_crypto_alg_handlers_t *
oct_crypto_get_alg_handlers (union cpt_eng_caps *caps)
{
  vnet_dev_crypto_alg_handlers_t *handlers = 0;

  for (u32 i = 0; i < VNET_CRYPTO_N_ALGS; i++)
    {
      const oct_crypto_alg_data_t *a = oct_crypto_algs + i;
      vnet_dev_crypto_alg_handlers_t h = { .alg = i };

      if (a->valid == 0 || oct_crypto_alg_supported (a, caps) == 0)
	continue;

      if (a->cipher_type != ROC_SE_AES_GCM && a->cipher_type != ROC_SE_CHACHA20)
	{
	  h.enc_node = &oct_crypto_enq_enc_node;
	  h.dec_node = &oct_crypto_enq_dec_node;
	}
      else if (a->aad_len == 8)
	{
	  h.enc_node = &oct_crypto_enq_aead_aad8_enc_node;
	  h.dec_node = &oct_crypto_enq_aead_aad8_dec_node;
	}
      else if (a->aad_len == 12)
	{
	  h.enc_node = &oct_crypto_enq_aead_aad12_enc_node;
	  h.dec_node = &oct_crypto_enq_aead_aad12_dec_node;
	}
      else
	{
	  h.enc_node = &oct_crypto_enq_aead_aad0_enc_node;
	  h.dec_node = &oct_crypto_enq_aead_aad0_dec_node;
	}

      vec_add1 (handlers, h);
    }

  return handlers;
}

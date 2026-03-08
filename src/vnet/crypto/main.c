/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>

#define VNET_CRYPTO_OP_TYPE_MASK_ENC_DEC                                                           \
  ((1 << VNET_CRYPTO_OP_TYPE_ENCRYPT) | (1 << VNET_CRYPTO_OP_TYPE_DECRYPT))
#define VNET_CRYPTO_OP_TYPE_MASK_HMAC (1 << VNET_CRYPTO_OP_TYPE_HMAC)

vnet_crypto_main_t crypto_main =
{
  .algs = {
#define _(n, s, f, k, b)                                                                           \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .cipher_key_len = (k),                                                                         \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_ENC_DEC,                                              \
    .alg_type = VNET_CRYPTO_ALG_T_CIPHER,                                                          \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##f,                                                   \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_NONE,                                                    \
  },
  foreach_crypto_cipher_alg_non_ctr foreach_crypto_cipher_alg_ctr
#undef _

#define _(n, s, f, k, b)                                                                           \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .cipher_key_len = (k),                                                                         \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_ENC_DEC,                                              \
    .alg_type = VNET_CRYPTO_ALG_T_AEAD,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##f,                                                   \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##f,                                                     \
    .variable_aad_len = 1,                                                                         \
  },
  foreach_crypto_aead_alg
#undef _

#define _(n, s, cf, inf, d, b)                                                                     \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .auth_key_len = (b),                                                                           \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_HMAC,                                                 \
    .alg_type = VNET_CRYPTO_ALG_T_AUTH,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_auth_key_len = 1,                                                                    \
  },
  foreach_crypto_hash_alg
#undef _

#define _(n, s, cf, inf, d, b)                                                                     \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .auth_key_len = (b),                                                                           \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_HMAC,                                                 \
    .alg_type = VNET_CRYPTO_ALG_T_AUTH,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_auth_key_len = 1,                                                                    \
  },
  foreach_crypto_hash_fixed_alg
#undef _

#define _(n, s, f, k, t, a, b)                                                                     \
  [VNET_CRYPTO_ALG_##n##_ICV##t##_AAD##a] = {                                                      \
    .name = (s),                                                                                   \
    .cipher_key_len = (k),                                                                         \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_ENC_DEC,                                              \
    .alg_type = VNET_CRYPTO_ALG_T_AEAD,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##f,                                                   \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##f,                                                     \
    .aad_len = a,                                                                                  \
    .auth_len = t,                                                                                 \
  },
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, cf, inf, k, d, ak, b)                                                           \
  [VNET_CRYPTO_ALG_##c##_##h] = {                                                                  \
    .name = (s),                                                                                   \
    .cipher_key_len = (k),                                                                         \
    .auth_key_len = (ak),                                                                          \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_ENC_DEC,                                              \
    .alg_type = VNET_CRYPTO_ALG_T_COMBINED,                                                        \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_auth_key_len = 1,                                                                    \
  },
  foreach_crypto_combined_alg
#undef _

#define _(c, h, s, cf, inf, k, d, ak, b)                                                           \
  [VNET_CRYPTO_ALG_##c##_##h##_ICV##d] = {                                                         \
    .name = (s),                                                                                   \
    .cipher_key_len = (k),                                                                         \
    .auth_key_len = (ak),                                                                          \
    .block_len = (b),                                                                              \
    .op_type_mask = VNET_CRYPTO_OP_TYPE_MASK_ENC_DEC,                                              \
    .alg_type = VNET_CRYPTO_ALG_T_COMBINED,                                                        \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_auth_key_len = 1,                                                                    \
  },
  foreach_crypto_combined_fixed_alg
#undef _
  },
  .hash_algs = {
#define _(n, s, cf, inf, d, b)                                                                     \
  [VNET_CRYPTO_HASH_ALG_##n] = {                                                                   \
    .name = (s),                                                                                   \
    .family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                        \
    .digest_len = (d),                                                                             \
    .block_len = (b),                                                                              \
    .alg = VNET_CRYPTO_ALG_##n,                                                                    \
  },
  foreach_crypto_hash_alg
#undef _
  },
};

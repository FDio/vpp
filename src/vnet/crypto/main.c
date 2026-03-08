/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>

vnet_crypto_main_t crypto_main =
{
  .algs = {
#define _(n, s, cf, inf, k, b)                                                                     \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .key_len = (k),                                                                                \
    .block_len = (b),                                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_CIPHER,                                                          \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
  },
  foreach_crypto_cipher_alg_non_ctr foreach_crypto_cipher_alg_ctr
#undef _

#define _(n, s, cf, inf, k, b)                                                                     \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .key_len = (k),                                                                                \
    .block_len = (b),                                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_AEAD,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .variable_aad_length = 1,                                                                      \
  },
  foreach_crypto_aead_alg
#undef _

#define _(n, s, cf, inf, d, b)                                                                     \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .block_len = (b),                                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_AUTH,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_cipher_key_length = 1,                                                               \
  },
  foreach_crypto_hash_alg
#undef _

#define _(n, s, cf, inf, k, t, a, b)                                                               \
  [VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a] = {                                                      \
    .name = (s),                                                                                   \
    .key_len = (k),                                                                                \
    .block_len = (b),                                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_AEAD,                                                            \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .aad_len = a,                                                                                  \
    .auth_len = t,                                                                                 \
  },
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, cf, inf, k, d, b)                                                               \
  [VNET_CRYPTO_ALG_##c##_##h] = {                                                                  \
    .name = (s),                                                                                   \
    .key_len = (k),                                                                                \
    .block_len = (b),                                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_COMBINED,                                                        \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_auth_key_length = 1,                                                                 \
  },
  foreach_crypto_combined_alg
#undef _

#define _(c, h, s, cf, inf, k, d, b)                                                               \
  [VNET_CRYPTO_ALG_##c##_##h##_TAG##d] = {                                                         \
    .name = (s),                                                                                   \
    .key_len = (k),                                                                                \
    .block_len = (b),                                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_COMBINED,                                                        \
    .cipher_family = VNET_CRYPTO_ALG_FAMILY_##cf,                                                  \
    .auth_family = VNET_CRYPTO_ALG_FAMILY_##inf,                                                   \
    .auth_len = d,                                                                                 \
    .variable_auth_key_length = 1,                                                                 \
  },
  foreach_crypto_combined_fixed_alg
#undef _
  },
};

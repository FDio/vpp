/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>

vnet_crypto_main_t crypto_main =
{
  .algs = {
#define _(n, s, ...)                                                                               \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .alg_type = VNET_CRYPTO_ALG_T_CYPHER,                                                          \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] = VNET_CRYPTO_OP_##n##_ENC,                           \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] = VNET_CRYPTO_OP_##n##_DEC,                           \
    __VA_ARGS__,                                                                                   \
  },
  foreach_crypto_cipher_alg_non_ctr foreach_crypto_cipher_alg_ctr
#undef _

#define _(n, s, ...)                                                                               \
  [VNET_CRYPTO_ALG_##n] = {                                                                        \
    .name = (s),                                                                                   \
    .alg_type = VNET_CRYPTO_ALG_T_AEAD,                                                            \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] = VNET_CRYPTO_OP_##n##_ENC,                           \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] = VNET_CRYPTO_OP_##n##_DEC,                           \
    __VA_ARGS__,                                                                                   \
  },
  foreach_crypto_aead_alg
#undef _

#define _(n, s)                                                                                    \
  [VNET_CRYPTO_ALG_HASH_##n] = {                                              \
    .name = (s),                                                              \
    .alg_type = VNET_CRYPTO_ALG_T_HASH,                                      \
    .op_by_type[VNET_CRYPTO_OP_TYPE_HASH] = VNET_CRYPTO_OP_##n##_HASH,        \
  },                                                                          \
  [VNET_CRYPTO_ALG_HMAC_##n] = {                                              \
    .name = ("hmac-" s),                                                      \
    .alg_type = VNET_CRYPTO_ALG_T_INTEG,                                     \
    .op_by_type[VNET_CRYPTO_OP_TYPE_HMAC] = VNET_CRYPTO_OP_##n##_HMAC,        \
    .variable_cypher_key_length = 1,                                          \
  },
  foreach_crypto_hash_alg
#undef _

#define _(n, s, k, t, a)                                                                           \
  [VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a] = {                                                      \
    .name = (s),                                                                                   \
    .key_length = (k),                                                                             \
    .alg_type = VNET_CRYPTO_ALG_T_AEAD,                                                            \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] = VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,         \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] = VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,         \
  },
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                                           \
  [VNET_CRYPTO_ALG_##c##_##h##_TAG##d] = {                                                         \
    .name = (s),                                                                                   \
    .key_length = (k),                                                                             \
    .alg_type = VNET_CRYPTO_ALG_T_COMBINED,                                                        \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] = VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,            \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] = VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,            \
    .variable_integ_key_length = 1,                                                                \
  },
  foreach_crypto_combined_fixed_alg
#undef _

  },
  .opt_data = {
#define _(n, s, ...)                                                                               \
  [VNET_CRYPTO_OP_##n##_ENC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
      .is_ctr = 0,                                                            \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_DEC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
      .is_ctr = 0,                                                            \
  },
  foreach_crypto_cipher_alg_non_ctr
#undef _

#define _(n, s, ...)                                                                               \
  [VNET_CRYPTO_OP_##n##_ENC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
      .is_ctr = 1,                                                            \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_DEC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
      .is_ctr = 1,                                                            \
  },
  foreach_crypto_cipher_alg_ctr
#undef _

#define _(n, s, ...)                                                                               \
  [VNET_CRYPTO_OP_##n##_ENC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
      .is_aead = 1,                                                           \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_DEC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
      .is_aead = 1,                                                           \
  },
  foreach_crypto_aead_alg
#undef _

#define _(n, s)                                                               \
  [VNET_CRYPTO_OP_##n##_HASH] = {                                             \
    .alg = VNET_CRYPTO_ALG_HASH_##n,                                          \
    .type = VNET_CRYPTO_OP_TYPE_HASH,                                         \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_HMAC] = {                                             \
    .alg = VNET_CRYPTO_ALG_HMAC_##n,                                          \
    .type = VNET_CRYPTO_OP_TYPE_HMAC,                                         \
  },
  foreach_crypto_hash_alg
#undef _

#define _(n, s, k, t, a)                                                                           \
  [VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC] = {                            \
      .alg = VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,                           \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
      .is_aead = 1,                                                           \
      .aad_len = a,                                                           \
      .digest_len = t,                                                        \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC] = {                            \
      .alg = VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,                           \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
      .is_aead = 1,                                                           \
      .aad_len = a,                                                           \
      .digest_len = t,                                                        \
  },
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                                           \
  [VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC] = {                               \
      .alg = VNET_CRYPTO_ALG_##c##_##h##_TAG##d,                              \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
      .is_ctr = 0,                                                            \
      .digest_len = d,                                                        \
  },                                                                          \
  [VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC] = {                               \
      .alg = VNET_CRYPTO_ALG_##c##_##h##_TAG##d,                              \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
      .is_ctr = 0,                                                            \
      .digest_len = d,                                                        \
  },
    foreach_crypto_combined_fixed_alg_non_ctr
#undef _

#define _(c, h, s, k, d)                                                                           \
  [VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC] = {                               \
      .alg = VNET_CRYPTO_ALG_##c##_##h##_TAG##d,                              \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
      .is_ctr = 1,                                                            \
      .digest_len = d,                                                        \
  },                                                                          \
  [VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC] = {                               \
      .alg = VNET_CRYPTO_ALG_##c##_##h##_TAG##d,                              \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
      .is_ctr = 1,                                                            \
      .digest_len = d,                                                        \
  },
    foreach_crypto_combined_fixed_alg_ctr
#undef _

  },
};

/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>

vnet_crypto_main_t crypto_main =
{
  .algs = {
#define _(n, s, ...)                                                          \
  [VNET_CRYPTO_ALG_##n] = {                                                   \
    .name = (s),                                                              \
    .is_link = 0,                                                             \
    .link_crypto_alg = VNET_CRYPTO_ALG_NONE,                                  \
    .link_integ_alg = VNET_CRYPTO_ALG_NONE,                                   \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] = VNET_CRYPTO_OP_##n##_ENC,      \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] = VNET_CRYPTO_OP_##n##_DEC,      \
    __VA_ARGS__,                                                              \
  },
  foreach_crypto_cipher_alg foreach_crypto_aead_alg
#undef _

#define _(n, s)                                                               \
  [VNET_CRYPTO_ALG_HASH_##n] = {                                              \
    .name = (s),                                                              \
    .is_link = 0,                                                             \
    .link_crypto_alg = VNET_CRYPTO_ALG_NONE,                                  \
    .link_integ_alg = VNET_CRYPTO_ALG_NONE,                                   \
    .op_by_type[VNET_CRYPTO_OP_TYPE_HASH] = VNET_CRYPTO_OP_##n##_HASH,        \
  },                                                                          \
  [VNET_CRYPTO_ALG_HMAC_##n] = {                                              \
    .name = ("hmac-" s),                                                      \
    .is_link = 0,                                                             \
    .link_crypto_alg = VNET_CRYPTO_ALG_NONE,                                  \
    .link_integ_alg = VNET_CRYPTO_ALG_NONE,                                   \
    .op_by_type[VNET_CRYPTO_OP_TYPE_HMAC] = VNET_CRYPTO_OP_##n##_HMAC,        \
    .variable_key_length = 1,                                                 \
  },
  foreach_crypto_hash_alg
#undef _

#define _(n, s, k, t, a)                                                      \
  [VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a] = {                                 \
    .name = (s),                                                              \
    .is_link = 0,                                                             \
    .link_crypto_alg = VNET_CRYPTO_ALG_NONE,                                  \
    .link_integ_alg = VNET_CRYPTO_ALG_NONE,                                   \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] =                                \
      VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,                             \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] =                                \
      VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,                             \
  },
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                      \
  [VNET_CRYPTO_ALG_##c##_##h##_TAG##d] = {                                    \
    .name = (s),                                                              \
    .is_link = 1,                                                             \
    .link_crypto_alg = VNET_CRYPTO_ALG_##c,                                   \
    .link_integ_alg = VNET_CRYPTO_ALG_HMAC_##h,                               \
    .op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT] =                                \
      VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,                                \
    .op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] =                                \
      VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,                                \
  },
  foreach_crypto_link_async_alg
#undef _

  },
  .opt_data = {
#define _(n, s, ...)                                                          \
  [VNET_CRYPTO_OP_##n##_ENC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_DEC] = {                                              \
      .alg = VNET_CRYPTO_ALG_##n,                                             \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
  },
  foreach_crypto_cipher_alg foreach_crypto_aead_alg
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

#define _(n, s, k, t, a)                                                      \
  [VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC] = {                            \
      .alg = VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,                           \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
  },                                                                          \
  [VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC] = {                            \
      .alg = VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,                           \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
  },
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                      \
  [VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC] = {                               \
      .alg = VNET_CRYPTO_ALG_##c##_##h##_TAG##d,                              \
      .type = VNET_CRYPTO_OP_TYPE_ENCRYPT,                                    \
  } ,                                                                         \
  [VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC] = {                               \
      .alg = VNET_CRYPTO_ALG_##c##_##h##_TAG##d,                              \
      .type = VNET_CRYPTO_OP_TYPE_DECRYPT,                                    \
  },
    foreach_crypto_link_async_alg
#undef _

  },
};

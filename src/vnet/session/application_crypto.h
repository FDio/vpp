/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_SESSION_APPLICATION_CRYPTO_H_
#define SRC_VNET_SESSION_APPLICATION_CRYPTO_H_

#include <vnet/tls/tls_test.h>

typedef struct certificate_
{
  u32 *app_interests; /* vec of application index asking for deletion cb */
  u32 cert_key_index; /* index in cert & key pool */
  u8 *key;
  u8 *cert;
} app_cert_key_pair_t;

typedef enum crypto_engine_type_
{
  CRYPTO_ENGINE_NONE,
  CRYPTO_ENGINE_OPENSSL,
  CRYPTO_ENGINE_MBEDTLS,
  CRYPTO_ENGINE_VPP,
  CRYPTO_ENGINE_PICOTLS,
  CRYPTO_ENGINE_LAST = CRYPTO_ENGINE_PICOTLS,
} crypto_engine_type_t;

typedef struct _vnet_app_add_cert_key_pair_args_
{
  u8 *cert;
  u8 *key;
  u32 cert_len;
  u32 key_len;
  u32 index;
} vnet_app_add_cert_key_pair_args_t;

typedef struct crypto_ctx_
{
  u32 ctx_index;     /**< index in crypto context pool */
  u32 n_subscribers; /**< refcount of sessions using said context */
  u32 ckpair_index;  /**< certificate & key */
  u8 crypto_engine;
  void *data; /**< protocol specific data */
} crypto_context_t;

/*
 * Certificate key-pair management
 */

app_cert_key_pair_t *app_cert_key_pair_get (u32 index);
app_cert_key_pair_t *app_cert_key_pair_get_if_valid (u32 index);
app_cert_key_pair_t *app_cert_key_pair_get_default ();

int vnet_app_add_cert_key_pair (vnet_app_add_cert_key_pair_args_t *a);
int vnet_app_add_cert_key_interest (u32 index, u32 app_index);
int vnet_app_del_cert_key_pair (u32 index);

/*
 * Crypto engine management
 */
crypto_engine_type_t app_crypto_engine_type_add (void);
u8 app_crypto_engine_n_types (void);
u8 *format_crypto_engine (u8 *s, va_list *args);
uword unformat_crypto_engine (unformat_input_t *input, va_list *args);

clib_error_t *application_crypto_init ();

#endif /* SRC_VNET_SESSION_APPLICATION_CRYPTO_H_ */

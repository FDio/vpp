/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 ARM Ltd and/or its affiliates.
 */

#ifndef __crypto_openssl_h__
#define __crypto_openssl_h__

typedef void (crypto_openssl_ctx_fn_t) (vnet_crypto_key_op_t kop, vnet_crypto_key_handler_args_t a);

typedef struct
{
  crypto_openssl_ctx_fn_t *ctx_fn[VNET_CRYPTO_N_ALGS];
} crypto_openssl_main_t;

extern crypto_openssl_main_t crypto_openssl_main;

#endif /* __crypto_openssl_h__ */

/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <openssl/evp.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>

#define foreach_openssl_evp_op \
  _(DES_CBC, EVP_des_cbc) \
  _(3DES_CBC, EVP_des_ede3_cbc) \
  _(AES_128_CBC, EVP_aes_128_cbc) \
  _(AES_192_CBC, EVP_aes_192_cbc) \
  _(AES_256_CBC, EVP_aes_256_cbc)

static_always_inline u32
openssl_ops_enc_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len;

      EVP_EncryptInit_ex (ctx, cipher, NULL, op->key, op->iv);
      EVP_EncryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
      EVP_EncryptFinal_ex (ctx, op->dst + out_len, &out_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  EVP_CIPHER_CTX_free (ctx);
  return n_ops;
}

static_always_inline u32
openssl_ops_dec_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len;

      EVP_DecryptInit_ex (ctx, cipher, NULL, op->key, op->iv);
      EVP_DecryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
      EVP_DecryptFinal_ex (ctx, op->dst + out_len, &out_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  EVP_CIPHER_CTX_free (ctx);
  return n_ops;
}

#define _(a, b) \
static u32 \
openssl_ops_enc_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return openssl_ops_enc_cbc (vm, ops, n_ops, b ()); } \
\
u32 \
openssl_ops_dec_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return openssl_ops_dec_cbc (vm, ops, n_ops, b ()); }

foreach_openssl_evp_op;
#undef _


clib_error_t *
crypto_openssl_init (vlib_main_t * vm)
{
  u32 eidx = vnet_crypto_register_engine (vm, "openssl", 50, "OpenSSL");
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vnet_crypto_init)))
    return error;

#define _(a, b) \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
				    openssl_ops_enc_##a); \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
				    openssl_ops_dec_##a);

  foreach_openssl_evp_op;
#undef _

  return 0;
}

VLIB_INIT_FUNCTION (crypto_openssl_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

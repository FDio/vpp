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
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vpp/app/version.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  EVP_CIPHER_CTX *evp_cipher_ctx;
  HMAC_CTX *hmac_ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX _hmac_ctx;
#endif
} openssl_per_thread_data_t;

static openssl_per_thread_data_t *per_thread_data = 0;

#define foreach_openssl_evp_op \
  _(DES_CBC, EVP_des_cbc) \
  _(3DES_CBC, EVP_des_ede3_cbc) \
  _(AES_128_CBC, EVP_aes_128_cbc) \
  _(AES_192_CBC, EVP_aes_192_cbc) \
  _(AES_256_CBC, EVP_aes_256_cbc)

#define foreach_openssl_hmac_op \
  _(MD5, EVP_md5) \
  _(SHA1, EVP_sha1) \
  _(SHA224, EVP_sha224) \
  _(SHA256, EVP_sha256) \
  _(SHA384, EVP_sha384) \
  _(SHA512, EVP_sha512)

static_always_inline u32
openssl_ops_enc_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  EVP_CIPHER_CTX *ctx = ptd->evp_cipher_ctx;
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len;

      if (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	RAND_bytes (op->iv, 16);

      EVP_EncryptInit_ex (ctx, cipher, NULL, op->key, op->iv);
      EVP_EncryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_EncryptFinal_ex (ctx, op->dst + out_len, &out_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_dec_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  EVP_CIPHER_CTX *ctx = ptd->evp_cipher_ctx;
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len;

      EVP_DecryptInit_ex (ctx, cipher, NULL, op->key, op->iv);
      EVP_DecryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_DecryptFinal_ex (ctx, op->dst + out_len, &out_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_hmac (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		  const EVP_MD * md)
{
  u8 buffer[64];
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  HMAC_CTX *ctx = ptd->hmac_ctx;
  u32 i, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      unsigned int out_len;
      size_t sz = op->hmac_trunc_len ? op->hmac_trunc_len : EVP_MD_size (md);

      HMAC_Init_ex (ctx, op->key, op->key_len, md, NULL);
      HMAC_Update (ctx, op->src, op->len);
      HMAC_Final (ctx, buffer, &out_len);

      if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	{
	  if ((memcmp (op->dst, buffer, sz)))
	    {
	      n_fail++;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      continue;
	    }
	}
      else
	clib_memcpy_fast (op->dst, buffer, sz);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
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

#define _(a, b) \
static u32 \
openssl_ops_hmac_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return openssl_ops_hmac (vm, ops, n_ops, b ()); } \

foreach_openssl_hmac_op;
#undef _


clib_error_t *
crypto_openssl_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  openssl_per_thread_data_t *ptd;
  u8 *seed_data = 0;
  time_t t;
  pid_t pid;

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

#define _(a, b) \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
				    openssl_ops_hmac_##a); \

  foreach_openssl_hmac_op;
#undef _

  vec_validate_aligned (per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vec_foreach (ptd, per_thread_data)
  {
    ptd->evp_cipher_ctx = EVP_CIPHER_CTX_new ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ptd->hmac_ctx = HMAC_CTX_new ();
#else
    HMAC_CTX_init (&(ptd->_hmac_ctx));
    ptd->hmac_ctx = &ptd->_hmac_ctx;
#endif
  }

  t = time (NULL);
  pid = getpid ();
  vec_add (seed_data, &t, sizeof (t));
  vec_add (seed_data, &pid, sizeof (pid));
  vec_add (seed_data, seed_data, sizeof (seed_data));

  RAND_seed ((const void *) seed_data, vec_len (seed_data));

  vec_free (seed_data);

  return 0;
}

VLIB_INIT_FUNCTION (crypto_openssl_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OpenSSL Crypto Engine Plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

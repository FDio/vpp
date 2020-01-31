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

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>
#include <crypto_native/aes.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

typedef struct
{
  u8x16 encrypt_key[15];
#if __VAES__
  __m512i decrypt_key[15];
#else
  u8x16 decrypt_key[15];
#endif
} aes_cbc_key_data_t;

#include <crypto_native/aes_cbc_aesni.h>
#include <crypto_native/aes_cbc_neon.h>

static_always_inline void *
aesni_cbc_key_exp (vnet_crypto_key_t * key, aes_key_size_t ks)
{
  u8x16 e[15], d[15];
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  aes_key_expand (e, key->data, ks);
  aes_key_enc_to_dec (e, d, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    {
#if __VAES__
      kd->decrypt_key[i] = _mm512_broadcast_i64x2 ((__m128i) d[i]);
#else
      kd->decrypt_key[i] = d[i];
#endif
      kd->encrypt_key[i] = e[i];
    }
  return kd;
}

#define foreach_aesni_cbc_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aesni_ops_dec_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_dec_aes_cbc (vm, ops, n_ops, AES_KEY_##x); } \
static u32 aesni_ops_enc_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_enc_aes_cbc (vm, ops, n_ops, AES_KEY_##x); } \
static void * aesni_cbc_key_exp_##x (vnet_crypto_key_t *key) \
{ return aesni_cbc_key_exp (key, AES_KEY_##x); }

foreach_aesni_cbc_handler_type;
#undef _

#include <fcntl.h>

clib_error_t *
#ifdef __VAES__
crypto_native_aes_cbc_init_vaes (vlib_main_t * vm)
#elif __AVX512F__
crypto_native_aes_cbc_init_avx512 (vlib_main_t * vm)
#elif __aarch64__
crypto_native_aes_cbc_init_neon (vlib_main_t * vm)
#elif __AVX2__
crypto_native_aes_cbc_init_avx2 (vlib_main_t * vm)
#else
crypto_native_aes_cbc_init_sse42 (vlib_main_t * vm)
#endif
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd;
  clib_error_t *err = 0;
  int fd;

  if ((fd = open ("/dev/urandom", O_RDONLY)) < 0)
    return clib_error_return_unix (0, "failed to open '/dev/urandom'");

  /* *INDENT-OFF* */
  vec_foreach (ptd, cm->per_thread_data)
    {
      for (int i = 0; i < 4; i++)
	{
	  if (read(fd, ptd->cbc_iv, sizeof (ptd->cbc_iv)) !=
	      sizeof (ptd->cbc_iv))
	    {
	      err = clib_error_return_unix (0, "'/dev/urandom' read failure");
	      goto error;
	    }
	}
    }
  /* *INDENT-ON* */

#define _(x) \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_CBC_ENC, \
				    aesni_ops_enc_aes_cbc_##x); \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_CBC_DEC, \
				    aesni_ops_dec_aes_cbc_##x); \
  cm->key_fn[VNET_CRYPTO_ALG_AES_##x##_CBC] = aesni_cbc_key_exp_##x;
  foreach_aesni_cbc_handler_type;
#undef _

error:
  close (fd);
  return err;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

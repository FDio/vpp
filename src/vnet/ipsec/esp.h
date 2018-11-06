/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
#ifndef __ESP_H__
#define __ESP_H__

#include <vnet/ip/ip.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/udp/udp.h>

typedef struct
{
  u32 spi;
  u32 seq;
  u8 data[0];
} esp_header_t;

typedef struct
{
  u8 pad_length;
  u8 next_header;
} esp_footer_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  esp_header_t esp;
}) ip4_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  udp_header_t udp;
  esp_header_t esp;
}) ip4_and_udp_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;
/* *INDENT-ON* */

u8 *format_esp_header (u8 * s, va_list * args);

always_inline void
ipsec_proto_init ()
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  clib_memset (em, 0, sizeof (em[0]));

  vec_validate (em->ipsec_proto_main_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].type =
    EVP_aes_128_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].type =
    EVP_aes_192_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].type =
    EVP_aes_256_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].iv_size = 16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].iv_size = 16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].iv_size = 16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].block_size =
    16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].block_size =
    16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].block_size =
    16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].type =
    EVP_des_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].type =
    EVP_des_ede3_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].block_size = 8;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].block_size = 8;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].iv_size = 8;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].iv_size = 8;

  vec_validate (em->ipsec_proto_main_integ_algs, IPSEC_INTEG_N_ALG - 1);
  ipsec_proto_main_integ_alg_t *i;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->md = EVP_sha1 ();
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256 ();
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256 ();
  i->trunc_size = 16;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384 ();
  i->trunc_size = 24;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512 ();
  i->trunc_size = 32;

  vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  int thread_id;

  for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      em->per_thread_data[thread_id].encrypt_ctx = EVP_CIPHER_CTX_new ();
      em->per_thread_data[thread_id].decrypt_ctx = EVP_CIPHER_CTX_new ();
#else
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].encrypt_ctx));
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].decrypt_ctx));
#endif
    }
}

always_inline int
esp_cipher (ipsec_proto_main_t * em, ipsec_crypto_alg_t alg, u8 * src,
	    u8 * dst, int len, u8 * key, u8 * iv, int is_encrypt)
{
  u32 thread_index = vlib_get_thread_index ();
  EVP_CIPHER_CTX *ctx;
  if (is_encrypt)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      ctx = em->per_thread_data[thread_index].encrypt_ctx;
#else
      ctx = &(em->per_thread_data[thread_index].encrypt_ctx);
#endif
    }
  else
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      ctx = em->per_thread_data[thread_index].decrypt_ctx;
#else
      ctx = &(em->per_thread_data[thread_index].decrypt_ctx);
#endif
    }
  const EVP_CIPHER *cipher = NULL;
  int out_len;

  if (PREDICT_FALSE (em->ipsec_proto_main_crypto_algs[alg].type == 0))
    {
      return 0;
    }

  if (is_encrypt)
    {
      if (PREDICT_FALSE
	  (alg != em->per_thread_data[thread_index].last_encrypt_alg))
	{
	  cipher = em->ipsec_proto_main_crypto_algs[alg].type;
	  em->per_thread_data[thread_index].last_encrypt_alg = alg;
	}
    }
  else
    {
      if (PREDICT_FALSE
	  (alg != em->per_thread_data[thread_index].last_decrypt_alg))
	{
	  cipher = em->ipsec_proto_main_crypto_algs[alg].type;
	  em->per_thread_data[thread_index].last_decrypt_alg = alg;
	}
    }
  const int block_size = em->ipsec_proto_main_crypto_algs[alg].block_size;

  int rv;
  if (is_encrypt)
    rv = EVP_EncryptInit_ex (ctx, cipher, NULL, key, iv);
  else
    rv = EVP_DecryptInit_ex (ctx, cipher, NULL, key, iv);
  if (!rv)
    return 0;

  EVP_CIPHER_CTX_set_padding (ctx, 0);

  static u8 *tmp = 0;
  if ((dst >= src && dst < src + len) || (src >= dst && src < dst + len))
    {
      /* sadly, openssl doesn't handle overlapping data */
      vec_validate (tmp, len);
      clib_memcpy_fast (tmp, src, len);
      src = tmp;
    }

  if (is_encrypt)
    rv = EVP_EncryptUpdate (ctx, dst, &out_len, src, len);
  else
    rv = EVP_DecryptUpdate (ctx, dst, &out_len, src, len);
  if (!rv)
    return 0;

  u8 dummy[block_size + 1];
  if (is_encrypt)
    rv = EVP_EncryptFinal_ex (ctx, dummy, &out_len);
  else
    rv = EVP_DecryptFinal_ex (ctx, dummy, &out_len);
  if (!rv)
    return 0;
  if (out_len != 0)
    return 0;			/* this really shouldn't happen, because padding is disabled */

  return 1;
}

void esp_encrypt_prepare_jobs (vlib_main_t * vm, u32 thread_index,
			       ipsec_main_t * im, ipsec_proto_main_t * em,
			       vlib_buffer_t ** b, ipsec_job_desc_t * job,
			       u32 n_jobs, int is_ip6,
			       int (*random_bytes) (u8 * dest, int len),
			       u32 next_index_drop, u32 next_index_ip4_lookup,
			       u32 next_index_ip6_lookup);

void
esp_encrypt_finish (vlib_main_t * vm, ipsec_main_t * im, u16 * next,
		    ipsec_job_desc_t * job, u32 n_jobs, int thread_index,
		    int is_ip6, u32 next_index_drop,
		    u32 next_index_interface_output);

void
esp_decrypt_prepare_jobs (vlib_main_t * vm, u32 thread_index,
			  ipsec_main_t * im, ipsec_proto_main_t * em,
			  vlib_buffer_t ** b, ipsec_job_desc_t * job,
			  u32 n_jobs, int is_ip6, u32 next_index_drop);

void
esp_decrypt_finish (vlib_main_t * vm, u16 * next, ipsec_job_desc_t * job,
		    u32 n_jobs, int is_ip6, u32 next_index_drop,
		    u32 next_index_ip4_input, u32 next_index_ip6_input,
		    u32 next_index_gre_input);

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

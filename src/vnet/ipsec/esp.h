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

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

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
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;
/* *INDENT-ON* */

typedef struct
{
  const EVP_CIPHER *type;
} esp_crypto_alg_t;

typedef struct
{
  const EVP_MD *md;
  u8 trunc_size;
} esp_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  EVP_CIPHER_CTX encrypt_ctx;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  EVP_CIPHER_CTX decrypt_ctx;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  HMAC_CTX hmac_ctx;
  ipsec_crypto_alg_t last_encrypt_alg;
  ipsec_crypto_alg_t last_decrypt_alg;
  ipsec_integ_alg_t last_integ_alg;
} esp_main_per_thread_data_t;

typedef struct
{
  esp_crypto_alg_t *esp_crypto_algs;
  esp_integ_alg_t *esp_integ_algs;
  esp_main_per_thread_data_t *per_thread_data;
} esp_main_t;

extern esp_main_t esp_main;

#define ESP_WINDOW_SIZE		(64)
#define ESP_SEQ_MAX 		(4294967295UL)

u8 *format_esp_header (u8 * s, va_list * args);

always_inline int
esp_replay_check (ipsec_sa_t * sa, u32 seq)
{
  u32 diff;

  if (PREDICT_TRUE (seq > sa->last_seq))
    return 0;

  diff = sa->last_seq - seq;

  if (ESP_WINDOW_SIZE > diff)
    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
  else
    return 1;

  return 0;
}

always_inline int
esp_replay_check_esn (ipsec_sa_t * sa, u32 seq)
{
  u32 tl = sa->last_seq;
  u32 th = sa->last_seq_hi;
  u32 diff = tl - seq;

  if (PREDICT_TRUE (tl >= (ESP_WINDOW_SIZE - 1)))
    {
      if (seq >= (tl - ESP_WINDOW_SIZE + 1))
	{
	  sa->seq_hi = th;
	  if (seq <= tl)
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	  else
	    return 0;
	}
      else
	{
	  sa->seq_hi = th + 1;
	  return 0;
	}
    }
  else
    {
      if (seq >= (tl - ESP_WINDOW_SIZE + 1))
	{
	  sa->seq_hi = th - 1;
	  return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	}
      else
	{
	  sa->seq_hi = th;
	  if (seq <= tl)
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	  else
	    return 0;
	}
    }

  return 0;
}

/* TODO seq increment should be atomic to be accessed by multiple workers */
always_inline void
esp_replay_advance (ipsec_sa_t * sa, u32 seq)
{
  u32 pos;

  if (seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < ESP_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

always_inline void
esp_replay_advance_esn (ipsec_sa_t * sa, u32 seq)
{
  int wrap = sa->seq_hi - sa->last_seq_hi;
  u32 pos;

  if (wrap == 0 && seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < ESP_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else if (wrap > 0)
    {
      pos = ~seq + sa->last_seq + 1;
      if (pos < ESP_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
      sa->last_seq_hi = sa->seq_hi;
    }
  else if (wrap < 0)
    {
      pos = ~seq + sa->last_seq + 1;
      sa->replay_window |= (1ULL << pos);
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

always_inline int
esp_seq_advance (ipsec_sa_t * sa)
{
  if (PREDICT_TRUE (sa->use_esn))
    {
      if (PREDICT_FALSE (sa->seq == ESP_SEQ_MAX))
	{
	  if (PREDICT_FALSE
	      (sa->use_anti_replay && sa->seq_hi == ESP_SEQ_MAX))
	    return 1;
	  sa->seq_hi++;
	}
      sa->seq++;
    }
  else
    {
      if (PREDICT_FALSE (sa->use_anti_replay && sa->seq == ESP_SEQ_MAX))
	return 1;
      sa->seq++;
    }

  return 0;
}

always_inline void
esp_init ()
{
  esp_main_t *em = &esp_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (em, 0, sizeof (em[0]));

  vec_validate (em->esp_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].type = EVP_aes_128_cbc ();
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].type = EVP_aes_192_cbc ();
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].type = EVP_aes_256_cbc ();

  vec_validate (em->esp_integ_algs, IPSEC_INTEG_N_ALG - 1);
  esp_integ_alg_t *i;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->md = EVP_sha1 ();
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256 ();
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256 ();
  i->trunc_size = 16;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384 ();
  i->trunc_size = 24;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512 ();
  i->trunc_size = 32;

  vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  int thread_id;

  for (thread_id = 0; thread_id < tm->n_vlib_mains - 1; thread_id++)
    {
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].encrypt_ctx));
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].decrypt_ctx));
      HMAC_CTX_init (&(em->per_thread_data[thread_id].hmac_ctx));
    }
}

always_inline unsigned int
hmac_calc (ipsec_integ_alg_t alg,
	   u8 * key,
	   int key_len,
	   u8 * data, int data_len, u8 * signature, u8 use_esn, u32 seq_hi)
{
  esp_main_t *em = &esp_main;
  u32 thread_index = vlib_get_thread_index ();
  HMAC_CTX *ctx = &(em->per_thread_data[thread_index].hmac_ctx);
  const EVP_MD *md = NULL;
  unsigned int len;

  ASSERT (alg < IPSEC_INTEG_N_ALG);

  if (PREDICT_FALSE (em->esp_integ_algs[alg].md == 0))
    return 0;

  if (PREDICT_FALSE (alg != em->per_thread_data[thread_index].last_integ_alg))
    {
      md = em->esp_integ_algs[alg].md;
      em->per_thread_data[thread_index].last_integ_alg = alg;
    }

  HMAC_Init (ctx, key, key_len, md);

  HMAC_Update (ctx, data, data_len);

  if (PREDICT_TRUE (use_esn))
    HMAC_Update (ctx, (u8 *) & seq_hi, sizeof (seq_hi));
  HMAC_Final (ctx, signature, &len);

  return em->esp_integ_algs[alg].trunc_size;
}

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

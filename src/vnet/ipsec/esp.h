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
      em->per_thread_data[thread_id].hmac_ctx = HMAC_CTX_new ();
#else
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].encrypt_ctx));
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].decrypt_ctx));
      HMAC_CTX_init (&(em->per_thread_data[thread_id].hmac_ctx));
#endif
    }
}

always_inline int
esp_cipher_cbc (vlib_main_t * vm, ipsec_crypto_alg_t alg, vlib_buffer_t * ib,
		u32 ib_offset, vlib_buffer_t * ob, u8 * key,
		u8 * iv, vlib_buffer_t ** last_ob, u32 * empty_buffers,
		int is_encrypt)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
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

  if (!EVP_CipherInit_ex (ctx, cipher, NULL, key, iv, is_encrypt))
    {
      return 0;
    }

  EVP_CIPHER_CTX_set_padding (ctx, 0);

  vlib_buffer_t *first_ob = ob;
  u32 total_length = ob->current_length;
  do
    {
      size_t in_length = ib->current_length - ib_offset;
      const size_t cipher_could_write = in_length + block_size - 1;
      size_t space_left_in_buffer =
	VLIB_BUFFER_DATA_SIZE - ((u8 *) vlib_buffer_get_current (ob) +
				 ob->current_length - ob->data);
      if (space_left_in_buffer < block_size)
	{
	  u32 last_empty_buffer = vec_len (empty_buffers) - 1;
	  u32 ebi = empty_buffers[last_empty_buffer];
	  vlib_buffer_t *eb = vlib_get_buffer (vm, ebi);
	  eb->current_data = 0;
	  eb->current_length = 0;
	  vlib_buffer_chain_buffer (vm, ob, ebi);
	  vlib_prefetch_buffer_with_index (vm,
					   empty_buffers[last_empty_buffer -
							 1], STORE);
	  _vec_len (empty_buffers) = last_empty_buffer;
	  ob = eb;
	  space_left_in_buffer =
	    VLIB_BUFFER_DATA_SIZE - ((u8 *) vlib_buffer_get_current (ob) +
				     ob->current_length - ob->data);
	}
      if (space_left_in_buffer < cipher_could_write)
	{
	  in_length -= cipher_could_write - space_left_in_buffer;
	}

      if (!EVP_CipherUpdate
	  (ctx, vlib_buffer_get_current (ob) + ob->current_length,
	   &out_len, vlib_buffer_get_current (ib) + ib_offset, in_length))
	{
	  return 0;
	}
      total_length += out_len;
      ob->current_length += out_len;
      ib_offset += in_length;

      if (ib_offset == ib->current_length
	  && ib->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  ib = vlib_get_buffer (vm, ib->next_buffer);
	  ib_offset = 0;
	}
    }
  while (ib_offset < ib->current_length
	 || ib->flags & VLIB_BUFFER_NEXT_PRESENT);


  u8 dummy[block_size + 1];
  if (!EVP_CipherFinal_ex (ctx, dummy, &out_len))
    {
      return 0;
    }
  if (out_len != 0)
    {
      /* this really shouldn't happen, because padding is disabled */
      return 0;
    }

  if (ob != first_ob)
    {
      first_ob->total_length_not_including_first_buffer =
	total_length - first_ob->current_length;
      first_ob->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
#if 0
      u32 x = vlib_buffer_length_in_chain (vm, first_ob);
      first_ob->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
      u32 y = vlib_buffer_length_in_chain (vm, first_ob);
      ASSERT (x == y);
#endif
    }
  if (last_ob)
    {
      *last_ob = ob;
    }
  return 1;
}

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

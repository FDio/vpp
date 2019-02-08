/*
 * ipsec.c : IPSEC module functions
 *
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/udp/udp.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>

ipsec_main_t ipsec_main;

static void
ipsec_rand_seed (void)
{
  struct
  {
    time_t time;
    pid_t pid;
    void *p;
  } seed_data;

  seed_data.time = time (NULL);
  seed_data.pid = getpid ();
  seed_data.p = (void *) &seed_data;

  RAND_seed ((const void *) &seed_data, sizeof (seed_data));
}

static clib_error_t *
ipsec_check_ah_support (ipsec_sa_t * sa)
{
  if (sa->integ_alg == IPSEC_INTEG_ALG_NONE)
    return clib_error_return (0, "unsupported none integ-alg");
  return 0;
}

static clib_error_t *
ipsec_check_esp_support (ipsec_sa_t * sa)
{
  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
    return clib_error_return (0, "unsupported aes-gcm-128 crypto-alg");
  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_192)
    return clib_error_return (0, "unsupported aes-gcm-192 crypto-alg");
  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_256)
    return clib_error_return (0, "unsupported aes-gcm-256 crypto-alg");

  return 0;
}

clib_error_t *
ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index, u8 is_add)
{
  ipsec_ah_backend_t *ah =
    pool_elt_at_index (im->ah_backends, im->ah_current_backend);
  if (ah->add_del_sa_sess_cb)
    {
      clib_error_t *err = ah->add_del_sa_sess_cb (sa_index, is_add);
      if (err)
	return err;
    }
  ipsec_esp_backend_t *esp =
    pool_elt_at_index (im->esp_backends, im->esp_current_backend);
  if (esp->add_del_sa_sess_cb)
    {
      clib_error_t *err = esp->add_del_sa_sess_cb (sa_index, is_add);
      if (err)
	return err;
    }
  return 0;
}

clib_error_t *
ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa)
{
  clib_error_t *error = 0;

  if (PREDICT_FALSE (sa->protocol == IPSEC_PROTOCOL_AH))
    {
      ipsec_ah_backend_t *ah =
	pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      ASSERT (ah->check_support_cb);
      error = ah->check_support_cb (sa);
    }
  else
    {
      ipsec_esp_backend_t *esp =
	pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      ASSERT (esp->check_support_cb);
      error = esp->check_support_cb (sa);
    }
  return error;
}


static void
ipsec_add_node (vlib_main_t * vm, const char *node_name,
		const char *prev_node_name, u32 * out_node_index,
		u32 * out_next_index)
{
  vlib_node_t *prev_node, *node;
  prev_node = vlib_get_node_by_name (vm, (u8 *) prev_node_name);
  ASSERT (prev_node);
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  ASSERT (node);
  *out_node_index = node->index;
  *out_next_index = vlib_node_add_next (vm, prev_node->index, node->index);
}

u32
ipsec_register_ah_backend (vlib_main_t * vm, ipsec_main_t * im,
			   const char *name,
			   const char *ah4_encrypt_node_name,
			   const char *ah4_decrypt_node_name,
			   const char *ah6_encrypt_node_name,
			   const char *ah6_decrypt_node_name,
			   check_support_cb_t ah_check_support_cb,
			   add_del_sa_sess_cb_t ah_add_del_sa_sess_cb)
{
  ipsec_ah_backend_t *b;
  pool_get (im->ah_backends, b);
  b->name = format (NULL, "%s", name);

  ipsec_add_node (vm, ah4_encrypt_node_name, "ipsec4-output-feature",
		  &b->ah4_encrypt_node_index, &b->ah4_encrypt_next_index);
  ipsec_add_node (vm, ah4_decrypt_node_name, "ipsec4-input-feature",
		  &b->ah4_decrypt_node_index, &b->ah4_decrypt_next_index);
  ipsec_add_node (vm, ah6_encrypt_node_name, "ipsec6-output-feature",
		  &b->ah6_encrypt_node_index, &b->ah6_encrypt_next_index);
  ipsec_add_node (vm, ah6_decrypt_node_name, "ipsec6-input-feature",
		  &b->ah6_decrypt_node_index, &b->ah6_decrypt_next_index);

  b->check_support_cb = ah_check_support_cb;
  b->add_del_sa_sess_cb = ah_add_del_sa_sess_cb;
  return b - im->ah_backends;
}

u32
ipsec_register_esp_backend (vlib_main_t * vm, ipsec_main_t * im,
			    const char *name,
			    const char *esp4_encrypt_node_name,
			    const char *esp4_decrypt_node_name,
			    const char *esp6_encrypt_node_name,
			    const char *esp6_decrypt_node_name,
			    check_support_cb_t esp_check_support_cb,
			    add_del_sa_sess_cb_t esp_add_del_sa_sess_cb)
{
  ipsec_esp_backend_t *b;
  pool_get (im->esp_backends, b);
  b->name = format (NULL, "%s", name);

  ipsec_add_node (vm, esp4_encrypt_node_name, "ipsec4-output-feature",
		  &b->esp4_encrypt_node_index, &b->esp4_encrypt_next_index);
  ipsec_add_node (vm, esp4_decrypt_node_name, "ipsec4-input-feature",
		  &b->esp4_decrypt_node_index, &b->esp4_decrypt_next_index);
  ipsec_add_node (vm, esp6_encrypt_node_name, "ipsec6-output-feature",
		  &b->esp6_encrypt_node_index, &b->esp6_encrypt_next_index);
  ipsec_add_node (vm, esp6_decrypt_node_name, "ipsec6-input-feature",
		  &b->esp6_decrypt_node_index, &b->esp6_decrypt_next_index);

  b->check_support_cb = esp_check_support_cb;
  b->add_del_sa_sess_cb = esp_add_del_sa_sess_cb;
  return b - im->esp_backends;
}

int
ipsec_select_ah_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (pool_elts (im->sad) > 0
      || pool_is_free_index (im->ah_backends, backend_idx))
    {
      return -1;
    }
  ipsec_ah_backend_t *b = pool_elt_at_index (im->ah_backends, backend_idx);
  im->ah_current_backend = backend_idx;
  im->ah4_encrypt_node_index = b->ah4_encrypt_node_index;
  im->ah4_decrypt_node_index = b->ah4_decrypt_node_index;
  im->ah4_encrypt_next_index = b->ah4_encrypt_next_index;
  im->ah4_decrypt_next_index = b->ah4_decrypt_next_index;
  im->ah6_encrypt_node_index = b->ah6_encrypt_node_index;
  im->ah6_decrypt_node_index = b->ah6_decrypt_node_index;
  im->ah6_encrypt_next_index = b->ah6_encrypt_next_index;
  im->ah6_decrypt_next_index = b->ah6_decrypt_next_index;
  return 0;
}

int
ipsec_select_esp_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (pool_elts (im->sad) > 0
      || pool_is_free_index (im->esp_backends, backend_idx))
    {
      return -1;
    }
  ipsec_esp_backend_t *b = pool_elt_at_index (im->esp_backends, backend_idx);
  im->esp_current_backend = backend_idx;
  im->esp4_encrypt_node_index = b->esp4_encrypt_node_index;
  im->esp4_decrypt_node_index = b->esp4_decrypt_node_index;
  im->esp4_encrypt_next_index = b->esp4_encrypt_next_index;
  im->esp4_decrypt_next_index = b->esp4_decrypt_next_index;
  im->esp6_encrypt_node_index = b->esp6_encrypt_node_index;
  im->esp6_decrypt_node_index = b->esp6_decrypt_node_index;
  im->esp6_encrypt_next_index = b->esp6_encrypt_next_index;
  im->esp6_decrypt_next_index = b->esp6_decrypt_next_index;
  return 0;
}

static void
ipsec_proto_init (void)
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
  i->padding_len[0] = ah_calc_icv_padding_len (i->trunc_size, 0);
  i->padding_len[1] = ah_calc_icv_padding_len (i->trunc_size, 1);

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256 ();
  i->trunc_size = 12;
  i->padding_len[0] = ah_calc_icv_padding_len (i->trunc_size, 0);
  i->padding_len[1] = ah_calc_icv_padding_len (i->trunc_size, 1);

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256 ();
  i->trunc_size = 16;
  i->padding_len[0] = ah_calc_icv_padding_len (i->trunc_size, 0);
  i->padding_len[1] = ah_calc_icv_padding_len (i->trunc_size, 1);

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384 ();
  i->trunc_size = 24;
  i->padding_len[0] = ah_calc_icv_padding_len (i->trunc_size, 0);
  i->padding_len[1] = ah_calc_icv_padding_len (i->trunc_size, 1);

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512 ();
  i->trunc_size = 32;
  i->padding_len[0] = ah_calc_icv_padding_len (i->trunc_size, 0);
  i->padding_len[1] = ah_calc_icv_padding_len (i->trunc_size, 1);

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

static clib_error_t *
ipsec_init (vlib_main_t * vm)
{
  clib_error_t *error;
  ipsec_main_t *im = &ipsec_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  ipsec_rand_seed ();

  clib_memset (im, 0, sizeof (im[0]));

  im->vnet_main = vnet_get_main ();
  im->vlib_main = vm;

  im->spd_index_by_spd_id = hash_create (0, sizeof (uword));
  im->sa_index_by_sa_id = hash_create (0, sizeof (uword));
  im->spd_index_by_sw_if_index = hash_create (0, sizeof (uword));

  vec_validate_aligned (im->empty_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  ASSERT (node);
  im->error_drop_node_index = node->index;

  u32 idx = ipsec_register_ah_backend (vm, im, "default openssl backend",
				       "ah4-encrypt",
				       "ah4-decrypt",
				       "ah6-encrypt",
				       "ah6-decrypt",
				       ipsec_check_ah_support,
				       NULL);

  im->ah_default_backend = idx;
  int rv = ipsec_select_ah_backend (im, idx);
  ASSERT (0 == rv);
  (void) (rv);			// avoid warning

  idx = ipsec_register_esp_backend (vm, im, "default openssl backend",
				    "esp4-encrypt",
				    "esp4-decrypt",
				    "esp6-encrypt",
				    "esp6-decrypt",
				    ipsec_check_esp_support, NULL);
  im->esp_default_backend = idx;

  rv = ipsec_select_esp_backend (im, idx);
  ASSERT (0 == rv);
  (void) (rv);			// avoid warning

  if ((error = vlib_call_init_function (vm, ipsec_cli_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ipsec_tunnel_if_init)))
    return error;

  ipsec_proto_init ();

  if ((error = ikev2_init (vm)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>

ipsec_main_t ipsec_main;

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

static void
ipsec_add_feature (const char *arc_name,
		   const char *node_name, u32 * out_feature_index)
{
  u8 arc;

  arc = vnet_get_feature_arc_index (arc_name);
  *out_feature_index = vnet_get_feature_index (arc, node_name);
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
  b->name = format (0, "%s%c", name, 0);

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
			    const char *esp4_encrypt_node_tun_name,
			    const char *esp4_decrypt_node_name,
			    const char *esp6_encrypt_node_name,
			    const char *esp6_encrypt_node_tun_name,
			    const char *esp6_decrypt_node_name,
			    check_support_cb_t esp_check_support_cb,
			    add_del_sa_sess_cb_t esp_add_del_sa_sess_cb)
{
  ipsec_esp_backend_t *b;

  pool_get (im->esp_backends, b);
  b->name = format (0, "%s%c", name, 0);

  ipsec_add_node (vm, esp4_encrypt_node_name, "ipsec4-output-feature",
		  &b->esp4_encrypt_node_index, &b->esp4_encrypt_next_index);
  ipsec_add_node (vm, esp4_decrypt_node_name, "ipsec4-input-feature",
		  &b->esp4_decrypt_node_index, &b->esp4_decrypt_next_index);
  ipsec_add_node (vm, esp6_encrypt_node_name, "ipsec6-output-feature",
		  &b->esp6_encrypt_node_index, &b->esp6_encrypt_next_index);
  ipsec_add_node (vm, esp6_decrypt_node_name, "ipsec6-input-feature",
		  &b->esp6_decrypt_node_index, &b->esp6_decrypt_next_index);

  ipsec_add_feature ("ip4-output", esp4_encrypt_node_tun_name,
		     &b->esp4_encrypt_tun_feature_index);
  ipsec_add_feature ("ip6-output", esp6_encrypt_node_tun_name,
		     &b->esp6_encrypt_tun_feature_index);

  b->check_support_cb = esp_check_support_cb;
  b->add_del_sa_sess_cb = esp_add_del_sa_sess_cb;
  return b - im->esp_backends;
}

clib_error_t *
ipsec_rsc_in_use (ipsec_main_t * im)
{
  /* return an error is crypto resource are in use */
  if (pool_elts (im->sad) > 0)
    return clib_error_return (0,
			      "%d SA entries configured",
			      pool_elts (im->sad));

  if (pool_elts (im->tunnel_interfaces))
    return clib_error_return (0,
			      "%d tunnel-interface entries configured",
			      pool_elts (im->tunnel_interfaces));

  return (NULL);
}

int
ipsec_select_ah_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (ipsec_rsc_in_use (im))
    return VNET_API_ERROR_RSRC_IN_USE;

  if (pool_is_free_index (im->ah_backends, backend_idx))
    return VNET_API_ERROR_INVALID_VALUE;

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
  if (ipsec_rsc_in_use (im))
    return VNET_API_ERROR_RSRC_IN_USE;

  if (pool_is_free_index (im->esp_backends, backend_idx))
    return VNET_API_ERROR_INVALID_VALUE;

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

  im->esp4_encrypt_tun_feature_index = b->esp4_encrypt_tun_feature_index;
  im->esp6_encrypt_tun_feature_index = b->esp6_encrypt_tun_feature_index;

  return 0;
}

static clib_error_t *
ipsec_init (vlib_main_t * vm)
{
  clib_error_t *error;
  ipsec_main_t *im = &ipsec_main;
  ipsec_main_crypto_alg_t *a;

  im->vnet_main = vnet_get_main ();
  im->vlib_main = vm;

  im->spd_index_by_spd_id = hash_create (0, sizeof (uword));
  im->sa_index_by_sa_id = hash_create (0, sizeof (uword));
  im->spd_index_by_sw_if_index = hash_create (0, sizeof (uword));

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
				    "esp4-encrypt-tun",
				    "esp4-decrypt",
				    "esp6-encrypt",
				    "esp6-encrypt-tun",
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

  vec_validate (im->crypto_algs, IPSEC_CRYPTO_N_ALG - 1);

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_DES_CBC;
  a->enc_op_id = VNET_CRYPTO_OP_DES_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_DES_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_DES_CBC;
  a->iv_size = a->block_size = 8;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_3DES_CBC;
  a->enc_op_id = VNET_CRYPTO_OP_3DES_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_3DES_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_3DES_CBC;
  a->iv_size = a->block_size = 8;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CBC_128;
  a->enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_128_CBC;
  a->iv_size = a->block_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CBC_192;
  a->enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_192_CBC;
  a->iv_size = a->block_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CBC_256;
  a->enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_256_CBC;
  a->iv_size = a->block_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_GCM_128;
  a->enc_op_id = VNET_CRYPTO_OP_AES_128_GCM_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_128_GCM_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_128_GCM;
  a->iv_size = a->block_size = 8;
  a->icv_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_GCM_192;
  a->enc_op_id = VNET_CRYPTO_OP_AES_192_GCM_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_192_GCM_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_192_GCM;
  a->iv_size = a->block_size = 8;
  a->icv_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_GCM_256;
  a->enc_op_id = VNET_CRYPTO_OP_AES_256_GCM_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_256_GCM_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_256_GCM;
  a->iv_size = a->block_size = 8;
  a->icv_size = 16;

  vec_validate (im->integ_algs, IPSEC_INTEG_N_ALG - 1);
  ipsec_main_integ_alg_t *i;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->op_id = VNET_CRYPTO_OP_SHA1_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA1;
  i->icv_size = 12;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->op_id = VNET_CRYPTO_OP_SHA1_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA256;
  i->icv_size = 12;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->op_id = VNET_CRYPTO_OP_SHA256_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA256;
  i->icv_size = 16;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->op_id = VNET_CRYPTO_OP_SHA384_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA384;
  i->icv_size = 24;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->op_id = VNET_CRYPTO_OP_SHA512_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA512;
  i->icv_size = 32;

  vec_validate_aligned (im->ptd, vlib_num_workers (), CLIB_CACHE_LINE_BYTES);

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

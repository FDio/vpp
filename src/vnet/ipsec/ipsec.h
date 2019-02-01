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
#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_policy.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/ipsec/ipsec_if.h>
#include <vnet/ipsec/ipsec_io.h>

typedef clib_error_t *(*add_del_sa_sess_cb_t) (u32 sa_index, u8 is_add);
typedef clib_error_t *(*check_support_cb_t) (ipsec_sa_t * sa);

typedef struct
{
  u8 *name;
  /* add/del callback */
  add_del_sa_sess_cb_t add_del_sa_sess_cb;
  /* check support function */
  check_support_cb_t check_support_cb;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  u32 ah6_encrypt_next_index;
  u32 ah6_decrypt_next_index;
} ipsec_ah_backend_t;

typedef struct
{
  u8 *name;
  /* add/del callback */
  add_del_sa_sess_cb_t add_del_sa_sess_cb;
  /* check support function */
  check_support_cb_t check_support_cb;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
} ipsec_esp_backend_t;

typedef struct
{
  const EVP_CIPHER *type;
  u8 iv_size;
  u8 block_size;
} ipsec_proto_main_crypto_alg_t;

typedef struct
{
  const EVP_MD *md;
  u8 trunc_size;
} ipsec_proto_main_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *encrypt_ctx;
#else
  EVP_CIPHER_CTX encrypt_ctx;
#endif
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *decrypt_ctx;
#else
  EVP_CIPHER_CTX decrypt_ctx;
#endif
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX *hmac_ctx;
#else
  HMAC_CTX hmac_ctx;
#endif
  ipsec_crypto_alg_t last_encrypt_alg;
  ipsec_crypto_alg_t last_decrypt_alg;
  ipsec_integ_alg_t last_integ_alg;
} ipsec_proto_main_per_thread_data_t;

typedef struct
{
  ipsec_proto_main_crypto_alg_t *ipsec_proto_main_crypto_algs;
  ipsec_proto_main_integ_alg_t *ipsec_proto_main_integ_algs;
  ipsec_proto_main_per_thread_data_t *per_thread_data;
} ipsec_proto_main_t;

extern ipsec_proto_main_t ipsec_proto_main;

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  ipsec_sa_t *sad;

  /* pool of tunnel interfaces */
  ipsec_tunnel_if_t *tunnel_interfaces;
  u32 *free_tunnel_if_indices;

  u32 **empty_buffers;

  uword *tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* next node indices */
  u32 feature_next_node_index[32];

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;

  /* node indices */
  u32 error_drop_node_index;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  /* next node indices */
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
  u32 ah6_encrypt_next_index;
  u32 ah6_decrypt_next_index;

  /* pool of ah backends */
  ipsec_ah_backend_t *ah_backends;
  /* pool of esp backends */
  ipsec_esp_backend_t *esp_backends;
  /* index of current ah backend */
  u32 ah_current_backend;
  /* index of current esp backend */
  u32 esp_current_backend;
  /* index of default ah backend */
  u32 ah_default_backend;
  /* index of default esp backend */
  u32 esp_default_backend;

  /* helper for sort function */
  ipsec_spd_t *spd_to_sort;
} ipsec_main_t;

extern ipsec_main_t ipsec_main;

clib_error_t *ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index,
					u8 is_add);

clib_error_t *ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa);

extern vlib_node_registration_t esp4_encrypt_node;
extern vlib_node_registration_t esp4_decrypt_node;
extern vlib_node_registration_t ah4_encrypt_node;
extern vlib_node_registration_t ah4_decrypt_node;
extern vlib_node_registration_t esp6_encrypt_node;
extern vlib_node_registration_t esp6_decrypt_node;
extern vlib_node_registration_t ah6_encrypt_node;
extern vlib_node_registration_t ah6_decrypt_node;
extern vlib_node_registration_t ipsec_if_input_node;

/*
 * functions
 */
u8 *format_ipsec_replay_window (u8 * s, va_list * args);

/*
 *  inline functions
 */

always_inline void
ipsec_alloc_empty_buffers (vlib_main_t * vm, ipsec_main_t * im)
{
  u32 thread_index = vm->thread_index;
  uword l = vec_len (im->empty_buffers[thread_index]);
  uword n_alloc = 0;

  if (PREDICT_FALSE (l < VLIB_FRAME_SIZE))
    {
      if (!im->empty_buffers[thread_index])
	{
	  vec_alloc (im->empty_buffers[thread_index], 2 * VLIB_FRAME_SIZE);
	}

      n_alloc = vlib_buffer_alloc (vm, im->empty_buffers[thread_index] + l,
				   2 * VLIB_FRAME_SIZE - l);

      _vec_len (im->empty_buffers[thread_index]) = l + n_alloc;
    }
}

static_always_inline u32
get_next_output_feature_node_index (vlib_buffer_t * b,
				    vlib_node_runtime_t * nr)
{
  u32 next;
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *node = vlib_get_node (vm, nr->node_index);

  vnet_feature_next (&next, b);
  return node->next_nodes[next];
}

u32 ipsec_register_ah_backend (vlib_main_t * vm, ipsec_main_t * im,
			       const char *name,
			       const char *ah4_encrypt_node_name,
			       const char *ah4_decrypt_node_name,
			       const char *ah6_encrypt_node_name,
			       const char *ah6_decrypt_node_name,
			       check_support_cb_t ah_check_support_cb,
			       add_del_sa_sess_cb_t ah_add_del_sa_sess_cb);

u32 ipsec_register_esp_backend (vlib_main_t * vm, ipsec_main_t * im,
				const char *name,
				const char *esp4_encrypt_node_name,
				const char *esp4_decrypt_node_name,
				const char *esp6_encrypt_node_name,
				const char *esp6_decrypt_node_name,
				check_support_cb_t esp_check_support_cb,
				add_del_sa_sess_cb_t esp_add_del_sa_sess_cb);

int ipsec_select_ah_backend (ipsec_main_t * im, u32 ah_backend_idx);
int ipsec_select_esp_backend (ipsec_main_t * im, u32 esp_backend_idx);
#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

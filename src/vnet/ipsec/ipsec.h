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
#include <vnet/crypto/crypto.h>
#include <vnet/feature/feature.h>

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_policy.h>
#include <vnet/ipsec/ipsec_sa.h>

typedef clib_error_t *(*add_del_sa_sess_cb_t) (u32 sa_index, u8 is_add);
typedef clib_error_t *(*check_support_cb_t) (ipsec_sa_t * sa);
typedef clib_error_t *(*enable_disable_cb_t) (int is_enable);

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
  /* enable or disable function */
  enable_disable_cb_t enable_disable_cb;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
  u32 esp4_decrypt_tun_node_index;
  u32 esp4_decrypt_tun_next_index;
  u32 esp4_encrypt_tun_node_index;
  u32 esp6_decrypt_tun_node_index;
  u32 esp6_decrypt_tun_next_index;
  u32 esp6_encrypt_tun_node_index;
} ipsec_esp_backend_t;

typedef struct
{
  vnet_crypto_op_id_t enc_op_id;
  vnet_crypto_op_id_t dec_op_id;
  vnet_crypto_alg_t alg;
  u8 iv_size;
  u8 block_size;
  u8 icv_size;
} ipsec_main_crypto_alg_t;

typedef struct
{
  vnet_crypto_op_id_t op_id;
  vnet_crypto_alg_t alg;
  u8 icv_size;
} ipsec_main_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *integ_ops;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_t *chained_integ_ops;
  vnet_crypto_op_chunk_t *chunks;
} ipsec_per_thread_data_t;

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  /* Pool of security associations */
  ipsec_sa_t *sad;
  /* pool of policies */
  ipsec_policy_t *policies;

  /* hash tables of UDP port registrations */
  uword *udp_port_registrations;

  uword *tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec4_if_pool_index_by_key;
  uword *ipsec6_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;
  uword *ipsec_if_by_sw_if_index;
  uword *tun4_protect_by_key;
  uword *tun6_protect_by_key;

  /* node indices */
  u32 error_drop_node_index;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_decrypt_tun_node_index;
  u32 esp4_encrypt_tun_node_index;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_decrypt_tun_node_index;
  u32 esp6_encrypt_tun_node_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  /* next node indices */
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp4_decrypt_tun_next_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
  u32 esp6_decrypt_tun_next_index;
  u32 ah6_encrypt_next_index;
  u32 ah6_decrypt_next_index;

  /* tun nodes to drop packets when no crypto alg set on outbound SA */
  u32 esp4_no_crypto_tun_node_index;
  u32 esp6_no_crypto_tun_node_index;

  /* tun nodes for encrypt on L2 interfaces */
  u32 esp4_encrypt_l2_tun_node_index;
  u32 esp6_encrypt_l2_tun_node_index;

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

  /* crypto alg data */
  ipsec_main_crypto_alg_t *crypto_algs;

  /* crypto integ data */
  ipsec_main_integ_alg_t *integ_algs;

  /* per-thread data */
  ipsec_per_thread_data_t *ptd;

  /** Worker handoff */
  u32 ah4_enc_fq_index;
  u32 ah4_dec_fq_index;
  u32 ah6_enc_fq_index;
  u32 ah6_dec_fq_index;

  u32 esp4_enc_fq_index;
  u32 esp4_dec_fq_index;
  u32 esp6_enc_fq_index;
  u32 esp6_dec_fq_index;
  u32 esp4_enc_tun_fq_index;
  u32 esp6_enc_tun_fq_index;
  u32 esp4_dec_tun_fq_index;
  u32 esp6_dec_tun_fq_index;

  u8 async_mode;
} ipsec_main_t;

typedef enum ipsec_format_flags_t_
{
  IPSEC_FORMAT_BRIEF = 0,
  IPSEC_FORMAT_DETAIL = (1 << 0),
  IPSEC_FORMAT_INSECURE = (1 << 1),
} ipsec_format_flags_t;

extern ipsec_main_t ipsec_main;

clib_error_t *ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index,
					u8 is_add);

clib_error_t *ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa);

extern vlib_node_registration_t ah4_encrypt_node;
extern vlib_node_registration_t ah4_decrypt_node;
extern vlib_node_registration_t ah6_encrypt_node;
extern vlib_node_registration_t ah6_decrypt_node;
extern vlib_node_registration_t esp4_encrypt_node;
extern vlib_node_registration_t esp4_decrypt_node;
extern vlib_node_registration_t esp6_encrypt_node;
extern vlib_node_registration_t esp6_decrypt_node;
extern vlib_node_registration_t esp4_encrypt_tun_node;
extern vlib_node_registration_t esp6_encrypt_tun_node;
extern vlib_node_registration_t esp4_decrypt_tun_node;
extern vlib_node_registration_t esp6_decrypt_tun_node;
extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

/*
 * functions
 */
u8 *format_ipsec_replay_window (u8 * s, va_list * args);

/*
 *  inline functions
 */

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
				const char *esp4_encrypt_tun_node_name,
				const char *esp4_decrypt_node_name,
				const char *esp4_decrypt_tun_node_name,
				const char *esp6_encrypt_node_name,
				const char *esp6_encrypt_tun_node_name,
				const char *esp6_decrypt_node_name,
				const char *esp6_decrypt_tun_node_name,
				check_support_cb_t esp_check_support_cb,
				add_del_sa_sess_cb_t esp_add_del_sa_sess_cb,
				enable_disable_cb_t enable_disable_cb);

int ipsec_select_ah_backend (ipsec_main_t * im, u32 ah_backend_idx);
int ipsec_select_esp_backend (ipsec_main_t * im, u32 esp_backend_idx);

clib_error_t *ipsec_rsc_in_use (ipsec_main_t * im);
void ipsec_set_async_mode (u32 is_enabled);

always_inline ipsec_sa_t *
ipsec_sa_get (u32 sa_index)
{
  return (pool_elt_at_index (ipsec_main.sad, sa_index));
}

void ipsec_add_feature (const char *arc_name, const char *node_name,
			u32 * out_feature_index);

void ipsec_set_async_mode (u32 is_enabled);
extern void ipsec_register_udp_port (u16 udp_port);
extern void ipsec_unregister_udp_port (u16 udp_port);

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
